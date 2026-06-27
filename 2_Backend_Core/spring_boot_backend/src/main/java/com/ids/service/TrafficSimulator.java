package com.ids.service;

import com.ids.model.IoTDevice;
import com.ids.model.Packet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * TrafficSimulator — IoT network traffic simulation and detection engine.
 * Simulates CIC-IoT 2023 dataset traffic for 3 physical IoT devices:
 *   - ESP32 Gateway (192.168.4.1)
 *   - ESP32-CAM     (192.168.4.2)
 *   - DHT11 Sensor  (192.168.4.3)
 *
 * Traffic Distribution (based on CIC-IoT 2023 dataset ratios):
 *   60% BENIGN    — Normal MQTT/CoAP sensor data
 *   18% UDP_FLOOD — Volumetric DDoS on ESP32-CAM
 *    8% DATA_SNIFF — DHT11 sensor data interception
 *    7% ARP_SPOOF  — Gateway MAC table poisoning
 *    7% PORT_SCAN  — TCP SYN recon
 *
 * Device State Machine:
 *   ONLINE → [3+ hits] → UNDER_ATTACK → [8+ hits] → OFFLINE
 *   OFFLINE → [15s no attacks] → ONLINE (auto-recovery)
 */
@Service
@Slf4j
public class TrafficSimulator {

    private final SimpMessagingTemplate ws;
    private final TelegramAlertService telegramAlertService;
    private final Random rng               = new Random();
    private final AtomicBoolean running    = new AtomicBoolean(false); // OFF by default — only real ESP32 data shown
    private final AtomicInteger tickCount  = new AtomicInteger(0);

    private final Map<String, Integer> attackHits   = new ConcurrentHashMap<>();
    private final Map<String, Long>    lastAttackMs = new ConcurrentHashMap<>();
    // Sliding-window attack timestamps per device (for rate-based IDS threshold)
    private final Map<String, Deque<Long>> attackTimestamps = new ConcurrentHashMap<>();
    // IDS threshold constants
    // IDS threshold constants (Telegram Alert Threshold: 5 seconds continuous)
    private static final int  ATTACK_THRESHOLD_COUNT   = 5;      // need 5 detections...
    private static final long ATTACK_THRESHOLD_WINDOW  = 5_000;  // ...within this 5s window
    private static final long RECOVERY_CLEAN_WINDOW    = 15_000; // clear after this ms of no attacks

    // 3 real IoT devices only
    private final Map<String, IoTDevice> devices = new LinkedHashMap<>();

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    // Device IPs matching physical hardware
    private static final String GW_IP  = "192.168.4.1";   // ESP32 Gateway
    private static final String CAM_IP = "192.168.4.2";   // ESP32-CAM
    private static final String DHT_IP = "192.168.4.3";   // DHT11 Sensor
    private static final String IDS_IP = "192.168.1.100"; // IDS Host (collector only)

    // Simulated external attacker IPs
    private static final String[] EXTERNAL_IPS = {
        "203.0.113.15", "198.51.100.42", "45.33.32.156",
        "185.220.101.1", "89.248.167.131"
    };

    public TrafficSimulator(SimpMessagingTemplate ws, TelegramAlertService telegramAlertService) {
        this.ws = ws;
        this.telegramAlertService = telegramAlertService;
        initDevices();
    }

    /**
     * Initialises the 3 real IoT devices that match the physical hardware assembly.
     */
    private void initDevices() {
        devices.put("esp32-gw", IoTDevice.builder()
            .deviceId("esp32-gw")
            .deviceName("ESP32 Gateway")
            .deviceType("ESP32_GATEWAY")
            .ipAddress(GW_IP)
            .macAddress("AA:BB:CC:11:22:01")
            .status("OFFLINE")          // OFFLINE until real ESP32 connects
            .lastSeen(0L)
            .build());

        devices.put("esp32-cam", IoTDevice.builder()
            .deviceId("esp32-cam")
            .deviceName("ESP32-CAM")
            .deviceType("ESP32_CAM")
            .ipAddress(CAM_IP)
            .macAddress("AA:BB:CC:11:22:02")
            .status("OFFLINE")          // OFFLINE until real ESP32 connects
            .lastSeen(0L)
            .build());

        devices.put("dht11", IoTDevice.builder()
            .deviceId("dht11")
            .deviceName("DHT11 Sensor")
            .deviceType("DHT11")
            .ipAddress(DHT_IP)
            .macAddress("AA:BB:CC:11:22:03")
            .status("OFFLINE")          // OFFLINE until real ESP32 connects
            .lastSeen(0L)
            .build());

        log.info("[IDS] {} devices initialised — all OFFLINE until ESP32 connects", devices.size());
    }

    /** Simulation permanently disabled — only real ESP32 traffic shown. */
    public void start()  { log.warn("[IDS] Simulation disabled — real hardware mode only"); }
    public void stop()   { running.set(false); }
    public boolean isRunning() { return false; }
    public Collection<IoTDevice> getDevices() { return devices.values(); }

    /**
     * Called by Esp32DataController every time real ESP32 data arrives.
     * Updates device lastSeen timestamp and sets it ONLINE.
     * This is how the dashboard knows hardware is actually connected.
     */
    public void markDeviceOnline(String deviceId, String ipAddress) {
        IoTDevice device = devices.get(deviceId);
        if (device == null) return;
        device.setLastSeen(System.currentTimeMillis());
        if (ipAddress != null && !ipAddress.isBlank()) device.setIpAddress(ipAddress);
        if ("OFFLINE".equals(device.getStatus())) {
            device.setStatus("ONLINE");
            log.info("[IDS] Device {} came ONLINE (real hardware heartbeat)", deviceId);
        }
        broadcastDevices();
    }

    /**
     * Called by InferenceController when XGBoost detects an attack.
     *
     * SLIDING-WINDOW THRESHOLD (like real IDS — Snort/Suricata rate-based rules):
     *   - Keeps a timestamp queue per device
     *   - Only raises UNDER_ATTACK if >= ATTACK_THRESHOLD_COUNT detections
     *     occur within ATTACK_THRESHOLD_WINDOW milliseconds
     *   - A single stray packet never triggers an alert
     */
    public void markDeviceAttack(String deviceId, String attackType) {
        IoTDevice device = devices.get(deviceId);
        if (device == null) return;
        device.setLastSeen(System.currentTimeMillis());
        lastAttackMs.put(deviceId, System.currentTimeMillis());

        // Build / retrieve sliding window deque for this device
        attackTimestamps.putIfAbsent(deviceId, new ArrayDeque<>());
        Deque<Long> window = attackTimestamps.get(deviceId);
        long now = System.currentTimeMillis();

        // Push current timestamp, evict entries outside the time window
        window.addLast(now);
        while (!window.isEmpty() && (now - window.peekFirst()) > ATTACK_THRESHOLD_WINDOW) {
            window.pollFirst();
        }

        int hitsInWindow = window.size();
        int totalHits    = attackHits.merge(deviceId, 1, Integer::sum);
        device.setConsecutiveAttacks(hitsInWindow);
        device.setLastAttack(attackType);

        if (hitsInWindow >= ATTACK_THRESHOLD_COUNT) {
            // Enough detections in the window — genuine attack
            if (!"UNDER_ATTACK".equals(device.getStatus())) {
                device.setStatus("UNDER_ATTACK");
                log.warn("[IDS] Device {} UNDER_ATTACK: {} ({} hits in {}ms window)",
                         deviceId, attackType, hitsInWindow, ATTACK_THRESHOLD_WINDOW);
                telegramAlertService.sendAlert(
                    "🚨 *[AI-IDS ALERT]* \n\n" +
                    "⚠️ Device `" + deviceId + "` is *UNDER ATTACK!*\n" +
                    "🛡️ Detected: *" + attackType + "*\n" +
                    "📊 Threshold: " + hitsInWindow + " hits"
                );
            }
            broadcastDevices();
        } else {
            // Below threshold — log but do NOT raise alert
            log.info("[IDS] Device {} — attack candidate {} ({}/{} hits in window, threshold not reached)",
                     deviceId, attackType, hitsInWindow, ATTACK_THRESHOLD_COUNT);
        }
    }


    /**
     * Heartbeat watchdog — runs every 10 seconds.
     * 1. If a real device has not sent data in 45s → mark OFFLINE
     * 2. If a device is UNDER_ATTACK but no new attacks in RECOVERY_CLEAN_WINDOW → recover to ONLINE
     */
    @Scheduled(fixedRate = 10_000)
    public void heartbeatWatchdog() {
        long now     = System.currentTimeMillis();
        long timeout = 45_000;
        boolean changed = false;

        for (IoTDevice device : devices.values()) {
            if ("MONITORING".equals(device.getStatus())) continue;
            long lastSeen = device.getLastSeen();
            if (lastSeen == 0L) continue;

            // ── Offline timeout ──
            boolean timedOut = (now - lastSeen) > timeout;
            if (timedOut && !"OFFLINE".equals(device.getStatus())) {
                device.setStatus("OFFLINE");
                device.setConsecutiveAttacks(0);
                log.warn("[IDS] Device {} → OFFLINE (no heartbeat in {}s)",
                         device.getDeviceId(), timeout / 1000);
                changed = true;
                continue;
            }

            // ── Attack recovery ──
            if ("UNDER_ATTACK".equals(device.getStatus())) {
                Long lastAtk = lastAttackMs.get(device.getDeviceId());
                if (lastAtk != null && (now - lastAtk) > RECOVERY_CLEAN_WINDOW) {
                    device.setStatus("ONLINE");
                    device.setConsecutiveAttacks(0);
                    attackHits.put(device.getDeviceId(), 0);
                    Deque<Long> win = attackTimestamps.get(device.getDeviceId());
                    if (win != null) win.clear();
                    log.info("[IDS] Device {} recovered → ONLINE ({}s clean)",
                             device.getDeviceId(), RECOVERY_CLEAN_WINDOW / 1000);
                    changed = true;
                }
            }
        }
        if (changed) broadcastDevices();
    }

    /**
     * Manually inject one specific attack packet for the Simulation Lab.
     */
    public void injectAttack(String attackType) {
        Packet pkt;
        switch (attackType) {
            case "UDP_FLOOD": pkt = buildUdpFlood(); break;
            case "DATA_SNIFF": pkt = buildDataSniff(); break;
            case "ARP_SPOOF": pkt = buildArpSpoof(); break;
            case "PORT_SCAN": pkt = buildPortScan(); break;
            default: pkt = buildBenign(); break;
        }
        ws.convertAndSend("/topic/packets", pkt);
        checkDeviceRecovery();
    }

    /**
     * Main simulation tick — called every 700ms by Spring scheduler.
     */
    @Scheduled(fixedRate = 700)
    public void broadcastPacket() {
        if (!running.get()) return;
        Packet pkt = generatePacket();
        ws.convertAndSend("/topic/packets", pkt);
        checkDeviceRecovery();
    }

    /**
     * Selects traffic type by weighted probability (CIC-IoT 2023 ratios).
     */
    private Packet generatePacket() {
        int roll = rng.nextInt(100);
        if (roll < 60) return buildBenign();
        if (roll < 78) return buildUdpFlood();
        if (roll < 86) return buildDataSniff();
        if (roll < 93) return buildArpSpoof();
        return buildPortScan();
    }

    // ── Packet Builders ───────────────────────────────────────────────────────

    private Packet buildBenign() {
        String[] srcs  = { CAM_IP, DHT_IP, GW_IP };
        int[]    ports = { 1883, 5683, 80 };
        String src = srcs[rng.nextInt(srcs.length)];
        return Packet.builder()
            .id(uid()).timestamp(now())
            .sourceIp(src).destIp(IDS_IP)
            .protocol(rng.nextBoolean() ? "TCP" : "UDP")
            .port(ports[rng.nextInt(ports.length)])
            .packetSize(50 + rng.nextInt(200))
            .attackType("BENIGN").attackLayer("NONE")
            .confidence(0.92 + rng.nextDouble() * 0.08)
            .severityScore(rng.nextInt(15))
            .sourceNode(nodeId(src)).attack(false)
            .build();
    }

    private Packet buildUdpFlood() {
        String attacker = EXTERNAL_IPS[rng.nextInt(EXTERNAL_IPS.length)];
        Packet pkt = Packet.builder()
            .id(uid()).timestamp(now())
            .sourceIp(attacker).destIp(CAM_IP)
            .protocol("UDP")
            .port(rng.nextBoolean() ? 80 : 443)
            .packetSize(900 + rng.nextInt(500))
            .attackType("UDP_FLOOD").attackLayer("L4")
            .confidence(0.88 + rng.nextDouble() * 0.12)
            .severityScore(80 + rng.nextInt(21))
            .sourceNode("esp32-cam").attack(true)
            .build();
        recordAttack("esp32-cam", "UDP_FLOOD");
        return pkt;
    }

    private Packet buildDataSniff() {
        String attacker = "10.0.0." + (200 + rng.nextInt(55));
        Packet pkt = Packet.builder()
            .id(uid()).timestamp(now())
            .sourceIp(attacker).destIp(DHT_IP)
            .protocol("TCP").port(23)
            .packetSize(64 + rng.nextInt(128))
            .attackType("DATA_SNIFF").attackLayer("L7")
            .confidence(0.75 + rng.nextDouble() * 0.20)
            .severityScore(60 + rng.nextInt(20))
            .sourceNode("dht11").attack(true)
            .build();
        recordAttack("dht11", "DATA_SNIFF");
        return pkt;
    }

    private Packet buildArpSpoof() {
        Packet pkt = Packet.builder()
            .id(uid()).timestamp(now())
            .sourceIp("192.168.4." + (50 + rng.nextInt(50))).destIp(GW_IP)
            .protocol("ARP").port(0)
            .packetSize(42 + rng.nextInt(20))
            .attackType("ARP_SPOOF").attackLayer("L2")
            .confidence(0.78 + rng.nextDouble() * 0.18)
            .severityScore(55 + rng.nextInt(20))
            .sourceNode("esp32-gw").attack(true)
            .build();
        recordAttack("esp32-gw", "ARP_SPOOF");
        return pkt;
    }

    private Packet buildPortScan() {
        String[] targets   = { GW_IP, CAM_IP, DHT_IP };
        int[]    scanPorts = { 22, 23, 80, 443, 8080, 1883 };
        String target = targets[rng.nextInt(targets.length)];
        Packet pkt = Packet.builder()
            .id(uid()).timestamp(now())
            .sourceIp("172.16.0." + (1 + rng.nextInt(254))).destIp(target)
            .protocol("TCP")
            .port(scanPorts[rng.nextInt(scanPorts.length)])
            .packetSize(54 + rng.nextInt(80))
            .attackType("PORT_SCAN").attackLayer("L4")
            .confidence(0.80 + rng.nextDouble() * 0.15)
            .severityScore(45 + rng.nextInt(25))
            .sourceNode(nodeId(target)).attack(true)
            .build();
        recordAttack(nodeId(target), "PORT_SCAN");
        return pkt;
    }

    // ── Device State Machine ──────────────────────────────────────────────────

    private void recordAttack(String deviceId, String attackType) {
        IoTDevice device = devices.get(deviceId);
        if (device == null) return;

        int hits = attackHits.merge(deviceId, 1, Integer::sum);
        lastAttackMs.put(deviceId, System.currentTimeMillis());
        device.setLastAttack(attackType);
        device.setLastSeen(System.currentTimeMillis());
        device.setConsecutiveAttacks(hits);

        if (hits >= 12 && !"MONITORING".equals(device.getStatus())) {
            device.setStatus("OFFLINE");
            log.warn("[IDS] Device {} OFFLINE after {} attack hits", deviceId, hits);
        } else if (hits >= 7 && "ONLINE".equals(device.getStatus())) {
            // 7 hits @ 700ms tick rate = approx 5 seconds of continuous attack
            device.setStatus("UNDER_ATTACK");
            log.info("[IDS] Device {} UNDER_ATTACK ({} hits)", deviceId, hits);
            telegramAlertService.sendAlert(
                "🚨 *[AI-IDS ALERT]* \n\n" +
                "⚠️ Device `" + deviceId + "` is *UNDER ATTACK!*\n" +
                "🛡️ Detected: *" + attackType + "* (Simulation)\n" +
                "⏱️ Duration: > 5 Seconds"
            );
        }
    }

    private void checkDeviceRecovery() {
        if (!running.get()) return; // only run recovery logic during simulation
        long now = System.currentTimeMillis();
        for (Map.Entry<String, IoTDevice> entry : devices.entrySet()) {
            String id = entry.getKey();
            IoTDevice device = entry.getValue();
            if ("MONITORING".equals(device.getStatus())) continue;
            Long lastAttack = lastAttackMs.get(id);
            boolean noAttacks = (lastAttack == null) || ((now - lastAttack) > 15_000);
            if (noAttacks && !"ONLINE".equals(device.getStatus()) && device.getLastSeen() > 0) {
                device.setStatus("ONLINE");
                device.setLastAttack(null);
                device.setConsecutiveAttacks(0);
                attackHits.put(id, 0);
                log.info("[IDS] Device {} recovered → ONLINE", id);
            }
        }
    }

    private void broadcastDevices() {
        ws.convertAndSend("/topic/devices", new ArrayList<>(devices.values()));
    }

    private String nodeId(String ip) {
        return switch (ip) {
            case GW_IP  -> "esp32-gw";
            case CAM_IP -> "esp32-cam";
            case DHT_IP -> "dht11";
            default     -> "esp32-gw";
        };
    }

    private String uid() { return UUID.randomUUID().toString().substring(0, 8); }
    private String now() { return LocalDateTime.now().format(FMT); }
}
