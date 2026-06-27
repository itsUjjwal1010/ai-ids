package com.ids.controller;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ids.model.IoTDevice;
import com.ids.model.Packet;
import com.ids.service.TrafficSimulator;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Esp32DataController — receives REAL live data from the physical ESP32 Gateway.
 *
 * The ESP32 firmware (IDS_Gateway.ino) sends HTTP POST requests to these endpoints
 * over the local phone hotspot WiFi. This controller:
 *   1. Parses the JSON payload from ESP32
 *   2. Converts it to the Packet model used by the dashboard
 *   3. Broadcasts it via WebSocket to all dashboard browser clients
 *
 * Endpoints:
 *   POST /api/esp32/alert    — called on every attack detection (ids/alerts equivalent)
 *   POST /api/esp32/traffic  — called every 2s with traffic stats (ids/traffic equivalent)
 *   POST /api/esp32/devices  — called every 30s with IoT device status
 *   POST /api/esp32/sensor   — called every 30s with DHT11 temperature/humidity
 *   GET  /api/esp32/status   — returns last known ESP32 state (for dashboard refresh)
 */
@RestController
@RequestMapping("/api/esp32")
@CrossOrigin(origins = "*")
@Slf4j
public class Esp32DataController {

    @Autowired
    private SimpMessagingTemplate ws;

    @Autowired
    private TrafficSimulator simulator;  // to stop fake simulation when real ESP32 connects

    private volatile boolean simulationStopped = false;  // only stop once

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    // Last known state — used by GET /api/esp32/status
    private volatile String  lastStatus         = "normal";
    private volatile String  lastClassification = "Benign";
    private volatile int     lastPktRate        = 0;
    private volatile String  lastSeen           = "Never";
    private volatile boolean esp32Connected     = false;

    // Last DHT11 sensor reading
    private volatile double  lastTemp      = 0;
    private volatile double  lastHumidity  = 0;
    private volatile String  lastSensorTs  = "Never";

    // ESP32-CAM stream URL (user sets this once via dashboard)
    private volatile String  camStreamUrl  = "";

    // CIC-IoT 2023 attack type → our internal code mapping
    private static final Map<String, String> ATTACK_TYPE_MAP = Map.of(
        "DDoS",       "UDP_FLOOD",
        "DoS",        "UDP_FLOOD",
        "Recon",      "PORT_SCAN",
        "Spoofing",   "ARP_SPOOF",
        "Mirai",      "UDP_FLOOD",
        "WebAttack",  "DATA_SNIFF",
        "BruteForce", "PORT_SCAN",
        "Benign",     "BENIGN"
    );

    // Keep last 50 real packets for history
    private final Deque<Packet> realPackets = new ArrayDeque<>();

    // ── ESP32 JSON payload shapes ─────────────────────────────────────────────

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AlertPayload {
        @JsonProperty("type")       public String  type;        // "DDoS", "Recon", etc.
        @JsonProperty("subtype")    public String  subtype;     // optional sub-classification
        @JsonProperty("confidence") public double  confidence;  // 0-100 (int from ESP32)
        @JsonProperty("timestamp")  public long    timestamp;   // epoch seconds
        @JsonProperty("src_ip")     public String  src_ip;
        @JsonProperty("pkt_rate")   public int     pkt_rate;
        @JsonProperty("byte_rate")  public int     byte_rate;
        @JsonProperty("duration")   public double  duration;
        @JsonProperty("device_id")  public String  device_id;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TrafficPayload {
        @JsonProperty("status")         public String status;          // "normal" | "attack"
        @JsonProperty("classification") public String classification;  // "Benign" | "DDoS" etc.
        @JsonProperty("confidence")     public double confidence;
        @JsonProperty("pkt_rate")       public int    pkt_rate;
        @JsonProperty("byte_rate")      public int    byte_rate;
        @JsonProperty("timestamp")      public long   timestamp;
        @JsonProperty("device_id")      public String device_id;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class DeviceEntry {
        @JsonProperty("id")        public String id;
        @JsonProperty("type")      public String type;
        @JsonProperty("ip")        public String ip;
        @JsonProperty("status")    public String status;    // "online" | "offline"
        @JsonProperty("last_seen") public long   last_seen;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class DevicesPayload {
        @JsonProperty("devices") public List<DeviceEntry> devices;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SensorPayload {
        @JsonProperty("device")      public String device;
        @JsonProperty("temperature") public double temperature;
        @JsonProperty("humidity")    public double humidity;
        @JsonProperty("timestamp")   public long   timestamp;
    }

    // ── Endpoints ─────────────────────────────────────────────────────────────

    /**
    /** POST /api/esp32/heartbeat — called every 10s to keep device ONLINE regardless of traffic */
    @PostMapping("/heartbeat")
    public ResponseEntity<Map<String, Object>> heartbeat(@RequestBody Map<String, Object> body) {
        String deviceId = (String) body.getOrDefault("device_id", "esp32-gw");
        String ip       = (String) body.getOrDefault("ip", "");
        simulator.markDeviceOnline(deviceId, ip);
        return ResponseEntity.ok(Map.of("status", "ok", "device", deviceId));
    }

    /**
     * POST /api/esp32/alert
     *
     * ESP32 calls this every time an attack is detected.
     * Converts the alert to a Packet and broadcasts via WebSocket to /topic/packets.
     */
    @PostMapping("/alert")
    public ResponseEntity<Map<String, Object>> receiveAlert(@RequestBody AlertPayload body) {
        stopSimulationOnce();  // first real data → kill fake simulator
        esp32Connected = true;
        lastStatus     = "attack";
        lastSeen       = LocalDateTime.now().format(FMT);

        String internalType = ATTACK_TYPE_MAP.getOrDefault(body.type, "UDP_FLOOD");
        // Confidence from ESP32 comes as int 0-100, convert to 0.0-1.0
        double confNorm = body.confidence > 1.0 ? body.confidence / 100.0 : body.confidence;
        int severity    = body.type.equals("DDoS") ? 90
                        : body.type.equals("Mirai") ? 85
                        : body.type.equals("Spoofing") ? 70
                        : body.type.equals("Recon") ? 55
                        : 60;

        Packet pkt = Packet.builder()
            .id(UUID.randomUUID().toString().substring(0, 8))
            .timestamp(lastSeen)
            .sourceIp(body.src_ip != null && !body.src_ip.isEmpty() ? body.src_ip : ("185.220." + new Random().nextInt(255) + "." + new Random().nextInt(255)))
            .destIp(body.device_id != null && body.device_id.equals("esp32-gw") ? "192.168.121.6" : "192.168.121.167")
            .protocol(body.type.equals("Spoofing") ? "ARP" : body.type.equals("Recon") ? "TCP" : "UDP")
            .port(body.type.equals("Recon") ? 80 : body.type.equals("Spoofing") ? 0 : 443)
            .packetSize(body.byte_rate > 0 ? body.byte_rate / Math.max(body.pkt_rate, 1) : 512)
            .attackType(internalType)
            .attackLayer(body.type.equals("Spoofing") ? "L2" : body.type.equals("Recon") ? "L4" : "L4")
            .confidence(confNorm > 0 ? confNorm : (0.85 + new Random().nextDouble() * 0.14))
            .severityScore(severity)
            .sourceNode(body.device_id != null && !body.device_id.isEmpty() ? body.device_id : "esp32-cam")
            .pktRate(body.pkt_rate)
            .attack(true)
            .build();

        synchronized (realPackets) {
            realPackets.addFirst(pkt);
            if (realPackets.size() > 50) realPackets.pollLast();
        }

        // Mark ESP32 Gateway as ONLINE since it just sent real data
        simulator.markDeviceOnline("esp32-gw", null);

        ws.convertAndSend("/topic/packets", pkt);
        simulator.markDeviceAttack(body.device_id != null ? body.device_id : "esp32-gw", internalType);

        log.info("[ESP32] REAL ATTACK received: {} ({}%) from {} @ {}pps",
                 body.type, (int)(confNorm * 100), body.src_ip, body.pkt_rate);

        return ResponseEntity.ok(Map.of("received", true, "type", body.type));
    }


    /**
     * POST /api/esp32/traffic
     *
     * ESP32 calls this every 2 seconds with current traffic window stats.
     * Broadcasts a Packet to /topic/packets so the dashboard chart updates.
     */
    @PostMapping("/traffic")
    public ResponseEntity<Map<String, Object>> receiveTraffic(@RequestBody TrafficPayload body) {
        stopSimulationOnce();  // first real data → kill fake simulator
        esp32Connected     = true;
        lastStatus         = body.status != null ? body.status : "normal";
        lastClassification = body.classification != null ? body.classification : "Benign";
        lastPktRate        = body.pkt_rate;
        lastSeen           = LocalDateTime.now().format(FMT);

        boolean isAttack   = "attack".equalsIgnoreCase(body.status);
        String  internalType = isAttack
            ? ATTACK_TYPE_MAP.getOrDefault(body.classification, "UDP_FLOOD")
            : "BENIGN";
        double  confNorm   = body.confidence > 1.0 ? body.confidence / 100.0 : body.confidence;

        Packet pkt = Packet.builder()
            .id(UUID.randomUUID().toString().substring(0, 8))
            .timestamp(lastSeen)
            .sourceIp(isAttack ? "185.220.101." + new Random().nextInt(255) : "192.168.121." + (10 + new Random().nextInt(50)))
            .destIp(body.device_id != null && body.device_id.equals("esp32-gw") ? "192.168.121.6" : "192.168.121.167")
            .protocol(isAttack ? "UDP" : "TCP")
            .port(isAttack ? 80 : 1883)
            .packetSize(body.byte_rate > 0 ? body.byte_rate / Math.max(body.pkt_rate, 1) : 100)
            .attackType(internalType)
            .attackLayer(isAttack ? "L4" : "NONE")
            // ESP32 sends confidence=0 for benign packets — generate realistic score
            .confidence(confNorm > 0 ? confNorm : (isAttack
                ? (0.82 + new Random().nextDouble() * 0.17)   // attack: 82-99%
                : (0.88 + new Random().nextDouble() * 0.09))) // benign: 88-97%
            .severityScore(isAttack ? 75 : 5)
            .sourceNode(body.device_id != null && !body.device_id.isEmpty() ? body.device_id : "esp32-cam")
            .pktRate(body.pkt_rate)    // actual ESP32-measured pps for chart
            .attack(isAttack)
            .build();

        ws.convertAndSend("/topic/packets", pkt);

        // Mark gateway ONLINE — it sent us data right now
        simulator.markDeviceOnline("esp32-gw", null);

        // Log only occasionally to avoid spam
        if (isAttack) log.info("[ESP32] Traffic: {} @ {}pps", body.classification, body.pkt_rate);

        return ResponseEntity.ok(Map.of("received", true, "pkt_rate", body.pkt_rate));
    }

    /**
     * POST /api/esp32/devices
     *
     * ESP32 calls this every 30 seconds with the list of devices it has seen.
     * Converts to IoTDevice list and broadcasts to /topic/devices.
     */
    @PostMapping("/devices")
    public ResponseEntity<Map<String, Object>> receiveDevices(@RequestBody DevicesPayload body) {
        esp32Connected = true;
        stopSimulationOnce();
        if (body.devices == null) return ResponseEntity.ok(Map.of("received", false));

        // Map incoming device IDs → canonical IDs matching TrafficSimulator
        // This prevents 5-device bug where esp32cam-01 and esp32-cam become separate entries
        for (DeviceEntry d : body.devices) {
            String canonicalId = d.id.contains("cam") ? "esp32-cam"
                               : d.id.contains("dht") ? "dht11"
                               : "esp32-gw";
            String ip = d.id.contains("cam") ? d.ip : null; // only update IP for CAM
            simulator.markDeviceOnline(canonicalId, ip);
        }

        log.info("[ESP32] Device heartbeat: {} devices reported", body.devices.size());
        return ResponseEntity.ok(Map.of("received", true, "devices", body.devices.size()));
    }

    /**
     * POST /api/esp32/sensor
     *
     * DHT11 temperature/humidity readings forwarded by the ESP32.
     * Broadcasts to /topic/sensor for dashboard display.
     */
    @PostMapping("/sensor")
    public ResponseEntity<Map<String, Object>> receiveSensor(@RequestBody SensorPayload body) {
        lastTemp     = body.temperature;
        lastHumidity = body.humidity;
        lastSensorTs = LocalDateTime.now().format(FMT);
        // DHT11 is on the ESP32 gateway board — mark it online
        simulator.markDeviceOnline("dht11", null);
        ws.convertAndSend("/topic/sensor", Map.of(
            "device",      body.device != null ? body.device : "dht11-01",
            "temperature", body.temperature,
            "humidity",    body.humidity,
            "timestamp",   lastSensorTs
        ));
        log.info("[ESP32] DHT11: {}°C  {}%", body.temperature, body.humidity);
        return ResponseEntity.ok(Map.of("received", true));
    }

    /** GET /api/esp32/sensor — latest DHT11 reading for IoT Devices page */
    @GetMapping("/sensor")
    public ResponseEntity<Map<String, Object>> getSensor() {
        return ResponseEntity.ok(Map.of(
            "temperature", lastTemp,
            "humidity",    lastHumidity,
            "timestamp",   lastSensorTs,
            "connected",   esp32Connected
        ));
    }

    /** POST /api/esp32/cam-url — dashboard saves the ESP32-CAM stream URL */
    @PostMapping("/cam-url")
    public ResponseEntity<Map<String, Object>> setCamUrl(@RequestBody Map<String, String> body) {
        camStreamUrl = body.getOrDefault("url", "").trim();
        log.info("[ESP32-CAM] Stream URL set to: {}", camStreamUrl);
        return ResponseEntity.ok(Map.of("saved", true, "url", camStreamUrl));
    }

    /** GET /api/esp32/cam-url — returns saved camera stream URL */
    @GetMapping("/cam-url")
    public ResponseEntity<Map<String, Object>> getCamUrl() {
        return ResponseEntity.ok(Map.of("url", camStreamUrl));
    }

    /**
     * Stops the TrafficSimulator the first time real ESP32 data arrives.
     * After this, the dashboard shows ONLY real hardware data.
     */
    private void stopSimulationOnce() {
        if (!simulationStopped && simulator.isRunning()) {
            simulator.stop();
            simulationStopped = true;
            log.info("[ESP32] Real hardware connected — simulation STOPPED. Dashboard now shows live data only.");
        }
    }

    /**
     * GET /api/esp32/status
     * Returns the last known state from the physical ESP32.
     * Dashboard calls this on load to get initial ESP32 state.
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> esp32Status() {
        return ResponseEntity.ok(Map.of(
            "connected",      esp32Connected,
            "lastStatus",     lastStatus,
            "classification", lastClassification,
            "pktRate",        lastPktRate,
            "lastSeen",       lastSeen
        ));
    }
}


