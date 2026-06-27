package com.ids.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * IoTDevice — represents one physical IoT node in the monitored network.
 *
 * The 5 devices in this project (all assembled on a Zero PCB, USB-powered):
 *
 *   ESP32 Gateway  (192.168.4.1) — Wi-Fi AP + traffic router/capturer
 *   ESP32-CAM      (192.168.4.2) — camera IoT node, attacked via UDP flood
 *   DHT11 Sensor   (192.168.4.3) — temp/humidity node, attacked via data sniff
 *   OLED Display   (192.168.4.4) — shows "ATTACK DETECTED" or "NORMAL" locally
 *   IDS Laptop     (192.168.1.100) — runs this Spring Boot detection engine
 *
 * Device Status State Machine (managed by TrafficSimulator):
 *
 *   ONLINE → [3+ consecutive attacks] → UNDER_ATTACK
 *   UNDER_ATTACK → [8+ consecutive attacks] → OFFLINE
 *   OFFLINE → [15 seconds with no attacks] → ONLINE (auto-recovery)
 *   MONITORING → always (IDS Laptop never changes state)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IoTDevice {

    /** Unique ID — matches keys in TrafficSimulator.devices map */
    private String deviceId;

    /** Human-readable name shown on the dashboard hardware monitor card */
    private String deviceName;

    /**
     * Device type code — used by app.js to pick the right icon.
     * Values: ESP32_GATEWAY, ESP32_CAM, DHT11, OLED, LAPTOP
     */
    private String deviceType;

    private String ipAddress;
    private String macAddress;

    /**
     * Current operational status of this device.
     *
     * ONLINE       — device healthy, only benign traffic seen
     * UNDER_ATTACK — receiving attack packets, still responding (3+ hits)
     * OFFLINE      — overwhelmed by attack, simulating real DoS effect (8+ hits)
     * MONITORING   — used only for the IDS laptop (always active, never attacked)
     */
    private String status;

    /** System.currentTimeMillis() of the last packet seen from/to this device */
    private long lastSeen;

    /** Name of the most recent attack type targeting this device (null if none) */
    private String lastAttack;

    /** Approximate packets per second seen on this device in the last cycle */
    private int packetsPerSec;

    /**
     * Counts consecutive attack packets without a benign break.
     * Used by TrafficSimulator for the state machine:
     *   consecutiveAttacks >= 3 → status becomes UNDER_ATTACK
     *   consecutiveAttacks >= 8 → status becomes OFFLINE
     * Resets to 0 on recovery (15s no attacks).
     */
    private int consecutiveAttacks;
}
