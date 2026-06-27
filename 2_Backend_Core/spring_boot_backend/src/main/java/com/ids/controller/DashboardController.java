package com.ids.controller;

import com.ids.model.IoTDevice;
import com.ids.service.TrafficSimulator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Map;

/**
 * DashboardController — REST API for controlling the IDS Dashboard.
 *
 * All these endpoints are called by app.js (the frontend JavaScript file).
 *
 * Endpoint summary:
 *   GET  /api/health              — health check, confirms backend is alive
 *   GET  /api/devices             — current status of all 5 IoT devices
 *   POST /api/simulation/start    — start the @Scheduled packet broadcast
 *   POST /api/simulation/stop     — pause the @Scheduled packet broadcast
 *   GET  /api/simulation/status   — check if simulation is currently running
 *   POST /api/inject?type=...     — manually inject one attack packet (viva demo)
 *
 * Annotations explained:
 *   @RestController       — combines @Controller + @ResponseBody (returns JSON, not HTML)
 *   @RequestMapping       — all endpoints prefixed with /api
 *   @CrossOrigin("*")     — allows AJAX calls from any origin (same-server or browser tools)
 *   @RequiredArgsConstructor — Lombok: Spring injects TrafficSimulator via constructor
 *   @Slf4j                — Lombok: auto-creates a logger field named 'log'
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
@Slf4j
public class DashboardController {

    // Spring's Dependency Injection provides this automatically
    private final TrafficSimulator simulator;

    /**
     * GET /api/health
     *
     * Health check endpoint. Called by app.js on page load to confirm the
     * backend is running before attempting the WebSocket connection.
     *
     * Also returns useful info for viva: WebSocket endpoint, topics, model info.
     *
     * @return 200 OK with JSON status object
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
            "status",      "UP",
            "service",     "AI Multi-Layer IDS — CIC-IoT 2023 + XGBoost",
            "timestamp",   LocalDateTime.now().toString(),
            "wsEndpoint",  "/ws",
            "topics",      new String[]{ "/topic/packets", "/topic/devices" },
            "running",     simulator.isRunning()
        ));
    }

    /**
     * GET /api/devices
     *
     * Returns the current status of all 5 IoT devices.
     * Called on page load so the hardware monitor cards show immediately
     * (before the first WebSocket push at 700ms).
     *
     * @return 200 OK with JSON array of IoTDevice objects
     */
    @GetMapping("/devices")
    public ResponseEntity<Collection<IoTDevice>> devices() {
        return ResponseEntity.ok(simulator.getDevices());
    }

    /**
     * POST /api/simulation/start
     *
     * Starts the @Scheduled packet broadcast in TrafficSimulator.
     * Called when user clicks the "▶ Start" button on the dashboard.
     *
     * @return 200 OK with { "running": true }
     */
    @PostMapping("/simulation/start")
    public ResponseEntity<Map<String, Object>> start() {
        simulator.start();
        log.info("[API] Simulation START requested");
        return ResponseEntity.ok(Map.of(
            "running", true,
            "message", "Live capture started"
        ));
    }

    /**
     * POST /api/simulation/stop
     *
     * Pauses the @Scheduled packet broadcast in TrafficSimulator.
     * Called when user clicks the "■ Stop" button on the dashboard.
     *
     * @return 200 OK with { "running": false }
     */
    @PostMapping("/simulation/stop")
    public ResponseEntity<Map<String, Object>> stop() {
        simulator.stop();
        log.info("[API] Simulation STOP requested");
        return ResponseEntity.ok(Map.of(
            "running", false,
            "message", "Capture paused"
        ));
    }

    /**
     * GET /api/simulation/status
     *
     * Simple status check — returns whether the simulation is running.
     * Called by app.js on page load to sync the button state with backend.
     *
     * @return 200 OK with { "running": true/false }
     */
    @GetMapping("/simulation/status")
    public ResponseEntity<Map<String, Object>> status() {
        return ResponseEntity.ok(Map.of("running", simulator.isRunning()));
    }

    /**
     * POST /api/inject?type=UDP_FLOOD
     *
     * Manually injects one specific attack packet immediately.
     * Useful during viva/demo to trigger a visible alert without waiting
     * for the random scheduler to generate that attack type.
     *
     * Supported attack types:
     *   UDP_FLOOD  — volumetric attack on ESP32-CAM (takes it OFFLINE fast)
     *   DATA_SNIFF — data interception on DHT11 sensor
     *   ARP_SPOOF  — gateway poisoning (Layer 2)
     *   PORT_SCAN  — reconnaissance on IoT subnet
     *   BENIGN     — normal traffic (resets device recovery)
     *
     * @param type attack type to inject (defaults to UDP_FLOOD if not provided)
     * @return 200 OK with confirmation
     */
    @PostMapping("/inject")
    public ResponseEntity<Map<String, Object>> inject(
            @RequestParam(defaultValue = "UDP_FLOOD") String type) {
        simulator.injectAttack(type);
        log.info("[API] Manual attack injected: {}", type);
        return ResponseEntity.ok(Map.of(
            "injected", type,
            "status",   "sent to WebSocket /topic/packets"
        ));
    }
}
