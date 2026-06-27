package com.ids.controller;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ids.model.InferenceResult;
import com.ids.model.Packet;
import com.ids.service.IDSInferenceService;
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

@RestController
@RequestMapping("/api/esp32")
@CrossOrigin(origins = "*")
@Slf4j
public class InferenceController {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private static final Map<String, String> TYPE_MAP = Map.of(
        "DDoS","UDP_FLOOD","DoS","UDP_FLOOD","Recon","PORT_SCAN",
        "Spoofing","ARP_SPOOF","Mirai","UDP_FLOOD","WebAttack","DATA_SNIFF",
        "BruteForce","PORT_SCAN","Benign","BENIGN","Attack","UDP_FLOOD"
    );

    @Autowired private IDSInferenceService inferenceService;
    @Autowired private SimpMessagingTemplate ws;
    @Autowired private TrafficSimulator simulator;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AnalyzeRequest {
        @JsonProperty("features")  public List<Double> features;
        @JsonProperty("device_id") public String deviceId;
        @JsonProperty("timestamp") public Long timestamp;
    }

    @PostMapping("/analyze")
    public ResponseEntity<Map<String, Object>> analyze(@RequestBody AnalyzeRequest body) {
        if (body.features == null || body.features.size() != 15) {
            return ResponseEntity.badRequest().body(Map.of("error","Expected 15 features",
                "received", body.features == null ? 0 : body.features.size()));
        }
        String deviceId = body.deviceId != null ? body.deviceId : "esp32-gw";
        String ts = LocalDateTime.now().format(FMT);
        double[] raw = new double[15];
        for (int i = 0; i < 15; i++) raw[i] = body.features.get(i);

        InferenceResult result = inferenceService.predict(raw, deviceId);
        simulator.markDeviceOnline("esp32-gw", null);

        String dashType = TYPE_MAP.getOrDefault(result.getAttackType(), "BENIGN");
        String proto = "Spoofing".equals(result.getAttackType()) ? "ARP"
                     : "Recon".equals(result.getAttackType()) ? "TCP" : "UDP";

        Packet pkt = Packet.builder()
            .id(UUID.randomUUID().toString().substring(0, 8)).timestamp(ts)
            .sourceIp("185.220." + new Random().nextInt(255) + "." + new Random().nextInt(255)).destIp(deviceId != null && deviceId.equals("esp32-cam") ? "192.168.13.167" : "192.168.4.1")
            .protocol(result.isAttack() ? proto : "TCP")
            .port(result.isAttack() ? 80 : 1883)
            .packetSize((int)(raw[4] / Math.max(raw[10], 1)))
            .attackType(dashType).attackLayer(result.isAttack() ? "L4" : "NONE")
            .confidence(result.getConfidence())
            .severityScore(result.isAttack() ? calcSeverity(result.getAttackType()) : 5)
            .sourceNode(deviceId != null ? deviceId : "esp32-gw").attack(result.isAttack()).build();

        ws.convertAndSend("/topic/packets", pkt);
        if (result.isAttack()) simulator.markDeviceAttack("esp32-gw", dashType);

        return ResponseEntity.ok(Map.of(
            "is_attack", result.isAttack(), "attack_type", result.getAttackType(),
            "confidence", Math.round(result.getConfidence()*1000.0)/1000.0,
            "label_index", result.getLabelIndex(), "timestamp", ts));
    }

    @GetMapping("/inference-status")
    public ResponseEntity<Map<String, Object>> status() {
        return ResponseEntity.ok(Map.of("ready", inferenceService.isReady(),
            "engine","Python XGBoost via Flask","threshold",0.3));
    }

    private int calcSeverity(String t) {
        return switch (t) {
            case "DDoS","Mirai" -> 90; case "DoS" -> 85; case "Spoofing" -> 75;
            case "BruteForce" -> 70; case "WebAttack" -> 65; case "Recon" -> 55;
            default -> 60;
        };
    }
}

