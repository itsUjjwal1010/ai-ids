package com.ids.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.model.InferenceResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
@Slf4j
public class IDSInferenceService {

    private static final String PYTHON_INFER_URL  = "http://localhost:5000/infer";
    private static final String PYTHON_STATUS_URL = "http://localhost:5000/status";
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    @Autowired private RobustScaler scaler;
    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(2000)).build();
    private final ObjectMapper mapper = new ObjectMapper();
    private boolean pythonReady = false;

    @PostConstruct
    public void checkPythonServer() {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(PYTHON_STATUS_URL))
                .timeout(Duration.ofMillis(1500)).GET().build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                pythonReady = true;
                log.info("[IDS] Python inference server UP");
            }
        } catch (Exception e) {
            log.warn("[IDS] Python server not reachable. Run: python ids_inference_server.py");
        }
    }

    public InferenceResult predict(double[] rawFeatures, String deviceId) {
        String ts = LocalDateTime.now().format(FMT);
        if (!pythonReady) checkPythonServer();
        if (!pythonReady) return benign(rawFeatures, deviceId, ts);
        try {
            List<Double> featureList = new ArrayList<>();
            for (double v : rawFeatures) featureList.add(v);
            String json = mapper.writeValueAsString(Map.of("features", featureList, "device_id", deviceId));
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(PYTHON_INFER_URL))
                .timeout(Duration.ofMillis(2000))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json)).build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return benign(rawFeatures, deviceId, ts);
            @SuppressWarnings("unchecked")
            Map<String, Object> result = mapper.readValue(resp.body(), Map.class);
            boolean isAttack   = Boolean.TRUE.equals(result.get("is_attack"));
            String  attackType = (String) result.getOrDefault("attack_type", "Benign");
            double  confidence = ((Number) result.getOrDefault("confidence", 0.0)).doubleValue();
            int     labelIdx   = ((Number) result.getOrDefault("label_index", -1)).intValue();
            return InferenceResult.builder()
                .isAttack(isAttack).attackType(attackType).confidence(confidence)
                .labelIndex(labelIdx).timestamp(ts).deviceId(deviceId)
                .rawFeatures(rawFeatures).scaledFeatures(scaler.scale(rawFeatures)).build();
        } catch (Exception e) {
            pythonReady = false;
            log.error("[IDS] Python call failed: {}", e.getMessage());
            return benign(rawFeatures, deviceId, ts);
        }
    }

    private InferenceResult benign(double[] raw, String id, String ts) {
        return InferenceResult.builder().isAttack(false).attackType("Benign")
            .confidence(0.95).labelIndex(-1).timestamp(ts).deviceId(id).rawFeatures(raw).build();
    }


    public boolean isReady() { return pythonReady; }
}