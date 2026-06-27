package com.ids.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class InferenceResult {
    private boolean isAttack;
    private String  attackType;
    private double  confidence;
    private int     labelIndex;
    private String  timestamp;
    private String  deviceId;
    private double[] rawFeatures;
    private double[] scaledFeatures;
}