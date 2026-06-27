package com.ids.service;

import org.springframework.stereotype.Component;

@Component
public class RobustScaler {

    public static final int N_FEATURES = 15;

    public static final String[] FEATURE_NAMES = {
        "IAT", "Variance", "Protocol Type", "Magnitue", "Tot size",
        "Header_Length", "Max", "AVG", "Min", "Weight",
        "Number", "rst_count", "Tot sum", "urg_count", "ack_flag_number"
    };

    private static final double[] MEDIAN = {
        83149675.62785280, 0.80000000, 7.10000000, 15.62865635, 120.90000000,
        10425.00000000, 276.00000000, 123.64587324, 60.00000000, 141.55000000,
        9.50000000, 6.50000000, 1419.10000000, 1.90000000, 0.00000000
    };

    private static final double[] IQR = {
        166517718.02748576, 1.00000000, 7.70000000, 22.46843496, 496.50000000,
        138560.20000000, 665.60000000, 495.63199638, 28.80000000, 206.10000000,
        8.00000000, 177.20000000, 5220.24000000, 40.42500000, 1.00000000
    };

    public double[] scale(double[] raw) {
        if (raw.length != N_FEATURES)
            throw new IllegalArgumentException("Expected " + N_FEATURES + " features, got " + raw.length);
        double[] scaled = new double[N_FEATURES];
        for (int i = 0; i < N_FEATURES; i++)
            scaled[i] = (raw[i] - MEDIAN[i]) / IQR[i];
        return scaled;
    }
}