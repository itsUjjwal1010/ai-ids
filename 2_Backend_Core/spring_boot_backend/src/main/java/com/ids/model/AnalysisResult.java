package com.ids.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * AnalysisResult — represents one classified network flow from offline file analysis.
 *
 * Used by FileAnalysisController when a user uploads a CSV or PCAP file
 * for offline AI threat detection using the XGBoost-based classifier.
 *
 * Each row in the uploaded CSV becomes one AnalysisResult object.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalysisResult {

    /** Row index in the uploaded file */
    private int rowIndex;

    /** Source IP address */
    private String sourceIp;

    /** Destination IP address */
    private String destIp;

    /** Protocol: TCP, UDP, ICMP, ARP */
    private String protocol;

    /** Destination port number */
    private int port;

    /** Packet/flow size in bytes */
    private int packetSize;

    /** Flow duration in milliseconds */
    private String flowDuration;

    /**
     * CIC-IoT 2023 attack type key.
     * Values: BENIGN, UDP_FLOOD, ARP_SPOOF, PORT_SCAN, DATA_SNIFF
     */
    private String attackType;

    /** True if classified as an attack (not benign) */
    private boolean attack;

    /**
     * XGBoost classifier confidence score (0.0 to 1.0).
     * Higher = more certain about this classification.
     */
    private double confidence;

    /** Severity score 0–100 (0 = benign, 100 = critical) */
    private int severityScore;

    /** Full CIC-IoT 2023 label string (e.g., "DDoS-UDP_Flood") */
    private String cicLabel;
}
