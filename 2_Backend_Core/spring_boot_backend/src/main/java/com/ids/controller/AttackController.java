package com.ids.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/attack")
public class AttackController {

    private static final Map<String, String> ATTACK_MAP = new HashMap<>();
    private static final Map<String, Process> RUNNING_ATTACKS = new ConcurrentHashMap<>();

    static {
        ATTACK_MAP.put("ddos", "attack2_ddos_udp_flood.py");
        ATTACK_MAP.put("dos", "attack1_dos_syn_flood.py");
        ATTACK_MAP.put("recon", "attack4_recon_portscan.py");
        ATTACK_MAP.put("mirai", "attack6_mirai.py");
        ATTACK_MAP.put("spoofing", "attack7_arp_spoof.py");
        ATTACK_MAP.put("web", "attack9_sqli.py");
        ATTACK_MAP.put("bruteforce", "attack8_bruteforce.py");
        ATTACK_MAP.put("demo", "run_demo.py");
    }

    @PostMapping("/start")
    public ResponseEntity<?> startAttack(@RequestParam String type, 
                                         @RequestParam(defaultValue = "192.168.121.167") String target, 
                                         @RequestParam(defaultValue = "30") int duration) {
        String scriptName = ATTACK_MAP.get(type.toLowerCase());
        
        if (scriptName == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Unknown attack type"));
        }

        String scriptDir = "C:\\AI_IDS_IOT_PROJECT_MAIN_FOLDER\\attack_scripts";
        File scriptFile = new File(scriptDir, scriptName);

        if (!scriptFile.exists()) {
            return ResponseEntity.status(404).body(Map.of("error", "Script not found: " + scriptName));
        }

        try {
            // Build the command line for python
            ProcessBuilder pb;
            if (type.equals("spoofing")) {
                pb = new ProcessBuilder("cmd", "/c", "start", "python", scriptName, "--target", target, "--gateway", "192.168.121.6", "--duration", String.valueOf(duration));
            } else if (type.equals("recon") || type.equals("web")) {
                pb = new ProcessBuilder("cmd", "/c", "start", "python", scriptName, "--target", target);
            } else if (type.equals("bruteforce") || type.equals("demo")) {
                pb = new ProcessBuilder("cmd", "/c", "start", "python", scriptName, "--broker", "YOUR_CLUSTER.s1.eu.hivemq.cloud");
            } else {
                pb = new ProcessBuilder("cmd", "/c", "start", "python", scriptName, "--target", target, "--duration", String.valueOf(duration));
            }
            
            pb.directory(new File(scriptDir));
            Process p = pb.start();
            RUNNING_ATTACKS.put(type, p);
            
            return ResponseEntity.ok(Map.of("status", "success", "message", "Launched " + scriptName + " on " + target));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Failed to launch script: " + e.getMessage()));
        }
    }

    @PostMapping("/stop")
    public ResponseEntity<?> stopAttack() {
        try {
            // Kill all running python attack processes spawned via cmd
            ProcessBuilder pb = new ProcessBuilder("taskkill", "/IM", "python.exe", "/F");
            pb.start();
            RUNNING_ATTACKS.clear();
            return ResponseEntity.ok(Map.of("status", "success", "message", "All attacks stopped."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Failed to stop attacks: " + e.getMessage()));
        }
    }
}
