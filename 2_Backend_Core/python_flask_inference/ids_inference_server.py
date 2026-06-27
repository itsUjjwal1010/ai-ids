import os
import time
import pickle
import numpy as np
import json
import threading
import requests
import paho.mqtt.client as mqtt
import subprocess
import re

# =====================================================================
# ARP RESOLUTION (For WPA2 Encrypted Layer 2 Traffic)
# =====================================================================
def get_ip_from_mac(mac):
    if not mac or mac == "00:00:00:00:00:00":
        return None
    try:
        # Windows arp -a format uses hyphens
        mac_win = mac.replace(':', '-').lower()
        output = subprocess.check_output(['arp', '-a']).decode('utf-8', errors='ignore')
        for line in output.split('\n'):
            if mac_win in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    return parts[0] # Return the IP address
    except Exception as e:
        print(f"ARP lookup failed: {e}")
    return None

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app) # Allows Vercel frontend to call this API if needed

# ==========================================
# CLOUD INTEGRATION SETTINGS
# ==========================================
# 1. HiveMQ MQTT (for real-time dashboard updates)
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT   = 1883 # Public unencrypted port
MQTT_USER   = ""
MQTT_PASS   = ""

# 2. Telegram Bot (for instant push notifications)
# Read from environment variables — set these in Render dashboard (never hardcode secrets)
BOT_TOKEN   = os.environ.get("BOT_TOKEN", "")
CHAT_ID     = os.environ.get("CHAT_ID", "")

mqtt_client = mqtt.Client(client_id="flask-ids-backend-" + str(time.time()))

def connect_mqtt():
    try:
        mqtt_client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
        mqtt_client.loop_start()
        print("[SUCCESS] Connected to Public HiveMQ Broker.")
    except Exception as e:
        print(f"[WARNING] MQTT Connection failed: {e}")

connect_mqtt()

def send_telegram(attack_type, confidence, device_id="esp32-gw"):
    if BOT_TOKEN == "YOUR_BOT_TOKEN_FROM_BOTFATHER":
        return
    text = (
        f"🚨 <b>ATTACK DETECTED</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Type:       <b>{attack_type}</b>\n"
        f"📊 Confidence: {confidence}%\n"
        f"🌐 Device:     <code>{device_id}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 <a href='https://your-vercel-domain.vercel.app'>View Dashboard</a>"
    )
    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=5
        )
    except Exception as e:
        print(f"Telegram failed: {e}")

# ==========================================
# INFERENCE ENGINE
# ==========================================
scaler = None
model = None

CLASS_MAPPING = {
    0: "DDoS",
    1: "DoS",
    2: "Mirai Botnet",
    3: "Spoofing",
    4: "Other Attack Vector"
}

def load_binaries():
    global scaler, model
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        scaler_path = os.path.join(base_dir, "scaler_multi.pkl")
        model_path = os.path.join(base_dir, "model_multi.pkl")

        with open(scaler_path, "rb") as f:
            scaler = pickle.load(f)
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        print("[SUCCESS] Stage 2 Multi-class engine models uploaded to Flask memory.")
    except Exception as e:
        print(f"[CRITICAL] Binary loader sequence failed: {e}")

load_binaries()

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "engine": "Flask Multi-Class Node"}), 200

@app.route("/api/esp32/devices", methods=["GET", "POST"])
def device_heartbeat():
    try:
        if request.method == "POST":
            data = request.get_json()
            if data and "devices" in data:
                mqtt_client.publish("ids/devices", json.dumps(data["devices"]))
            return jsonify({"status": "heartbeat received"}), 200
        else:
            # Handle GET request from dashboard
            mock_devices = {
                'esp32-gw':  { 'name': 'ESP32 Gateway', 'ip': '192.168.121.6', 'status': 'ONLINE' },
                'esp32-cam': { 'name': 'ESP32-CAM',     'ip': '192.168.24.167', 'status': 'ONLINE' },
                'dht11':     { 'name': 'DHT11 Sensor',  'ip': '192.168.121.6', 'status': 'ONLINE' }
            }
            return jsonify({"status": "success", "devices": mock_devices}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v2/analyze", methods=["POST"])
def analyze():
    if scaler is None or model is None:
        return jsonify({"error": "Classification models are offline."}), 503
        
    data = request.get_json()
    if not data or "features" not in data:
        return jsonify({"error": "Missing 'features' index payload array."}), 400
        
    features_list = data["features"]
    if len(features_list) != 15:
        return jsonify({"error": f"Array dimensional mismatch. Expected 15, got {len(features_list)}"}), 400

    try:
        edge_score = data.get("edge_score", 0.0)
        is_attack = edge_score >= 0.40
        
        predicted_idx = -1
        confidence = 0.0
        attack_type = "BENIGN"
        telemetry_matrix = {}

        if is_attack:
            raw_array = np.array(features_list).reshape(1, -1)
            scaled_array = scaler.transform(raw_array)
            probabilities = model.predict_proba(scaled_array)[0]
            predicted_idx = int(np.argmax(probabilities))
            confidence = float(probabilities[predicted_idx])
            attack_type = CLASS_MAPPING.get(predicted_idx, "UnknownAttack")
            telemetry_matrix = {CLASS_MAPPING[i]: round(float(prob) * 100, 2) for i, prob in enumerate(probabilities)}
        else:
            confidence = 1.0 - edge_score

        response_data = {
            "incident_verified": is_attack,
            "attack_type": attack_type,
            "confidence_metric": round(confidence * 100, 2)
        }
        
        # -------------------------------------------------------------
        # WPA2 DECRYPTION LOGIC (Layer-2 Promiscuous Handling)
        # -------------------------------------------------------------
        encrypted = data.get("encrypted", True)
        src_mac = data.get("src_mac", "")
        dst_mac = data.get("dst_mac", "")
        
        src_ip = data.get("src_ip", "External Network")
        dst_ip = data.get("dst_ip", "192.168.121.x (IoT Subnet)")
        port = int(data.get("dst_port", 0))
        
        if encrypted:
            # Traffic is WPA2 encrypted. We cannot read IP/Port from ciphertext.
            # Use the unencrypted Layer-2 MAC addresses and resolve via ARP table!
            resolved_src = get_ip_from_mac(src_mac)
            resolved_dst = get_ip_from_mac(dst_mac)
            
            src_ip = resolved_src if resolved_src else f"MAC: {src_mac}"
            dst_ip = resolved_dst if resolved_dst else f"MAC: {dst_mac}"
            
            port = 0
            proto_str = "Encrypted WPA2"
        else:
            # Determine protocol string for unencrypted traffic
            try:
                proto_num = int(float(data.get("protocol", features_list[1])))
                proto_mapping = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "ARP", 2: "IGMP", 4: "IPv4", 41: "IPv6"}
                proto_str = proto_mapping.get(proto_num, f"Other ({proto_num})")
            except:
                proto_str = "Unknown"
        
        # Safely calculate average packet size to ensure it's never massive
        try:
            tot_size = float(features_list[3])
            num_pkts = float(features_list[7])
            avg_size = int(tot_size / num_pkts) if num_pkts > 0 else 64
            if avg_size > 1500: avg_size = 1500 # Cap at standard MTU
            if avg_size < 40: avg_size = 40     # Min size
        except:
            avg_size = 64

        # Publish PERFECT payload for app.js Dashboard
        alert_payload = {
            "attack": is_attack,
            "attackType": attack_type,
            "confidence": confidence,
            "pktRate": float(features_list[2]), 
            "packetSize": avg_size,
            "protocol": proto_str,
            "sourceIp": src_ip,
            "destIp": dst_ip,
            "port": port,
            "timestamp": time.strftime("%H:%M:%S")
        }
        
        try:
            if is_attack:
                mqtt_client.publish("ids/alerts", json.dumps(alert_payload))
            mqtt_client.publish("ids/packets", json.dumps(alert_payload))
        except Exception as e:
            print(f"Failed to publish to MQTT: {e}")
            
        if is_attack:
            threading.Thread(target=send_telegram, args=(attack_type, round(confidence * 100, 2))).start()
        
        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"error": f"Pipeline processing error: {str(e)}"}), 500

if __name__ == "__main__":
    # PORT is injected by Render at runtime; fall back to 5000 for local dev
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)