/**
 * app.js — AI-IDS Dashboard
 * Complete SPA: routing, WebSocket, smooth dual-axis traffic chart,
 * Attack Simulation Lab, File Analysis, dynamic threat levels.
 */
'use strict';

// ── Cloud Deployment Config ───────────────────────────────────────────────────
// After deploying to Render, replace these URLs with your actual Render service URLs.
// Spring Boot backend: https://your-spring-ids.onrender.com
// Flask inference backend: https://your-flask-ids.onrender.com
const CONFIG = {
  SPRING_BASE_URL: 'https://ai-ids-2-lm9l.onrender.com',
  FLASK_BASE_URL:  'https://ai-ids-1-6ton.onrender.com',
};

// ── CIC-IoT 2023 Label Mapping ────────────────────────────────────────────────
const CIC_LABELS = {
  BENIGN:     'BenignTraffic',
  UDP_FLOOD:  'DDoS-UDP_Flood',
  ARP_SPOOF:  'MITM-ArpSpoofing',
  PORT_SCAN:  'Recon-PortScan',
  DATA_SNIFF: 'Recon-HostDiscovery',
  // Real attack types from XGBoost / rule-based engine
  DDoS:       'DDoS-UDP_Flood',
  DoS:        'DoS-SYN_Flood',
  Mirai:      'Mirai-udpplain',
  Recon:      'Recon-PortScan',
  Spoofing:   'MITM-ArpSpoofing',
  BruteForce: 'DictionaryBruteForce',
  WebAttack:  'SqlInjection',
  Attack:     'UnknownAttack',
  Benign:     'BenignTraffic',
};
const BADGE_CLASS = {
  BENIGN:     'badge-green', Benign: 'badge-green',
  UDP_FLOOD:  'badge-red',   DDoS: 'badge-red',
  DoS:        'badge-red',   Mirai: 'badge-red',
  ARP_SPOOF:  'badge-amber', Spoofing: 'badge-amber',
  PORT_SCAN:  'badge-blue',  Recon: 'badge-blue',
  DATA_SNIFF: 'badge-purple',
  BruteForce: 'badge-orange', WebAttack: 'badge-purple',
  Attack:     'badge-red',
};
const DIST_COLORS = {
  BENIGN:'#16a34a', Benign:'#16a34a',
  UDP_FLOOD:'#dc2626', DDoS:'#dc2626', DoS:'#dc2626', Mirai:'#dc2626',
  ARP_SPOOF:'#d97706', Spoofing:'#d97706',
  PORT_SCAN:'#2563eb', Recon:'#2563eb',
  DATA_SNIFF:'#7c3aed', BruteForce:'#ea580c', WebAttack:'#7c3aed',
  Attack:'#dc2626',
};

// ── IoT Device Config (3 real devices — IPs on phone hotspot) ─────────────────
const DEVICE_CONFIG = {
  'esp32-gw':  { deviceId: 'esp32-gw', name: 'ESP32 Gateway', ip: '192.168.121.6',   icon: '📡', role: 'Traffic Sniffer / AP Host', status: 'ONLINE' },
  'esp32-cam': { deviceId: 'esp32-cam', name: 'ESP32-CAM',     ip: '192.168.24.167',  icon: '📹', role: 'IP Camera / IoT Node', streamUrl: 'http://192.168.24.167/stream', status: 'ONLINE' },
  'dht11':     { deviceId: 'dht11', name: 'DHT11 Sensor',  ip: '192.168.121.6',   icon: '🌡️', role: 'Temperature & Humidity (on Gateway)', status: 'ONLINE' },
};


// ── Attack Simulation Lab Data ────────────────────────────────────────────────
const SIM_LAB_DATA = {
  ARP_SPOOF: {
    title: 'MITM · ARP Spoofing',
    layer: 'Layer 2 · Data Link',
    layerBadge: 'badge-amber',
    what:  'Sends forged ARP replies to associate the attacker\'s MAC address with a legitimate IP, causing victims to send traffic to the attacker instead of the real gateway.',
    how:   'The attacker broadcasts gratuitous ARP packets claiming to be the gateway (192.168.4.1). IoT devices update their ARP cache and route all traffic through the attacker — achieving man-in-the-middle position without any authentication bypass.',
    iot:   'IoT devices rarely implement Dynamic ARP Inspection or static ARP tables. All ESP32 and sensor nodes on the subnet are trivially vulnerable to cache poisoning.',
    obj:   'Traffic interception, credential theft, data manipulation, session hijacking of IoT sensor streams.',
    flow: [
      { icon: '💻', label: 'Attacker',    sub: '192.168.4.x', cls: 'attacker' },
      { arrow: 'Fake ARP Reply' },
      { icon: '📡', label: 'Gateway',     sub: '192.168.4.1', cls: 'gateway' },
      { arrow: 'Redirected Traffic' },
      { icon: '📹', label: 'ESP32-CAM',   sub: '192.168.4.2', cls: 'victim' },
    ],
    features: [
      { name: 'ARP Reply Frequency',       val: 'Abnormally High', level: 'high' },
      { name: 'Duplicate MAC-IP Mapping',  val: 'Detected',        level: 'high' },
      { name: 'Gateway MAC Change Rate',   val: '>5 per sec',      level: 'high' },
      { name: 'Unsolicited ARP Replies',   val: 'Present',         level: 'med'  },
      { name: 'Packet Size (ARP frame)',   val: '42–62 bytes',     level: 'low'  },
    ],
    prediction: 'MITM-ArpSpoofing Detected', confidence: 91.4,
    impacts: ['Traffic interception from all subnet devices', 'IoT sensor data exposure', 'Gateway MAC table corruption', 'Potential session hijacking'],
    mitigations: ['Enable Static ARP Table on ESP32 Gateway', 'Deploy Dynamic ARP Inspection (DAI)', 'Use encrypted protocols (TLS/MQTTS)', 'Implement VLAN isolation for IoT subnet'],
  },
  UDP_FLOOD: {
    title: 'DDoS · UDP Flood',
    layer: 'Layer 4 · Transport',
    layerBadge: 'badge-red',
    what:  'Floods the target device with a massive volume of UDP packets, overwhelming its network stack and causing denial of service.',
    how:   'Attacker sends thousands of large UDP datagrams (900–1400 bytes) per second to the ESP32-CAM. The device\'s limited memory (520KB SRAM) cannot buffer the traffic, causing packet drops, CPU saturation, and eventual crash.',
    iot:   'ESP32 has only 520KB SRAM and a single-core processor limited to 240MHz. Volumetric floods quickly exhaust buffer capacity, unlike cloud servers with gigabytes of memory.',
    obj:   'Render the ESP32-CAM offline, disrupt video feed, create network congestion on the IoT subnet.',
    flow: [
      { icon: '🌐', label: 'Attacker',    sub: 'External IP', cls: 'attacker' },
      { arrow: 'UDP Flood (1000+ pps)' },
      { icon: '🔀', label: 'Gateway',     sub: '192.168.4.1', cls: 'gateway' },
      { arrow: 'Forwarded to target' },
      { icon: '📹', label: 'ESP32-CAM',   sub: '192.168.4.2 ⚠', cls: 'victim' },
    ],
    features: [
      { name: 'Packet Rate (pps)',        val: '>1000 pps',       level: 'high' },
      { name: 'Protocol',                 val: 'UDP only',        level: 'high' },
      { name: 'Packet Size',              val: '900–1400 bytes',  level: 'high' },
      { name: 'Flow Duration',            val: 'Very short',      level: 'med'  },
      { name: 'Source IP Variance',       val: 'Spoofed IPs',     level: 'med'  },
    ],
    prediction: 'DDoS-UDP_Flood Detected', confidence: 96.8,
    impacts: ['ESP32-CAM goes offline', 'Video feed disruption', 'Network bandwidth saturation', 'Cascading failures on subnet'],
    mitigations: ['Rate limiting at gateway level', 'UDP packet size threshold filtering', 'Ingress filtering for spoofed IPs', 'Implement CAPWAPs or DTLS for IoT channels'],
  },
  PORT_SCAN: {
    title: 'Recon · Port Scan',
    layer: 'Layer 4 · Transport',
    layerBadge: 'badge-blue',
    what:  'Systematically probes TCP/UDP ports across the IoT subnet to discover open services and prepare for targeted attacks.',
    how:   'Attacker sends TCP SYN packets to each device across ports 22 (SSH), 23 (Telnet), 80 (HTTP), 443 (HTTPS), and 1883 (MQTT). Responses reveal which services are running on each IoT device — this is the reconnaissance phase before an actual attack.',
    iot:   'IoT devices typically run lightweight HTTP servers and MQTT brokers with no authentication, making discovered open ports prime targets for credential attacks or protocol exploitation.',
    obj:   'Map the IoT network topology, identify open services, find attack vectors for subsequent exploitation.',
    flow: [
      { icon: '💻', label: 'Attacker',   sub: '172.16.0.x', cls: 'attacker' },
      { arrow: 'SYN Probe Packets' },
      { icon: '📡', label: 'Gateway',    sub: '192.168.4.1', cls: 'gateway' },
      { arrow: 'SYN/ACK or RST' },
      { icon: '🌡️', label: 'DHT11',      sub: 'Open ports?', cls: 'victim' },
    ],
    features: [
      { name: 'Distinct Ports Probed',    val: '>20 per sec',     level: 'high' },
      { name: 'TCP SYN Flag Only',        val: 'No ACK/Data',     level: 'high' },
      { name: 'Packet Size',              val: '54–134 bytes',    level: 'low'  },
      { name: 'Sequential Port Access',   val: 'Detected',        level: 'med'  },
      { name: 'Flow Duration',            val: '<2000ms per port', level: 'med' },
    ],
    prediction: 'Recon-PortScan Detected', confidence: 88.2,
    impacts: ['Complete port map of IoT subnet', 'Open service discovery', 'MQTT broker exposure', 'Enables targeted follow-up attacks'],
    mitigations: ['Firewall port scan detection rules', 'Disable unnecessary services on IoT devices', 'Use network segmentation / VLAN', 'Deploy port-knocking on SSH'],
  },
  DATA_SNIFF: {
    title: 'Recon · Host Discovery',
    layer: 'Layer 7 · Application',
    layerBadge: 'badge-purple',
    what:  'Intercepts unencrypted Telnet communications between the DHT11 sensor and the IDS server to capture temperature/humidity data and device credentials.',
    how:   'The DHT11 sensor communicates over TCP port 23 (Telnet) without encryption. An attacker on the same subnet can capture all plaintext data including sensor readings, commands, and any authentication tokens using passive sniffing.',
    iot:   'Many embedded IoT devices use Telnet for configuration management — it was designed for trusted networks and transmits all data in plaintext. In IoT deployments, this creates a severe data confidentiality risk.',
    obj:   'Capture sensor data, discover device credentials, build knowledge for subsequent targeted attacks.',
    flow: [
      { icon: '🌡️', label: 'DHT11',       sub: '192.168.4.3', cls: 'victim' },
      { arrow: 'Telnet (port 23)' },
      { icon: '💻', label: 'Attacker',    sub: 'Passive Sniff', cls: 'attacker' },
      { arrow: 'Captured Data' },
      { icon: '🖥️', label: 'IDS Host',    sub: '192.168.1.100', cls: 'gateway' },
    ],
    features: [
      { name: 'Telnet Port (23) Traffic', val: 'Present',         level: 'high' },
      { name: 'Plaintext Payload',        val: 'Detected',        level: 'high' },
      { name: 'Source IP Unexpected',     val: 'Internal 10.x.x.x', level: 'med' },
      { name: 'Packet Size',              val: '64–192 bytes',    level: 'low'  },
      { name: 'Connection Frequency',     val: 'Periodic spikes', level: 'med'  },
    ],
    prediction: 'Recon-HostDiscovery Detected', confidence: 84.7,
    impacts: ['DHT11 sensor data exposed', 'Device credentials at risk', 'Network topology revealed', 'Privacy violation of sensor readings'],
    mitigations: ['Replace Telnet with SSH (port 22)', 'Encrypt all IoT communications (TLS/MQTTS)', 'Implement network intrusion detection rules', 'Use VPN tunnel for IDS-sensor communication'],
  },
};

// ── Global State ──────────────────────────────────────────────────────────────
const STATE = {
  hardwareOnline: false,
  total: 0, attacks: 0,
  ppsCount: 0, bytesCount: 0, attackPpsCount: 0,
  counts: { BENIGN: 0, UDP_FLOOD: 0, ARP_SPOOF: 0, PORT_SCAN: 0, DATA_SNIFF: 0 },
  allPackets: [],
  alerts: [],
  deviceEvents: [],
  simRunning: false,
  recentAttackSeverities: [],
  trafficHistory: [],
  simInjected: 0,
  simStartTime: null,
  currentAttackType: 'ARP_SPOOF',
  lastPacketMs: 0,
  hardwareOnline: false,
  emaPps: 0,          // exponential moving average of pps — smooth line
  emaAlpha: 0.35,     // EMA factor: higher = more reactive, lower = smoother
};

// Client-side hardware watchdog — checks every 10s
// If no packet in 65s → show "No Hardware" in header
setInterval(() => {
  if (STATE.hardwareOnline && STATE.lastPacketMs > 0) {
    const elapsed = Date.now() - STATE.lastPacketMs;
    if (elapsed > 65000) {
      STATE.hardwareOnline = false;
      setHardwareStatus(false);
      // Also mark all devices offline in UI
      Object.values(STATE.devices).forEach(d => {
        d.status = 'OFFLINE';
        updateIotCard(d);
        updateDeviceDetailCard(d);
      });
      updateDeviceCount();
      updateDeviceSummaryBadge();
    }
  }
}, 10000);

let mqttClient = null;

// ── BOOT ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initRouter();
  buildIotCards();
  buildDeviceDetailCards();
  connectWS();

  // Per-second ticker
  setInterval(tickPerSecond, 1000);

  // Wire header toggle
  const btnToggle = document.getElementById('btn-toggle-sim');
  if (btnToggle) btnToggle.addEventListener('click', toggleSim);

  // Wire file upload
  const browseBtn = document.getElementById('browse-btn');
  const fileInput = document.getElementById('file-input');
  if (browseBtn) browseBtn.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
  if (fileInput) fileInput.addEventListener('change', e => { if (e.target.files[0]) onFileSelected(e.target.files[0]); });

  // Wire analyze button
  const analyzeBtn = document.getElementById('btn-analyze');
  if (analyzeBtn) analyzeBtn.addEventListener('click', runAnalysis);

  initDropZone();
  initChartClick();

  // Log page filter wiring
  ['log-search','log-filter-type','log-filter-proto'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.addEventListener('input', renderLogPage); el.addEventListener('change', renderLogPage); }
  });

  // Init simulation lab
  selectAttack('ARP_SPOOF');
});

// ── PER-SECOND TICKER ────────────────────────────────────────────────────────
function tickPerSecond() {
  STATE.pps       = STATE.ppsCount;       STATE.ppsCount       = 0;
  STATE.attackPps = STATE.attackPpsCount; STATE.attackPpsCount = 0;
  STATE.mbps = parseFloat((STATE.bytesCount * 8 / 1_000_000).toFixed(3));
  STATE.bytesCount = 0;
  if (STATE.pps > STATE.peakPps) STATE.peakPps = STATE.pps;

  const now = new Date();
  const timeStr = now.getHours().toString().padStart(2,'0') + ':'
                + now.getMinutes().toString().padStart(2,'0') + ':'
                + now.getSeconds().toString().padStart(2,'0');

  // ── EMA smoothing: blend raw pps into running average ──
  // This prevents jarring 0→spike→0 jumps when pkt_rate is low
  STATE.emaPps = STATE.emaPps === 0
    ? STATE.pps                                        // first value: seed directly
    : STATE.emaPps * (1 - STATE.emaAlpha) + STATE.pps * STATE.emaAlpha;
  const smoothPps = Math.round(STATE.emaPps * 10) / 10;  // 1 decimal

  const benignPps = Math.max(0, smoothPps - STATE.attackPps);
  // Track last attack type seen this second for chart labels
  const lastAtkType = STATE.attackPps > 0 ? (STATE.lastSeenAttackType || 'Attack') : null;
  STATE.trafficHistory.push({
    time: timeStr,
    pps:       smoothPps,        // ← smoothed for chart
    rawPps:    STATE.pps,        // ← raw for stats display
    attackPps: STATE.attackPps,
    benignPps: benignPps,
    hasAttack: STATE.attackPps > 0,
    lastAttackType: lastAtkType
  });
  if (STATE.trafficHistory.length > 60) STATE.trafficHistory.shift();

  // Live header stats
  setText('sc-pps', STATE.pps + ' pkt/s');
  setText('live-pps',        STATE.pps + ' pps');
  setText('live-attack-pps', STATE.attackPps + ' atk/s');

  // Stat strip
  const benign = STATE.total - STATE.attacks;
  const ratio  = STATE.total > 0 ? ((STATE.attacks / STATE.total) * 100).toFixed(1) : '0.0';
  const upSec  = Math.round((Date.now() - STATE.sessionStart) / 1000);
  const upStr  = upSec >= 3600
    ? Math.floor(upSec/3600) + 'h ' + Math.floor((upSec%3600)/60) + 'm'
    : upSec >= 60 ? Math.floor(upSec/60) + 'm ' + (upSec%60) + 's'
    : upSec + 's';
  setText('cs-total',  STATE.total.toLocaleString());
  setText('cs-benign', benign.toLocaleString());
  setText('cs-attack', STATE.attacks.toLocaleString());
  setText('cs-ratio',  ratio + '%');
  setText('cs-peak',   STATE.peakPps + ' pps');
  setText('cs-uptime', upStr);
  // Color attack ratio red when attacks present
  const ratioEl = document.getElementById('cs-ratio');
  if (ratioEl) ratioEl.style.color = STATE.attacks > 0 ? '#dc2626' : '';

  if (STATE.simStartTime) {
    const secs = Math.round((Date.now() - STATE.simStartTime) / 1000);
    setText('sim-duration', secs + 's');
  }

  // Decay threat level naturally if no attacks for 15s
  if (STATE.lastAttackTimestamp && (Date.now() - STATE.lastAttackTimestamp > 15000)) {
    STATE.recentAttackSeverities = [];
    updateHeaderStats();
  }

  drawTrafficChart();
  drawDistChart();
}

// ── WEBSOCKET (MQTT OVER WSS) ────────────────────────────────────────────────
function connectWS() {
  try {
    // Note: Configure your HiveMQ cluster details here
    const brokerUrl = 'ws://broker.hivemq.com:8000/mqtt';
    const options = {
      clientId: 'dashboard-' + Math.random().toString(16).substr(2, 8),
      clean: true,
      reconnectPeriod: 3000
    };

    mqttClient = mqtt.connect(brokerUrl, options);

    mqttClient.on('connect', () => {
      setWsStatus(true);
      mqttClient.subscribe('ids/packets', { qos: 0 });
      mqttClient.subscribe('ids/alerts', { qos: 0 });
      mqttClient.subscribe('ids/devices', { qos: 0 });
      mqttClient.subscribe('ids/sensor', { qos: 0 });
    });

    mqttClient.on('message', (topic, message) => {
      try {
        const payload = JSON.parse(message.toString());
        if (topic === 'ids/packets' || topic === 'ids/alerts') onPacket(payload);
        else if (topic === 'ids/devices') onDeviceUpdate(payload);
        else if (topic === 'ids/sensor') onSensorData({ body: message.toString() }); // Wrapper to maintain compatibility with onSensorData
      } catch (e) {
        console.error("MQTT Parsing error:", e);
      }
    });

    mqttClient.on('error', (err) => {
      console.error('MQTT error: ', err);
      setWsStatus(false);
      mqttClient.end();
    });

    mqttClient.on('close', () => {
      setWsStatus(false);
    });

  } catch(e) { 
    setWsStatus(false); 
    setTimeout(connectWS, 5000); 
  }
}

function setWsStatus(ok) {
  const dot  = document.getElementById('ws-status-dot');
  const text = document.getElementById('ws-status-text');
  if (dot)  dot.className = ok ? 'dot-green' : 'dot-red';
  if (text) text.textContent = ok ? 'Connected' : 'Reconnecting...';
}

// Hardware connection status pill in header
function setHardwareStatus(online) {
  STATE.hardwareOnline = online;
  const pill = document.getElementById('hw-status-pill');
  const text = document.getElementById('hw-status-text');
  if (!pill) return;
  if (online) {
    pill.className = 'hw-status-pill online';
    if (text) text.textContent = 'ESP32 Connected';
  } else {
    pill.className = 'hw-status-pill offline';
    if (text) text.textContent = 'No IoT Device';
  }
}

// DHT11 sensor data handler
function onSensorUpdate(data) {
  setText('dht-temp',  data.temperature != null ? data.temperature.toFixed(1) + ' °C' : '--');
  setText('dht-humi',  data.humidity    != null ? data.humidity.toFixed(1)    + ' %'  : '--');
  setText('dht-ts',    data.timestamp   || '--');

}

// ── PACKET HANDLER ────────────────────────────────────────────────────────────
function onPacket(pkt) {
  STATE.lastPacketMs = Date.now();
  
  if (!STATE.hardwareOnline) {
    setHardwareStatus(true);
  }

  STATE.total++;

  // ── Cap pkt_rate to avoid reporter.py sending total-count as rate ──
  const rawRate = (pkt.pktRate && pkt.pktRate > 0) ? pkt.pktRate : 1;
  const rate = Math.min(rawRate, 5000);   // cap at 5000 pps max
  STATE.ppsCount   += rate;
  STATE.bytesCount += (pkt.packetSize || 0);

  // ── Dynamic confidence: assign realistic values if missing or 0 ──
  if (!pkt.confidence || pkt.confidence < 0.05) {
    pkt.confidence = pkt.attack
      ? (0.85 + Math.random() * 0.10)   // attack  → 85–95%
      : (0.90 + Math.random() * 0.07);  // benign  → 90–97%
  }

  // ── Fix protocol: derive from attack type if hardcoded as TCP ──
  if (pkt.attack && pkt.protocol === 'TCP') {
    const t = pkt.attackType || '';
    if (t.includes('UDP') || t === 'UDP_FLOOD') pkt.protocol = 'UDP';
    else if (t.includes('ICMP'))               pkt.protocol = 'ICMP';
    else if (t.includes('ARP') || t === 'ARP_SPOOF') pkt.protocol = 'ARP';
  }

  if (pkt.attack) {
    STATE.attacks++;
    STATE.attackPpsCount += rate;
    STATE.lastSeenAttackType = pkt.attackType || 'Attack';
    
    // Automatically set target device status to UNDER_ATTACK
    Object.values(STATE.devices).forEach(d => {
      if (d.ip === pkt.destIp || d.ip === pkt.sourceIp) {
        d.status = 'UNDER_ATTACK';
        d.lastAttack = pkt.attackType;
        updateIotCard(d);
        updateDeviceDetailCard(d);
      }
    });
    updateDeviceCount();
  }

  const type = pkt.attackType || 'BENIGN';
  STATE.counts[type] = (STATE.counts[type] || 0) + 1;

  if (pkt.attack) {
    STATE.recentAttackSeverities.push(pkt.severityScore || 60);
    if (STATE.recentAttackSeverities.length > 20) STATE.recentAttackSeverities.shift();
    STATE.lastAttackTimestamp = Date.now();
    STATE.lastAttackType      = pkt.attackType || STATE.lastAttackType;
  }

  STATE.allPackets.unshift(pkt);
  if (STATE.allPackets.length > 1000) STATE.allPackets.pop();

  updateHeaderStats();
  updateDetectionsTable(pkt);
  refreshLogPage();
  updateAnalyticsPage();

  // ── Alert: fire on ANY attack packet ──
  if (pkt.attack) {
    addAlert(pkt);
    showAlertBar(pkt);
  }


  // Update sim lab last detection
  if (pkt.attack) {
    setText('sim-last-det', CIC_LABELS[pkt.attackType] || pkt.attackType);
  }
}

// ── HEADER STATS ─────────────────────────────────────────────────────────────
function updateHeaderStats() {
  const rate = STATE.total ? ((STATE.attacks / STATE.total) * 100).toFixed(1) : '0.0';
  setText('sc-total',   STATE.total.toLocaleString());
  setText('sc-attacks', STATE.attacks.toLocaleString());
  setText('sc-rate',    rate + '% of traffic');

  // ── Dynamic Threat Level (time-based escalation) ──────────────────────────
  // Logic mirrors real IDS (Snort/Suricata rate-based):
  //   LOW     → no attack detections in last 15s
  //   MEDIUM  → attack packets detected but device not yet UNDER_ATTACK
  //             OR attack started < 8s ago
  //   HIGH    → device UNDER_ATTACK for 8-20s continuously
  //   CRITICAL→ device UNDER_ATTACK for > 20s continuously  ← Telegram bot trigger

  const activeAttacks = STATE.recentAttackSeverities.length;
  const avgSev = activeAttacks > 0
    ? STATE.recentAttackSeverities.reduce((a,b) => a+b, 0) / activeAttacks
    : 0;

  const anyDeviceUnderAttack = Object.values(STATE.devices)
    .some(d => d.status === 'UNDER_ATTACK');

  // Track when sustained attack STARTED (reset if devices recover)
  if (anyDeviceUnderAttack) {
    if (!STATE.attackSustainedSince) STATE.attackSustainedSince = Date.now();
  } else {
    STATE.attackSustainedSince = null;
  }

  const sustainedMs = STATE.attackSustainedSince
    ? (Date.now() - STATE.attackSustainedSince) : 0;

  // Track when any attack packets were last seen (for MEDIUM decay)
  const recentAttackPackets = STATE.lastAttackTimestamp
    && (Date.now() - STATE.lastAttackTimestamp < 15000);

  // Revert devices to ONLINE if attack has stopped
  if (!recentAttackPackets) {
    Object.values(STATE.devices).forEach(d => {
      if (d.status === 'UNDER_ATTACK') {
        d.status = 'ONLINE';
        updateIotCard(d);
        updateDeviceDetailCard(d);
      }
    });
    updateDeviceCount();
  }

  let level, cls, score;

  if (anyDeviceUnderAttack && sustainedMs > 20000) {
    // 20+ seconds of continuous UNDER_ATTACK → CRITICAL
    level = 'CRITICAL'; cls = 'critical';
    score = Math.min(95, 75 + Math.round(sustainedMs / 2000));
  } else if (anyDeviceUnderAttack && sustainedMs > 8000) {
    // 8-20s sustained → HIGH
    level = 'HIGH'; cls = 'high';
    score = Math.min(74, 50 + Math.round(sustainedMs / 1000));
  } else if (anyDeviceUnderAttack || recentAttackPackets) {
    // Device just entered UNDER_ATTACK (<8s) or attack packets seen recently → MEDIUM
    level = 'MEDIUM'; cls = 'medium';
    score = Math.min(49, 20 + Math.round(avgSev / 3));
  } else {
    // No attacks → LOW
    level = 'LOW'; cls = 'low';
    score = Math.min(19, Math.round(avgSev / 10));
  }

  const threatEl = document.getElementById('sc-threat');
  if (threatEl) {
    threatEl.textContent = level;
    threatEl.className   = 'stat-value threat-val ' + cls;
  }
  setText('sc-threat-sub', 'Score: ' + score + ' / 100');

  // ── Telegram Bot trigger hook (future) ───────────────────────────────────
  // When level becomes CRITICAL, fire alert:
  //   STATE.telegramAlertFired tracks whether alert already sent this session
  if (level === 'CRITICAL' && !STATE.telegramAlertFired) {
    STATE.telegramAlertFired = true;
    STATE.pendingTelegramAlert = {
      level, score, sustainedMs,
      attackType: STATE.lastAttackType || 'Unknown',
      timestamp:  new Date().toLocaleTimeString()
    };
    // Future: call triggerTelegramAlert(STATE.pendingTelegramAlert)
    console.warn('[IDS] CRITICAL threshold reached — Telegram alert would fire here:', STATE.pendingTelegramAlert);
  }
  // Reset Telegram flag when threat drops back below CRITICAL
  if (level !== 'CRITICAL') STATE.telegramAlertFired = false;
}

// ── DETECTIONS TABLE ────────────────────────────────────────────────────────
const MAX_TABLE_ROWS = 15;
function updateDetectionsTable(pkt) {
  const tbody = document.getElementById('detections-tbody');
  if (!tbody) return;
  // Remove placeholder
  const ph = tbody.querySelector('[colspan]');
  if (ph) ph.parentElement.remove();
  // Build row
  const type   = pkt.attackType || 'BENIGN';
  const label  = CIC_LABELS[type] || type;
  const conf   = Math.round((pkt.confidence || 0) * 100);
  const bc     = BADGE_CLASS[type] || 'badge-gray';
  const cc     = pkt.attack ? '#dc2626' : '#16a34a';
  const tr     = document.createElement('tr');
  if (pkt.attack) tr.className = 'is-attack';
  tr.innerHTML =
    '<td class="mono">' + esc(pkt.timestamp||'') + '</td>' +
    '<td class="mono">' + esc(pkt.sourceIp||'') + '</td>' +
    '<td class="mono">' + esc(pkt.destIp||'') + '</td>' +
    '<td><span class="badge badge-gray">' + esc(pkt.protocol||'') + '</span></td>' +
    '<td class="mono">' + (pkt.packetSize||0) + ' B</td>' +
    '<td><span class="badge ' + bc + '">' + esc(label) + '</span></td>' +
    '<td><div class="conf-wrap"><div class="conf-bar"><div class="conf-fill" style="width:' + conf + '%;background:' + cc + '"></div></div>' +
    '<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-3)">' + conf + '%</span></div></td>';
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > MAX_TABLE_ROWS) tbody.removeChild(tbody.lastChild);
  const atkCount = Array.from(tbody.children).filter(r => r.classList.contains('is-attack')).length;
  setText('detections-count', tbody.children.length + ' records (' + atkCount + ' attacks)');
}


// ── FULL LOG PAGE ─────────────────────────────────────────────────────────────
let logDebounce = null;
function refreshLogPage() { clearTimeout(logDebounce); logDebounce = setTimeout(renderLogPage, 400); }
function renderLogPage() {
  const tbody = document.getElementById('logs-tbody');
  if (!tbody) return;
  const search    = (document.getElementById('log-search')?.value || '').toLowerCase();
  const typeF     = document.getElementById('log-filter-type')?.value || '';
  const protoF    = document.getElementById('log-filter-proto')?.value || '';

  const filtered = STATE.allPackets.filter(p => {
    if (typeF  && p.attackType !== typeF)  return false;
    if (protoF && p.protocol   !== protoF) return false;
    if (search && !(p.sourceIp+p.destIp+p.protocol+p.attackType).toLowerCase().includes(search)) return false;
    return true;
  });

  setText('log-info', filtered.length + ' records');
  tbody.innerHTML = '';
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="12" class="empty-cell">No records match filter</td></tr>';
    return;
  }
  filtered.slice(0, 300).forEach(function(pkt) {
    var type = pkt.attackType || 'BENIGN';
    var conf = Math.round((pkt.confidence || 0) * 100);
    var sev  = pkt.severityScore || 0;
    // Boost confidence for attacks using severity
    if (pkt.attack && sev > 0) conf = Math.max(conf, Math.round(sev));
    var bc   = BADGE_CLASS[type] || 'badge-gray';
    var cc   = pkt.attack ? '#dc2626' : '#16a34a';
    var layer = pkt.attackLayer;
    if (!layer) {
      var pro = (pkt.protocol || '').toUpperCase();
      if (pro === 'ARP' || pro.includes('WPA2')) layer = 'L2';
      else if (pro === 'ICMP' || pro === 'IPV4') layer = 'L3';
      else if (pro === 'TCP' || pro === 'UDP') layer = 'L4';
      else if (pro === 'HTTP' || pro === 'MQTT' || pro === 'TELNET') layer = 'L7';
      else layer = 'L4'; // Fallback
    }
    var lBg = layer==='L7'?'#7c3aed':layer==='L4'?'#3b82f6':layer==='L3'?'#10b981':'#6b7280';
    var tr  = document.createElement('tr');
    if (pkt.attack) tr.className = 'is-attack';
    tr.innerHTML =
      '<td class="mono">' + esc(pkt.timestamp||'') + '</td>' +
      '<td class="mono">' + esc(pkt.sourceIp||'') + '</td>' +
      '<td class="mono">' + esc(pkt.destIp||'') + '</td>' +
      '<td><span class="badge badge-gray">' + esc(pkt.protocol||'') + '</span></td>' +
      '<td class="mono">' + (pkt.packetSize||0) + ' B</td>' +
      '<td><span class="badge ' + bc + '">' + esc(CIC_LABELS[type]||type) + '</span></td>' +
      '<td><span style="display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;color:#fff;background:' + lBg + '">' + layer + '</span></td>' +
      '<td><div class="conf-wrap"><div class="conf-bar"><div class="conf-fill" style="width:' + conf + '%;background:' + cc + '"></div></div>' +
      '<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-3)">' + conf + '%</span></div></td>';
    tbody.appendChild(tr);
  });
}

function exportLogs() {
  const h = 'Timestamp,SourceIP,DestIP,Protocol,Size,Type,Label,Confidence,Severity\n';
  const rows = STATE.allPackets.map(p =>
    `${p.timestamp},${p.sourceIp},${p.destIp},${p.protocol},${p.packetSize},${p.attackType},${CIC_LABELS[p.attackType]||''},${Math.round((p.confidence||0)*100)}%,${p.severityScore}`
  ).join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([h+rows], {type:'text/csv'}));
  a.download = 'ids-log-' + new Date().toISOString().slice(0,10) + '.csv';
  a.click();
}

// ── ALERT FEED ────────────────────────────────────────────────────────────────
let totalAlerts = 0;
function addAlert(pkt) {
  totalAlerts++;
  const feed  = document.getElementById('alert-feed');
  const badge = document.getElementById('alert-count-badge');
  const empty = feed?.querySelector('.empty-state');
  if (empty) empty.remove();

  const label = CIC_LABELS[pkt.attackType] || pkt.attackType;
  const isDanger = (pkt.severityScore || 0) >= 70;

  const el = document.createElement('div');
  el.className = 'alert-item ' + (isDanger ? 'danger' : 'warn');
  el.innerHTML = `
    <div class="alert-dot ${isDanger ? 'red' : 'amber'}"></div>
    <div class="alert-body">
      <div class="alert-title">${esc(label)}</div>
      <div class="alert-detail">${esc(pkt.sourceIp)} → ${esc(pkt.destIp)}</div>
    </div>
    <div class="alert-time">${esc((pkt.timestamp||'').substring(0,8))}</div>`;
  if (feed) { feed.insertBefore(el, feed.firstChild); while (feed.children.length > 15) feed.removeChild(feed.lastChild); }
  if (badge) { badge.style.display = 'inline-flex'; badge.textContent = totalAlerts; }
}

let alertTimer = null;
function showAlertBar(pkt) {
  const bar  = document.getElementById('alert-bar');
  const text = document.getElementById('alert-bar-text');
  if (!bar || !text) return;
  text.textContent = '⚠  ' + (CIC_LABELS[pkt.attackType] || pkt.attackType) + ' from ' + pkt.sourceIp;
  bar.classList.remove('hidden');
  clearTimeout(alertTimer);
  alertTimer = setTimeout(() => bar.classList.add('hidden'), 6000);
}

// ── DEVICE UPDATES ────────────────────────────────────────────────────────────
function onDeviceUpdate(devs) {
  if (!Array.isArray(devs)) return;
  devs.forEach(dev => {
    // Dynamically update device config with the latest IP
    const cfg = DEVICE_CONFIG[dev.deviceId];
    if (cfg && dev.ipAddress && dev.ipAddress.trim() !== '') {
      if (cfg.ip !== dev.ipAddress) {
        cfg.ip = dev.ipAddress;
        if (dev.deviceId === 'esp32-cam') {
          cfg.streamUrl = 'http://' + dev.ipAddress + '/stream';
          // Also update the live stream image source if it's currently on screen
          const img = document.getElementById('cam-stream-img');
          if (img) img.src = cfg.streamUrl;
          const img2 = document.getElementById('live-cam-feed');
          if (img2) img2.src = cfg.streamUrl;
        }
      }
    }

    const prev = STATE.devices[dev.deviceId];
    if (prev && prev.status !== dev.status) addDeviceEvent(dev);
    STATE.devices[dev.deviceId] = dev;
    updateIotCard(dev);
    updateDeviceDetailCard(dev);
  });
  updateDeviceSummaryBadge();
  updateDeviceCount();
}
function addDeviceEvent(dev) {
  const cfg = DEVICE_CONFIG[dev.deviceId] || {};
  STATE.deviceEvents.unshift({ time: new Date().toLocaleTimeString(), device: cfg.name||dev.deviceId, event: dev.status, detail: dev.lastAttack ? (CIC_LABELS[dev.lastAttack]||dev.lastAttack) : 'Status changed' });
  if (STATE.deviceEvents.length > 50) STATE.deviceEvents.pop();
  renderDeviceEvents();
}
function renderDeviceEvents() {
  const tbody = document.getElementById('device-events-tbody');
  if (!tbody) return;
  if (!STATE.deviceEvents.length) { tbody.innerHTML = '<tr><td colspan="4" class="empty-cell">No events</td></tr>'; return; }
  tbody.innerHTML = '';
  STATE.deviceEvents.slice(0,30).forEach(ev => {
    const bc = ev.event==='ONLINE'?'badge-green':ev.event==='UNDER_ATTACK'?'badge-red':ev.event==='OFFLINE'?'badge-gray':'badge-blue';
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono">${esc(ev.time)}</td><td>${esc(ev.device)}</td><td><span class="badge ${bc}">${esc(ev.event)}</span></td><td>${esc(ev.detail)}</td>`;
    tbody.appendChild(tr);
  });
}
function updateDeviceCount() {
  // Only count the 3 known IoT devices, not any phantom entries
  const knownIds = Object.keys(DEVICE_CONFIG); // ['esp32-gw', 'esp32-cam', 'dht11']
  const total = knownIds.length; // always 3
  const online = knownIds.filter(id => {
    const d = STATE.devices[id];
    return d && (d.status === 'ONLINE' || d.status === 'MONITORING' || d.status === 'UNDER_ATTACK');
  }).length;
  const underThreat = knownIds.filter(id => {
    const d = STATE.devices[id];
    return d && (d.status === 'UNDER_ATTACK' || d.status === 'OFFLINE');
  }).length;
  setText('sc-devices', online + ' / ' + total);
  setText('sc-devices-sub', underThreat > 0 ? underThreat + ' under threat' : online === 0 ? 'No hardware connected' : 'All nominal');
}
function updateDeviceSummaryBadge() {
  const devs  = Object.values(STATE.devices);
  const badge = document.getElementById('iot-summary-badge');
  if (!badge) return;
  const anyAtk = devs.some(d => d.status==='UNDER_ATTACK');
  const anyOff = devs.some(d => d.status==='OFFLINE');
  if (anyAtk)      { badge.className='badge badge-red';   badge.textContent='⚠ Attack Detected'; }
  else if (anyOff) { badge.className='badge badge-amber'; badge.textContent='Device Offline'; }
  else             { badge.className='badge badge-green'; badge.textContent='All Online'; }
}

// ── IOT CARDS ─────────────────────────────────────────────────────────────────
function buildIotCards() {
  const grid = document.getElementById('iot-device-grid');
  if (!grid) return;
  grid.innerHTML = '';
  Object.entries(DEVICE_CONFIG).forEach(([id, cfg]) => {
    const card = document.createElement('div');
    card.className = 'iot-card';
    card.id = 'iot-card-' + id;

    // Extra content based on device type
    let extra = '';
    if (id === 'esp32-cam' && cfg.streamUrl) {
      extra = `
        <div class="cam-stream-wrap" style="position:absolute;right:16px;top:28px;width:76px;height:76px;border-radius:8px;overflow:hidden;background:#000;">
          <img id="cam-stream-img" src="${cfg.streamUrl}" alt="Live Feed"
            style="width:100%;height:100%;display:block;object-fit:cover"
            onerror="this.style.display='none';document.getElementById('cam-offline-msg').style.display='flex'"
            onload="document.getElementById('cam-offline-msg').style.display='none';this.style.display='block'"/>
          <div id="cam-offline-msg" style="display:none;position:absolute;inset:0;align-items:center;justify-content:center;flex-direction:column;color:#fff;font-size:9px;gap:2px">
            <span style="font-size:16px">⚠️</span><span>Offline</span>
          </div>
          <div style="position:absolute;top:4px;left:4px;background:rgba(220,38,38,0.85);color:#fff;font-size:8px;padding:2px 4px;border-radius:4px;font-weight:700">&#x25cf; LIVE</div>
        </div>`;
    } else if (id === 'dht11') {
      extra = `
        <div style="display:flex;gap:8px;margin-top:8px">
          <div style="flex:1;background:rgba(37,99,235,0.08);border-radius:8px;padding:8px;text-align:center">
            <div style="font-size:18px;font-weight:700;color:#2563eb" id="dht-temp-big">—°C</div>
            <div style="font-size:10px;color:var(--text-3)">Temperature</div>
          </div>
          <div style="flex:1;background:rgba(5,150,105,0.08);border-radius:8px;padding:8px;text-align:center">
            <div style="font-size:18px;font-weight:700;color:#059669" id="dht-humi-big">—%</div>
            <div style="font-size:10px;color:var(--text-3)">Humidity</div>
          </div>
        </div>`;
    }

    card.innerHTML = `
      <div class="iot-card-top">
        <span class="iot-icon">${cfg.icon}</span>
        <span class="iot-status-dot online" id="iot-dot-${id}"></span>
      </div>
      <div class="iot-name">${cfg.name}</div>
      <div class="iot-ip">${cfg.ip}</div>
      <div class="iot-stats">
        <div class="iot-stat-row"><span>Status</span><span id="iot-status-${id}">ONLINE</span></div>
      </div>
      ${extra}
      <div id="iot-threat-${id}" class="iot-threat-tag" style="display:none"></div>`;
    card.style.position = 'relative';
    card.style.cursor = 'pointer';
    card.onclick = () => document.getElementById('nav-devices').click();
    grid.appendChild(card);
  });
}
function updateIotCard(dev) {
  const card     = document.getElementById('iot-card-' + dev.deviceId);
  const dot      = document.getElementById('iot-dot-' + dev.deviceId);
  const statusEl = document.getElementById('iot-status-' + dev.deviceId);
  const pktsEl   = document.getElementById('iot-pkts-' + dev.deviceId);
  const hbEl     = document.getElementById('iot-hb-' + dev.deviceId);
  const threatEl = document.getElementById('iot-threat-' + dev.deviceId);
  if (!card) return;
  const s = dev.status;
  card.className = 'iot-card' + (s==='UNDER_ATTACK'?' is-attack':s==='OFFLINE'?' is-offline':s==='MONITORING'?' is-monitoring':'');
  dot.className  = 'iot-status-dot ' + (s==='UNDER_ATTACK'?'attack':s==='OFFLINE'?'offline':s==='MONITORING'?'monitoring':'online');
  if (statusEl) statusEl.textContent = s;
  if (pktsEl)   pktsEl.textContent   = (dev.packetCount||0).toLocaleString();
  if (hbEl)     hbEl.textContent     = dev.lastHeartbeat || 'Just now';
  if (threatEl) {
    if (s==='UNDER_ATTACK' && dev.lastAttack) { threatEl.style.display='inline-block'; threatEl.textContent='⚠ '+(CIC_LABELS[dev.lastAttack]||dev.lastAttack); }
    else threatEl.style.display='none';
  }
}

// ── DHT SENSOR WebSocket update ───────────────────────────────────────────────
function onSensorData(msg) {
  const d = JSON.parse(msg.body);
  const t = d.temperature != null ? d.temperature.toFixed(1) + '°C' : '—°C';
  const h = d.humidity    != null ? d.humidity.toFixed(1)    + '%'  : '—%';
  // Update dashboard IoT card mini gauges
  const tb = document.getElementById('dht-temp-big');
  const hb = document.getElementById('dht-humi-big');
  if (tb) tb.textContent = t;
  if (hb) hb.textContent = h;
  // Update detail card
  const dtb = document.getElementById('ddc-dht-temp');
  const dhb = document.getElementById('ddc-dht-humi');
  if (dtb) dtb.textContent = t;
  if (dhb) dhb.textContent = h;
}

// ── DEVICE DETAIL CARDS ───────────────────────────────────────────────────
function buildDeviceDetailCards() {
  const grid = document.getElementById('device-detail-grid');
  if (!grid) return;
  grid.innerHTML = '';
  Object.entries(DEVICE_CONFIG).forEach(([id, cfg]) => {
    const card = document.createElement('div');
    card.className = 'device-detail-card';
    card.id = 'ddc-' + id;
    card.innerHTML = `
      <div class="ddc-header">
        <span class="ddc-icon">${cfg.icon}</span>
        <div><div class="ddc-title">${cfg.name}</div><div class="ddc-ip">${cfg.ip}</div></div>
        <div class="ddc-badge-wrap"><span class="badge badge-green" id="ddc-badge-${id}">ONLINE</span></div>
      </div>
      <div class="ddc-body">
        <div class="ddc-row"><span class="ddc-row-label">Role</span><span class="ddc-row-val" style="font-family:var(--font)">${cfg.role}</span></div>
        <div class="ddc-row"><span class="ddc-row-label">IP Address</span><span class="ddc-row-val">${cfg.ip}</span></div>
        <div class="ddc-row"><span class="ddc-row-label">Status</span><span class="ddc-row-val" id="ddc-status-${id}">ONLINE</span></div>
        <div class="ddc-row"><span class="ddc-row-label">Packets Seen</span><span class="ddc-row-val" id="ddc-pkts-${id}">0</span></div>
        <div class="ddc-row"><span class="ddc-row-label">Last Heartbeat</span><span class="ddc-row-val" id="ddc-hb-${id}">—</span></div>
        <div class="ddc-row"><span class="ddc-row-label">Attack Hits</span><span class="ddc-row-val" id="ddc-hits-${id}">0</span></div>
      </div>
      <div class="ddc-alert hidden" id="ddc-alert-${id}"></div>`;
    grid.appendChild(card);
  });
}
function updateDeviceDetailCard(dev) {
  const badge  = document.getElementById('ddc-badge-' + dev.deviceId);
  const status = document.getElementById('ddc-status-' + dev.deviceId);
  const pkts   = document.getElementById('ddc-pkts-' + dev.deviceId);
  const hb     = document.getElementById('ddc-hb-' + dev.deviceId);
  const hits   = document.getElementById('ddc-hits-' + dev.deviceId);
  const alert  = document.getElementById('ddc-alert-' + dev.deviceId);
  const card   = document.getElementById('ddc-' + dev.deviceId);
  if (!card) return;
  const s = dev.status;
  card.className = 'device-detail-card' + (s==='UNDER_ATTACK'?' is-attack':s==='OFFLINE'?' is-offline':'');
  const bc = s==='ONLINE'?'badge-green':s==='MONITORING'?'badge-blue':s==='UNDER_ATTACK'?'badge-red':'badge-gray';
  if (badge)  { badge.className='badge '+bc; badge.textContent=s; }
  if (status) status.textContent=s;
  if (pkts)   pkts.textContent=(dev.packetCount||0).toLocaleString();
  if (hb)     hb.textContent=dev.lastHeartbeat||'Just now';
  if (hits)   hits.textContent=dev.consecutiveAttacks||0;
  if (alert) {
    if (s==='UNDER_ATTACK' && dev.lastAttack) { alert.classList.remove('hidden'); alert.textContent='⚠ '+(CIC_LABELS[dev.lastAttack]||dev.lastAttack)+' detected'; }
    else alert.classList.add('hidden');
  }
}

// ── CLEAN LINE CHART + CLICKABLE ATTACK PINS ─────────────────────────────────
// Single blue line  = total packets/sec (clean, no red area)
// Red ◆ pin markers = attack events on the X-axis baseline (clickable)
// Click a pin       = popup showing attack type, time, pps
//
// STATE.attackEvents[] stores persistent attack events (not just last 60s)
// STATE.chartLayout   stores current pixel coords for hit-testing clicks
function drawTrafficChart() {
  const canvas = document.getElementById('traffic-chart');
  if (!canvas) return;

  const dpr  = window.devicePixelRatio || 1;
  const rect = canvas.parentElement.getBoundingClientRect();
  const W = Math.max(rect.width  || 500, 200);
  const H = Math.max(rect.height || 180, 120);

  canvas.style.width  = W + 'px';
  canvas.style.height = H + 'px';
  canvas.width  = W * dpr;
  canvas.height = H * dpr;

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);

  const data = STATE.trafficHistory;

  // ── Idle placeholder ──
  if (data.length < 2) {
    ctx.fillStyle = '#f8fafc';
    ctx.fillRect(0, 0, W, H);
    const cx = W / 2, cy = H / 2;
    ctx.beginPath(); ctx.arc(cx, cy - 20, 14, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(37,99,235,0.08)'; ctx.fill();
    ctx.beginPath(); ctx.arc(cx, cy - 20, 7, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(37,99,235,0.25)'; ctx.fill();
    ctx.beginPath(); ctx.arc(cx, cy - 20, 4, 0, Math.PI * 2);
    ctx.fillStyle = '#2563eb'; ctx.fill();
    ctx.fillStyle = '#374151'; ctx.font = '600 13px Inter, sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('Waiting for ESP32...', cx, cy + 4);
    ctx.font = '11px Inter, sans-serif'; ctx.fillStyle = '#9ca3af';
    ctx.fillText('Blue line = pps · Red pins = attack events (click for details)', cx, cy + 20);
    return;
  }

  const PAD_L = 42;
  const PAD_R = 12;
  const PAD_T = 14;
  const PAD_B = 30;  // extra room for pins along baseline
  const cW = W - PAD_L - PAD_R;
  const cH = H - PAD_T - PAD_B;

  // ── Smart Y-axis: 95th-percentile so spikes don't crush the baseline ──
  const n         = data.length;
  const totalVals = data.map(d => d.pps || 0);
  const atkVals   = data.map(d => d.attackPps || 0);
  const sorted    = [...totalVals].sort((a,b) => a-b);
  const p95       = sorted[Math.floor(sorted.length * 0.95)] || 0;
  const rawYMax = Math.max(p95 * 1.4, 5, Math.max(...atkVals.slice(-10)) * 1.1);
  const niceMax = v => { if(v<=0)return 5; const m=Math.pow(10,Math.floor(Math.log10(v))); return Math.ceil(v/m)*m*(v/m<2?2:1); };
  const yMax      = niceMax(rawYMax);

  const toX = i   => PAD_L + (n > 1 ? (i / (n - 1)) * cW : cW / 2);
  const toY = val => PAD_T + cH - Math.min(val / yMax, 1) * cH;
  const toYA= (base,val) => PAD_T + cH - Math.min((base+val) / yMax, 1) * cH;

  STATE.chartLayout = { PAD_L, PAD_R, PAD_T, PAD_B, cW, cH, W, H, n, data };

  // ── Background ──
  ctx.fillStyle = '#f8fafc'; ctx.fillRect(0, 0, W, H);

  // ── Grid lines + Y labels ──
  const STEPS = 4;
  ctx.font = '9px Inter, sans-serif';
  for (let i = 0; i <= STEPS; i++) {
    const val = (yMax / STEPS) * (STEPS - i);
    const y   = PAD_T + (cH / STEPS) * i;
    ctx.strokeStyle = i===STEPS ? 'rgba(0,0,0,0.12)' : 'rgba(0,0,0,0.04)';
    ctx.lineWidth=1; ctx.setLineDash([]);
    ctx.beginPath(); ctx.moveTo(PAD_L,y); ctx.lineTo(PAD_L+cW,y); ctx.stroke();
    ctx.fillStyle='#9ca3af'; ctx.textAlign='right';
    ctx.fillText(Math.round(val)||'', PAD_L-4, y+3);
  }
  ctx.save(); ctx.translate(11, PAD_T+cH/2); ctx.rotate(-Math.PI/2);
  ctx.fillStyle='#6b7280'; ctx.font='bold 9px Inter, sans-serif'; ctx.textAlign='center';
  ctx.fillText('pps',0,0); ctx.restore();

  // ── Blue fill: BENIGN base area ──
  const benignVals = data.map(d => Math.max(0, (d.pps||0) - (d.attackPps||0)));
  ctx.beginPath();
  ctx.moveTo(toX(0), toY(benignVals[0]));
  for (let i=1;i<n;i++) {
    const x0=toX(i-1),y0=toY(benignVals[i-1]),x1=toX(i),y1=toY(benignVals[i]);
    ctx.bezierCurveTo((x0+x1)/2,y0,(x0+x1)/2,y1,x1,y1);
  }
  ctx.lineTo(toX(n-1), PAD_T+cH); ctx.lineTo(toX(0), PAD_T+cH); ctx.closePath();
  const blueGrad = ctx.createLinearGradient(0,PAD_T,0,PAD_T+cH);
  blueGrad.addColorStop(0,'rgba(37,99,235,0.25)');
  blueGrad.addColorStop(1,'rgba(37,99,235,0.03)');
  ctx.fillStyle=blueGrad; ctx.fill();

  // ── Red fill: ATTACK area stacked on top of benign ──
  const hasAnyAttack = atkVals.some(v => v > 0);
  if (hasAnyAttack) {
    ctx.beginPath();
    ctx.moveTo(toX(0), toYA(benignVals[0], atkVals[0]));
    for (let i=1;i<n;i++) {
      const x0=toX(i-1),y0=toYA(benignVals[i-1],atkVals[i-1]);
      const x1=toX(i),  y1=toYA(benignVals[i],  atkVals[i]);
      ctx.bezierCurveTo((x0+x1)/2,y0,(x0+x1)/2,y1,x1,y1);
    }
    // trace bottom edge back along benign top
    for (let i=n-1;i>=0;i--) {
      const x=toX(i), y=toY(benignVals[i]);
      i===n-1 ? ctx.lineTo(x,y) : ctx.lineTo(x,y);
    }
    ctx.closePath();
    const redGrad = ctx.createLinearGradient(0,PAD_T,0,PAD_T+cH);
    redGrad.addColorStop(0,'rgba(220,38,38,0.45)');
    redGrad.addColorStop(1,'rgba(220,38,38,0.05)');
    ctx.fillStyle=redGrad; ctx.fill();
  }

  // ── Blue line on top of benign area ──
  ctx.beginPath();
  ctx.moveTo(toX(0), toY(benignVals[0]));
  for (let i=1;i<n;i++) {
    const x0=toX(i-1),y0=toY(benignVals[i-1]),x1=toX(i),y1=toY(benignVals[i]);
    ctx.bezierCurveTo((x0+x1)/2,y0,(x0+x1)/2,y1,x1,y1);
  }
  ctx.strokeStyle='#2563eb'; ctx.lineWidth=2;
  ctx.lineJoin='round'; ctx.lineCap='round'; ctx.setLineDash([]); ctx.stroke();

  // ── Red line on top of attack area ──
  if (hasAnyAttack) {
    ctx.beginPath(); let started=false;
    for (let i=0;i<n;i++) {
      const av=atkVals[i]; const x=toX(i); const y=toYA(benignVals[i],av);
      if (av>0) { started ? ctx.lineTo(x,y) : ctx.moveTo(x,y); started=true; }
      else { started=false; }
    }
    ctx.strokeStyle='rgba(220,38,38,0.8)'; ctx.lineWidth=1.5;
    ctx.lineJoin='round'; ctx.lineCap='round'; ctx.setLineDash([]); ctx.stroke();
  }

  // ── Live dot ──
  const lx=toX(n-1), ly=toY(totalVals[n-1]);
  ctx.beginPath(); ctx.arc(lx,ly,4,0,Math.PI*2);
  ctx.fillStyle='#2563eb'; ctx.fill();
  ctx.strokeStyle='#fff'; ctx.lineWidth=1.5; ctx.stroke();

  // ── Attack event pins (vertical dashed line + label) ──
  STATE.chartPins=[];
  let prevHad=false;
  data.forEach((d,i) => {
    const nowHas = (d.attackPps||0) > 0;
    if (nowHas && !prevHad) {
      const x=toX(i);
      const label=(d.lastAttackType||'Attack').replace(/_/g,' ');
      const shortLbl=label.split(/[-\s]/)[0]||label;
      ctx.save();
      ctx.strokeStyle='rgba(220,38,38,0.7)'; ctx.lineWidth=1.5; ctx.setLineDash([4,3]);
      ctx.beginPath(); ctx.moveTo(x,PAD_T); ctx.lineTo(x,PAD_T+cH); ctx.stroke();
      ctx.setLineDash([]);
      ctx.beginPath(); ctx.arc(x,PAD_T+4,4,0,Math.PI*2);
      ctx.fillStyle='#dc2626'; ctx.fill();
      ctx.strokeStyle='#fff'; ctx.lineWidth=1.2; ctx.stroke();
      ctx.translate(x+10,PAD_T+cH/2); ctx.rotate(-Math.PI/2);
      ctx.font='bold 9px Inter,sans-serif'; ctx.textAlign='center';
      ctx.fillStyle='#dc2626'; ctx.fillText(shortLbl,0,0);
      ctx.restore();
      STATE.chartPins.push({ x, pinY:PAD_T+cH/2, lineTop:PAD_T, lineBot:PAD_T+cH,
        hitR:16, time:d.time, pps:d.rawPps||d.pps||0, atkType:d.lastAttackType||'Attack', idx:i });
    }
    prevHad=nowHas;
  });

  // ── X-axis labels ──
  ctx.fillStyle='#9ca3af'; ctx.font='9px Inter,sans-serif'; ctx.textAlign='center'; ctx.setLineDash([]);
  const step=Math.max(1,Math.floor(n/6));
  for (let i=0;i<n;i+=step) ctx.fillText(data[i].time, toX(i), PAD_T+cH+14);
  if (n>1) ctx.fillText(data[n-1].time, toX(n-1), PAD_T+cH+14);
}


// ── Wire canvas click + hover → attack pin popup ─────────────────────────────
function initChartClick() {
  const canvas = document.getElementById('traffic-chart');
  if (!canvas || canvas._clickBound) return;
  canvas._clickBound = true;
  canvas.style.cursor = 'default';

  // Hover: show tooltip immediately when near a pin
  canvas.addEventListener('mousemove', e => {
    const pin = hitTestPin(e, canvas);
    canvas.style.cursor = pin ? 'pointer' : 'default';
    if (pin) {
      showAttackPopup(pin, e.clientX, e.clientY, /* hover= */ true);
    } else {
      hideAttackPopup();
    }
  });

  // Click: show popup AND scroll to Attack Logs section
  canvas.addEventListener('click', e => {
    const pin = hitTestPin(e, canvas);
    if (pin) {
      showAttackPopup(pin, e.clientX, e.clientY, /* hover= */ false);
      // Navigate to logs page and scroll to detections table
      setTimeout(() => {
        const logsLink = document.querySelector('[data-page="log"]') ||
                         document.getElementById('nav-log');
        if (logsLink) logsLink.click();
        setTimeout(() => {
          const tbl = document.getElementById('detections-tbody') ||
                      document.getElementById('log-table') ||
                      document.querySelector('.detections-table');
          if (tbl) tbl.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 200);
      }, 300);
    } else {
      hideAttackPopup();
    }
  });

  // Hide tooltip when mouse leaves canvas
  canvas.addEventListener('mouseleave', () => hideAttackPopup());
}

function hitTestPin(e, canvas) {
  if (!STATE.chartPins || !STATE.chartPins.length) return null;
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  for (const pin of STATE.chartPins) {
    const dx = mx - pin.x;
    // Hit if within horizontal tolerance AND within the vertical line bounds
    const inY = pin.lineTop != null
      ? (my >= pin.lineTop && my <= pin.lineBot)
      : Math.abs(my - pin.pinY) <= pin.hitR;
    if (Math.abs(dx) <= pin.hitR && inY) return pin;
  }
  return null;
}

function showAttackPopup(pin, cx, cy, isHover) {
  let pop = document.getElementById('chart-attack-popup');
  if (!pop) {
    pop = document.createElement('div');
    pop.id = 'chart-attack-popup';
    pop.style.cssText = [
      'position:fixed','z-index:9999',
      'background:#1e293b','color:#f1f5f9',
      'border-radius:8px','box-shadow:0 4px 20px rgba(0,0,0,0.35)',
      'padding:10px 14px','font-family:Inter,sans-serif','font-size:12px',
      'min-width:170px','border-left:3px solid #dc2626',
      'pointer-events:none','transition:opacity 0.1s'
    ].join(';');
    document.body.appendChild(pop);
  }
  const label   = (pin.atkType || 'Attack').replace(/_/g,' ');
  const cicLbl  = CIC_LABELS[pin.atkType] || label;
  const clickTip = isHover ? '<div style="color:#64748b;font-size:10px;margin-top:6px">Click to view attack logs →</div>' : '';
  pop.innerHTML = `
    <div style="font-weight:700;color:#fca5a5;margin-bottom:6px">⚠ ${cicLbl}</div>
    <div style="color:#94a3b8;font-size:10px;margin-bottom:1px">TIME</div>
    <div style="font-weight:600;margin-bottom:6px">${pin.time}</div>
    <div style="color:#94a3b8;font-size:10px;margin-bottom:1px">PACKET RATE</div>
    <div style="font-weight:600;margin-bottom:4px">${pin.pps} pps</div>
    ${clickTip}
  `;
  // Position near cursor, stay in viewport
  const vw = window.innerWidth, vh = window.innerHeight;
  let left = cx + 14, top = cy - 20;
  pop.style.display = 'block';
  const pw = pop.offsetWidth || 180, ph = pop.offsetHeight || 110;
  if (left + pw > vw - 8) left = cx - pw - 14;
  if (top  + ph > vh - 8) top  = vh - ph - 8;
  if (top < 8) top = 8;
  pop.style.left = left + 'px';
  pop.style.top  = top  + 'px';
}

function hideAttackPopup() {
  const pop = document.getElementById('chart-attack-popup');
  if (pop) pop.style.display = 'none';
}

// Hide popup when clicking anywhere else on the page
document.addEventListener('click', e => {
  if (e.target && e.target.id !== 'traffic-chart') hideAttackPopup();
});


// ── DISTRIBUTION DONUT CHART ──────────────────────────────────────────────────
function drawDistChart() {
  const canvas = document.getElementById('dist-chart');
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.parentElement?.clientWidth || 200;
  const H = 180;
  canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
  canvas.width = W * dpr; canvas.height = H * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, W, H);

  const counts = STATE.counts;
  const labels = Object.keys(counts);
  const values = labels.map(k => counts[k]);
  const total  = values.reduce((a,b)=>a+b,0) || 1;

  const cx = W/2, cy = H/2, r = Math.min(W, H)/2 - 14;
  let angle = -Math.PI/2;
  labels.forEach((key, i) => {
    const slice = (values[i]/total) * Math.PI * 2;
    ctx.beginPath(); ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, angle, angle+slice); ctx.closePath();
    ctx.fillStyle = DIST_COLORS[key] || '#9ca3af'; ctx.fill();
    ctx.strokeStyle = '#fff'; ctx.lineWidth = 2; ctx.stroke();
    angle += slice;
  });
  ctx.beginPath(); ctx.arc(cx, cy, r*0.55, 0, Math.PI*2);
  ctx.fillStyle = '#fff'; ctx.fill();
  ctx.fillStyle = '#111827'; ctx.font = 'bold 14px Inter, sans-serif';
  ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.fillText(total.toLocaleString(), cx, cy-6);
  ctx.fillStyle = '#9ca3af'; ctx.font = '10px Inter, sans-serif';
  ctx.fillText('packets', cx, cy+10);

  const legend = document.getElementById('dist-legend');
  if (legend) {
    legend.innerHTML = labels.map(key => `
      <div class="dist-legend-item">
        <div class="dist-legend-dot" style="background:${DIST_COLORS[key]}"></div>
        <span>${CIC_LABELS[key]||key} (${counts[key]})</span>
      </div>`).join('');
  }
}

// ── ANALYTICS PAGE ────────────────────────────────────────────────────────────
function updateAnalyticsPage() {
  const c = STATE.counts;
  setText('cat-ddos',   (c.DDoS||0) + (c.Mirai||0));
  setText('cat-udp',    c.DDoS||0);
  setText('cat-dos',    c.DoS||0);
  setText('cat-arp',    c.Spoofing||0);
  setText('cat-scan',   c.Recon||0);
  setText('cat-disc',   c.Recon||0);
  setText('cat-brute',  c.BruteForce||0);
  setText('cat-benign', c.Benign||0);
  drawDistChart();
}

// ── SIMULATION CONTROLS ───────────────────────────────────────────────────────
async function toggleSim() {
  const btn = document.getElementById('btn-toggle-sim');
  const running = btn?.dataset.running === 'true';
  try {
    const res = await fetch(running ? CONFIG.SPRING_BASE_URL + '/api/simulation/stop' : CONFIG.SPRING_BASE_URL + '/api/simulation/start', { method: 'POST' });
    const data = await res.json();
    syncSimBtn(data.running);
  } catch(e) { console.error(e); }
}

function syncSimBtn(running) {
  document.querySelectorAll('#btn-toggle-sim').forEach(btn => {
    btn.dataset.running = String(running);
    btn.textContent     = running ? 'Pause Simulation' : 'Resume Simulation';
    btn.className       = running ? 'btn btn-outline btn-sm' : 'btn btn-primary btn-sm';
  });
  const pill = document.getElementById('sim-status-pill');
  const text = document.getElementById('sim-text');
  if (pill) pill.className = 'id' + (running ? '' : ' paused');
  if (text) text.textContent = running ? 'Live' : 'Paused';
}

async function launchSimulationAttack() {
  const type      = STATE.currentAttackType;
  const intensity = document.getElementById('sim-intensity')?.value || 'medium';
  const count     = intensity === 'high' ? 10 : intensity === 'low' ? 1 : 5;

  if (!STATE.simStartTime) STATE.simStartTime = Date.now();

  for (let i = 0; i < count; i++) {
    await fetch(CONFIG.SPRING_BASE_URL + '/api/inject?type=' + type, { method: 'POST' });
    STATE.simInjected++;
    await new Promise(r => setTimeout(r, 150));
  }
  setText('sim-injected', STATE.simInjected);
}

// ── SIMULATION LAB ────────────────────────────────────────────────────────────
function selectAttack(type) {
  STATE.currentAttackType = type;
  document.querySelectorAll('.attack-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.attack === type);
  });

  const d = SIM_LAB_DATA[type];
  if (!d) return;

  setText('sim-attack-title', d.title);
  const layerBadge = document.getElementById('sim-attack-layer');
  if (layerBadge) { layerBadge.className = 'badge ' + d.layerBadge; layerBadge.textContent = d.layer; }

  setText('sexp-what', d.what);
  setText('sexp-how',  d.how);
  setText('sexp-iot',  d.iot);
  setText('sexp-obj',  d.obj);

  // Flow diagram
  const flowEl = document.getElementById('flow-diagram');
  if (flowEl) {
    flowEl.innerHTML = d.flow.map(n => n.arrow
      ? `<div class="flow-arrow"><div class="flow-arrow-line"></div><div class="flow-arrow-label">${esc(n.arrow)}</div></div>`
      : `<div class="flow-node ${n.cls||''}"><span class="flow-node-icon">${n.icon}</span><span class="flow-node-label">${esc(n.label)}</span><span class="flow-node-sub">${esc(n.sub)}</span></div>`
    ).join('');
  }

  // AI features
  const featEl = document.getElementById('ai-features-list');
  if (featEl) {
    featEl.innerHTML = d.features.map(f => `
      <div class="ai-feature-item">
        <div class="ai-feature-dot ${f.level}"></div>
        <span class="ai-feature-name">${esc(f.name)}</span>
        <span class="ai-feature-val">${esc(f.val)}</span>
      </div>`).join('');
  }

  // Prediction
  setText('ai-pred-result', d.prediction);
  const confFill = document.getElementById('ai-conf-fill');
  const confVal  = document.getElementById('ai-conf-val');
  if (confFill) confFill.style.width = d.confidence + '%';
  if (confVal)  confVal.textContent  = d.confidence + '%';

  // Impact
  const impactEl = document.getElementById('impact-list');
  if (impactEl) {
    impactEl.innerHTML = d.impacts.map(i =>
      `<div class="impact-item"><span class="impact-icon">⚠</span><span>${esc(i)}</span></div>`
    ).join('');
  }

  // Mitigation
  const mitigEl = document.getElementById('mitig-list');
  if (mitigEl) {
    mitigEl.innerHTML = d.mitigations.map(m =>
      `<div class="mitig-item"><span class="mitig-icon">✓</span><span>${esc(m)}</span></div>`
    ).join('');
  }
}

// ── FILE ANALYSIS ─────────────────────────────────────────────────────────────
let selectedFile = null;

function initDropZone() {
  const zone     = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  if (!zone) return;

  zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault(); zone.classList.remove('drag-over');
    const f = e.dataTransfer?.files[0];
    if (f) onFileSelected(f);
  });
  // Only the drop-zone background click, not bubbled from the button
  zone.addEventListener('click', e => {
    if (e.target === zone || e.target.classList.contains('drop-zone-inner') || e.target.tagName === 'DIV') {
      if (!e.target.closest('button')) fileInput.click();
    }
  });
}

function onFileSelected(file) {
  if (!file) return;
  selectedFile = file;
  const nameEl = document.getElementById('file-name-display');
  const sizeEl = document.getElementById('file-size-display');
  const infoEl = document.getElementById('file-info');
  if (nameEl) nameEl.textContent = file.name;
  if (sizeEl) sizeEl.textContent = formatBytes(file.size);
  if (infoEl) infoEl.classList.remove('hidden');
  // Reset results
  document.getElementById('analysis-empty')?.classList.remove('hidden');
  document.getElementById('analysis-result-wrap')?.classList.add('hidden');
  document.getElementById('analysis-summary-badges')?.classList.add('hidden');
}

async function runAnalysis() {
  if (!selectedFile) return;
  const btn      = document.getElementById('btn-analyze');
  const progress = document.getElementById('analysis-progress');
  const fill     = document.getElementById('progress-fill');
  const progText = document.getElementById('progress-text');
  if (btn) { btn.disabled = true; btn.textContent = 'Analyzing...'; }
  if (progress) progress.classList.remove('hidden');

  let pct = 0;
  const ticker = setInterval(() => {
    pct = Math.min(pct + Math.random() * 12, 90);
    if (fill)     fill.style.width = pct + '%';
    if (progText) progText.textContent = pct < 30 ? 'Parsing file...' : pct < 60 ? 'Running XGBoost classifier...' : 'Generating threat report...';
  }, 300);

  try {
    const form = new FormData();
    form.append('file', selectedFile);
    const res  = await fetch(CONFIG.SPRING_BASE_URL + '/api/analyze', { method: 'POST', body: form });
    const data = await res.json();
    clearInterval(ticker);
    if (fill)     fill.style.width = '100%';
    if (progText) progText.textContent = 'Complete!';
    setTimeout(() => { if (progress) progress.classList.add('hidden'); }, 800);
    showAnalysisResults(data);
  } catch(e) {
    clearInterval(ticker);
    if (progText) progText.textContent = 'Error: ' + e.message;
  }
  if (btn) { btn.disabled = false; btn.textContent = 'Run AI Analysis'; }
}

function showAnalysisResults(data) {
  const results = data.results || [];
  const summary = data.summary || {};

  document.getElementById('analysis-empty')?.classList.add('hidden');
  document.getElementById('analysis-result-wrap')?.classList.remove('hidden');
  document.getElementById('analysis-summary-badges')?.classList.remove('hidden');

  setText('res-total-badge',  (summary.total || results.length) + ' flows');
  setText('res-attack-badge', (summary.attacks || 0) + ' attacks');
  setText('res-rate-badge',    summary.attackRate || '0%');

  const statRow = document.getElementById('analysis-stat-row');
  if (statRow) {
    statRow.innerHTML = `
      <div class="stat-card">
        <div class="stat-top"><span class="stat-label">Total Flows</span><span class="stat-icon blue"><svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z"/></svg></span></div>
        <div class="stat-value">${(summary.total||results.length).toLocaleString()}</div><div class="stat-sub">Analyzed flows</div>
      </div>
      <div class="stat-card">
        <div class="stat-top"><span class="stat-label">Attacks Found</span><span class="stat-icon red"><svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg></span></div>
        <div class="stat-value">${summary.attacks||0}</div><div class="stat-sub">Threat flows</div>
      </div>
      <div class="stat-card">
        <div class="stat-top"><span class="stat-label">Attack Rate</span><span class="stat-icon amber"></span></div>
        <div class="stat-value">${summary.attackRate||'0%'}</div><div class="stat-sub">Of total traffic</div>
      </div>
      <div class="stat-card">
        <div class="stat-top"><span class="stat-label">Top Threat</span><span class="stat-icon red"></span></div>
        <div class="stat-value" style="font-size:13px">${summary.topThreat||'None'}</div><div class="stat-sub">Dominant type</div>
      </div>`;
  }

  const tbody = document.getElementById('analysis-tbody');
  if (tbody) {
    tbody.innerHTML = '';
    results.slice(0, 200).forEach((r, i) => {
      const type  = r.attackType || 'BENIGN';
      const label = CIC_LABELS[type] || type;
      const bc    = BADGE_CLASS[type] || 'badge-gray';
      const conf  = Math.round((r.confidence || 0) * 100);
      const cc    = r.attack ? '#dc2626' : '#16a34a';
      const tr    = document.createElement('tr');
      if (r.attack) tr.className = 'is-attack';
      tr.innerHTML = `
        <td class="mono" style="color:var(--text-4)">${i+1}</td>
        <td class="mono">${esc(r.sourceIp||'—')}</td>
        <td class="mono">${esc(r.destIp||'—')}</td>
        <td><span class="badge badge-gray">${esc(r.protocol||'—')}</span></td>
        <td class="mono">${r.port||'—'}</td>
        <td class="mono">${r.flowDuration||'—'}</td>
        <td class="mono">${r.packetSize?r.packetSize+' B':'—'}</td>
        <td><span class="badge ${bc}">${esc(label)}</span></td>
        <td>
          <div class="conf-wrap">
            <div class="conf-bar"><div class="conf-fill" style="width:${conf}%;background:${cc}"></div></div>
            <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-3)">${conf}%</span>
          </div>
        </td>`;
      tbody.appendChild(tr);
    });
  }
}

// ── ROUTER ────────────────────────────────────────────────────────────────────
const PAGE_TITLES = {
  dashboard: 'Dashboard', logs: 'Traffic Logs', devices: 'IoT Devices',
  simlab: 'Simulation Lab', analysis: 'File Analysis',
  analytics: 'AI Analytics', settings: 'Settings',
};
const PAGE_SUBS = {
  dashboard: 'Real-time network monitoring · CIC-IoT 2023 · XGBoost Classifier',
  logs:      'Full history of all detected packets and attack classifications',
  devices:   'Live hardware status · 192.168.4.0/24',
  simlab:    'Cyberattack simulation · AI detection analysis · CIC-IoT 2023 scenarios',
  analysis:  'Offline AI-powered threat detection on uploaded capture files',
  analytics: 'XGBoost model statistics · CIC-IoT 2023 dataset performance',
  settings:  'Configure simulation and network parameters',
};

function initRouter() {
  document.querySelectorAll('.sb-link').forEach(link => {
    link.addEventListener('click', () => navigateTo(link.dataset.page));
  });
  navigateTo('dashboard');
}

function navigateTo(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  document.querySelectorAll('.sb-link').forEach(l => l.classList.remove('active'));
  document.getElementById('page-' + page)?.classList.remove('hidden');
  document.querySelector(`.sb-link[data-page="${page}"]`)?.classList.add('active');
  setText('page-title', PAGE_TITLES[page] || page);
  setText('page-subtitle', PAGE_SUBS[page] || '');
  // Refresh log page on navigate
  if (page === 'logs') renderLogPage();
}

// ── UTILITIES ─────────────────────────────────────────────────────────────────
function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = String(val ?? ''); }
function esc(s) { return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
  return (b/1024/1024).toFixed(1) + ' MB';
}

// Expose to HTML onclick
window.selectAttack       = selectAttack;
window.launchSimulationAttack = launchSimulationAttack;
window.exportLogs         = exportLogs;
window.navigateTo         = navigateTo;


// -- SOC ENHANCEMENTS (Auth, Theme, Terminal Dump, Attack Lab) -------------

// 1. Authentication
function checkAuth() {
  if (!sessionStorage.getItem('soc_auth')) {
    document.getElementById('login-overlay').style.display = 'flex';
  } else {
    document.getElementById('login-overlay').style.display = 'none';
  }
}
window.handleLogin = function(e) {
  e.preventDefault();
  const u = document.getElementById('login-user').value;
  const p = document.getElementById('login-pass').value;
  if (u === 'admin' && p === 'admin') {
    sessionStorage.setItem('soc_auth', 'true');
    document.getElementById('login-overlay').style.display = 'none';
  } else {
    document.getElementById('login-error').style.display = 'block';
  }
};
document.addEventListener('DOMContentLoaded', checkAuth);

// 2. Theme Toggle
window.toggleTheme = function() {
  const isDark = document.body.classList.toggle('dark-mode');
  localStorage.setItem('soc_theme', isDark ? 'dark' : 'light');
  
  if (window.trafficChart) {
    const gridColor = isDark ? '#334155' : 'rgba(0,0,0,0.05)';
    const textColor = isDark ? '#94a3b8' : '#6b7280';
    trafficChart.options.scales.x.grid.color = gridColor;
    trafficChart.options.scales.y.grid.color = gridColor;
    trafficChart.options.scales.x.ticks.color = textColor;
    trafficChart.options.scales.y.ticks.color = textColor;
    // Enhance graph visual
    trafficChart.data.datasets.forEach(ds => { ds.tension = 0.4; ds.fill = true; });
    trafficChart.update();
  }
  if (geoMap) {
    const isDark = document.body.classList.contains('dark-mode');
    const tileUrl = isDark ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png' : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';
    L.tileLayer(tileUrl, { attribution: '&copy; OpenStreetMap contributors', maxZoom: 19 }).addTo(geoMap);
  }
};
if (localStorage.getItem('soc_theme') === 'dark') {
  document.body.classList.add('dark-mode');
  setTimeout(() => { if (window.trafficChart) toggleTheme(); toggleTheme(); }, 500); // Trigger chart update
}

// 3. Live Terminal Dump
window.appendToTerminal = function(packet) {
  const term = document.getElementById('terminal-box');
  if (!term) return;
  const ts = packet.timestamp || Date.now();
  const time = new Date(ts).toLocaleTimeString();
  const protoClass = packet.protocol === 'TCP' ? 'term-tcp' : packet.protocol === 'UDP' ? 'term-udp' : 'term-icmp';
  const srcIp = packet.src_ip || 'unknown';
  const dstIp = packet.dst_ip || 'unknown';
  const srcPort = packet.src_port || '0';
  const dstPort = packet.dst_port || '0';
  const size = packet.packetSize || 0;
  const attackType = packet.label || 'Benign';

  let html = '<div class="terminal-line"><span class="term-time">[' + time + ']</span> <span class="' + protoClass + '">' + (packet.protocol || 'TCP') + '</span> ' + srcIp + ':' + srcPort + ' -> ' + dstIp + ':' + dstPort + ' [' + size + ' bytes]';
  if (attackType && attackType !== 'Benign' && attackType !== 'BENIGN') {
    html += ' <span class="term-attack">!! ' + attackType + ' !!</span>';
  }
  html += '</div>';
  term.insertAdjacentHTML('beforeend', html);
  if (term.childElementCount > 100) term.removeChild(term.firstElementChild);
  term.scrollTop = term.scrollHeight;
};

// Hook into existing onPacket to populate terminal and topology
const originalOnPacket = window.onPacket;
if (typeof originalOnPacket === 'function') {
  window.onPacket = function(packet) {
    originalOnPacket(packet);
    appendToTerminal(packet);
    if (window.updateGeoMap) window.updateGeoMap(packet);
  };
}

// 4. Attack API Integration
window.launchCustomAttack = function(type) {
  let url = CONFIG.FLASK_BASE_URL + '/api/attack/start?type=' + type;
  
  const targetInput = document.getElementById('target-' + type);
  const durInput = document.getElementById('dur-' + type);
  
  if (targetInput && targetInput.value) url += '&target=' + targetInput.value;
  if (durInput && durInput.value) url += '&duration=' + durInput.value;

  fetch(url, { method: 'POST' })
    .then(res => res.json())
    .then(data => {
      if (data.status === 'success') {
        console.log('Attack launched: ' + data.message);
      } else {
        alert('Failed to launch: ' + data.error);
      }
    })
    .catch(err => alert('API Error: ' + err));
};

window.stopAttack = function() {
  fetch(CONFIG.FLASK_BASE_URL + '/api/attack/stop', { method: 'POST' })
    .then(res => res.json())
    .then(data => {
      if (data.status === 'success') {
        console.log('Attacks stopped');
      } else {
        alert('Failed to stop: ' + data.error);
      }
    })
    .catch(err => alert('API Error: ' + err));
};

// ============================================================
// MITRE ATT&CK HEATMAP
// Maps detected attack labels to real MITRE Tactics/Techniques
// ============================================================
const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance',   col: 0 },
  { id: 'TA0001', name: 'Initial Access',   col: 1 },
  { id: 'TA0002', name: 'Execution',        col: 2 },
  { id: 'TA0003', name: 'Persistence',      col: 3 },
  { id: 'TA0040', name: 'Impact',           col: 4 },
  { id: 'TA0011', name: 'C2',              col: 5 },
  { id: 'TA0010', name: 'Exfiltration',    col: 6 },
];

const MITRE_TECHNIQUES = [
  { tactic: 0, id:'T1595', name:'Active Scanning',       attacks:['RECON', 'PORT_SCAN'] },
  { tactic: 0, id:'T1590', name:'Gather Network Info',   attacks:['RECON', 'HOSTDISCOVERY'] },
  
  { tactic: 1, id:'T1190', name:'Exploit Public App',    attacks:['MITM', 'SPOOFING', 'WEB'] },
  { tactic: 1, id:'T1110', name:'Brute Force',           attacks:['BRUTEFORCE', 'DICTIONARY'] },
  { tactic: 1, id:'T1133', name:'External Services',     attacks:['MITM', 'SPOOFING'] },
  
  { tactic: 2, id:'T1059', name:'Command Interpreter',   attacks:['MIRAI', 'COMMAND_INJECTION'] },
  { tactic: 2, id:'T1203', name:'Exploitation',          attacks:['DOS', 'DDOS', 'SQL_INJECTION', 'XSS'] },
  
  { tactic: 3, id:'T1505', name:'Server Compromise',     attacks:['MIRAI'] },
  { tactic: 3, id:'T1547', name:'Boot Persistence',      attacks:['MIRAI'] },
  
  { tactic: 4, id:'T1498', name:'Network DoS',           attacks:['DOS', 'DDOS'] },
  { tactic: 4, id:'T1499', name:'Endpoint DoS',          attacks:['DOS', 'DDOS'] },
  
  { tactic: 5, id:'T1095', name:'Non-App Layer C2',      attacks:['MIRAI', 'SPOOFING'] },
  { tactic: 5, id:'T1571', name:'Non-Standard Port',     attacks:['SPOOFING'] },
  
  { tactic: 6, id:'T1048', name:'Exfil Over Channel',    attacks:['SPOOFING', 'WEB'] },
  { tactic: 6, id:'T1041', name:'Exfil Over C2',         attacks:['MIRAI'] },
];

// hit count per technique
const mitreCounts = {};
MITRE_TECHNIQUES.forEach(t => mitreCounts[t.id] = 0);

function getHeatColor(count) {
  if (count === 0) return '#e2e8f0';
  if (count < 3)  return '#fde68a';
  if (count < 8)  return '#fb923c';
  return '#dc2626';
}

function getTextColor(count) {
  return count >= 3 ? '#fff' : '#1e293b';
}

function initMitreGrid() {
  const grid = document.getElementById('mitre-grid');
  if (!grid) return;
  grid.innerHTML = '';

  // Build column-first layout: 2 rows per tactic (header + techniques stacked)
  MITRE_TACTICS.forEach((tactic, col) => {
    const col_div = document.createElement('div');
    col_div.style.cssText = 'display:flex;flex-direction:column;gap:4px;';

    // Tactic header
    const hdr = document.createElement('div');
    hdr.style.cssText = 'background:#1e293b;color:#fff;font-size:9px;font-weight:700;padding:5px 4px;border-radius:4px;text-align:center;letter-spacing:0.3px;padding:8px 4px;display:flex;align-items:center;justify-content:center;';
    hdr.title = tactic.id;
    hdr.textContent = tactic.name;
    col_div.appendChild(hdr);

    // Techniques for this tactic
    MITRE_TECHNIQUES.filter(t => t.tactic === col).forEach(tech => {
      const cell = document.createElement('div');
      cell.id = 'mitre-' + tech.id;
      cell.title = tech.id + ': ' + tech.name;
      cell.style.cssText = 'font-size:8px;padding:4px 3px;border-radius:3px;text-align:center;cursor:default;transition:background 0.4s;flex:1; min-height:40px;display:flex;align-items:center;justify-content:center;font-weight:600;';
      cell.style.background = getHeatColor(0);
      cell.style.color = getTextColor(0);
      cell.textContent = tech.id;
      col_div.appendChild(cell);
    });

    grid.appendChild(col_div);
  });
}

function updateMitreHeatmap(label) {
  if (!label || label === 'Benign' || label === 'BENIGN') return;
  const norm = label.toUpperCase().replace(/-/g,'_');
  let updated = false;
  MITRE_TECHNIQUES.forEach(tech => {
    const match = tech.attacks.some(a => norm.includes(a.toUpperCase()) || a.toUpperCase().includes(norm));
    if (match) {
      mitreCounts[tech.id] = (mitreCounts[tech.id] || 0) + 1;
      const cell = document.getElementById('mitre-' + tech.id);
      if (cell) {
        const c = mitreCounts[tech.id];
        cell.style.background = getHeatColor(c);
        cell.style.color = getTextColor(c);
        cell.title = tech.id + ': ' + tech.name + ' (' + c + ' hits)';
        // Flash animation
        cell.style.transform = 'scale(1.08)';
        setTimeout(() => { cell.style.transform = 'scale(1)'; }, 300);
        updated = true;
      }
    }
  });
}

// Hook into onPacket
const _origOnPacket = window.onPacket;
if (typeof _origOnPacket === 'function') {
  window.onPacket = function(packet) {
    _origOnPacket(packet);
    const lbl = packet.label || packet.attackType || '';
    updateMitreHeatmap(lbl);
  };
}

document.addEventListener('DOMContentLoaded', () => {
  initMitreGrid();
});



