"""
Clean Cyber Attack Detection Dashboard
Individual attack tiles with explanations and proper plotting
"""

from flask import Flask, render_template_string, jsonify, request
from flask_cors import CORS
from prediction_api import predict_single_row, get_model_info
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
from collections import deque
import random
import threading
import time

app = Flask(__name__)
CORS(app)

# Global data storage
predictions_history = deque(maxlen=500)
logs = deque(maxlen=200)
attack_logs = deque(maxlen=200)
network_logs = deque(maxlen=1000)

# Individual attack histories for charts
attack_histories = {
    'DoS': deque(maxlen=50),
    'Fuzzer': deque(maxlen=50),
    'Port_Scan': deque(maxlen=50),
    'Brute_Force': deque(maxlen=50),
    'Reconnaissance': deque(maxlen=50),
    'Anomalous_IP': deque(maxlen=50),
    'High_Bandwidth': deque(maxlen=50),
    'Suspicious_TCP': deque(maxlen=50),
    'Replay_Attack': deque(maxlen=50),
    'Abnormal_Packet': deque(maxlen=50),
    'Session_Hijacking': deque(maxlen=50),
    'Jitter_Anomaly': deque(maxlen=50),
    'Slowloris': deque(maxlen=50),
    'Service_Abuse': deque(maxlen=50),
    'Traffic_Correlation': deque(maxlen=50),
    'Worm_Spread': deque(maxlen=50),
    'Timing_Attack': deque(maxlen=50),
    'Other': deque(maxlen=50)
}

stats = {
    'total_predictions': 0,
    'attacks_detected': 0,
    'normal_traffic': 0,
    'attack_types': {
        'DoS': 0, 'Fuzzer': 0, 'Port_Scan': 0, 'Brute_Force': 0,
        'Reconnaissance': 0, 'Anomalous_IP': 0, 'High_Bandwidth': 0,
        'Suspicious_TCP': 0, 'Replay_Attack': 0, 'Abnormal_Packet': 0,
        'Session_Hijacking': 0, 'Jitter_Anomaly': 0, 'Slowloris': 0,
        'Service_Abuse': 0, 'Traffic_Correlation': 0, 'Worm_Spread': 0,
        'Timing_Attack': 0, 'Other': 0
    },
    'model_usage': {
        'random_forest': 0, 'decision_tree': 0, 'xgboost': 0, 'lightgbm': 0, 'ensemble': 0
    }
}

def generate_network_log():
    """Generate realistic network traffic log entries"""
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS']
    actions = ['ACCEPT', 'DROP', 'REJECT', 'FORWARD']
    sources = ['192.168.1.', '10.0.0.', '172.16.0.', '203.0.113.', '198.51.100.']
    
    protocol = random.choice(protocols)
    action = random.choice(actions)
    src_ip = random.choice(sources) + str(random.randint(1, 254))
    dst_ip = random.choice(sources) + str(random.randint(1, 254))
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 21, 25, 53, 3389, random.randint(1024, 65535)])
    bytes_transferred = random.randint(64, 8192)
    
    return f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {action} {protocol} {src_ip}:{src_port} → {dst_ip}:{dst_port} [{bytes_transferred} bytes]"

# Background thread for generating network logs
def log_generator():
    while True:
        log_entry = generate_network_log()
        network_logs.append({
            'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'message': log_entry
        })
        time.sleep(0.3)  # 0.3 second interval

# Start log generator thread
log_thread = threading.Thread(target=log_generator, daemon=True)
log_thread.start()

def load_sample_data():
    """Load sample data for predictions"""
    try:
        df = pd.read_csv("C:\\Users\\priya\\Desktop\\DATA\\processed_train.csv")
        return df.sample(n=1).drop('target', axis=1).iloc[0].to_dict()
    except:
        # Generate random sample data if file not found
        features = [
            'tcp', 'udp', '-', 'unas', 'arp', '-.1', 'dns', 'http', 'smtp', 'INT',
            'FIN', 'CON', 'REQ', 'RST', 'dur', 'proto', 'service', 'state',
            'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
            'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
            'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
            'smean', 'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src',
            'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
            'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd',
            'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
        ]
        return {f: random.uniform(-2, 2) for f in features}

def detect_attack_types(data):
    """Detect specific attack types using the 20 features"""
    attack_types = []
    
    # DoS Detection
    sload = abs(data.get('sload', 0))
    dload = abs(data.get('dload', 0))
    spkts = abs(data.get('spkts', 0))
    dpkts = abs(data.get('dpkts', 0))
    
    if sload > 1.5 or dload > 1.5 or spkts > 1.5 or dpkts > 1.5:
        attack_types.append('DoS')
    
    # Fuzzer Detection
    trans_depth = abs(data.get('trans_depth', 0))
    response_body_len = abs(data.get('response_body_len', 0))
    
    if trans_depth > 1.5 or response_body_len < -1.5:
        attack_types.append('Fuzzer')
    
    # Port Scan Detection
    ct_src_dport_ltm = abs(data.get('ct_src_dport_ltm', 0))
    ct_dst_sport_ltm = abs(data.get('ct_dst_sport_ltm', 0))
    
    if ct_src_dport_ltm > 1.5 or ct_dst_sport_ltm > 1.5:
        attack_types.append('Port_Scan')
    
    # Brute Force Detection
    is_ftp_login = abs(data.get('is_ftp_login', 0))
    ct_ftp_cmd = abs(data.get('ct_ftp_cmd', 0))
    
    if is_ftp_login > 0.5 and ct_ftp_cmd > 0.5:
        attack_types.append('Brute_Force')
    
    # Reconnaissance Detection
    ct_dst_ltm = abs(data.get('ct_dst_ltm', 0))
    
    if ct_dst_ltm > 1.5:
        attack_types.append('Reconnaissance')
    
    # Anomalous IP Detection
    is_sm_ips_ports = abs(data.get('is_sm_ips_ports', 0))
    
    if is_sm_ips_ports > 1.5:
        attack_types.append('Anomalous_IP')
    
    # High Bandwidth Detection
    if sload > 1.0 or dload > 1.0:
        attack_types.append('High_Bandwidth')
    
    # Suspicious TCP Detection
    tcprtt = abs(data.get('tcprtt', 0))
    synack = abs(data.get('synack', 0))
    ackdat = abs(data.get('ackdat', 0))
    
    if tcprtt > 1.0 or synack > 1.0 or ackdat > 1.0:
        attack_types.append('Suspicious_TCP')
    
    # Replay Attack Detection
    stcpb = abs(data.get('stcpb', 0))
    dtcpb = abs(data.get('dtcpb', 0))
    
    if stcpb > 1.5 or dtcpb > 1.5:
        attack_types.append('Replay_Attack')
    
    # Abnormal Packet Detection
    smean = abs(data.get('smean', 0))
    dmean = abs(data.get('dmean', 0))
    
    if smean > 1.5 or dmean > 1.5:
        attack_types.append('Abnormal_Packet')
    
    # Session Hijacking Detection
    state = abs(data.get('state', 0))
    dur = abs(data.get('dur', 0))
    
    if state > 1.0 and dur < -1.0:
        attack_types.append('Session_Hijacking')
    
    # Jitter Anomaly Detection
    sjit = abs(data.get('sjit', 0))
    djit = abs(data.get('djit', 0))
    
    if sjit > 1.0 or djit > 1.0:
        attack_types.append('Jitter_Anomaly')
    
    # Slowloris Detection
    if dur > 1.0 and trans_depth > 1.0:
        attack_types.append('Slowloris')
    
    # Service Abuse Detection
    ct_srv_src = abs(data.get('ct_srv_src', 0))
    ct_srv_dst = abs(data.get('ct_srv_dst', 0))
    
    if ct_srv_src > 1.0 or ct_srv_dst > 1.0:
        attack_types.append('Service_Abuse')
    
    # Traffic Correlation Detection
    ct_dst_src_ltm = abs(data.get('ct_dst_src_ltm', 0))
    ct_src_ltm = abs(data.get('ct_src_ltm', 0))
    
    if ct_dst_src_ltm > 1.0 and ct_src_ltm > 1.0:
        attack_types.append('Traffic_Correlation')
    
    # Worm Spread Detection
    if sload > 1.0 and dload > 1.0 and dur > 1.0:
        attack_types.append('Worm_Spread')
    
    # Timing Attack Detection
    sinpkt = abs(data.get('sinpkt', 0))
    dinpkt = abs(data.get('dinpkt', 0))
    
    if sinpkt > 1.0 or dinpkt > 1.0:
        attack_types.append('Timing_Attack')
    
    return attack_types

@app.route('/')
def index():
    """Render the dashboard"""
    return render_template_string(CLEAN_HTML_TEMPLATE)

@app.route('/api/predict', methods=['POST'])
def predict():
    """Make a prediction"""
    try:
        data = load_sample_data()
        model = request.json.get('model', 'random_forest')
        
        result = predict_single_row(data, model_name=model)
        
        if 'error' not in result:
            attack_types = detect_attack_types(data)
            current_time = datetime.now()
            
            # Update attack histories
            for attack_type in attack_histories.keys():
                detection_value = 1 if attack_type in attack_types else 0
                attack_histories[attack_type].append({
                    'time': current_time.isoformat(),
                    'value': detection_value,
                    'count': stats['attack_types'].get(attack_type, 0)
                })
            
            prediction = {
                'timestamp': current_time.isoformat(),
                'prediction': result['prediction'],
                'confidence': result['confidence'],
                'interpretation': result['interpretation'],
                'model_used': result.get('model_used', model),
                'attack_types': attack_types,
                'raw_data': data
            }
            
            # Update stats
            stats['total_predictions'] += 1
            if result['prediction'] == 1:
                stats['attacks_detected'] += 1
                log_msg = f"🚨 ATTACK DETECTED! Types: {', '.join(attack_types) if attack_types else 'Unknown'}"
                attack_log_msg = f"🚨 {', '.join(attack_types) if attack_types else 'Unknown Attack'}"
                
                for attack_type in attack_types:
                    if attack_type in stats['attack_types']:
                        stats['attack_types'][attack_type] += 1
                    else:
                        stats['attack_types']['Other'] += 1
            else:
                stats['normal_traffic'] += 1
                log_msg = f"✓ Normal traffic detected. Confidence: {result['confidence']:.2%}"
                attack_log_msg = f"✓ Normal Traffic"
            
            stats['model_usage'][model] += 1
            predictions_history.append(prediction)
            logs.append({'time': current_time.strftime('%H:%M:%S'), 'message': log_msg})
            attack_logs.append({'time': current_time.strftime('%H:%M:%S'), 'message': attack_log_msg})
            
            return jsonify({
                'success': True,
                'result': result,
                'attack_types': attack_types,
                'stats': stats
            })
        else:
            return jsonify({'success': False, 'error': result['error']})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify({
        'stats': stats,
        'recent_predictions': list(predictions_history)[-10:],
        'logs': list(logs)[-20:],
        'attack_logs': list(attack_logs)[-20:],
        'network_logs': list(network_logs)[-50:]
    })

@app.route('/api/attack_histories')
def get_attack_histories():
    """Get attack histories for individual charts"""
    return jsonify({
        'histories': {k: list(v) for k, v in attack_histories.items()}
    })

@app.route('/api/network_logs')
def get_network_logs():
    """Get latest network logs"""
    return jsonify({
        'logs': list(network_logs)[-100:]
    })

@app.route('/api/predictions')
def get_predictions():
    """Get prediction history for charts"""
    history = list(predictions_history)
    return jsonify({
        'predictions': history,
        'attack_rate': stats['attacks_detected'] / max(stats['total_predictions'], 1) * 100,
        'attack_types': stats['attack_types']
    })

@app.route('/api/clear', methods=['POST'])
def clear_history():
    """Clear prediction history"""
    global predictions_history, logs, attack_logs, attack_histories, stats
    predictions_history.clear()
    logs.clear()
    attack_logs.clear()
    
    # Clear attack histories
    for key in attack_histories:
        attack_histories[key].clear()
    
    stats = {
        'total_predictions': 0,
        'attacks_detected': 0,
        'normal_traffic': 0,
        'attack_types': {k: 0 for k in stats['attack_types']},
        'model_usage': {k: 0 for k in stats['model_usage']}
    }
    return jsonify({'success': True})

# Clean HTML Template
CLEAN_HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Clean Attack Detection Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container { max-width: 1600px; margin: 0 auto; }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 20px;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .controls {
            background: white;
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        select, button {
            padding: 10px 20px;
            border: 2px solid #667eea;
            border-radius: 8px;
            font-size: 1rem;
            background: white;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        select {
            flex: 1;
            min-width: 200px;
        }
        
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            font-weight: bold;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        
        .start-btn {
            background: linear-gradient(135deg, #4caf50 0%, #45a049 100%) !important;
        }
        
        .stop-btn {
            background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%) !important;
        }
        
        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .panel {
            background: white;
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .panel h2 {
            color: #333;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .logs-container {
            max-height: 300px;
            overflow-y: auto;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
        }
        
        .network-logs {
            color: #00ff00 !important;
        }
        
        .log-entry {
            padding: 3px 0;
            border-bottom: 1px solid #333;
            animation: fadeIn 0.3s;
        }
        
        .log-time {
            color: #888;
            margin-right: 10px;
        }
        
        .attack-tiles {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .attack-tile {
            background: white;
            border-radius: 12px;
            padding: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        
        .attack-tile:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.15);
        }
        
        .attack-tile.active {
            border-left: 5px solid #f44336;
            background: linear-gradient(135deg, #fff 0%, #ffebee 100%);
        }
        
        .attack-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .attack-name {
            font-size: 1.1rem;
            font-weight: bold;
            color: #333;
        }
        
        .attack-count {
            font-size: 1.5rem;
            font-weight: bold;
            color: #667eea;
        }
        
        .attack-description {
            font-size: 0.85rem;
            color: #666;
            margin-bottom: 8px;
            line-height: 1.4;
        }
        
        .detection-method {
            font-size: 0.75rem;
            color: #444;
            background: #f5f5f5;
            padding: 6px 8px;
            border-radius: 5px;
            margin-bottom: 10px;
            font-style: italic;
        }
        
        .chart-container {
            height: 120px;
            margin-top: 10px;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Clean Attack Detection Dashboard</h1>
            <p>Individual Attack Monitoring with Explanations</p>
        </div>
        
        <div class="controls">
            <label for="model-select"><strong>Select Model:</strong></label>
            <select id="model-select">
                <option value="random_forest">Random Forest</option>
                <option value="decision_tree">Decision Tree</option>
                <option value="xgboost">XGBoost</option>
                <option value="lightgbm">LightGBM</option>
                <option value="ensemble">Ensemble</option>
            </select>
            <button id="start-btn" class="start-btn" onclick="startDetection()">▶️ Start Detection</button>
            <button id="stop-btn" class="stop-btn" onclick="stopDetection()" style="display: none;">⏹️ Stop Detection</button>
            <button onclick="clearHistory()">🗑️ Clear History</button>
        </div>
        
        <div class="main-content">
            <div class="panel">
                <h2>📋 Network Traffic Logs (Live)</h2>
                <div class="logs-container network-logs" id="network-logs">
                    <div class="log-entry">Network monitoring stopped. Press Start to begin...</div>
                </div>
            </div>
            
            <div class="panel">
                <h2>🚨 Attack Detection Logs</h2>
                <div class="logs-container" id="attack-logs">
                    <div class="log-entry">No attack logs yet. Start detection to begin monitoring...</div>
                </div>
            </div>
        </div>
        
        <div class="attack-tiles" id="attack-tiles">
            <!-- Attack tiles will be populated by JavaScript -->
        </div>
    </div>
    
    <script>
        let autoMode = false;
        let autoInterval;
        let networkLogsInterval;
        let attackCharts = {};
        
        const attackTypes = [
            'DoS', 'Fuzzer', 'Port_Scan', 'Brute_Force', 'Reconnaissance',
            'Anomalous_IP', 'High_Bandwidth', 'Suspicious_TCP', 'Replay_Attack',
            'Abnormal_Packet', 'Session_Hijacking', 'Jitter_Anomaly', 'Slowloris',
            'Service_Abuse', 'Traffic_Correlation', 'Worm_Spread', 'Timing_Attack', 'Other'
        ];
        
        const attackInfo = {
            'DoS': {
                name: 'DoS Detection',
                icon: '📈',
                description: 'Denial of Service attacks targeting system availability',
                calculation: 'Detected when: sload > 1.5 OR dload > 1.5 OR spkts > 1.5 OR dpkts > 1.5',
                color: '#ff6b6b'
            },
            'Fuzzer': {
                name: 'Fuzzer Detection', 
                icon: '🔍',
                description: 'Fuzzing attacks using random input injection',
                calculation: 'Detected when: trans_depth > 1.5 OR response_body_len < -1.5',
                color: '#4ecdc4'
            },
            'Port_Scan': {
                name: 'Port Scan',
                icon: '🔎', 
                description: 'Network port scanning for reconnaissance',
                calculation: 'Detected when: ct_src_dport_ltm > 1.5 OR ct_dst_sport_ltm > 1.5',
                color: '#45b7d1'
            },
            'Brute_Force': {
                name: 'Brute Force',
                icon: '🔐',
                description: 'Brute force login attempts',
                calculation: 'Detected when: is_ftp_login > 0.5 AND ct_ftp_cmd > 0.5',
                color: '#96ceb4'
            },
            'Reconnaissance': {
                name: 'Reconnaissance',
                icon: '🕵️',
                description: 'Network reconnaissance and information gathering',
                calculation: 'Detected when: ct_dst_ltm > 1.5',
                color: '#feca57'
            },
            'Anomalous_IP': {
                name: 'Anomalous IP',
                icon: '🌐',
                description: 'Suspicious IP communication patterns',
                calculation: 'Detected when: is_sm_ips_ports > 1.5',
                color: '#ff9ff3'
            },
            'High_Bandwidth': {
                name: 'High Bandwidth',
                icon: '📊',
                description: 'Excessive bandwidth usage patterns',
                calculation: 'Detected when: sload > 1.0 OR dload > 1.0',
                color: '#54a0ff'
            },
            'Suspicious_TCP': {
                name: 'Suspicious TCP',
                icon: '🔗',
                description: 'Abnormal TCP connection behavior',
                calculation: 'Detected when: tcprtt > 1.0 OR synack > 1.0 OR ackdat > 1.0',
                color: '#5f27cd'
            },
            'Replay_Attack': {
                name: 'Replay Attack',
                icon: '🔄',
                description: 'Packet replay and retransmission attacks',
                calculation: 'Detected when: stcpb > 1.5 OR dtcpb > 1.5',
                color: '#00d2d3'
            },
            'Abnormal_Packet': {
                name: 'Abnormal Packet',
                icon: '📦',
                description: 'Unusual packet sizes and structures',
                calculation: 'Detected when: smean > 1.5 OR dmean > 1.5',
                color: '#ff9f43'
            },
            'Session_Hijacking': {
                name: 'Session Hijacking',
                icon: '🎭',
                description: 'Session takeover and manipulation attempts',
                calculation: 'Detected when: state > 1.0 AND dur < -1.0',
                color: '#10ac84'
            },
            'Jitter_Anomaly': {
                name: 'Jitter Anomaly',
                icon: '⚡',
                description: 'Network timing and latency irregularities',
                calculation: 'Detected when: sjit > 1.0 OR djit > 1.0',
                color: '#ee5a24'
            },
            'Slowloris': {
                name: 'Slowloris',
                icon: '🐌',
                description: 'Slow connection exhaustion attacks',
                calculation: 'Detected when: dur > 1.0 AND trans_depth > 1.0',
                color: '#0984e3'
            },
            'Service_Abuse': {
                name: 'Service Abuse',
                icon: '⚙️',
                description: 'API and service flooding attacks',
                calculation: 'Detected when: ct_srv_src > 1.0 OR ct_srv_dst > 1.0',
                color: '#6c5ce7'
            },
            'Traffic_Correlation': {
                name: 'Traffic Correlation',
                icon: '🔗',
                description: 'Traffic flow analysis and correlation attacks',
                calculation: 'Detected when: ct_dst_src_ltm > 1.0 AND ct_src_ltm > 1.0',
                color: '#a29bfe'
            },
            'Worm_Spread': {
                name: 'Worm Spread',
                icon: '🐛',
                description: 'Self-replicating malware propagation',
                calculation: 'Detected when: sload > 1.0 AND dload > 1.0 AND dur > 1.0',
                color: '#fd79a8'
            },
            'Timing_Attack': {
                name: 'Timing Attack',
                icon: '⏱️',
                description: 'Cryptographic timing analysis attacks',
                calculation: 'Detected when: sinpkt > 1.0 OR dinpkt > 1.0',
                color: '#fdcb6e'
            },
            'Other': {
                name: 'Other Attacks',
                icon: '🚨',
                description: 'Miscellaneous and unknown attack vectors',
                calculation: 'Detected when: Other patterns not matching specific categories',
                color: '#e17055'
            }
        };
        
        function createAttackTiles() {
            const container = document.getElementById('attack-tiles');
            
            attackTypes.forEach(attackType => {
                const info = attackInfo[attackType];
                const tile = document.createElement('div');
                tile.className = 'attack-tile';
                tile.id = `tile-${attackType.toLowerCase()}`;
                
                tile.innerHTML = `
                    <div class="attack-header">
                        <div class="attack-name">${info.icon} ${info.name}</div>
                        <div class="attack-count" id="count-${attackType.toLowerCase()}">0</div>
                    </div>
                    <div class="attack-description">${info.description}</div>
                    <div class="detection-method">${info.calculation}</div>
                    <div class="chart-container">
                        <canvas id="chart-${attackType.toLowerCase()}"></canvas>
                    </div>
                `;
                
                container.appendChild(tile);
                
                // Create chart
                const ctx = document.getElementById(`chart-${attackType.toLowerCase()}`).getContext('2d');
                attackCharts[attackType] = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: info.name,
                            data: [],
                            borderColor: info.color,
                            backgroundColor: info.color + '20',
                            tension: 0.4,
                            borderWidth: 2,
                            pointRadius: 3,
                            pointBackgroundColor: info.color,
                            pointBorderColor: '#fff',
                            pointBorderWidth: 1,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            }
                        },
                        scales: {
                            x: {
                                display: false
                            },
                            y: {
                                display: false,
                                beginAtZero: true
                            }
                        },
                        animation: {
                            duration: 200
                        }
                    }
                });
            });
        }
        
        function makePrediction() {
            const model = document.getElementById('model-select').value;
            
            fetch('/api/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({model: model})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateDashboard();
                } else {
                    console.error('Error:', data.error);
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function startDetection() {
            autoMode = true;
            const startBtn = document.getElementById('start-btn');
            const stopBtn = document.getElementById('stop-btn');
            
            startBtn.style.display = 'none';
            stopBtn.style.display = 'inline-block';
            
            // Start prediction and network logs
            autoInterval = setInterval(makePrediction, 1000);
            networkLogsInterval = setInterval(updateNetworkLogs, 300);
            
            makePrediction();
            updateNetworkLogs();
        }
        
        function stopDetection() {
            autoMode = false;
            const startBtn = document.getElementById('start-btn');
            const stopBtn = document.getElementById('stop-btn');
            
            stopBtn.style.display = 'none';
            startBtn.style.display = 'inline-block';
            
            clearInterval(autoInterval);
            clearInterval(networkLogsInterval);
            
            // Show stopped message
            const networkLogsDiv = document.getElementById('network-logs');
            networkLogsDiv.innerHTML = '<div class="log-entry">Network monitoring stopped. Press Start to begin...</div>';
        }
        
        function clearHistory() {
            fetch('/api/clear', {method: 'POST'})
                .then(() => {
                    updateDashboard();
                    // Clear all charts
                    attackTypes.forEach(attackType => {
                        const chart = attackCharts[attackType];
                        if (chart) {
                            chart.data.labels = [];
                            chart.data.datasets[0].data = [];
                            chart.update();
                        }
                        
                        const countEl = document.getElementById(`count-${attackType.toLowerCase()}`);
                        if (countEl) countEl.textContent = '0';
                        
                        const tileEl = document.getElementById(`tile-${attackType.toLowerCase()}`);
                        if (tileEl) tileEl.classList.remove('active');
                    });
                });
        }
        
        function updateNetworkLogs() {
            fetch('/api/network_logs')
                .then(response => response.json())
                .then(data => {
                    const logsDiv = document.getElementById('network-logs');
                    const logs = data.logs.slice(-15);
                    
                    logsDiv.innerHTML = '';
                    logs.forEach(log => {
                        const logDiv = document.createElement('div');
                        logDiv.className = 'log-entry';
                        logDiv.textContent = log.message;
                        logsDiv.appendChild(logDiv);
                    });
                    
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                });
        }
        
        function updateDashboard() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    // Update attack logs
                    const attackLogsDiv = document.getElementById('attack-logs');
                    if (data.attack_logs && data.attack_logs.length > 0) {
                        attackLogsDiv.innerHTML = '';
                        data.attack_logs.slice().reverse().slice(0, 15).forEach(log => {
                            const logDiv = document.createElement('div');
                            logDiv.className = 'log-entry';
                            logDiv.innerHTML = `<span class="log-time">[${log.time}]</span> ${log.message}`;
                            attackLogsDiv.appendChild(logDiv);
                        });
                        attackLogsDiv.scrollTop = attackLogsDiv.scrollHeight;
                    }
                    
                    // Update attack tiles and charts
                    fetch('/api/attack_histories')
                        .then(response => response.json())
                        .then(historyData => {
                            attackTypes.forEach(attackType => {
                                const currentCount = data.stats.attack_types[attackType] || 0;
                                const countEl = document.getElementById(`count-${attackType.toLowerCase()}`);
                                const tileEl = document.getElementById(`tile-${attackType.toLowerCase()}`);
                                const chart = attackCharts[attackType];
                                
                                // Update count
                                if (countEl) countEl.textContent = currentCount;
                                
                                // Update tile appearance
                                if (tileEl) {
                                    if (currentCount > 0) {
                                        tileEl.classList.add('active');
                                    } else {
                                        tileEl.classList.remove('active');
                                    }
                                }
                                
                                // Update chart
                                if (chart && historyData.histories[attackType]) {
                                    const history = historyData.histories[attackType].slice(-20);
                                    const labels = history.map((_, i) => `T-${20-i}`);
                                    const values = history.map(h => h.value);
                                    
                                    chart.data.labels = labels;
                                    chart.data.datasets[0].data = values;
                                    chart.update('none');
                                }
                            });
                        });
                });
        }
        
        // Initialize
        createAttackTiles();
        setInterval(updateDashboard, 2000);
        updateDashboard();
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    print("=" * 80)
    print("CLEAN CYBER ATTACK DETECTION DASHBOARD")
    print("Individual Attack Tiles with Explanations and Proper Plotting")
    print("=" * 80)
    print("Starting server...")
    print("Open your browser and go to: http://localhost:9001")
    print("=" * 80)
    app.run(debug=True, host='0.0.0.0', port=9001)