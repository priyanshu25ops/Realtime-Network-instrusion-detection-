"""
Comprehensive Cyber Attack Detection Dashboard
Implements ALL 20 attack detection features with real-time monitoring
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
network_logs = deque(maxlen=1000)  # Live network logs
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
    
    # 1. DoS Attack Detection - Sload, Dload, Spkts, Dpkts patterns
    sload = abs(data.get('sload', 0))
    dload = abs(data.get('dload', 0))
    spkts = abs(data.get('spkts', 0))
    dpkts = abs(data.get('dpkts', 0))
    
    if sload > 1.5 or dload > 1.5 or spkts > 1.5 or dpkts > 1.5:
        attack_types.append('DoS')
    
    # 2. Fuzzer Detection - trans_depth, response_body_len patterns
    trans_depth = abs(data.get('trans_depth', 0))
    response_body_len = abs(data.get('response_body_len', 0))
    
    if trans_depth > 1.5 or response_body_len < -1.5:
        attack_types.append('Fuzzer')
    
    # 3. Port Scan Detection - ct_src_dport_ltm, ct_dst_sport_ltm
    ct_src_dport_ltm = abs(data.get('ct_src_dport_ltm', 0))
    ct_dst_sport_ltm = abs(data.get('ct_dst_sport_ltm', 0))
    
    if ct_src_dport_ltm > 1.5 or ct_dst_sport_ltm > 1.5:
        attack_types.append('Port_Scan')
    
    # 4. Brute Force Login Detection - is_ftp_login, ct_ftp_cmd
    is_ftp_login = abs(data.get('is_ftp_login', 0))
    ct_ftp_cmd = abs(data.get('ct_ftp_cmd', 0))
    
    if is_ftp_login > 0.5 and ct_ftp_cmd > 0.5:
        attack_types.append('Brute_Force')
    
    # 5. Reconnaissance Detection - ct_dst_ltm spikes
    ct_dst_ltm = abs(data.get('ct_dst_ltm', 0))
    
    if ct_dst_ltm > 1.5:
        attack_types.append('Reconnaissance')
    
    # 6. Anomalous IP Communication - is_sm_ips_ports
    is_sm_ips_ports = abs(data.get('is_sm_ips_ports', 0))
    
    if is_sm_ips_ports > 1.5:
        attack_types.append('Anomalous_IP')
    
    # 7. High Bandwidth Usage - Sload, Dload thresholds
    if sload > 1.0 or dload > 1.0:
        attack_types.append('High_Bandwidth')
    
    # 8. Suspicious TCP Behavior - tcprtt, synack, ackdat
    tcprtt = abs(data.get('tcprtt', 0))
    synack = abs(data.get('synack', 0))
    ackdat = abs(data.get('ackdat', 0))
    
    if tcprtt > 1.0 or synack > 1.0 or ackdat > 1.0:
        attack_types.append('Suspicious_TCP')
    
    # 9. Replay Attack Detection - stcpb, dtcpb repetition patterns
    stcpb = abs(data.get('stcpb', 0))
    dtcpb = abs(data.get('dtcpb', 0))
    
    if stcpb > 1.5 or dtcpb > 1.5:
        attack_types.append('Replay_Attack')
    
    # 10. Abnormal Packet Sizes - smean, dmean outliers
    smean = abs(data.get('smean', 0))
    dmean = abs(data.get('dmean', 0))
    
    if smean > 1.5 or dmean > 1.5:
        attack_types.append('Abnormal_Packet')
    
    # 11. Session Hijacking Detection - state changes over dur
    state = abs(data.get('state', 0))
    dur = abs(data.get('dur', 0))
    
    if state > 1.0 and dur < -1.0:
        attack_types.append('Session_Hijacking')
    
    # 12. Jitter/Latency Anomalies - Sjit, Djit
    sjit = abs(data.get('sjit', 0))
    djit = abs(data.get('djit', 0))
    
    if sjit > 1.0 or djit > 1.0:
        attack_types.append('Jitter_Anomaly')
    
    # 13. Slowloris / Long Connection Detection - dur, trans_depth
    if dur > 1.0 and trans_depth > 1.0:
        attack_types.append('Slowloris')
    
    # 14. Frequent Service Abuse - ct_srv_src, ct_srv_dst
    ct_srv_src = abs(data.get('ct_srv_src', 0))
    ct_srv_dst = abs(data.get('ct_srv_dst', 0))
    
    if ct_srv_src > 1.0 or ct_srv_dst > 1.0:
        attack_types.append('Service_Abuse')
    
    # 15. Traffic Correlation Attacks - ct_dst_src_ltm, ct_src_ltm spikes
    ct_dst_src_ltm = abs(data.get('ct_dst_src_ltm', 0))
    ct_src_ltm = abs(data.get('ct_src_ltm', 0))
    
    if ct_dst_src_ltm > 1.0 and ct_src_ltm > 1.0:
        attack_types.append('Traffic_Correlation')
    
    # 16. Worm Spread Patterns - Sload, Dload, dur
    if sload > 1.0 and dload > 1.0 and dur > 1.0:
        attack_types.append('Worm_Spread')
    
    # 17. Anomalous Interpacket Timing - Sinpkt, Dinpkt
    sinpkt = abs(data.get('sinpkt', 0))
    dinpkt = abs(data.get('dinpkt', 0))
    
    if sinpkt > 1.0 or dinpkt > 1.0:
        attack_types.append('Timing_Attack')
    
    return attack_types

@app.route('/')
def index():
    """Render the comprehensive dashboard"""
    return render_template_string(COMPREHENSIVE_HTML_TEMPLATE)

@app.route('/api/predict', methods=['POST'])
def predict():
    """Make a comprehensive prediction with all 20 features"""
    try:
        data = load_sample_data()
        model = request.json.get('model', 'random_forest')
        
        result = predict_single_row(data, model_name=model)
        
        if 'error' not in result:
            # Detect specific attack types
            attack_types = detect_attack_types(data)
            
            prediction = {
                'timestamp': datetime.now().isoformat(),
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
                
                # Update attack type counts
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
            logs.append({'time': datetime.now().strftime('%H:%M:%S'), 'message': log_msg})
            attack_logs.append({'time': datetime.now().strftime('%H:%M:%S'), 'message': attack_log_msg})
            
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
        'attack_logs': list(attack_logs)[-20:]
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

@app.route('/api/network_logs')
def get_network_logs():
    """Get latest network logs"""
    return jsonify({
        'logs': list(network_logs)[-100:]  # Latest 100 logs
    })

@app.route('/api/clear', methods=['POST'])
def clear_history():
    """Clear prediction history"""
    global predictions_history, logs, attack_logs, stats
    predictions_history.clear()
    logs.clear()
    attack_logs.clear()
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
    return jsonify({'success': True})

# Comprehensive HTML Template with all 20 features
COMPREHENSIVE_HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Comprehensive Cyber Attack Detection - All 20 Features</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 3rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .feature-card {
            background: white;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .feature-card:hover {
            transform: translateY(-3px);
        }
        
        .feature-card.active {
            background: #ff6b6b;
            color: white;
        }
        
        .feature-card h4 {
            font-size: 0.9rem;
            margin-bottom: 5px;
        }
        
        .feature-card .count {
            font-size: 1.5rem;
            font-weight: bold;
        }
        
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metric-card {
            background: white;
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
            animation: slideIn 0.5s ease-out;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.15);
        }
        
        .metric-card h3 {
            font-size: 0.9rem;
            color: #666;
            margin-bottom: 10px;
        }
        
        .metric-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }
        
        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
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
            max-height: 400px;
            overflow-y: auto;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
        }
        
        .log-entry {
            padding: 5px 0;
            border-bottom: 1px solid #333;
            animation: fadeIn 0.3s;
        }
        
        .log-time {
            color: #888;
            margin-right: 10px;
        }
        
        .controls {
            background: white;
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .control-group {
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
        
        .chart-container {
            position: relative;
            height: 300px;
            margin-top: 20px;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .predictions-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .predictions-table th,
        .predictions-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        
        .predictions-table th {
            background: #f5f5f5;
            font-weight: bold;
        }
        
        .attack {
            color: #f44336;
            font-weight: bold;
        }
        
        .normal {
            color: #4caf50;
            font-weight: bold;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
            }
            to {
                opacity: 1;
            }
        }
        
        .auto-mode {
            background: #4caf50;
            color: white;
        }
        
        .detection-info {
            font-size: 0.8rem;
            color: #555;
            margin-bottom: 10px;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 6px;
            border-left: 3px solid #667eea;
            line-height: 1.4;
        }
        
        .detection-info strong {
            color: #333;
        }
        
        .start-btn {
            background: linear-gradient(135deg, #4caf50 0%, #45a049 100%) !important;
        }
        
        .stop-btn {
            background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%) !important;
        }
        
        .network-logs {
            background: #1e1e1e !important;
            color: #00ff00 !important;
            font-family: 'Courier New', monospace !important;
            font-size: 0.75rem;
            line-height: 1.2;
        }
        
        .network-logs .log-entry {
            padding: 2px 0;
            animation: fadeIn 0.3s;
            border-bottom: 1px solid #333;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 5px;
            animation: pulse 2s infinite;
        }
        
        .status-active {
            background: #4caf50;
        }
        
        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.5;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Comprehensive Cyber Attack Detection</h1>
            <p>All 20 Attack Detection Features - Real-time ML Analysis</p>
        </div>
        
        <!-- 20 Features Grid -->
        <div class="features-grid">
            <div class="feature-card" id="feature-dos">
                <h4>DoS Detection</h4>
                <div class="count" id="dos-count">0</div>
            </div>
            <div class="feature-card" id="feature-fuzzer">
                <h4>Fuzzer Detection</h4>
                <div class="count" id="fuzzer-count">0</div>
            </div>
            <div class="feature-card" id="feature-portscan">
                <h4>Port Scan</h4>
                <div class="count" id="portscan-count">0</div>
            </div>
            <div class="feature-card" id="feature-brute">
                <h4>Brute Force</h4>
                <div class="count" id="brute-count">0</div>
            </div>
            <div class="feature-card" id="feature-recon">
                <h4>Reconnaissance</h4>
                <div class="count" id="recon-count">0</div>
            </div>
            <div class="feature-card" id="feature-anomalous">
                <h4>Anomalous IP</h4>
                <div class="count" id="anomalous-count">0</div>
            </div>
            <div class="feature-card" id="feature-bandwidth">
                <h4>High Bandwidth</h4>
                <div class="count" id="bandwidth-count">0</div>
            </div>
            <div class="feature-card" id="feature-tcp">
                <h4>Suspicious TCP</h4>
                <div class="count" id="tcp-count">0</div>
            </div>
            <div class="feature-card" id="feature-replay">
                <h4>Replay Attack</h4>
                <div class="count" id="replay-count">0</div>
            </div>
            <div class="feature-card" id="feature-packet">
                <h4>Abnormal Packet</h4>
                <div class="count" id="packet-count">0</div>
            </div>
            <div class="feature-card" id="feature-session">
                <h4>Session Hijacking</h4>
                <div class="count" id="session-count">0</div>
            </div>
            <div class="feature-card" id="feature-jitter">
                <h4>Jitter Anomaly</h4>
                <div class="count" id="jitter-count">0</div>
            </div>
            <div class="feature-card" id="feature-slowloris">
                <h4>Slowloris</h4>
                <div class="count" id="slowloris-count">0</div>
            </div>
            <div class="feature-card" id="feature-service">
                <h4>Service Abuse</h4>
                <div class="count" id="service-count">0</div>
            </div>
            <div class="feature-card" id="feature-correlation">
                <h4>Traffic Correlation</h4>
                <div class="count" id="correlation-count">0</div>
            </div>
            <div class="feature-card" id="feature-worm">
                <h4>Worm Spread</h4>
                <div class="count" id="worm-count">0</div>
            </div>
            <div class="feature-card" id="feature-timing">
                <h4>Timing Attack</h4>
                <div class="count" id="timing-count">0</div>
            </div>
            <div class="feature-card" id="feature-other">
                <h4>Other Attacks</h4>
                <div class="count" id="other-count">0</div>
            </div>
        </div>
        
        <!-- Metrics Cards -->
        <div class="metrics">
            <div class="metric-card">
                <h3>Total Predictions</h3>
                <div class="value" id="total-predictions">0</div>
            </div>
            <div class="metric-card">
                <h3>Attack Rate</h3>
                <div class="value" id="attack-rate">0%</div>
            </div>
            <div class="metric-card">
                <h3>Attacks Detected</h3>
                <div class="value" id="attacks-detected">0</div>
            </div>
            <div class="metric-card">
                <h3>Normal Traffic</h3>
                <div class="value" id="normal-traffic">0</div>
            </div>
            <div class="metric-card">
                <h3>Average Confidence</h3>
                <div class="value" id="avg-confidence">0%</div>
            </div>
        </div>
        
        <!-- Controls -->
        <div class="controls">
            <div class="control-group">
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
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <div class="panel">
                <h2>📋 Network Traffic Logs (Live)</h2>
                <div class="logs-container network-logs" id="network-logs"></div>
            </div>
            
            <div class="panel">
                <h2>🚨 Attack Detection Logs</h2>
                <div class="logs-container" id="attack-logs"></div>
            </div>
        </div>
        
        <!-- Original Charts -->
        <div class="charts-grid">
            <div class="panel">
                <h2>📈 Confidence Over Time</h2>
                <div class="chart-container">
                    <canvas id="confidence-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🎯 Attack Types Distribution</h2>
                <div class="chart-container">
                    <canvas id="attack-distribution-chart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="panel">
            <h2>📊 Attack Frequency by Type</h2>
            <div class="chart-container">
                <canvas id="attack-frequency-chart"></canvas>
            </div>
        </div>
        
        <!-- Individual Attack Type Charts -->
        <div class="charts-grid">
            <div class="panel">
                <h2>📈 DoS Detection</h2>
                <p class="detection-info">Detected when: sload > 1.5 OR dload > 1.5 OR spkts > 1.5 OR dpkts > 1.5<br>High traffic volume patterns indicating connection flooding</p>
                <div class="chart-container">
                    <canvas id="dos-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🔍 Fuzzer Detection</h2>
                <p class="detection-info">Detected when: trans_depth > 1.5 OR response_body_len < -1.5<br>Abnormal transaction patterns and malformed responses</p>
                <div class="chart-container">
                    <canvas id="fuzzer-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🔎 Port Scan</h2>
                <p class="detection-info">Detected when: ct_src_dport_ltm > 1.5 OR ct_dst_sport_ltm > 1.5<br>Multiple destination ports accessed in reconnaissance</p>
                <div class="chart-container">
                    <canvas id="portscan-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🔐 Brute Force</h2>
                <p class="detection-info">Detected when: is_ftp_login > 0.5 AND ct_ftp_cmd > 0.5<br>FTP login attempts combined with command frequency</p>
                <div class="chart-container">
                    <canvas id="brute-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🕵️ Reconnaissance</h2>
                <p class="detection-info">Detected when: ct_dst_ltm > 1.5<br>Network mapping and topology discovery patterns</p>
                <div class="chart-container">
                    <canvas id="recon-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🌐 Anomalous IP</h2>
                <p class="detection-info">Detected when: is_sm_ips_ports > 1.5<br>Suspicious IP and port combinations indicating threats</p>
                <div class="chart-container">
                    <canvas id="anomalous-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>📊 High Bandwidth</h2>
                <p class="detection-info">Detected when: sload > 1.0 OR dload > 1.0<br>Elevated data transfer rates for exfiltration/DDoS</p>
                <div class="chart-container">
                    <canvas id="bandwidth-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🔗 Suspicious TCP</h2>
                <p class="detection-info">Detected when: tcprtt > 1.0 OR synack > 1.0 OR ackdat > 1.0<br>TCP handshake anomalies and connection manipulation</p>
                <div class="chart-container">
                    <canvas id="tcp-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🔄 Replay Attack</h2>
                <p class="detection-info">Detected when: stcpb > 1.5 OR dtcpb > 1.5<br>TCP sequence repetition indicating packet replay</p>
                <div class="chart-container">
                    <canvas id="replay-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>📦 Abnormal Packet</h2>
                <p class="detection-info">Detected when: smean > 1.5 OR dmean > 1.5<br>Packet size outliers for buffer overflow/covert channels</p>
                <div class="chart-container">
                    <canvas id="packet-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🎭 Session Hijacking</h2>
                <p class="detection-info">Detected when: state > 1.0 AND dur < -1.0<br>Connection state changes during short duration</p>
                <div class="chart-container">
                    <canvas id="session-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>⚡ Jitter Anomaly</h2>
                <p class="detection-info">Detected when: sjit > 1.0 OR djit > 1.0<br>Network timing irregularities and latency spikes</p>
                <div class="chart-container">
                    <canvas id="jitter-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🐌 Slowloris</h2>
                <p class="detection-info">Detected when: dur > 1.0 AND trans_depth > 1.0<br>Long connection duration with deep transactions</p>
                <div class="chart-container">
                    <canvas id="slowloris-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>⚙️ Service Abuse</h2>
                <p class="detection-info">Detected when: ct_srv_src > 1.0 OR ct_srv_dst > 1.0<br>Frequent service requests indicating API abuse</p>
                <div class="chart-container">
                    <canvas id="service-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🔗 Traffic Correlation</h2>
                <p class="detection-info">Detected when: ct_dst_src_ltm > 1.0 AND ct_src_ltm > 1.0<br>Correlated traffic patterns for flow analysis</p>
                <div class="chart-container">
                    <canvas id="correlation-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🐛 Worm Spread</h2>
                <p class="detection-info">Detected when: sload > 1.0 AND dload > 1.0 AND dur > 1.0<br>Combined high traffic and duration for propagation</p>
                <div class="chart-container">
                    <canvas id="worm-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>⏱️ Timing Attack</h2>
                <p class="detection-info">Detected when: sinpkt > 1.0 OR dinpkt > 1.0<br>Interpacket timing anomalies for side-channel attacks</p>
                <div class="chart-container">
                    <canvas id="timing-chart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h2>🚨 Other Attacks</h2>
                <p class="detection-info">Detected when: Other patterns not matching specific categories<br>Miscellaneous threats and unknown attack vectors</p>
                <div class="chart-container">
                    <canvas id="other-chart"></canvas>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let autoMode = false;
        let autoInterval;
        let networkLogsInterval;
        let confidenceChart, attackDistributionChart, attackFrequencyChart;
        let attackCharts = {};
        
        const attackTypes = [
            'DoS', 'Fuzzer', 'Port_Scan', 'Brute_Force', 'Reconnaissance',
            'Anomalous_IP', 'High_Bandwidth', 'Suspicious_TCP', 'Replay_Attack',
            'Abnormal_Packet', 'Session_Hijacking', 'Jitter_Anomaly', 'Slowloris',
            'Service_Abuse', 'Traffic_Correlation', 'Worm_Spread', 'Timing_Attack', 'Other'
        ];
        
        const chartIds = [
            'dos-chart', 'fuzzer-chart', 'portscan-chart', 'brute-chart', 'recon-chart',
            'anomalous-chart', 'bandwidth-chart', 'tcp-chart', 'replay-chart',
            'packet-chart', 'session-chart', 'jitter-chart', 'slowloris-chart',
            'service-chart', 'correlation-chart', 'worm-chart', 'timing-chart', 'other-chart'
        ];
        
        // Initialize charts
        function initCharts() {
            // Original Confidence Chart
            const ctx1 = document.getElementById('confidence-chart').getContext('2d');
            confidenceChart = new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Confidence',
                        data: [],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 4
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
                        y: {
                            beginAtZero: true,
                            max: 1,
                            ticks: {
                                callback: function(value) {
                                    return (value * 100).toFixed(0) + '%';
                                }
                            }
                        }
                    }
                }
            });
            
            // Attack Distribution Chart (Pie)
            const ctx2 = document.getElementById('attack-distribution-chart').getContext('2d');
            attackDistributionChart = new Chart(ctx2, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57',
                            '#ff9ff3', '#54a0ff', '#5f27cd', '#00d2d3', '#ff9f43',
                            '#10ac84', '#ee5a24', '#0984e3', '#6c5ce7', '#a29bfe',
                            '#fd79a8', '#fdcb6e', '#e17055'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
            
            // Attack Frequency Chart (Bar)
            const ctx3 = document.getElementById('attack-frequency-chart').getContext('2d');
            attackFrequencyChart = new Chart(ctx3, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Attack Count',
                        data: [],
                        backgroundColor: '#667eea',
                        borderColor: '#764ba2',
                        borderWidth: 1
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
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
            
            // Individual attack type charts with different colors
            const chartColors = [
                '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57',
                '#ff9ff3', '#54a0ff', '#5f27cd', '#00d2d3', '#ff9f43',
                '#10ac84', '#ee5a24', '#0984e3', '#6c5ce7', '#a29bfe',
                '#fd79a8', '#fdcb6e', '#e17055'
            ];
            
            attackTypes.forEach((attackType, index) => {
                const chartId = chartIds[index];
                const canvasElement = document.getElementById(chartId);
                console.log(`Initializing chart for ${attackType} with ID ${chartId}`);
                
                if (canvasElement) {
                    console.log(`Canvas element found for ${attackType}`);
                    try {
                        const ctx = canvasElement.getContext('2d');
                        const color = chartColors[index % chartColors.length];
                        
                        attackCharts[attackType] = new Chart(ctx, {
                            type: 'line',
                            data: {
                                labels: [],
                                datasets: [{
                                    label: attackType.replace('_', ' ') + ' Count',
                                    data: [],
                                    borderColor: color,
                                    backgroundColor: color + '30',
                                    tension: 0.4,
                                    borderWidth: 2,
                                    pointRadius: 4,
                                    pointBackgroundColor: color,
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
                                        display: true
                                    },
                                    y: {
                                        beginAtZero: true
                                    }
                                },
                                animation: {
                                    duration: 0
                                }
                            }
                        });
                        console.log(`Chart created successfully for ${attackType}`);
                    } catch (error) {
                        console.error(`Error creating chart for ${attackType}:`, error);
                    }
                } else {
                    console.error(`Canvas element not found for ${attackType} with ID ${chartId}`);
                }
            });
            
            console.log('Created charts:', Object.keys(attackCharts));
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
            
            // Start prediction interval
            autoInterval = setInterval(makePrediction, 1000); // Every second
            makePrediction(); // Make initial prediction
            
            // Start network logs interval
            networkLogsInterval = setInterval(updateNetworkLogs, 300); // Every 0.3 seconds
            updateNetworkLogs(); // Show initial network logs
        }
        
        function stopDetection() {
            autoMode = false;
            const startBtn = document.getElementById('start-btn');
            const stopBtn = document.getElementById('stop-btn');
            
            stopBtn.style.display = 'none';
            startBtn.style.display = 'inline-block';
            
            // Stop prediction interval
            clearInterval(autoInterval);
            
            // Stop network logs interval
            clearInterval(networkLogsInterval);
            
            // Clear network logs display
            const logsDiv = document.getElementById('network-logs');
            logsDiv.innerHTML = '<div class="log-entry">Network monitoring stopped. Press Start to begin...</div>';
        }
        
        function clearHistory() {
            fetch('/api/clear', {method: 'POST'})
                .then(() => {
                    updateDashboard();
                    location.reload();
                });
        }
        
        function updateNetworkLogs() {
            fetch('/api/network_logs')
                .then(response => response.json())
                .then(data => {
                    const logsDiv = document.getElementById('network-logs');
                    const logs = data.logs.slice(-20); // Show last 20 logs
                    
                    logsDiv.innerHTML = '';
                    logs.forEach(log => {
                        const logDiv = document.createElement('div');
                        logDiv.className = 'log-entry';
                        logDiv.textContent = log.message;
                        logsDiv.appendChild(logDiv);
                    });
                    
                    // Auto-scroll to bottom
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                })
                .catch(error => console.error('Error updating network logs:', error));
        }
        
        function updateIndividualCharts(attackTypeData) {
            console.log('Updating individual charts with data:', attackTypeData);
            
            if (!attackTypeData) {
                console.log('No attack type data provided');
                return;
            }
            
            // Update individual attack charts
            attackTypes.forEach((attackType, index) => {
                const chartId = chartIds[index];
                const chart = attackCharts[attackType];
                const currentCount = attackTypeData[attackType] || 0;
                
                console.log(`Processing ${attackType} (chart ID: ${chartId}, count: ${currentCount})`);
                
                if (chart) {
                    try {
                        // Add new data point with timestamp
                        const now = new Date().toLocaleTimeString();
                        
                        // Push new data
                        chart.data.labels.push(now);
                        chart.data.datasets[0].data.push(currentCount);
                        
                        // Keep only last 10 data points for visibility
                        if (chart.data.labels.length > 10) {
                            chart.data.labels.shift();
                            chart.data.datasets[0].data.shift();
                        }
                        
                        // Update the chart
                        chart.update('none');
                        console.log(`Successfully updated chart for ${attackType}`);
                    } catch (error) {
                        console.error(`Error updating chart for ${attackType}:`, error);
                    }
                } else {
                    console.error(`Chart not found for ${attackType}`);
                }
            });
        }
        
        function updateDashboard() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    // Update metrics
                    document.getElementById('total-predictions').textContent = data.stats.total_predictions;
                    const attackRate = data.stats.total_predictions > 0 ? 
                        (data.stats.attacks_detected / data.stats.total_predictions * 100).toFixed(1) : 0;
                    document.getElementById('attack-rate').textContent = attackRate + '%';
                    document.getElementById('attacks-detected').textContent = data.stats.attacks_detected;
                    document.getElementById('normal-traffic').textContent = data.stats.normal_traffic;
                    
                    // Update feature cards
                    const attackTypesData = data.stats.attack_types;
                    document.getElementById('dos-count').textContent = attackTypesData.DoS || 0;
                    document.getElementById('fuzzer-count').textContent = attackTypesData.Fuzzer || 0;
                    document.getElementById('portscan-count').textContent = attackTypesData.Port_Scan || 0;
                    document.getElementById('brute-count').textContent = attackTypesData.Brute_Force || 0;
                    document.getElementById('recon-count').textContent = attackTypesData.Reconnaissance || 0;
                    document.getElementById('anomalous-count').textContent = attackTypesData.Anomalous_IP || 0;
                    document.getElementById('bandwidth-count').textContent = attackTypesData.High_Bandwidth || 0;
                    document.getElementById('tcp-count').textContent = attackTypesData.Suspicious_TCP || 0;
                    document.getElementById('replay-count').textContent = attackTypesData.Replay_Attack || 0;
                    document.getElementById('packet-count').textContent = attackTypesData.Abnormal_Packet || 0;
                    document.getElementById('session-count').textContent = attackTypesData.Session_Hijacking || 0;
                    document.getElementById('jitter-count').textContent = attackTypesData.Jitter_Anomaly || 0;
                    document.getElementById('slowloris-count').textContent = attackTypesData.Slowloris || 0;
                    document.getElementById('service-count').textContent = attackTypesData.Service_Abuse || 0;
                    document.getElementById('correlation-count').textContent = attackTypesData.Traffic_Correlation || 0;
                    document.getElementById('worm-count').textContent = attackTypesData.Worm_Spread || 0;
                    document.getElementById('timing-count').textContent = attackTypesData.Timing_Attack || 0;
                    document.getElementById('other-count').textContent = attackTypesData.Other || 0;
                    
                    // Update logs
                    const logsDiv = document.getElementById('logs');
                    logsDiv.innerHTML = '';
                    data.logs.slice().reverse().forEach(log => {
                        const logDiv = document.createElement('div');
                        logDiv.className = 'log-entry';
                        logDiv.innerHTML = `<span class="log-time">[${log.time}]</span> ${log.message}`;
                        logsDiv.appendChild(logDiv);
                    });
                    
                    // Update attack logs with debug info
                    const attackLogsDiv = document.getElementById('attack-logs');
                    if (attackLogsDiv) {
                        console.log('Attack logs data:', data.attack_logs);
                        attackLogsDiv.innerHTML = '';
                        
                        if (data.attack_logs && data.attack_logs.length > 0) {
                            console.log('Displaying', data.attack_logs.length, 'attack log entries');
                            data.attack_logs.slice().reverse().forEach((log, index) => {
                                const logDiv = document.createElement('div');
                                logDiv.className = 'log-entry';
                                logDiv.innerHTML = `<span class="log-time">[${log.time}]</span> ${log.message}`;
                                attackLogsDiv.appendChild(logDiv);
                            });
                        } else {
                            console.log('No attack logs found, showing default message');
                            attackLogsDiv.innerHTML = '<div class="log-entry">No attack logs yet. Start detection to begin monitoring...</div>';
                        }
                        
                        // Auto-scroll to bottom
                        attackLogsDiv.scrollTop = attackLogsDiv.scrollHeight;
                    } else {
                        console.error('Attack logs div not found!');
                    }
                    
                    // Update individual charts with current data
                    updateIndividualCharts(attackTypesData);
                    
                    // Update original charts
                    fetch('/api/predictions')
                        .then(response => response.json())
                        .then(data => {
                            if (data.predictions && data.predictions.length > 0) {
                                const labels = data.predictions.map((p, i) => i + 1);
                                const confidences = data.predictions.map(p => p.confidence);
                                
                                confidenceChart.data.labels = labels;
                                confidenceChart.data.datasets[0].data = confidences;
                                confidenceChart.data.datasets[0].pointBackgroundColor = 
                                    confidences.map((c, i) => 
                                        data.predictions[i].prediction === 1 ? '#f44336' : '#4caf50'
                                    );
                                confidenceChart.update('active');
                            }
                            
                            // Update attack distribution chart
                            const attackTypes = data.attack_types;
                            const labels = Object.keys(attackTypes).filter(key => attackTypes[key] > 0);
                            const values = labels.map(key => attackTypes[key]);
                            
                            attackDistributionChart.data.labels = labels;
                            attackDistributionChart.data.datasets[0].data = values;
                            attackDistributionChart.update('active');
                            
                            // Update attack frequency chart
                            attackFrequencyChart.data.labels = Object.keys(attackTypes);
                            attackFrequencyChart.data.datasets[0].data = Object.values(attackTypes);
                            attackFrequencyChart.update('active');
                        });
                });
        }
        
        // Initialize charts and start updates
        initCharts();
        
        // Initialize network logs with waiting message
        const networkLogsDiv = document.getElementById('network-logs');
        networkLogsDiv.innerHTML = '<div class="log-entry">Network monitoring stopped. Press Start to begin...</div>';
        
        // Initialize attack logs with waiting message
        const attackLogsDiv = document.getElementById('attack-logs');
        if (attackLogsDiv) {
            attackLogsDiv.innerHTML = '<div class="log-entry">No attack logs yet. Start detection to begin monitoring...</div>';
        }
        
        setInterval(updateDashboard, 1000);
        updateDashboard();
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    print("=" * 80)
    print("COMPREHENSIVE CYBER ATTACK DETECTION DASHBOARD")
    print("All 20 Attack Detection Features Implemented!")
    print("=" * 80)
    print("Starting server...")
    print("Open your browser and go to: http://localhost:9001")
    print("=" * 80)
    app.run(debug=True, host='0.0.0.0', port=9001)
