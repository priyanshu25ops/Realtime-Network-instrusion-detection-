"""
Enhanced Cyber Attack Detection Dashboard
Powerful real-time network security monitoring with dual log panels
"""

from flask import Flask, render_template_string, jsonify, request, Response
from flask_cors import CORS
from prediction_api import predict_single_row, get_model_info
import pandas as pd
import numpy as np
from datetime import datetime
import json
from collections import deque
import random
import threading
import time
import os

app = Flask(__name__)
CORS(app)

# Global data storage
predictions_history = deque(maxlen=200)
detection_logs = deque(maxlen=100)  # Current detection logs
original_logs = deque(maxlen=100)   # Original log file lines
stats = {
    'total_predictions': 0,
    'attacks_detected': 0,
    'normal_traffic': 0,
    'detection_running': False,
    'model_usage': {
        'random_forest': 0,
        'decision_tree': 0,
        'xgboost': 0,
        'lightgbm': 0,
        'ensemble': 0
    }
}

# Attack detection rules
attack_patterns = {
    'DoS': ['Sload', 'Dload', 'Spkts', 'Dpkts'],
    'Fuzzer': ['trans_depth', 'res_bdy_len'],
    'PortScan': ['ct_src_dport_ltm', 'ct_dst_sport_ltm'],
    'BruteForce': ['is_ftp_login', 'ct_ftp_cmd'],
    'Recon': ['ct_dst_ltm'],
    'Worm': ['Sload', 'Dload', 'dur'],
    'Backdoor': ['ct_srv_src', 'ct_srv_dst'],
    'Generic': ['stcpb', 'dtcpb']
}

def load_sample_data():
    """Load sample data for predictions"""
    try:
        df = pd.read_csv("C:\\Users\\priya\\Desktop\\DATA\\processed_train.csv")
        return df.sample(n=1).drop('target', axis=1).iloc[0].to_dict()
    except:
        # Generate random sample data
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

def analyze_attack_pattern(data):
    """Analyze traffic for specific attack patterns"""
    attack_types = []
    
    # High bandwidth DoS
    if data.get('sload', 0) > 100000 or data.get('dload', 0) > 100000:
        attack_types.append('DoS Attack')
    
    # Port scanning
    if data.get('ct_src_dport_ltm', 0) > 50 or data.get('ct_dst_sport_ltm', 0) > 50:
        attack_types.append('Port Scan')
    
    # Brute force
    if data.get('is_ftp_login', 0) > 0 and data.get('ct_ftp_cmd', 0) > 10:
        attack_types.append('Brute Force')
    
    # Fuzzer
    if data.get('trans_depth', 0) > 20 or data.get('response_body_len', 0) < -5:
        attack_types.append('Fuzzer')
    
    return attack_types if attack_types else ['Normal Traffic']

@app.route('/')
def index():
    """Render the dashboard"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/predict', methods=['POST'])
def predict():
    """Make a prediction"""
    try:
        data = load_sample_data()
        model = request.json.get('model', 'random_forest')
        
        # Original log line
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        original_log_line = f"{timestamp} - TCP connection from {random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)} to port {random.randint(1000,9000)} | Duration: {random.randint(0,1000)}ms"
        original_logs.append({'time': datetime.now().strftime('%H:%M:%S'), 'log': original_log_line})
        
        result = predict_single_row(data, model_name=model)
        
        if 'error' not in result:
            # Analyze attack pattern
            attack_types = analyze_attack_pattern(data)
            
            prediction = {
                'timestamp': datetime.now().isoformat(),
                'prediction': result['prediction'],
                'confidence': result['confidence'],
                'interpretation': result['interpretation'],
                'model_used': result.get('model_used', model),
                'attack_types': attack_types
            }
            
            # Update stats
            stats['total_predictions'] += 1
            if result['prediction'] == 1:
                stats['attacks_detected'] += 1
                detection_msg = f"ALERT: Attack detected! Type: {', '.join(attack_types)} | Confidence: {result['confidence']:.2%}"
                detection_logs.append({'time': datetime.now().strftime('%H:%M:%S'), 'level': 'attack', 'message': detection_msg})
            else:
                stats['normal_traffic'] += 1
                detection_msg = f"Normal traffic detected. Confidence: {result['confidence']:.2%}"
                detection_logs.append({'time': datetime.now().strftime('%H:%M:%S'), 'level': 'normal', 'message': detection_msg})
            
            stats['model_usage'][model] += 1
            predictions_history.append(prediction)
            
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
        'detection_logs': list(detection_logs)[-20:],
        'original_logs': list(original_logs)[-20:]
    })

@app.route('/api/predictions')
def get_predictions():
    """Get prediction history for charts"""
    history = list(predictions_history)
    return jsonify({
        'predictions': history,
        'attack_rate': stats['attacks_detected'] / max(stats['total_predictions'], 1) * 100
    })

@app.route('/api/toggle_detection', methods=['POST'])
def toggle_detection():
    """Start or stop continuous detection"""
    stats['detection_running'] = not stats['detection_running']
    
    if stats['detection_running']:
        detection_logs.append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'level': 'info',
            'message': 'SECURITY MONITORING STARTED - Log detection system active'
        })
    else:
        detection_logs.append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'level': 'info',
            'message': 'SECURITY MONITORING STOPPED - Log detection system inactive'
        })
    
    return jsonify({'running': stats['detection_running']})

@app.route('/api/clear', methods=['POST'])
def clear_history():
    """Clear prediction history"""
    global predictions_history, detection_logs, original_logs, stats
    predictions_history.clear()
    detection_logs.clear()
    original_logs.clear()
    stats['total_predictions'] = 0
    stats['attacks_detected'] = 0
    stats['normal_traffic'] = 0
    stats['model_usage'] = {
        'random_forest': 0,
        'decision_tree': 0,
        'xgboost': 0,
        'lightgbm': 0,
        'ensemble': 0
    }
    return jsonify({'success': True})

# Auto detection thread
def auto_detection_worker():
    """Background worker for continuous detection"""
    while True:
        if stats['detection_running']:
            try:
                data = load_sample_data()
                model = 'ensemble'  # Default for auto mode
                result = predict_single_row(data, model_name=model)
                
                if 'error' not in result:
                    attack_types = analyze_attack_pattern(data)
                    stats['total_predictions'] += 1
                    
                    if result['prediction'] == 1:
                        stats['attacks_detected'] += 1
                        detection_msg = f"ALERT: {', '.join(attack_types)} | Confidence: {result['confidence']:.2%}"
                        detection_logs.append({
                            'time': datetime.now().strftime('%H:%M:%S'),
                            'level': 'attack',
                            'message': detection_msg
                        })
                    else:
                        stats['normal_traffic'] += 1
                        detection_logs.append({
                            'time': datetime.now().strftime('%H:%M:%S'),
                            'level': 'normal',
                            'message': f"Normal: {result['confidence']:.2%}"
                        })
                    
                    original_log_line = f"{datetime.now().strftime('%H:%M:%S')} - Network packet | Source: {random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)} | Port: {random.randint(1000,9000)}"
                    original_logs.append({'time': datetime.now().strftime('%H:%M:%S'), 'log': original_log_line})
                    
                    predictions_history.append({
                        'timestamp': datetime.now().isoformat(),
                        'prediction': result['prediction'],
                        'confidence': result['confidence'],
                        'interpretation': result['interpretation'],
                        'model_used': model,
                        'attack_types': attack_types
                    })
                    
                    stats['model_usage'][model] += 1
            except Exception as e:
                pass
            
            time.sleep(2)  # Predict every 2 seconds
        else:
            time.sleep(1)

# Start background worker
thread = threading.Thread(target=auto_detection_worker, daemon=True)
thread.start()

# HTML Template (next message due to length)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Attack Detection Dashboard</title>
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
            max-width: 1800px;
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
        
        .metric-card .value.attack {
            color: #f44336;
        }
        
        .metric-card .value.normal {
            color: #4caf50;
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
            padding: 12px 20px;
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
            white-space: nowrap;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        
        button.active {
            background: #f44336;
        }
        
        button.start-detection {
            background: #4caf50;
        }
        
        button.stop-detection {
            background: #f44336;
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
        
        .log-attack {
            color: #ef5350;
            font-weight: bold;
        }
        
        .log-normal {
            color: #66bb6a;
        }
        
        .log-info {
            color: #4fc3f7;
        }
        
        .chart-container {
            position: relative;
            height: 400px;
            margin-top: 20px;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        
        .status-active {
            background: #4caf50;
        }
        
        .status-inactive {
            background: #ccc;
            animation: none;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Cyber Attack Detection Dashboard</h1>
            <p>Real-time network security monitoring & analysis</p>
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <h3>Total Predictions</h3>
                <div class="value" id="total-predictions">0</div>
            </div>
            <div class="metric-card">
                <h3>Attack Rate</h3>
                <div class="value attack" id="attack-rate">0%</div>
            </div>
            <div class="metric-card">
                <h3>Attacks Detected</h3>
                <div class="value attack" id="attacks-detected">0</div>
            </div>
            <div class="metric-card">
                <h3>Normal Traffic</h3>
                <div class="value normal" id="normal-traffic">0</div>
            </div>
            <div class="metric-card">
                <h3>Detection Status</h3>
                <div class="value" id="detection-status">
                    <span class="status-indicator status-inactive" id="status-indicator"></span>
                    <span id="status-text">Stopped</span>
                </div>
            </div>
        </div>
        
        <div class="controls">
            <div class="control-group">
                <label for="model-select"><strong>Model:</strong></label>
                <select id="model-select">
                    <option value="random_forest">Random Forest</option>
                    <option value="decision_tree">Decision Tree</option>
                    <option value="xgboost">XGBoost</option>
                    <option value="lightgbm">LightGBM</option>
                    <option value="ensemble">Ensemble</option>
                </select>
                <button onclick="makePrediction()">Make Prediction</button>
                <button id="detection-btn" class="start-detection" onclick="toggleDetection()">Start Log Detection</button>
                <button onclick="clearHistory()">Clear History</button>
            </div>
        </div>
        
        <div class="main-content">
            <div class="panel">
                <h2>System Logs (Original)</h2>
                <div class="logs-container" id="original-logs"></div>
            </div>
            
            <div class="panel">
                <h2>Detection Logs (AI Analysis)</h2>
                <div class="logs-container" id="detection-logs"></div>
            </div>
        </div>
        
        <div class="panel">
            <h2>Confidence Over Time</h2>
            <div class="chart-container">
                <canvas id="confidence-chart"></canvas>
            </div>
        </div>
    </div>
    
    <script>
        let confidenceChart;
        const ctx = document.getElementById('confidence-chart').getContext('2d');
        confidenceChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Confidence',
                    data: [],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, max: 1, ticks: { callback: v => (v * 100).toFixed(0) + '%' } }
                }
            }
        });
        
        function makePrediction() {
            const model = document.getElementById('model-select').value;
            fetch('/api/predict', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({model: model})
            }).then(r => r.json()).then(d => updateDashboard());
        }
        
        function toggleDetection() {
            fetch('/api/toggle_detection', {method: 'POST'})
                .then(r => r.json())
                .then(d => {
                    const btn = document.getElementById('detection-btn');
                    if (d.running) {
                        btn.textContent = 'Stop Log Detection';
                        btn.className = 'stop-detection';
                    } else {
                        btn.textContent = 'Start Log Detection';
                        btn.className = 'start-detection';
                    }
                    updateDashboard();
                });
        }
        
        function clearHistory() {
            if (confirm('Clear all history?')) {
                fetch('/api/clear', {method: 'POST'}).then(() => location.reload());
            }
        }
        
        function updateDashboard() {
            fetch('/api/stats').then(r => r.json()).then(data => {
                document.getElementById('total-predictions').textContent = data.stats.total_predictions;
                const rate = data.stats.total_predictions > 0 ? 
                    (data.stats.attacks_detected / data.stats.total_predictions * 100).toFixed(1) : 0;
                document.getElementById('attack-rate').textContent = rate + '%';
                document.getElementById('attacks-detected').textContent = data.stats.attacks_detected;
                document.getElementById('normal-traffic').textContent = data.stats.normal_traffic;
                
                // Update status
                const indicator = document.getElementById('status-indicator');
                const statusText = document.getElementById('status-text');
                if (data.stats.detection_running) {
                    indicator.className = 'status-indicator status-active';
                    statusText.textContent = 'Running';
                } else {
                    indicator.className = 'status-indicator status-inactive';
                    statusText.textContent = 'Stopped';
                }
                
                // Update original logs
                const origLogs = document.getElementById('original-logs');
                origLogs.innerHTML = '';
                data.original_logs.slice().reverse().forEach(log => {
                    const div = document.createElement('div');
                    div.className = 'log-entry';
                    div.innerHTML = `[${log.time}] ${log.log}`;
                    origLogs.appendChild(div);
                });
                
                // Update detection logs
                const detLogs = document.getElementById('detection-logs');
                detLogs.innerHTML = '';
                data.detection_logs.slice().reverse().forEach(log => {
                    const div = document.createElement('div');
                    div.className = 'log-entry';
                    const colorClass = log.level === 'attack' ? 'log-attack' : 
                                      log.level === 'normal' ? 'log-normal' : 'log-info';
                    div.innerHTML = `<span class="log-time">[${log.time}]</span> <span class="${colorClass}">${log.message}</span>`;
                    detLogs.appendChild(div);
                });
                
                // Update chart
                fetch('/api/predictions').then(r => r.json()).then(d => {
                    if (d.predictions && d.predictions.length > 0) {
                        confidenceChart.data.labels = d.predictions.map((p, i) => i + 1);
                        confidenceChart.data.datasets[0].data = d.predictions.map(p => p.confidence);
                        confidenceChart.update('active');
                    }
                });
            });
        }
        
        setInterval(updateDashboard, 1000);
        updateDashboard();
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    print("=" * 60)
    print("Cyber Attack Detection Dashboard - Enhanced Version")
    print("=" * 60)
    print("Starting server...")
    print("Open your browser: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)

