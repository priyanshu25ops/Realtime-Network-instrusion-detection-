"""
Flask Dashboard Server for Cyber Attack Detection
Real-time predictions with live analytics and visualizations
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
predictions_history = deque(maxlen=200)
logs = deque(maxlen=100)
stats = {
    'total_predictions': 0,
    'attacks_detected': 0,
    'normal_traffic': 0,
    'model_usage': {
        'random_forest': 0,
        'decision_tree': 0,
        'xgboost': 0,
        'lightgbm': 0,
        'ensemble': 0
    }
}

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
        
        result = predict_single_row(data, model_name=model)
        
        if 'error' not in result:
            prediction = {
                'timestamp': datetime.now().isoformat(),
                'prediction': result['prediction'],
                'confidence': result['confidence'],
                'interpretation': result['interpretation'],
                'model_used': result.get('model_used', model)
            }
            
            # Update stats
            stats['total_predictions'] += 1
            if result['prediction'] == 1:
                stats['attacks_detected'] += 1
                log_msg = f"🚨 ATTACK DETECTED! Confidence: {result['confidence']:.2%}"
            else:
                stats['normal_traffic'] += 1
                log_msg = f"✓ Normal traffic detected. Confidence: {result['confidence']:.2%}"
            
            stats['model_usage'][model] += 1
            predictions_history.append(prediction)
            logs.append({'time': datetime.now().strftime('%H:%M:%S'), 'message': log_msg})
            
            return jsonify({
                'success': True,
                'result': result,
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
        'logs': list(logs)[-20:]
    })

@app.route('/api/predictions')
def get_predictions():
    """Get prediction history for charts"""
    history = list(predictions_history)
    return jsonify({
        'predictions': history,
        'attack_rate': stats['attacks_detected'] / max(stats['total_predictions'], 1) * 100
    })

@app.route('/api/clear', methods=['POST'])
def clear_history():
    """Clear prediction history"""
    global predictions_history, logs, stats
    predictions_history.clear()
    logs.clear()
    stats = {
        'total_predictions': 0,
        'attacks_detected': 0,
        'normal_traffic': 0,
        'model_usage': {
            'random_forest': 0,
            'decision_tree': 0,
            'xgboost': 0,
            'lightgbm': 0,
            'ensemble': 0
        }
    }
    return jsonify({'success': True})

# HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Cyber Attack Detection Dashboard</title>
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
            max-width: 1400px;
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
            height: 400px;
            margin-top: 20px;
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
            <h1>🛡️ Cyber Attack Detection Dashboard</h1>
            <p>Real-time ML-powered network traffic analysis</p>
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
                <button onclick="makePrediction()">🔍 Make Prediction</button>
                <button id="auto-btn" onclick="toggleAutoMode()">▶️ Enable Auto Mode</button>
                <button onclick="clearHistory()">🗑️ Clear History</button>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <div class="panel">
                <h2>📋 Live Logs</h2>
                <div class="logs-container" id="logs"></div>
            </div>
            
            <div class="panel">
                <h2>📊 Recent Predictions</h2>
                <table class="predictions-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Status</th>
                            <th>Confidence</th>
                            <th>Model</th>
                        </tr>
                    </thead>
                    <tbody id="predictions-table-body">
                        <tr>
                            <td colspan="4" style="text-align: center; color: #999;">No predictions yet</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="panel">
            <h2>📈 Confidence Over Time</h2>
            <div class="chart-container">
                <canvas id="confidence-chart"></canvas>
            </div>
        </div>
    </div>
    
    <script>
        let autoMode = false;
        let autoInterval;
        let confidenceChart;
        
        // Initialize chart
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
                    alert('Error: ' + data.error);
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function toggleAutoMode() {
            autoMode = !autoMode;
            const btn = document.getElementById('auto-btn');
            
            if (autoMode) {
                btn.textContent = '⏸️ Disable Auto Mode';
                btn.classList.add('auto-mode');
                autoInterval = setInterval(makePrediction, 2000);
            } else {
                btn.textContent = '▶️ Enable Auto Mode';
                btn.classList.remove('auto-mode');
                clearInterval(autoInterval);
            }
        }
        
        function clearHistory() {
            fetch('/api/clear', {method: 'POST'})
                .then(() => {
                    updateDashboard();
                    location.reload();
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
                    
                    // Update logs
                    const logsDiv = document.getElementById('logs');
                    logsDiv.innerHTML = '';
                    data.logs.slice().reverse().forEach(log => {
                        const logDiv = document.createElement('div');
                        logDiv.className = 'log-entry';
                        logDiv.innerHTML = `<span class="log-time">[${log.time}]</span> ${log.message}`;
                        logsDiv.appendChild(logDiv);
                    });
                    
                    // Update predictions table
                    const tbody = document.getElementById('predictions-table-body');
                    tbody.innerHTML = '';
                    data.recent_predictions.slice().reverse().forEach(p => {
                        const tr = document.createElement('tr');
                        const time = new Date(p.timestamp).toLocaleTimeString();
                        const statusClass = p.interpretation === 'Attack' ? 'attack' : 'normal';
                        const statusIcon = p.interpretation === 'Attack' ? '🚨' : '✓';
                        tr.innerHTML = `
                            <td>${time}</td>
                            <td class="${statusClass}">${statusIcon} ${p.interpretation}</td>
                            <td>${(p.confidence * 100).toFixed(1)}%</td>
                            <td>${p.model_used}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                    
                    // Update chart
                    fetch('/api/predictions')
                        .then(response => response.json())
                        .then(data => {
                            if (data.predictions && data.predictions.length > 0) {
                                const labels = data.predictions.map((p, i) => i + 1);
                                const confidences = data.predictions.map(p => p.confidence);
                                
                                confidenceChart.data.labels = labels;
                                confidenceChart.data.datasets[0].data = confidences;
                                
                                // Color points based on prediction
                                confidenceChart.data.datasets[0].pointBackgroundColor = 
                                    confidences.map((c, i) => 
                                        data.predictions[i].prediction === 1 ? '#f44336' : '#4caf50'
                                    );
                                
                                confidenceChart.update('active');
                            }
                        });
                });
        }
        
        // Update dashboard every second
        setInterval(updateDashboard, 1000);
        
        // Initial update
        updateDashboard();
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    print("=" * 60)
    print("Cyber Attack Detection Dashboard")
    print("=" * 60)
    print("Starting server...")
    print("Open your browser and go to: http://localhost:5050")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5050)

