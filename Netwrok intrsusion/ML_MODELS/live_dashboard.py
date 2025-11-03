"""
Live Cyber Attack Detection Dashboard
Real-time predictions with analytics and visualizations
"""

import streamlit as st
import pandas as pd
import numpy as np
import time
import random
from datetime import datetime
from prediction_api import predict_single_row, get_model_info
import plotly.express as px
import plotly.graph_objects as go
from collections import deque
import json

# Page config
st.set_page_config(
    page_title="Cyber Attack Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #667eea;
    }
    .attack-alert {
        background-color: #ffebee;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #f44336;
        animation: pulse 2s infinite;
    }
    .normal-alert {
        background-color: #e8f5e9;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #4caf50;
    }
    .log-container {
        max-height: 400px;
        overflow-y: auto;
        background-color: #1e1e1e;
        padding: 1rem;
        border-radius: 0.5rem;
        font-family: 'Courier New', monospace;
        font-size: 0.85rem;
    }
    .log-entry {
        padding: 0.25rem 0;
        border-bottom: 1px solid #333;
    }
    .log-time { color: #888; }
    .log-info { color: #4fc3f7; }
    .log-success { color: #66bb6a; }
    .log-warning { color: #ffb74d; }
    .log-error { color: #e57373; }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'predictions_history' not in st.session_state:
    st.session_state.predictions_history = deque(maxlen=100)
if 'logs' not in st.session_state:
    st.session_state.logs = deque(maxlen=50)
if 'stats' not in st.session_state:
    st.session_state.stats = {
        'total_predictions': 0,
        'attacks_detected': 0,
        'normal_traffic': 0,
        'avg_confidence': 0,
        'model_usage': {'random_forest': 0, 'decision_tree': 0, 'xgboost': 0, 'lightgbm': 0, 'ensemble': 0}
    }

def add_log(message, level='info'):
    """Add a log entry"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    log_entry = {
        'time': timestamp,
        'message': message,
        'level': level
    }
    st.session_state.logs.append(log_entry)

def load_sample_data():
    """Load sample data for demo"""
    try:
        df = pd.read_csv("C:\\Users\\priya\\Desktop\\DATA\\processed_train.csv")
        return df.sample(n=1).drop('target', axis=1).iloc[0].to_dict()
    except:
        # Return random data if file not found
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

def make_prediction(data, model_name):
    """Make prediction and update stats"""
    try:
        result = predict_single_row(data, model_name=model_name)
        
        if 'error' not in result:
            prediction = {
                'timestamp': datetime.now(),
                'prediction': result['prediction'],
                'confidence': result['confidence'],
                'interpretation': result['interpretation'],
                'model_used': result.get('model_used', model_name)
            }
            
            # Update stats
            st.session_state.stats['total_predictions'] += 1
            if result['prediction'] == 1:
                st.session_state.stats['attacks_detected'] += 1
                add_log(f"🚨 ATTACK DETECTED! Confidence: {result['confidence']:.2%}", 'error')
            else:
                st.session_state.stats['normal_traffic'] += 1
                add_log(f"✓ Normal traffic detected. Confidence: {result['confidence']:.2%}", 'success')
            
            st.session_state.stats['model_usage'][model_name] += 1
            st.session_state.predictions_history.append(prediction)
            
            return result
    except Exception as e:
        add_log(f"Error in prediction: {str(e)}", 'error')
        return None

# Header
st.markdown('<h1 class="main-header">🛡️ Cyber Attack Detection Dashboard</h1>', unsafe_allow_html=True)

# Sidebar
st.sidebar.header("⚙️ Configuration")
model_choice = st.sidebar.selectbox(
    "Select Model",
    ['random_forest', 'decision_tree', 'xgboost', 'lightgbm', 'ensemble'],
    index=0
)

auto_mode = st.sidebar.checkbox("Auto Mode (Continuous Predictions)", value=False)
auto_interval = st.sidebar.slider("Update Interval (seconds)", 1, 10, 3)

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 Model Info")
model_info = get_model_info()
if 'error' not in model_info:
    st.sidebar.write(f"Features: {model_info['feature_count']}")
    st.sidebar.write(f"Models: {len(model_info['available_models'])}")

# Main content
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Predictions", st.session_state.stats['total_predictions'])
with col2:
    attack_rate = (st.session_state.stats['attacks_detected'] / 
                  max(st.session_state.stats['total_predictions'], 1) * 100)
    st.metric("Attack Rate", f"{attack_rate:.1f}%", 
               delta=f"{st.session_state.stats['attacks_detected']} detected")
with col3:
    st.metric("Normal Traffic", st.session_state.stats['normal_traffic'])
with col4:
    if st.session_state.predictions_history:
        avg_conf = np.mean([p['confidence'] for p in st.session_state.predictions_history])
        st.metric("Avg Confidence", f"{avg_conf:.2%}")

# Manual prediction button
col1, col2 = st.columns([3, 1])
with col1:
    st.subheader("🚀 Live Prediction System")
with col2:
    if st.button("🔍 Make Prediction", type="primary", use_container_width=True):
        data = load_sample_data()
        result = make_prediction(data, model_choice)
        if result:
            if result['prediction'] == 1:
                st.warning(f"⚠️ ATTACK DETECTED! Confidence: {result['confidence']:.2%}")
            else:
                st.success(f"✓ Normal Traffic. Confidence: {result['confidence']:.2%}")

# Auto mode
if auto_mode:
    with st.spinner("Making predictions..."):
        data = load_sample_data()
        result = make_prediction(data, model_choice)
        if result:
            if result['prediction'] == 1:
                st.warning(f"⚠️ ATTACK DETECTED! Confidence: {result['confidence']:.2%}")
            else:
                st.success(f"✓ Normal Traffic. Confidence: {result['confidence']:.2%}")
    time.sleep(auto_interval)
    st.rerun()

# Two column layout
col1, col2 = st.columns(2)

# Left column - Logs
with col1:
    st.subheader("📋 Live Logs")
    log_html = '<div class="log-container">'
    for log in reversed(list(st.session_state.logs)[-20:]):
        if log['level'] == 'info':
            log_html += f'<div class="log-entry"><span class="log-time">[{log["time"]}]</span> <span class="log-info">{log["message"]}</span></div>'
        elif log['level'] == 'success':
            log_html += f'<div class="log-entry"><span class="log-time">[{log["time"]}]</span> <span class="log-success">{log["message"]}</span></div>'
        elif log['level'] == 'warning':
            log_html += f'<div class="log-entry"><span class="log-time">[{log["time"]}]</span> <span class="log-warning">{log["message"]}</span></div>'
        elif log['level'] == 'error':
            log_html += f'<div class="log-entry"><span class="log-time">[{log["time"]}]</span> <span class="log-error">{log["message"]}</span></div>'
    log_html += '</div>'
    st.markdown(log_html, unsafe_allow_html=True)

# Right column - Recent predictions
with col2:
    st.subheader("📊 Recent Predictions")
    if st.session_state.predictions_history:
        recent_df = pd.DataFrame(list(st.session_state.predictions_history)[-10:])
        st.dataframe(recent_df[['timestamp', 'interpretation', 'confidence', 'model_used']], 
                    hide_index=True, use_container_width=True)
    else:
        st.info("No predictions yet. Click 'Make Prediction' to start!")

# Graphs section
if st.session_state.predictions_history:
    st.markdown("---")
    st.subheader("📈 Analytics & Visualizations")
    
    history_df = pd.DataFrame(list(st.session_state.predictions_history))
    history_df['timestamp'] = pd.to_datetime(history_df['timestamp'])
    
    # Create tabs for different visualizations
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Confidence Over Time", "🎯 Attack vs Normal", "🤖 Model Performance", "📉 Trend Analysis"])
    
    with tab1:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=history_df['timestamp'],
            y=history_df['confidence'],
            mode='lines+markers',
            name='Confidence',
            line=dict(color='#667eea', width=2),
            marker=dict(size=8, color=history_df['prediction'].map({0: 'green', 1: 'red'}))
        ))
        fig.update_layout(
            title="Prediction Confidence Over Time",
            xaxis_title="Time",
            yaxis_title="Confidence",
            height=400,
            hovermode='x unified'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        attack_count = st.session_state.stats['attacks_detected']
        normal_count = st.session_state.stats['normal_traffic']
        
        fig = go.Figure(data=[
            go.Pie(
                labels=['Attack Detected', 'Normal Traffic'],
                values=[attack_count, normal_count],
                hole=0.3,
                marker_colors=['#ef5350', '#66bb6a']
            )
        ])
        fig.update_layout(title="Traffic Classification", height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        model_usage = st.session_state.stats['model_usage']
        fig = go.Figure(data=[
            go.Bar(
                x=list(model_usage.keys()),
                y=list(model_usage.values()),
                marker_color='#764ba2'
            )
        ])
        fig.update_layout(
            title="Model Usage Statistics",
            xaxis_title="Model",
            yaxis_title="Usage Count",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab4:
        # Rolling average
        history_df_sorted = history_df.sort_values('timestamp')
        history_df_sorted['rolling_conf'] = history_df_sorted['confidence'].rolling(
            window=min(10, len(history_df_sorted)), min_periods=1).mean()
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=history_df_sorted['timestamp'],
            y=history_df_sorted['confidence'],
            name='Confidence',
            mode='markers',
            marker=dict(size=6, opacity=0.5)
        ))
        fig.add_trace(go.Scatter(
            x=history_df_sorted['timestamp'],
            y=history_df_sorted['rolling_conf'],
            name='Moving Average',
            mode='lines',
            line=dict(color='red', width=2)
        ))
        fig.update_layout(
            title="Confidence Trend with Moving Average",
            xaxis_title="Time",
            yaxis_title="Confidence",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)

# Initialize logs
if not st.session_state.logs:
    add_log("System initialized", 'info')
    add_log("Models loaded successfully", 'success')
    add_log("Ready to make predictions", 'info')

# Refresh page for auto mode
if st.button("🔄 Clear History"):
    st.session_state.predictions_history = deque(maxlen=100)
    st.session_state.logs = deque(maxlen=50)
    st.session_state.stats = {
        'total_predictions': 0,
        'attacks_detected': 0,
        'normal_traffic': 0,
        'avg_confidence': 0,
        'model_usage': {'random_forest': 0, 'decision_tree': 0, 'xgboost': 0, 'lightgbm': 0, 'ensemble': 0}
    }
    st.rerun()

