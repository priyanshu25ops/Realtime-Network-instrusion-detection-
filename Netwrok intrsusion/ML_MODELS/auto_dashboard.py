#!/usr/bin/env python3
"""
Comprehensive Cyber Attack Detection Dashboard - Auto Launch
Implements ALL 20 attack detection features with real-time monitoring
"""

import webbrowser
import threading
import time
from comprehensive_dashboard import app

def open_browser():
    """Open browser automatically after server starts"""
    time.sleep(2)  # Wait for server to fully start
    print("🌐 Opening browser automatically...")
    webbrowser.open('http://localhost:6000')

if __name__ == '__main__':
    print("=" * 80)
    print("🛡️ COMPREHENSIVE CYBER ATTACK DETECTION DASHBOARD")
    print("All 20 Attack Detection Features Implemented!")
    print("=" * 80)
    print("✅ DoS Attack Detection - Sload, Dload, Spkts, Dpkts patterns")
    print("✅ Fuzzer Detection - trans_depth, response_body_len patterns") 
    print("✅ Port Scan Detection - ct_src_dport_ltm, ct_dst_sport_ltm")
    print("✅ Brute Force Login Detection - is_ftp_login, ct_ftp_cmd")
    print("✅ Reconnaissance Detection - ct_dst_ltm spikes")
    print("✅ Anomalous IP Communication - is_sm_ips_ports")
    print("✅ High Bandwidth Usage Alerts - Sload, Dload monitoring")
    print("✅ Suspicious TCP Behavior - tcprtt, synack, ackdat")
    print("✅ Replay Attack Detection - stcpb, dtcpb repetition")
    print("✅ And 11 more advanced detection features!")
    print("=" * 80)
    print("🚀 Starting server...")
    print("🌐 Browser will open automatically!")
    print("📍 Manual URL: http://localhost:6000")
    print("=" * 80)
    
    # Start browser in background
    threading.Thread(target=open_browser, daemon=True).start()
    
    try:
        app.run(host='0.0.0.0', port=6000, debug=False)
    except Exception as e:
        print(f"❌ Server failed to start: {e}")
        print("Try manually opening: http://localhost:6000")
        input("Press Enter to exit...")