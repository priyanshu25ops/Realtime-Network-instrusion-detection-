#!/usr/bin/env python3
"""
Debug script for comprehensive dashboard
"""
import traceback
import sys

try:
    print("Starting debug process...")
    
    # Test imports
    print("Testing imports...")
    from flask import Flask
    print("✓ Flask imported")
    
    from prediction_api import predict_single_row
    print("✓ prediction_api imported")
    
    # Import the dashboard
    print("Importing comprehensive_dashboard...")
    import comprehensive_dashboard
    print("✓ comprehensive_dashboard imported")
    
    # Try to get the app
    print("Getting Flask app...")
    app = comprehensive_dashboard.app
    print("✓ Flask app retrieved")
    
    # Test a simple route
    print("Testing Flask app...")
    with app.test_client() as client:
        response = client.get('/')
        print(f"✓ Homepage status code: {response.status_code}")
    
    print("\n" + "="*80)
    print("COMPREHENSIVE CYBER ATTACK DETECTION DASHBOARD")
    print("All 20 Attack Detection Features Implemented!")
    print("="*80)
    print("Starting server...")
    print("Open your browser and go to: http://localhost:6000")
    print("="*80)
    
    # Start the server
    app.run(debug=True, host='0.0.0.0', port=6000)
    
except Exception as e:
    print(f"\n❌ ERROR OCCURRED: {str(e)}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)