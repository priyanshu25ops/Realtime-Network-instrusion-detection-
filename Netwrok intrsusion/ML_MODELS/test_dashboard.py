from flask import Flask

app = Flask(__name__)

@app.route('/')
def test():
    return '''
    <html>
    <head><title>Test Dashboard</title></head>
    <body style="font-family: Arial; padding: 50px; text-align: center;">
        <h1 style="color: green;">✅ CONNECTION SUCCESSFUL!</h1>
        <h2>Flask server is working properly</h2>
        <p>Port: 6000</p>
        <p>If you can see this, the server is accessible</p>
        <div style="margin: 20px; padding: 20px; background: #f0f0f0; border-radius: 10px;">
            <h3>Network Information:</h3>
            <p><strong>Local:</strong> http://localhost:6000</p>
            <p><strong>LAN:</strong> http://127.0.0.1:6000</p>
        </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print("="*60)
    print("🧪 TEST DASHBOARD")
    print("="*60)
    print("Testing network connectivity...")
    print("Open your browser and go to:")
    print("  → http://localhost:6000")
    print("  → http://127.0.0.1:6000")
    print("="*60)
    try:
        app.run(debug=True, host='0.0.0.0', port=6000)
    except Exception as e:
        print(f"❌ Server failed to start: {e}")