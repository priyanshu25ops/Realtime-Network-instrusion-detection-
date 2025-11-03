from flask import Flask
import webbrowser
import threading
import time

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>✅ Server Working!</title>
        <style>
            body { font-family: Arial; text-align: center; padding: 50px; background: #f0f8ff; }
            h1 { color: #008000; font-size: 3em; }
            .box { background: white; padding: 30px; margin: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        </style>
    </head>
    <body>
        <div class="box">
            <h1>🎉 SUCCESS!</h1>
            <h2>Flask Server is Working!</h2>
            <p><strong>Port:</strong> 8080</p>
            <p><strong>Status:</strong> ✅ Connected</p>
            <p>If you can see this page, the server is accessible!</p>
        </div>
    </body>
    </html>
    '''

def open_browser():
    time.sleep(1.5)
    webbrowser.open('http://localhost:8080')

if __name__ == '__main__':
    print("🚀 Starting Simple Server Test")
    print("Port: 8080")
    print("Opening browser automatically...")
    
    # Start browser in background
    threading.Thread(target=open_browser, daemon=True).start()
    
    try:
        app.run(host='0.0.0.0', port=8080, debug=False)
    except Exception as e:
        print(f"❌ Error: {e}")
        input("Press Enter to exit...")