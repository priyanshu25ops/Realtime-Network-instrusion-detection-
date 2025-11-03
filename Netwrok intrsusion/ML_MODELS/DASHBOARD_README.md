# 🛡️ Cyber Attack Detection - Live Dashboard

A real-time web-based dashboard for cyber attack detection with live analytics, graphs, and visualizations.

## 🚀 Quick Start

### Option 1: Double-click the batch file
```
run_dashboard.bat
```

### Option 2: Manual start
```bash
cd C:\Users\priya\Desktop\DATA\ML_MODELS
python dashboard_server.py
```

Then open your browser and go to: **http://localhost:5000**

## ✨ Features

### 📊 Real-Time Dashboard

#### Live Metrics
- **Total Predictions** - Running count of all predictions
- **Attack Rate** - Percentage of attacks detected
- **Attacks Detected** - Total number of attacks found
- **Normal Traffic** - Count of legitimate traffic
- **Average Confidence** - Overall prediction confidence

#### Interactive Controls
- **Model Selection** - Choose from 5 different models
- **Make Prediction** - Single prediction button
- **Auto Mode** - Continuous predictions every 2 seconds
- **Clear History** - Reset all stats and logs

#### Live Logs (Scrollable)
- Real-time log updates
- Color-coded log levels
- Auto-scrolling interface
- Shows timestamps for each event

#### Recent Predictions Table
- Last 10 predictions displayed
- Shows time, status, confidence, and model
- Color-coded (red for attacks, green for normal)

#### Charts & Analytics
- **Confidence Over Time** - Line chart showing prediction confidence trends
- **Real-time Updates** - Charts update automatically
- **Point Coloring** - Red points for attacks, green for normal traffic

## 🎨 Design Features

- **Modern UI** - Beautiful gradient background (purple-blue)
- **Animated Cards** - Smooth hover effects and transitions
- **Responsive Design** - Works on all screen sizes
- **Color-Coded Alerts** - Visual distinction between attacks and normal traffic
- **Smooth Animations** - Fade-in and slide-in effects
- **Dark Log Theme** - Terminal-style logs with syntax highlighting

## 📈 How It Works

1. **Click "Make Prediction"** or enable **Auto Mode**
2. The system loads a random sample from the training data
3. Runs it through the selected ML model
4. Displays the result with confidence score
5. Updates all metrics, logs, and charts in real-time

## 🎯 Using the Dashboard

### Single Predictions
1. Select a model from the dropdown (Random Forest, Decision Tree, XGBoost, LightGBM, or Ensemble)
2. Click "🔍 Make Prediction"
3. View the result in logs, metrics, and charts

### Auto Mode
1. Click "▶️ Enable Auto Mode"
2. Dashboard will make predictions every 2 seconds
3. Watch the metrics update in real-time
4. Charts will show trends as data comes in

### Model Selection

| Model | Best For |
|-------|----------|
| **Random Forest** | General use, balanced performance |
| **Decision Tree** | Highest attack detection (100% recall) |
| **XGBoost** | Speed and accuracy |
| **LightGBM** | Fast predictions |
| **Ensemble** | Best overall accuracy (combines all models) |

## 📊 Understanding the Charts

### Confidence Line Chart
- **X-axis**: Prediction number
- **Y-axis**: Confidence level (0-100%)
- **Red dots**: Attack detected
- **Green dots**: Normal traffic
- **Line**: Shows trend over time

### Metrics Interpretation
- **High Attack Rate**: Many attacks detected (red flag!)
- **High Confidence**: Model is certain of predictions
- **Low Attack Rate**: Mostly normal traffic (good!)
- **Low Confidence**: Model uncertain (needs more data)

## 🎬 What You'll See

### When Auto Mode is Enabled:

```
[00:12:34] ✓ Normal traffic detected. Confidence: 23.4%
[00:12:36] 🚨 ATTACK DETECTED! Confidence: 87.6%
[00:12:38] ✓ Normal traffic detected. Confidence: 15.2%
[00:12:40] 🚨 ATTACK DETECTED! Confidence: 92.1%
```

### Dashboard Updates:
- ✅ Metrics cards animate with new values
- ✅ Log entries scroll up automatically
- ✅ Chart line extends with new data points
- ✅ Recent predictions table updates
- ✅ Attack rate percentage recalculates

## 🔧 Technical Details

### Technologies Used
- **Backend**: Flask (Python web framework)
- **Frontend**: HTML5, CSS3, JavaScript
- **Charts**: Chart.js (Beautiful, interactive charts)
- **ML Models**: Trained models from `trained_models/` folder

### API Endpoints

- `POST /api/predict` - Make a prediction
- `GET /api/stats` - Get current statistics
- `GET /api/predictions` - Get prediction history
- `POST /api/clear` - Clear history

### Data Source
- Uses `processed_train.csv` for sample predictions
- Loads random samples each time
- Maintains last 200 predictions in memory

## 🎮 Demo Mode

The dashboard includes a demo mode that:
- Generates realistic sample data
- Simulates various attack patterns
- Shows both normal and malicious traffic
- Demonstrates all visualization features

## 📝 Tips

1. **Start with Ensemble** - Best accuracy for serious analysis
2. **Enable Auto Mode** - See trends develop over time
3. **Watch the Charts** - Patterns emerge with more predictions
4. **Clear History** - Reset when you want a fresh start
5. **Monitor Attack Rate** - High rates may indicate threats

## 🚨 Troubleshooting

### Dashboard won't load?
- Make sure port 5000 is available
- Check that Flask is installed: `pip install flask flask-cors`
- Verify models are trained: `python train_models.py`

### No predictions showing?
- Models may not be trained yet
- Check `trained_models/` folder exists
- Run training first if needed

### Charts not updating?
- Refresh the browser
- Check browser console for errors
- Clear browser cache

## 🎉 Features Highlights

✅ **Real-time Updates** - No refresh needed  
✅ **Scrollable Logs** - Auto-scrolling log panel  
✅ **Live Charts** - Dynamic Chart.js visualizations  
✅ **Multiple Models** - Switch between 5 ML models  
✅ **Auto Mode** - Continuous prediction stream  
✅ **Beautiful UI** - Modern gradient design  
✅ **Responsive** - Works on all devices  
✅ **Animated** - Smooth transitions and effects  

## 🎬 Screenshots

When running, you'll see:
- Purple gradient background
- 5 metric cards at the top
- Live scrollable logs (dark theme)
- Recent predictions table
- Interactive line chart
- Control buttons with smooth animations

---

**Enjoy your live cyber attack detection dashboard! 🛡️**

Open **http://localhost:5000** to get started!

