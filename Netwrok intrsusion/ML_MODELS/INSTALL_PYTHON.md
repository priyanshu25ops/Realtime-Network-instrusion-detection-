# Install Python and Run Training

## Python Installation Required

Python is not currently installed on your system. Follow these steps:

### Option 1: Install from Microsoft Store (Easiest)

1. Click Start and search for "Microsoft Store"
2. Search for "Python 3.11" or "Python 3.12"
3. Click "Install"

### Option 2: Install from python.org (Recommended)

1. Go to https://www.python.org/downloads/
2. Download Python 3.11 or 3.12
3. **IMPORTANT**: During installation, check "Add Python to PATH"
4. Click "Install Now"

### Option 3: Use Anaconda (For Data Science)

1. Go to https://www.anaconda.com/download
2. Download and install Anaconda
3. Python will be included

## After Installation

### 1. Verify Installation

Open a NEW terminal/command prompt and run:

```bash
python --version
```

You should see something like: `Python 3.11.x`

### 2. Navigate to ML_MODELS

```bash
cd C:\Users\priya\Desktop\DATA\ML_MODELS
```

### 3. Install Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run Training

```bash
python train_models.py
```

Or simply:

```bash
run_training.bat
```

## What Will Happen

The training will:
1. Load `processed_train.csv` (175,341 rows)
2. Train 4 ML models (will take 5-10 minutes)
3. Save models to `trained_models/` folder
4. Show performance metrics
5. Generate feature importance rankings

## Expected Output

```
Loading data...
Data shape: (175341, 50)
X_train shape: (122738, 49)
X_test shape: (52603, 49)

Training Decision Tree Model...
Best parameters: {...}
Decision Tree Recall: 0.95

Training Random Forest Model...
Random Forest Recall: 0.98

Training XGBoost Model...
XGBoost Recall: 0.99

Training LightGBM Model...
LightGBM Recall: 0.99

All models trained and saved successfully!
```

## After Training

Once training completes:

### Test the Models

```bash
python demo_prediction.py
```

### Use in Your Code

```python
from prediction_api import predict_single_row

# Your data
row = {
    'feature1': value1,
    'feature2': value2,
    # ... all 49 features
}

# Predict
result = predict_single_row(row, model_name='ensemble')
print(f"Prediction: {result['interpretation']}")
print(f"Confidence: {result['confidence']:.4f}")
```

## Troubleshooting

### "pip is not recognized"
After installing Python, restart your terminal or run:
```bash
python -m ensurepip --upgrade
```

### "ModuleNotFoundError"
Install dependencies:
```bash
pip install -r requirements.txt
```

### Out of Memory
The dataset is large (175K rows). If training fails:
1. Reduce number of rows in CSV (keep every Nth row)
2. Or reduce `n_estimators` in `train_models.py`

### Training Takes Too Long
Reduce `n_estimators` in train_models.py:
```python
rf = RandomForestClassifier(n_estimators=50)  # Instead of 100
```

## Quick Start (After Python Installed)

```bash
cd C:\Users\priya\Desktop\DATA\ML_MODELS
pip install -r requirements.txt
python train_models.py
```

That's it! 🚀

