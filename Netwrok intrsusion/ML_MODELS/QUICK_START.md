# Quick Start Guide

## 🚀 How to Train Models and Make Predictions

### Step 1: Install Dependencies

Open terminal/command prompt in the `ML_MODELS` folder and run:

```bash
pip install -r requirements.txt
```

Or use the batch file:
```bash
run_training.bat
```

### Step 2: Train the Models

Run the training script:

```bash
python train_models.py
```

Or double-click:
```bash
run_training.bat
```

**What this does:**
- Loads `C:\Users\priya\Desktop\DATA\processed_train.csv`
- Trains 4 ML models (Decision Tree, Random Forest, XGBoost, LightGBM)
- Saves all models to `trained_models/` folder
- Takes 5-10 minutes depending on your computer

### Step 3: Make Predictions

Now you can use the prediction API in two ways:

#### Option A: Use the Demo Script
```bash
python demo_prediction.py
```

#### Option B: Use in Your Own Code

```python
from prediction_api import predict_single_row
import pandas as pd

# Load a row from your data
df = pd.read_csv('processed_train.csv')
row = df.iloc[0].drop('target').to_dict()

# Make prediction
result = predict_single_row(row, model_name='ensemble')

print(f"Result: {result['interpretation']}")  # 'Normal' or 'Attack'
print(f"Confidence: {result['confidence']:.4f}")  # 0 to 1
```

### Step 4: Using the Model in Production

#### Single Row Prediction

```python
from prediction_api import predict_single_row

# Your data as dictionary
data = {
    'tcp': 0.0,
    'udp': 0.0,
    'dur': 0.0,
    # ... (all 49 features)
}

# Predict
result = predict_single_row(data, model_name='ensemble')

if result['prediction'] == 1:
    print(f"⚠️ ALERT: Potential Attack Detected!")
    print(f"Confidence: {result['confidence']*100:.2f}%")
else:
    print("✓ Normal traffic")
```

#### Multiple Rows

```python
from prediction_api import predict_batch

# List of dictionaries
rows = [
    {'tcp': 1.0, 'udp': 0.0, ...},
    {'tcp': 0.0, 'udp': 1.0, ...},
]

results = predict_batch(rows, model_name='ensemble')

for i, result in enumerate(results):
    print(f"Row {i}: {result['interpretation']} ({result['confidence']:.2f})")
```

### Available Models

1. **`ensemble`** (RECOMMENDED) - Combines all models for best accuracy
2. **`random_forest`** - Strong overall performer
3. **`xgboost`** - Fast and accurate
4. **`lightgbm`** - Very fast training
5. **`decision_tree`** - Simple and interpretable

### Understanding Results

```python
result = {
    'prediction': 0 or 1,           # 0=Normal, 1=Attack
    'confidence': 0.0 to 1.0,       # Probability of attack
    'interpretation': 'Normal' or 'Attack',
    'model_used': 'ensemble'
}
```

### Example Output

```
Result: Attack
Confidence: 0.8542
Model: ensemble
```

This means the model predicts this is an attack with 85.42% confidence.

## 📊 Model Performance

After training, check these files:
- `trained_models/model_comparison.csv` - Performance metrics
- `trained_models/feature_importance.csv` - Most important features

## 🔧 Troubleshooting

### Python not found
Install Python: https://www.python.org/downloads/

### Module not found
```bash
pip install -r requirements.txt
```

### Out of memory
Edit `train_models.py` and reduce `n_estimators` in Random Forest:
```python
rf = RandomForestClassifier(n_estimators=50, random_state=11)  # Changed from 100
```

### Training takes too long
Use fewer features or smaller dataset in `train_models.py`

## 📝 Notes

- Models work with **49 features** from `processed_train.csv`
- **Target**: 0 = Normal, 1 = Attack
- Best model is chosen based on **Recall** (attack detection rate)
- **Ensemble model** uses majority voting for best results

## 🎯 Next Steps

1. ✅ Train models: `python train_models.py`
2. ✅ Test with demo: `python demo_prediction.py`
3. ✅ Integrate in your application using `prediction_api.py`

---

**Need Help?** Check `README.md` for detailed documentation.

