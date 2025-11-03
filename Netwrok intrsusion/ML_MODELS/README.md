# Cyber Attack Detection - ML Models

This folder contains the machine learning models for cyber attack detection and a prediction API.

## Structure

```
ML_MODELS/
├── train_models.py          # Script to train ML models
├── prediction_api.py         # API for making predictions
├── demo_prediction.py        # Demo script showing how to use the API
├── requirements.txt          # Python dependencies
├── README.md                 # This file
└── trained_models/          # (Created after training)
    ├── random_forest_model.pkl
    ├── decision_tree_model.pkl
    ├── xgboost_model.pkl
    ├── lightgbm_model.pkl
    ├── feature_names.pkl
    ├── feature_importance.csv
    └── model_comparison.csv
```

## Setup

### 0. Install Python (if not already installed)

**IMPORTANT**: Python is required before proceeding!

**Quick Install Options:**
1. **Microsoft Store** (Easiest): Open Microsoft Store → Search "Python 3.11" → Install
2. **python.org** (Recommended): Go to https://www.python.org/downloads/ → Download → **Check "Add Python to PATH"**
3. **Anaconda**: Go to https://www.anaconda.com/download → Download and install

**After installing Python, CLOSE and REOPEN your terminal/command prompt!**

Verify installation:
```bash
python --version
```

For detailed instructions, see `INSTALL_PYTHON.md`

### 1. Install Dependencies

```bash
cd C:\Users\priya\Desktop\DATA\ML_MODELS
pip install -r requirements.txt
```

Or run:
```bash
SETUP_AND_RUN.bat
```

Required packages:
- numpy
- pandas
- scikit-learn
- matplotlib
- seaborn
- xgboost
- lightgbm
- scipy
- joblib

### 2. Train the Models

```bash
python train_models.py
```

This will:
- Load the `processed_train.csv` file
- Train 4 different models:
  - Decision Tree (with GridSearch optimization)
  - Random Forest
  - XGBoost
  - LightGBM
- Save all models in the `trained_models/` directory
- Generate feature importance rankings
- Compare model performance

**Training Time**: This may take several minutes depending on your computer.

## Usage

### Making Predictions

#### Basic Usage

```python
from prediction_api import predict_single_row

# Prepare your data as a dictionary
row_data = {
    'tcp': 0.0,
    'udp': 0.0,
    # ... all 49 features
}

# Make a prediction
result = predict_single_row(row_data, model_name='ensemble')

print(f"Prediction: {result['interpretation']}")  # 'Normal' or 'Attack'
print(f"Confidence: {result['confidence']:.4f}")    # 0.0 to 1.0
print(f"Model: {result['model_used']}")
```

#### Available Models

- `'random_forest'` - Random Forest (default, best overall)
- `'decision_tree'` - Decision Tree
- `'xgboost'` - XGBoost Classifier
- `'lightgbm'` - LightGBM Classifier
- `'ensemble'` - Voting ensemble of all models (recommended)

#### Example with Sample Data

```python
from prediction_api import predict_single_row
import pandas as pd

# Load sample data
df = pd.read_csv('processed_train.csv')
sample = df.iloc[0].drop('target').to_dict()

# Predict
result = predict_single_row(sample)
print(result)
```

### Running the Demo

```bash
python demo_prediction.py
```

This will demonstrate how to use the prediction API with sample data.

## API Reference

### `predict_single_row(row_data, model_name='random_forest')`

Predict if a single row represents a cyber attack.

**Parameters:**
- `row_data` (dict or list): Feature values for one data point
- `model_name` (str): Model to use for prediction

**Returns:**
```python
{
    'prediction': int,        # 0 (normal) or 1 (attack)
    'confidence': float,      # Probability of attack (0-1)
    'interpretation': str,    # 'Normal' or 'Attack'
    'model_used': str         # Name of model used
}
```

### `predict_batch(rows_data, model_name='random_forest')`

Predict for multiple rows at once.

**Parameters:**
- `rows_data` (list): List of rows to predict
- `model_name` (str): Model to use

**Returns:**
- List of prediction dictionaries

### `get_feature_names()`

Get the list of required feature names.

### `get_model_info()`

Get information about available models.

## Model Comparison

After training, check `trained_models/model_comparison.csv` for performance metrics.

## Feature Importance

Check `trained_models/feature_importance.csv` to see which features are most important for attack detection.

## Troubleshooting

### "Models not loaded" Error

Run the training script first:
```bash
python train_models.py
```

### "Module not found" Error

Install dependencies:
```bash
pip install -r requirements.txt
```

### Out of Memory

If training fails due to memory issues, you can modify `train_models.py` to use fewer estimators or reduce the dataset size.

## Notes

- All models are trained on binary classification (Attack vs Normal)
- The target column is 'target' (0 = Normal, 1 = Attack)
- Feature importance is calculated using Random Forest
- Ensemble predictions use majority voting
- Confidence scores represent the probability of being an attack

## Performance

Models are evaluated on:
- **Accuracy**: Overall correctness
- **Precision**: When predicting attack, how often is it correct?
- **Recall**: How many actual attacks are detected?

The best model is selected based on Recall score (maximizing attack detection).

