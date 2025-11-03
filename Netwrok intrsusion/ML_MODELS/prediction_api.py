"""
Cyber Attack Detection Prediction API

This module provides functions to predict if a network connection is an attack
based on trained ML models.
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Load models and feature names
MODEL_DIR = Path(__file__).parent / "trained_models"

def load_models():
    """Load all trained models"""
    try:
        models = {
            'random_forest': joblib.load(MODEL_DIR / 'random_forest_model.pkl'),
            'decision_tree': joblib.load(MODEL_DIR / 'decision_tree_model.pkl'),
            'xgboost': joblib.load(MODEL_DIR / 'xgboost_model.pkl'),
            'lightgbm': joblib.load(MODEL_DIR / 'lightgbm_model.pkl')
        }
        feature_names = joblib.load(MODEL_DIR / 'feature_names.pkl')
        return models, feature_names
    except FileNotFoundError as e:
        print(f"Error loading models: {e}")
        print("Please run train_models.py first to train and save the models.")
        return None, None

# Load models at module level
MODELS, FEATURE_NAMES = load_models()

def predict_single_row(row_data, model_name='random_forest'):
    """
    Predict if a single row represents a cyber attack
    
    Parameters:
    -----------
    row_data : dict or list
        - If dict: Keys should be feature names (strings)
        - If list: Values in the same order as training features
    model_name : str
        Model to use for prediction. Options:
        - 'random_forest' (default)
        - 'decision_tree'
        - 'xgboost'
        - 'lightgbm'
        - 'ensemble' (voting from all models)
    
    Returns:
    --------
    dict : Prediction results containing:
        - 'prediction': 0 (normal) or 1 (attack)
        - 'confidence': Probability of being an attack (0-1)
        - 'interpretation': 'Normal' or 'Attack'
    """
    if MODELS is None:
        return {
            'error': 'Models not loaded. Please train models first.',
            'prediction': None,
            'confidence': None,
            'interpretation': None
        }
    
    if model_name not in MODELS and model_name != 'ensemble':
        return {
            'error': f'Invalid model name. Available: {list(MODELS.keys())}',
            'prediction': None,
            'confidence': None,
            'interpretation': None
        }
    
    # Prepare input data
    if isinstance(row_data, dict):
        # Create pandas Series from dict
        data = pd.DataFrame([row_data])
        # Ensure all features are present
        for feature in FEATURE_NAMES:
            if feature not in data.columns:
                data[feature] = 0
        data = data[FEATURE_NAMES].values
    elif isinstance(row_data, list):
        data = np.array(row_data).reshape(1, -1)
    else:
        return {
            'error': 'Invalid input format. Provide dict or list.',
            'prediction': None,
            'confidence': None,
            'interpretation': None
        }
    
    # Make prediction
    if model_name == 'ensemble':
        # Ensemble prediction (voting)
        predictions = []
        probabilities = []
        
        for name, model in MODELS.items():
            pred = model.predict(data)[0]
            prob = model.predict_proba(data)[0][1]  # Probability of class 1 (attack)
            predictions.append(pred)
            probabilities.append(prob)
        
        # Majority voting for classification
        prediction = int(np.mean(predictions) > 0.5)
        # Average probability
        confidence = np.mean(probabilities)
    else:
        model = MODELS[model_name]
        prediction = model.predict(data)[0]
        
        # Get probability of attack (class 1)
        if hasattr(model, 'predict_proba'):
            confidence = model.predict_proba(data)[0][1]
        else:
            confidence = float(prediction)
    
    return {
        'prediction': int(prediction),
        'confidence': float(confidence),
        'interpretation': 'Attack' if prediction == 1 else 'Normal',
        'model_used': model_name
    }


def predict_batch(rows_data, model_name='random_forest'):
    """
    Predict for multiple rows at once
    
    Parameters:
    -----------
    rows_data : list of dicts or 2D list/array
        Multiple rows of data
    model_name : str
        Model to use (same options as predict_single_row)
    
    Returns:
    --------
    list of dicts : Predictions for each row
    """
    results = []
    
    for i, row in enumerate(rows_data):
        result = predict_single_row(row, model_name)
        result['row_index'] = i
        results.append(result)
    
    return results


def get_feature_names():
    """Get the list of required feature names"""
    return FEATURE_NAMES if FEATURE_NAMES else []


def get_model_info():
    """Get information about available models"""
    if MODELS is None:
        return {'error': 'No models loaded'}
    
    return {
        'available_models': list(MODELS.keys()),
        'feature_count': len(FEATURE_NAMES) if FEATURE_NAMES else 0,
        'features': FEATURE_NAMES if FEATURE_NAMES else []
    }


# Example usage
if __name__ == '__main__':
    print("="*60)
    print("Cyber Attack Detection Prediction API")
    print("="*60)
    
    # Check if models are loaded
    if MODELS is None:
        print("\nModels not found. Please run train_models.py first.")
    else:
        print("\n✓ Models loaded successfully!")
        print(f"Available models: {list(MODELS.keys())}")
        print(f"Features required: {len(FEATURE_NAMES)}")
        
        # Example prediction
        print("\n" + "="*60)
        print("Example: Predicting a sample row")
        print("="*60)
        
        # Create a sample row with zeros (you would replace this with real data)
        sample_row = {feature: 0.0 for feature in FEATURE_NAMES}
        
        # Make prediction
        result = predict_single_row(sample_row, model_name='random_forest')
        
        print(f"\nPrediction: {result['prediction']}")
        print(f"Interpretation: {result['interpretation']}")
        print(f"Confidence: {result['confidence']:.4f}")
        print(f"Model used: {result['model_used']}")
        
        # Try ensemble
        result_ensemble = predict_single_row(sample_row, model_name='ensemble')
        print(f"\nEnsemble Prediction: {result_ensemble['interpretation']}")
        print(f"Ensemble Confidence: {result_ensemble['confidence']:.4f}")

