"""
Demo: How to use the Cyber Attack Detection Prediction API

This script demonstrates how to use the trained models to make predictions
on new data.
"""

from prediction_api import predict_single_row, get_feature_names, get_model_info
import pandas as pd

def main():
    print("="*70)
    print("Cyber Attack Detection - Prediction Demo")
    print("="*70)
    
    # Get model information
    info = get_model_info()
    if 'error' in info:
        print("\n[ERROR]:", info['error'])
        print("Please run train_models.py first to train and save models.")
        return
    
    print("\n[OK] Model Information:")
    print(f"  Available models: {', '.join(info['available_models'])}")
    print(f"  Number of features: {info['feature_count']}")
    
    # Load a sample from the training data
    print("\n" + "="*70)
    print("Loading a sample row from processed_train.csv for demo...")
    print("="*70)
    
    df = pd.read_csv("C:\\Users\\priya\\Desktop\\DATA\\processed_train.csv")
    
    # Get first row
    sample_row_dict = df.iloc[0].drop('target').to_dict()
    actual_label = df.iloc[0]['target']
    
    print(f"\nActual label: {'Attack' if actual_label == 1 else 'Normal'}")
    
    # Make predictions using different models
    models_to_try = ['random_forest', 'decision_tree', 'xgboost', 'lightgbm', 'ensemble']
    
    print("\n" + "="*70)
    print("Predictions:")
    print("="*70)
    
    for model_name in models_to_try:
        result = predict_single_row(sample_row_dict, model_name=model_name)
        
        if 'error' not in result:
            print(f"\n{model_name.upper().replace('_', ' ')}:")
            print(f"  Prediction: {result['interpretation']}")
            print(f"  Confidence: {result['confidence']:.4f}")
        else:
            print(f"\n{model_name}: {result['error']}")
    
    # Try with custom values
    print("\n" + "="*70)
    print("Example: Predicting with custom values (all zeros)")
    print("="*70)
    
    # Create custom row
    custom_row = {feature: 0.0 for feature in get_feature_names()}
    result = predict_single_row(custom_row, model_name='ensemble')
    
    print(f"\nPrediction: {result['interpretation']}")
    print(f"Confidence: {result['confidence']:.4f}")
    
    print("\n" + "="*70)
    print("Demo completed!")
    print("="*70)
    
    print("\nHow to use in your code:")
    print("""
    from prediction_api import predict_single_row
    
    # Prepare your data as a dictionary
    row_data = {
        'feature1': 0.5,
        'feature2': 1.2,
        # ... all feature values
    }
    
    # Make prediction
    result = predict_single_row(row_data, model_name='ensemble')
    print(f"Prediction: {result['interpretation']}")
    print(f"Confidence: {result['confidence']:.4f}")
    """)

if __name__ == '__main__':
    main()

