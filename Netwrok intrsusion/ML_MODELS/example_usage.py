"""
Example Usage of Cyber Attack Detection Prediction API

This file demonstrates various ways to use the trained models.
"""

from prediction_api import predict_single_row, predict_batch, get_feature_names, get_model_info
import pandas as pd
import numpy as np

def example_1_basic_prediction():
    """Example 1: Basic single row prediction"""
    print("="*60)
    print("Example 1: Basic Prediction")
    print("="*60)
    
    # Get feature names
    features = get_feature_names()
    
    # Create a sample row with zeros (normal default values)
    # In practice, you'd have real data
    sample_data = {feature: 0.0 for feature in features}
    
    # Make prediction using ensemble
    result = predict_single_row(sample_data, model_name='ensemble')
    
    print(f"Prediction: {result['interpretation']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Model Used: {result['model_used']}")


def example_2_load_from_csv():
    """Example 2: Load data from CSV and predict"""
    print("\n" + "="*60)
    print("Example 2: Predict from CSV File")
    print("="*60)
    
    # Load your CSV
    df = pd.read_csv("C:\\Users\\priya\\Desktop\\DATA\\processed_train.csv")
    
    # Take first 3 rows for demo
    for idx in range(3):
        row_data = df.iloc[idx].drop('target').to_dict()
        actual = df.iloc[idx]['target']
        
        # Predict
        result = predict_single_row(row_data, model_name='ensemble')
        
        print(f"\nRow {idx + 1}:")
        print(f"  Actual: {'Attack' if actual == 1 else 'Normal'}")
        print(f"  Predicted: {result['interpretation']}")
        print(f"  Confidence: {result['confidence']:.4f}")


def example_3_batch_predictions():
    """Example 3: Predict multiple rows at once"""
    print("\n" + "="*60)
    print("Example 3: Batch Predictions")
    print("="*60)
    
    # Load data
    df = pd.read_csv("C:\\Users\\priya\\Desktop\\DATA\\processed_train.csv")
    
    # Get first 10 rows
    rows_to_predict = []
    for idx in range(10):
        row_dict = df.iloc[idx].drop('target').to_dict()
        rows_to_predict.append(row_dict)
    
    # Predict all at once
    results = predict_batch(rows_to_predict, model_name='ensemble')
    
    # Display results
    print(f"Predicted {len(results)} rows:")
    for i, result in enumerate(results):
        print(f"  Row {i+1}: {result['interpretation']} ({result['confidence']:.3f})")


def example_4_different_models():
    """Example 4: Compare different models"""
    print("\n" + "="*60)
    print("Example 4: Compare Different Models")
    print("="*60)
    
    # Load one row
    df = pd.read_csv("C:\\Users\\priya\\Desktop\\DATA\\processed_train.csv")
    row_data = df.iloc[0].drop('target').to_dict()
    
    models = ['random_forest', 'decision_tree', 'xgboost', 'lightgbm', 'ensemble']
    
    print("\nModel Comparison:")
    for model_name in models:
        result = predict_single_row(row_data, model_name=model_name)
        if 'error' not in result:
            print(f"\n{model_name.upper().replace('_', ' ')}:")
            print(f"  Prediction: {result['interpretation']}")
            print(f"  Confidence: {result['confidence']:.4f}")


def example_5_real_world_usage():
    """Example 5: Real-world usage pattern"""
    print("\n" + "="*60)
    print("Example 5: Real-World Usage Pattern")
    print("="*60)
    
    def check_network_traffic(feature_dict):
        """
        Function to check if network traffic is suspicious
        
        Args:
            feature_dict: Dictionary of network traffic features
            
        Returns:
            tuple: (is_attack, confidence, recommendation)
        """
        result = predict_single_row(feature_dict, model_name='ensemble')
        
        is_attack = result['prediction'] == 1
        confidence = result['confidence']
        
        if is_attack:
            recommendation = f"⚠️  Potential attack detected! (Confidence: {confidence*100:.1f}%)"
        else:
            recommendation = f"✓ Normal traffic (Confidence: {confidence*100:.1f}%)"
        
        return is_attack, confidence, recommendation
    
    # Simulate checking traffic
    features = get_feature_names()
    sample_traffic = {feature: np.random.randn() for feature in features}
    
    is_attack, confidence, recommendation = check_network_traffic(sample_traffic)
    
    print(f"\nTraffic Analysis:")
    print(f"  Status: {recommendation}")
    print(f"  Is Attack: {is_attack}")
    print(f"  Confidence: {confidence:.4f}")


def example_6_get_model_info():
    """Example 6: Get information about available models"""
    print("\n" + "="*60)
    print("Example 6: Model Information")
    print("="*60)
    
    info = get_model_info()
    
    if 'error' not in info:
        print("\nAvailable Models:")
        for model in info['available_models']:
            print(f"  - {model}")
        
        print(f"\nTotal Features: {info['feature_count']}")
        print(f"\nFirst 10 Features:")
        for i, feature in enumerate(info['features'][:10]):
            print(f"  {i+1}. {feature}")


def main():
    """Run all examples"""
    print("\n" + "="*60)
    print("Cyber Attack Detection - API Examples")
    print("="*60)
    
    # Check if models are loaded
    info = get_model_info()
    if 'error' in info:
        print("\n❌ ERROR: Models not loaded!")
        print("Please run train_models.py first to train the models.")
        return
    
    print("\n✓ Models loaded successfully!\n")
    
    # Run all examples
    example_1_basic_prediction()
    example_2_load_from_csv()
    example_3_batch_predictions()
    example_4_different_models()
    example_5_real_world_usage()
    example_6_get_model_info()
    
    print("\n" + "="*60)
    print("All examples completed!")
    print("="*60)


if __name__ == '__main__':
    main()

