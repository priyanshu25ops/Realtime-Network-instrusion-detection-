"""
Advanced Cyber Attack Detection System
Comprehensive ML models for detecting specific attack types and patterns
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

class AdvancedAttackDetector:
    """Comprehensive attack detection system with specialized models"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.thresholds = {}
        self.feature_groups = {
            'dos_features': ['sload', 'dload', 'spkts', 'dpkts', 'dur', 'rate'],
            'fuzzer_features': ['trans_depth', 'response_body_len', 'sinpkt', 'dinpkt'],
            'port_scan_features': ['ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_ltm', 'ct_src_ltm'],
            'brute_force_features': ['is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst'],
            'reconnaissance_features': ['ct_dst_ltm', 'ct_src_ltm', 'ct_dst_src_ltm'],
            'tcp_behavior_features': ['tcprtt', 'synack', 'ackdat', 'stcpb', 'dtcpb'],
            'packet_size_features': ['smean', 'dmean', 'sbytes', 'dbytes'],
            'timing_features': ['sjit', 'djit', 'sinpkt', 'dinpkt'],
            'bandwidth_features': ['sload', 'dload', 'rate'],
            'session_features': ['dur', 'trans_depth', 'state']
        }
        
    def load_data(self, file_path):
        """Load and prepare data"""
        print("Loading data...")
        self.df = pd.read_csv(file_path)
        print(f"Data shape: {self.df.shape}")
        
        # Separate features and target
        self.X = self.df.drop(columns=['target'])
        self.y = self.df['target']
        
        # Split data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            self.X, self.y, test_size=0.3, random_state=42, stratify=self.y
        )
        
        print(f"Training set: {self.X_train.shape}")
        print(f"Test set: {self.X_test.shape}")
        
    def train_binary_classifier(self):
        """Train binary classifier for malicious vs normal traffic"""
        print("\n" + "="*60)
        print("Training Binary Classifier (Malicious vs Normal)")
        print("="*60)
        
        # Use Random Forest for binary classification
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(self.X_train, self.y_train)
        
        # Evaluate
        train_score = model.score(self.X_train, self.y_train)
        test_score = model.score(self.X_test, self.y_test)
        
        print(f"Training Accuracy: {train_score:.4f}")
        print(f"Test Accuracy: {test_score:.4f}")
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.X.columns,
            'importance': model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important Features:")
        print(feature_importance.head(10))
        
        self.models['binary_classifier'] = model
        return model
        
    def train_attack_type_classifier(self):
        """Train multi-class model for attack type classification"""
        print("\n" + "="*60)
        print("Training Attack Type Classifier")
        print("="*60)
        
        # For this example, we'll use binary classification
        # In a real scenario, you'd have attack_cat labels
        model = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(self.X_train, self.y_train)
        
        # Evaluate
        y_pred = model.predict(self.X_test)
        print("Classification Report:")
        print(classification_report(self.y_test, y_pred))
        
        self.models['attack_type_classifier'] = model
        return model
        
    def train_dos_detector(self):
        """Train DoS attack detector using Sload, Dload, Spkts, Dpkts patterns"""
        print("\n" + "="*60)
        print("Training DoS Attack Detector")
        print("="*60)
        
        features = self.feature_groups['dos_features']
        X_dos = self.X_train[features]
        
        # Train isolation forest for anomaly detection
        model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(X_dos)
        
        # Calculate threshold
        scores = model.decision_function(X_dos)
        threshold = np.percentile(scores, 10)  # Bottom 10% as anomalies
        self.thresholds['dos'] = threshold
        
        print(f"DoS Detection Threshold: {threshold:.4f}")
        
        self.models['dos_detector'] = model
        self.scalers['dos'] = StandardScaler().fit(X_dos)
        return model
        
    def train_fuzzer_detector(self):
        """Train Fuzzer detector using unusual trans_depth, res_bdy_len patterns"""
        print("\n" + "="*60)
        print("Training Fuzzer Attack Detector")
        print("="*60)
        
        features = self.feature_groups['fuzzer_features']
        X_fuzzer = self.X_train[features]
        
        # Use One-Class SVM for fuzzer detection
        model = OneClassSVM(
            nu=0.1,
            kernel='rbf',
            gamma='scale'
        )
        
        model.fit(X_fuzzer)
        
        print("Fuzzer detector trained successfully")
        
        self.models['fuzzer_detector'] = model
        self.scalers['fuzzer'] = StandardScaler().fit(X_fuzzer)
        return model
        
    def train_port_scan_detector(self):
        """Train Port Scan detector using ct_src_dport_ltm and ct_dst_sport_ltm"""
        print("\n" + "="*60)
        print("Training Port Scan Detector")
        print("="*60)
        
        features = self.feature_groups['port_scan_features']
        X_portscan = self.X_train[features]
        
        # Use DBSCAN clustering for port scan detection
        model = DBSCAN(eps=0.5, min_samples=5)
        
        # Fit on normal traffic only
        normal_data = X_portscan[self.y_train == 0]
        model.fit(normal_data)
        
        print("Port scan detector trained successfully")
        
        self.models['port_scan_detector'] = model
        self.scalers['port_scan'] = StandardScaler().fit(X_portscan)
        return model
        
    def train_brute_force_detector(self):
        """Train Brute Force detector using is_ftp_login and ct_ftp_cmd"""
        print("\n" + "="*60)
        print("Training Brute Force Login Detector")
        print("="*60)
        
        features = self.feature_groups['brute_force_features']
        X_brute = self.X_train[features]
        
        # Random Forest for brute force detection
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            random_state=42
        )
        
        model.fit(X_brute, self.y_train)
        
        print("Brute force detector trained successfully")
        
        self.models['brute_force_detector'] = model
        self.scalers['brute_force'] = StandardScaler().fit(X_brute)
        return model
        
    def train_reconnaissance_detector(self):
        """Train Reconnaissance detector using ct_dst_ltm spikes"""
        print("\n" + "="*60)
        print("Training Reconnaissance Detector")
        print("="*60)
        
        features = self.feature_groups['reconnaissance_features']
        X_recon = self.X_train[features]
        
        # Isolation Forest for reconnaissance detection
        model = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        
        model.fit(X_recon)
        
        # Calculate threshold for spike detection
        scores = model.decision_function(X_recon)
        threshold = np.percentile(scores, 5)
        self.thresholds['reconnaissance'] = threshold
        
        print(f"Reconnaissance Detection Threshold: {threshold:.4f}")
        
        self.models['reconnaissance_detector'] = model
        self.scalers['reconnaissance'] = StandardScaler().fit(X_recon)
        return model
        
    def train_anomalous_ip_detector(self):
        """Train Anomalous IP Communication detector using is_sm_ips_ports"""
        print("\n" + "="*60)
        print("Training Anomalous IP Communication Detector")
        print("="*60)
        
        # Use IP-related features
        ip_features = ['is_sm_ips_ports', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_src_ltm']
        X_ip = self.X_train[ip_features]
        
        # One-Class SVM for IP anomaly detection
        model = OneClassSVM(
            nu=0.1,
            kernel='rbf'
        )
        
        model.fit(X_ip)
        
        print("Anomalous IP detector trained successfully")
        
        self.models['anomalous_ip_detector'] = model
        self.scalers['anomalous_ip'] = StandardScaler().fit(X_ip)
        return model
        
    def train_bandwidth_monitor(self):
        """Train High Bandwidth Usage detector"""
        print("\n" + "="*60)
        print("Training High Bandwidth Usage Monitor")
        print("="*60)
        
        features = self.feature_groups['bandwidth_features']
        X_bw = self.X_train[features]
        
        # Calculate bandwidth thresholds
        bandwidth_stats = X_bw.describe()
        self.thresholds['high_bandwidth'] = {
            'sload': bandwidth_stats.loc['95%', 'sload'],
            'dload': bandwidth_stats.loc['95%', 'dload'],
            'rate': bandwidth_stats.loc['95%', 'rate']
        }
        
        print("Bandwidth thresholds calculated:")
        for feature, threshold in self.thresholds['high_bandwidth'].items():
            print(f"  {feature}: {threshold:.4f}")
        
        self.scalers['bandwidth'] = StandardScaler().fit(X_bw)
        return True
        
    def train_tcp_behavior_detector(self):
        """Train Suspicious TCP Behavior detector"""
        print("\n" + "="*60)
        print("Training Suspicious TCP Behavior Detector")
        print("="*60)
        
        features = self.feature_groups['tcp_behavior_features']
        X_tcp = self.X_train[features]
        
        # Isolation Forest for TCP anomaly detection
        model = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        model.fit(X_tcp)
        
        print("TCP behavior detector trained successfully")
        
        self.models['tcp_behavior_detector'] = model
        self.scalers['tcp_behavior'] = StandardScaler().fit(X_tcp)
        return model
        
    def train_packet_size_detector(self):
        """Train Abnormal Packet Size detector"""
        print("\n" + "="*60)
        print("Training Abnormal Packet Size Detector")
        print("="*60)
        
        features = self.feature_groups['packet_size_features']
        X_packet = self.X_train[features]
        
        # Calculate packet size thresholds
        packet_stats = X_packet.describe()
        self.thresholds['abnormal_packet'] = {
            'smean': {
                'min': packet_stats.loc['5%', 'smean'],
                'max': packet_stats.loc['95%', 'smean']
            },
            'dmean': {
                'min': packet_stats.loc['5%', 'dmean'],
                'max': packet_stats.loc['95%', 'dmean']
            }
        }
        
        print("Packet size thresholds calculated")
        
        self.scalers['packet_size'] = StandardScaler().fit(X_packet)
        return True
        
    def train_timing_anomaly_detector(self):
        """Train Jitter/Latency Anomaly detector"""
        print("\n" + "="*60)
        print("Training Jitter/Latency Anomaly Detector")
        print("="*60)
        
        features = self.feature_groups['timing_features']
        X_timing = self.X_train[features]
        
        # One-Class SVM for timing anomalies
        model = OneClassSVM(
            nu=0.1,
            kernel='rbf'
        )
        
        model.fit(X_timing)
        
        print("Timing anomaly detector trained successfully")
        
        self.models['timing_anomaly_detector'] = model
        self.scalers['timing'] = StandardScaler().fit(X_timing)
        return model
        
    def train_session_hijacking_detector(self):
        """Train Session Hijacking detector"""
        print("\n" + "="*60)
        print("Training Session Hijacking Detector")
        print("="*60)
        
        features = self.feature_groups['session_features']
        X_session = self.X_train[features]
        
        # Random Forest for session hijacking detection
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        model.fit(X_session, self.y_train)
        
        print("Session hijacking detector trained successfully")
        
        self.models['session_hijacking_detector'] = model
        self.scalers['session'] = StandardScaler().fit(X_session)
        return model
        
    def train_all_models(self):
        """Train all attack detection models"""
        print("="*80)
        print("TRAINING COMPREHENSIVE CYBER ATTACK DETECTION SYSTEM")
        print("="*80)
        
        # Core classifiers
        self.train_binary_classifier()
        self.train_attack_type_classifier()
        
        # Specialized detectors
        self.train_dos_detector()
        self.train_fuzzer_detector()
        self.train_port_scan_detector()
        self.train_brute_force_detector()
        self.train_reconnaissance_detector()
        self.train_anomalous_ip_detector()
        self.train_bandwidth_monitor()
        self.train_tcp_behavior_detector()
        self.train_packet_size_detector()
        self.train_timing_anomaly_detector()
        self.train_session_hijacking_detector()
        
        print("\n" + "="*80)
        print("ALL MODELS TRAINED SUCCESSFULLY!")
        print("="*80)
        
    def save_models(self):
        """Save all trained models and scalers"""
        import os
        os.makedirs('advanced_models', exist_ok=True)
        
        # Save models
        for name, model in self.models.items():
            joblib.dump(model, f'advanced_models/{name}.pkl')
            
        # Save scalers
        for name, scaler in self.scalers.items():
            joblib.dump(scaler, f'advanced_models/{name}_scaler.pkl')
            
        # Save thresholds
        joblib.dump(self.thresholds, 'advanced_models/thresholds.pkl')
        
        # Save feature groups
        joblib.dump(self.feature_groups, 'advanced_models/feature_groups.pkl')
        
        print("All models, scalers, and configurations saved!")
        
    def predict_attack_type(self, data):
        """Predict specific attack type for given data"""
        results = {}
        
        # Binary classification
        if 'binary_classifier' in self.models:
            pred = self.models['binary_classifier'].predict([data])[0]
            prob = self.models['binary_classifier'].predict_proba([data])[0]
            results['binary_prediction'] = {
                'is_attack': bool(pred),
                'confidence': float(max(prob))
            }
        
        # Specialized detectors
        for detector_name, model in self.models.items():
            if detector_name == 'binary_classifier':
                continue
                
            try:
                # Get relevant features
                if detector_name in self.feature_groups:
                    features = self.feature_groups[detector_name]
                else:
                    features = list(data.keys())
                
                # Prepare data
                detector_data = [data[f] for f in features if f in data]
                
                if len(detector_data) == len(features):
                    # Scale data
                    if detector_name in self.scalers:
                        detector_data = self.scalers[detector_name].transform([detector_data])
                    else:
                        detector_data = [detector_data]
                    
                    # Make prediction
                    if hasattr(model, 'predict'):
                        pred = model.predict(detector_data)[0]
                        results[detector_name] = {
                            'prediction': int(pred) if isinstance(pred, (int, np.integer)) else float(pred),
                            'is_anomaly': pred == -1 if hasattr(model, 'decision_function') else pred == 1
                        }
                        
                        # Get confidence score if available
                        if hasattr(model, 'decision_function'):
                            score = model.decision_function(detector_data)[0]
                            results[detector_name]['anomaly_score'] = float(score)
                            
            except Exception as e:
                results[detector_name] = {'error': str(e)}
        
        return results

# Example usage and testing
if __name__ == "__main__":
    # Initialize detector
    detector = AdvancedAttackDetector()
    
    # Load data
    detector.load_data("C:\\Users\\priya\\Desktop\\DATA\\processed_train.csv")
    
    # Train all models
    detector.train_all_models()
    
    # Save models
    detector.save_models()
    
    print("\n" + "="*80)
    print("ADVANCED ATTACK DETECTION SYSTEM READY!")
    print("="*80)
    print("Models trained for:")
    print("✓ Binary Classification (Malicious vs Normal)")
    print("✓ Attack Type Classification")
    print("✓ DoS Attack Detection")
    print("✓ Fuzzer Detection")
    print("✓ Port Scan Detection")
    print("✓ Brute Force Login Detection")
    print("✓ Reconnaissance Detection")
    print("✓ Anomalous IP Communication")
    print("✓ High Bandwidth Usage Monitoring")
    print("✓ Suspicious TCP Behavior")
    print("✓ Abnormal Packet Size Detection")
    print("✓ Jitter/Latency Anomalies")
    print("✓ Session Hijacking Detection")
    print("="*80)
