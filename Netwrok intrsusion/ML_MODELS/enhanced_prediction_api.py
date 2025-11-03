"""
Enhanced Prediction API with Comprehensive Attack Detection
Integrates all specialized attack detectors for real-time analysis
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class EnhancedPredictionAPI:
    """Enhanced prediction API with comprehensive attack detection"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.thresholds = {}
        self.feature_groups = {}
        self.basic_models = {}
        self.feature_names = []
        
        # Load all models
        self.load_all_models()
        
    def load_all_models(self):
        """Load all trained models and configurations"""
        try:
            # Load basic models
            basic_model_dir = Path(__file__).parent / "trained_models"
            if basic_model_dir.exists():
                self.basic_models = {
                    'random_forest': joblib.load(basic_model_dir / 'random_forest_model.pkl'),
                    'decision_tree': joblib.load(basic_model_dir / 'decision_tree_model.pkl'),
                    'xgboost': joblib.load(basic_model_dir / 'xgboost_model.pkl'),
                    'lightgbm': joblib.load(basic_model_dir / 'lightgbm_model.pkl')
                }
                self.feature_names = joblib.load(basic_model_dir / 'feature_names.pkl')
            
            # Load advanced models
            advanced_model_dir = Path(__file__).parent / "advanced_models"
            if advanced_model_dir.exists():
                # Load models
                model_files = list(advanced_model_dir.glob("*.pkl"))
                for model_file in model_files:
                    if not model_file.name.endswith('_scaler.pkl'):
                        name = model_file.stem
                        if name != 'thresholds' and name != 'feature_groups':
                            self.models[name] = joblib.load(model_file)
                
                # Load scalers
                scaler_files = list(advanced_model_dir.glob("*_scaler.pkl"))
                for scaler_file in scaler_files:
                    name = scaler_file.stem.replace('_scaler', '')
                    self.scalers[name] = joblib.load(scaler_file)
                
                # Load thresholds and feature groups
                if (advanced_model_dir / 'thresholds.pkl').exists():
                    self.thresholds = joblib.load(advanced_model_dir / 'thresholds.pkl')
                if (advanced_model_dir / 'feature_groups.pkl').exists():
                    self.feature_groups = joblib.load(advanced_model_dir / 'feature_groups.pkl')
            
            print("✓ All models loaded successfully!")
            
        except Exception as e:
            print(f"Error loading models: {e}")
            print("Some advanced features may not be available")
    
    def predict_comprehensive(self, row_data, model_name='random_forest'):
        """
        Comprehensive attack prediction with detailed analysis
        
        Parameters:
        -----------
        row_data : dict or list
            Network traffic data
        model_name : str
            Basic model to use for primary classification
            
        Returns:
        --------
        dict : Comprehensive prediction results
        """
        results = {
            'timestamp': pd.Timestamp.now().isoformat(),
            'primary_prediction': None,
            'attack_probability': 0.0,
            'attack_type': 'Normal',
            'detailed_analysis': {},
            'risk_score': 0.0,
            'recommendations': []
        }
        
        try:
            # Prepare input data
            if isinstance(row_data, dict):
                data = pd.DataFrame([row_data])
                for feature in self.feature_names:
                    if feature not in data.columns:
                        data[feature] = 0
                data_array = data[self.feature_names].values
            elif isinstance(row_data, list):
                data_array = np.array(row_data).reshape(1, -1)
            else:
                raise ValueError("Invalid input format")
            
            # Primary prediction using basic models
            if model_name in self.basic_models:
                model = self.basic_models[model_name]
                primary_pred = model.predict(data_array)[0]
                primary_prob = model.predict_proba(data_array)[0][1] if hasattr(model, 'predict_proba') else float(primary_pred)
                
                results['primary_prediction'] = int(primary_pred)
                results['attack_probability'] = float(primary_prob)
                results['attack_type'] = 'Attack' if primary_pred == 1 else 'Normal'
            
            # Detailed analysis using specialized detectors
            detailed_analysis = {}
            risk_factors = []
            
            # Convert data to dict for specialized analysis
            if isinstance(row_data, list):
                data_dict = dict(zip(self.feature_names, row_data))
            else:
                data_dict = row_data
            
            # DoS Detection
            if 'dos_detector' in self.models:
                dos_result = self._detect_dos(data_dict)
                detailed_analysis['dos_detection'] = dos_result
                if dos_result['is_dos']:
                    risk_factors.append('DoS Attack Pattern')
            
            # Fuzzer Detection
            if 'fuzzer_detector' in self.models:
                fuzzer_result = self._detect_fuzzer(data_dict)
                detailed_analysis['fuzzer_detection'] = fuzzer_result
                if fuzzer_result['is_fuzzer']:
                    risk_factors.append('Fuzzer Attack Pattern')
            
            # Port Scan Detection
            if 'port_scan_detector' in self.models:
                portscan_result = self._detect_port_scan(data_dict)
                detailed_analysis['port_scan_detection'] = portscan_result
                if portscan_result['is_port_scan']:
                    risk_factors.append('Port Scan Pattern')
            
            # Brute Force Detection
            if 'brute_force_detector' in self.models:
                brute_result = self._detect_brute_force(data_dict)
                detailed_analysis['brute_force_detection'] = brute_result
                if brute_result['is_brute_force']:
                    risk_factors.append('Brute Force Pattern')
            
            # Reconnaissance Detection
            if 'reconnaissance_detector' in self.models:
                recon_result = self._detect_reconnaissance(data_dict)
                detailed_analysis['reconnaissance_detection'] = recon_result
                if recon_result['is_reconnaissance']:
                    risk_factors.append('Reconnaissance Pattern')
            
            # Bandwidth Analysis
            bandwidth_result = self._analyze_bandwidth(data_dict)
            detailed_analysis['bandwidth_analysis'] = bandwidth_result
            if bandwidth_result['high_bandwidth']:
                risk_factors.append('High Bandwidth Usage')
            
            # TCP Behavior Analysis
            if 'tcp_behavior_detector' in self.models:
                tcp_result = self._analyze_tcp_behavior(data_dict)
                detailed_analysis['tcp_behavior_analysis'] = tcp_result
                if tcp_result['suspicious_tcp']:
                    risk_factors.append('Suspicious TCP Behavior')
            
            # Packet Size Analysis
            packet_result = self._analyze_packet_sizes(data_dict)
            detailed_analysis['packet_size_analysis'] = packet_result
            if packet_result['abnormal_packet_size']:
                risk_factors.append('Abnormal Packet Size')
            
            # Timing Analysis
            if 'timing_anomaly_detector' in self.models:
                timing_result = self._analyze_timing(data_dict)
                detailed_analysis['timing_analysis'] = timing_result
                if timing_result['timing_anomaly']:
                    risk_factors.append('Timing Anomaly')
            
            # Session Analysis
            if 'session_hijacking_detector' in self.models:
                session_result = self._analyze_session(data_dict)
                detailed_analysis['session_analysis'] = session_result
                if session_result['session_anomaly']:
                    risk_factors.append('Session Anomaly')
            
            # Calculate overall risk score
            risk_score = self._calculate_risk_score(detailed_analysis, results['attack_probability'])
            results['risk_score'] = risk_score
            results['risk_factors'] = risk_factors
            results['detailed_analysis'] = detailed_analysis
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(detailed_analysis, risk_factors)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _detect_dos(self, data):
        """Detect DoS attacks"""
        try:
            features = self.feature_groups.get('dos_features', ['sload', 'dload', 'spkts', 'dpkts'])
            dos_data = [data.get(f, 0) for f in features]
            
            if 'dos_detector' in self.models and len(dos_data) == len(features):
                model = self.models['dos_detector']
                if 'dos' in self.scalers:
                    dos_data = self.scalers['dos'].transform([dos_data])
                else:
                    dos_data = [dos_data]
                
                score = model.decision_function(dos_data)[0]
                threshold = self.thresholds.get('dos', -0.1)
                
                return {
                    'is_dos': score < threshold,
                    'anomaly_score': float(score),
                    'threshold': float(threshold),
                    'confidence': abs(score - threshold) / abs(threshold) if threshold != 0 else 0
                }
        except:
            pass
        
        return {'is_dos': False, 'anomaly_score': 0, 'confidence': 0}
    
    def _detect_fuzzer(self, data):
        """Detect Fuzzer attacks"""
        try:
            features = self.feature_groups.get('fuzzer_features', ['trans_depth', 'response_body_len'])
            fuzzer_data = [data.get(f, 0) for f in features]
            
            if 'fuzzer_detector' in self.models and len(fuzzer_data) == len(features):
                model = self.models['fuzzer_detector']
                if 'fuzzer' in self.scalers:
                    fuzzer_data = self.scalers['fuzzer'].transform([fuzzer_data])
                else:
                    fuzzer_data = [fuzzer_data]
                
                pred = model.predict(fuzzer_data)[0]
                
                return {
                    'is_fuzzer': pred == -1,
                    'prediction': int(pred),
                    'confidence': 0.8 if pred == -1 else 0.2
                }
        except:
            pass
        
        return {'is_fuzzer': False, 'prediction': 1, 'confidence': 0}
    
    def _detect_port_scan(self, data):
        """Detect Port Scan attacks"""
        try:
            features = self.feature_groups.get('port_scan_features', ['ct_src_dport_ltm', 'ct_dst_sport_ltm'])
            portscan_data = [data.get(f, 0) for f in features]
            
            if 'port_scan_detector' in self.models and len(portscan_data) == len(features):
                model = self.models['port_scan_detector']
                if 'port_scan' in self.scalers:
                    portscan_data = self.scalers['port_scan'].transform([portscan_data])
                else:
                    portscan_data = [portscan_data]
                
                # DBSCAN returns -1 for outliers
                pred = model.fit_predict(portscan_data)[0]
                
                return {
                    'is_port_scan': pred == -1,
                    'cluster': int(pred),
                    'confidence': 0.9 if pred == -1 else 0.1
                }
        except:
            pass
        
        return {'is_port_scan': False, 'cluster': 0, 'confidence': 0}
    
    def _detect_brute_force(self, data):
        """Detect Brute Force attacks"""
        try:
            features = self.feature_groups.get('brute_force_features', ['is_ftp_login', 'ct_ftp_cmd'])
            brute_data = [data.get(f, 0) for f in features]
            
            if 'brute_force_detector' in self.models and len(brute_data) == len(features):
                model = self.models['brute_force_detector']
                if 'brute_force' in self.scalers:
                    brute_data = self.scalers['brute_force'].transform([brute_data])
                else:
                    brute_data = [brute_data]
                
                pred = model.predict(brute_data)[0]
                prob = model.predict_proba(brute_data)[0][1] if hasattr(model, 'predict_proba') else float(pred)
                
                return {
                    'is_brute_force': bool(pred),
                    'prediction': int(pred),
                    'confidence': float(prob)
                }
        except:
            pass
        
        return {'is_brute_force': False, 'prediction': 0, 'confidence': 0}
    
    def _detect_reconnaissance(self, data):
        """Detect Reconnaissance attacks"""
        try:
            features = self.feature_groups.get('reconnaissance_features', ['ct_dst_ltm', 'ct_src_ltm'])
            recon_data = [data.get(f, 0) for f in features]
            
            if 'reconnaissance_detector' in self.models and len(recon_data) == len(features):
                model = self.models['reconnaissance_detector']
                if 'reconnaissance' in self.scalers:
                    recon_data = self.scalers['reconnaissance'].transform([recon_data])
                else:
                    recon_data = [recon_data]
                
                score = model.decision_function(recon_data)[0]
                threshold = self.thresholds.get('reconnaissance', -0.1)
                
                return {
                    'is_reconnaissance': score < threshold,
                    'anomaly_score': float(score),
                    'threshold': float(threshold),
                    'confidence': abs(score - threshold) / abs(threshold) if threshold != 0 else 0
                }
        except:
            pass
        
        return {'is_reconnaissance': False, 'anomaly_score': 0, 'confidence': 0}
    
    def _analyze_bandwidth(self, data):
        """Analyze bandwidth usage"""
        try:
            thresholds = self.thresholds.get('high_bandwidth', {})
            
            sload = data.get('sload', 0)
            dload = data.get('dload', 0)
            rate = data.get('rate', 0)
            
            high_sload = sload > thresholds.get('sload', 1.0)
            high_dload = dload > thresholds.get('dload', 1.0)
            high_rate = rate > thresholds.get('rate', 1.0)
            
            return {
                'high_bandwidth': high_sload or high_dload or high_rate,
                'sload_high': high_sload,
                'dload_high': high_dload,
                'rate_high': high_rate,
                'sload_value': float(sload),
                'dload_value': float(dload),
                'rate_value': float(rate)
            }
        except:
            pass
        
        return {'high_bandwidth': False, 'sload_high': False, 'dload_high': False, 'rate_high': False}
    
    def _analyze_tcp_behavior(self, data):
        """Analyze TCP behavior"""
        try:
            features = self.feature_groups.get('tcp_behavior_features', ['tcprtt', 'synack', 'ackdat'])
            tcp_data = [data.get(f, 0) for f in features]
            
            if 'tcp_behavior_detector' in self.models and len(tcp_data) == len(features):
                model = self.models['tcp_behavior_detector']
                if 'tcp_behavior' in self.scalers:
                    tcp_data = self.scalers['tcp_behavior'].transform([tcp_data])
                else:
                    tcp_data = [tcp_data]
                
                score = model.decision_function(tcp_data)[0]
                
                return {
                    'suspicious_tcp': score < -0.1,
                    'anomaly_score': float(score),
                    'confidence': abs(score) if score < 0 else 0
                }
        except:
            pass
        
        return {'suspicious_tcp': False, 'anomaly_score': 0, 'confidence': 0}
    
    def _analyze_packet_sizes(self, data):
        """Analyze packet sizes"""
        try:
            thresholds = self.thresholds.get('abnormal_packet', {})
            
            smean = data.get('smean', 0)
            dmean = data.get('dmean', 0)
            
            smean_thresh = thresholds.get('smean', {'min': -2, 'max': 2})
            dmean_thresh = thresholds.get('dmean', {'min': -2, 'max': 2})
            
            abnormal_smean = smean < smean_thresh['min'] or smean > smean_thresh['max']
            abnormal_dmean = dmean < dmean_thresh['min'] or dmean > dmean_thresh['max']
            
            return {
                'abnormal_packet_size': abnormal_smean or abnormal_dmean,
                'smean_abnormal': abnormal_smean,
                'dmean_abnormal': abnormal_dmean,
                'smean_value': float(smean),
                'dmean_value': float(dmean)
            }
        except:
            pass
        
        return {'abnormal_packet_size': False, 'smean_abnormal': False, 'dmean_abnormal': False}
    
    def _analyze_timing(self, data):
        """Analyze timing patterns"""
        try:
            features = self.feature_groups.get('timing_features', ['sjit', 'djit'])
            timing_data = [data.get(f, 0) for f in features]
            
            if 'timing_anomaly_detector' in self.models and len(timing_data) == len(features):
                model = self.models['timing_anomaly_detector']
                if 'timing' in self.scalers:
                    timing_data = self.scalers['timing'].transform([timing_data])
                else:
                    timing_data = [timing_data]
                
                pred = model.predict(timing_data)[0]
                
                return {
                    'timing_anomaly': pred == -1,
                    'prediction': int(pred),
                    'confidence': 0.8 if pred == -1 else 0.2
                }
        except:
            pass
        
        return {'timing_anomaly': False, 'prediction': 1, 'confidence': 0}
    
    def _analyze_session(self, data):
        """Analyze session patterns"""
        try:
            features = self.feature_groups.get('session_features', ['dur', 'trans_depth'])
            session_data = [data.get(f, 0) for f in features]
            
            if 'session_hijacking_detector' in self.models and len(session_data) == len(features):
                model = self.models['session_hijacking_detector']
                if 'session' in self.scalers:
                    session_data = self.scalers['session'].transform([session_data])
                else:
                    session_data = [session_data]
                
                pred = model.predict(session_data)[0]
                prob = model.predict_proba(session_data)[0][1] if hasattr(model, 'predict_proba') else float(pred)
                
                return {
                    'session_anomaly': bool(pred),
                    'prediction': int(pred),
                    'confidence': float(prob)
                }
        except:
            pass
        
        return {'session_anomaly': False, 'prediction': 0, 'confidence': 0}
    
    def _calculate_risk_score(self, detailed_analysis, attack_probability):
        """Calculate overall risk score"""
        risk_score = attack_probability * 0.4  # Base risk from primary prediction
        
        # Add risk from specialized detectors
        risk_factors = [
            ('dos_detection', 'is_dos', 0.2),
            ('fuzzer_detection', 'is_fuzzer', 0.15),
            ('port_scan_detection', 'is_port_scan', 0.15),
            ('brute_force_detection', 'is_brute_force', 0.1),
            ('reconnaissance_detection', 'is_reconnaissance', 0.1),
            ('bandwidth_analysis', 'high_bandwidth', 0.05),
            ('tcp_behavior_analysis', 'suspicious_tcp', 0.05),
            ('packet_size_analysis', 'abnormal_packet_size', 0.05),
            ('timing_analysis', 'timing_anomaly', 0.05),
            ('session_analysis', 'session_anomaly', 0.05)
        ]
        
        for analysis_type, key, weight in risk_factors:
            if analysis_type in detailed_analysis:
                if detailed_analysis[analysis_type].get(key, False):
                    risk_score += weight
        
        return min(risk_score, 1.0)  # Cap at 1.0
    
    def _generate_recommendations(self, detailed_analysis, risk_factors):
        """Generate security recommendations"""
        recommendations = []
        
        if 'DoS Attack Pattern' in risk_factors:
            recommendations.append("🚨 HIGH PRIORITY: Block source IP - DoS attack detected")
            recommendations.append("📊 Monitor bandwidth usage and implement rate limiting")
        
        if 'Fuzzer Attack Pattern' in risk_factors:
            recommendations.append("🔍 Investigate unusual transaction patterns")
            recommendations.append("🛡️ Implement input validation and sanitization")
        
        if 'Port Scan Pattern' in risk_factors:
            recommendations.append("🔍 Monitor for reconnaissance activities")
            recommendations.append("🚫 Consider blocking suspicious IP addresses")
        
        if 'Brute Force Pattern' in risk_factors:
            recommendations.append("🔐 Implement account lockout policies")
            recommendations.append("🔑 Enable multi-factor authentication")
        
        if 'Reconnaissance Pattern' in risk_factors:
            recommendations.append("👁️ Monitor network scanning activities")
            recommendations.append("🛡️ Implement intrusion detection rules")
        
        if 'High Bandwidth Usage' in risk_factors:
            recommendations.append("📈 Investigate high bandwidth consumption")
            recommendations.append("⚡ Implement bandwidth throttling")
        
        if 'Suspicious TCP Behavior' in risk_factors:
            recommendations.append("🔍 Analyze TCP connection patterns")
            recommendations.append("🛡️ Review firewall rules")
        
        if 'Abnormal Packet Size' in risk_factors:
            recommendations.append("📦 Investigate unusual packet sizes")
            recommendations.append("🔍 Check for fragmentation attacks")
        
        if 'Timing Anomaly' in risk_factors:
            recommendations.append("⏱️ Analyze timing patterns for attacks")
            recommendations.append("🔍 Check for timing-based attacks")
        
        if 'Session Anomaly' in risk_factors:
            recommendations.append("🔐 Monitor session state changes")
            recommendations.append("🛡️ Implement session hijacking protection")
        
        if not recommendations:
            recommendations.append("✅ No immediate security concerns detected")
            recommendations.append("📊 Continue monitoring for anomalies")
        
        return recommendations

# Global instance
enhanced_api = EnhancedPredictionAPI()

def predict_comprehensive_attack(row_data, model_name='random_forest'):
    """
    Main function for comprehensive attack prediction
    
    Parameters:
    -----------
    row_data : dict or list
        Network traffic data
    model_name : str
        Basic model to use (random_forest, decision_tree, xgboost, lightgbm)
        
    Returns:
    --------
    dict : Comprehensive prediction results
    """
    return enhanced_api.predict_comprehensive(row_data, model_name)

# Example usage
if __name__ == "__main__":
    print("="*80)
    print("ENHANCED CYBER ATTACK DETECTION API")
    print("="*80)
    
    # Test with sample data
    sample_data = {feature: 0.0 for feature in enhanced_api.feature_names}
    
    result = predict_comprehensive_attack(sample_data)
    
    print(f"\nPrimary Prediction: {result['attack_type']}")
    print(f"Attack Probability: {result['attack_probability']:.4f}")
    print(f"Risk Score: {result['risk_score']:.4f}")
    print(f"Risk Factors: {result.get('risk_factors', [])}")
    print(f"\nRecommendations:")
    for rec in result.get('recommendations', []):
        print(f"  {rec}")
    
    print("\n" + "="*80)
    print("API READY FOR INTEGRATION!")
    print("="*80)
