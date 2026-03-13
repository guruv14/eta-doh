import os
import joblib
import numpy as np
import yaml
import multiprocessing

class InferenceEngine:
    def __init__(self):
        # 1. loading
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, 'config.yaml')
        model_path = os.path.join(base_dir, 'models', 'rf_doh_model.pkl')
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        # 2. Load Thresholds
        self.thresh_high = config['engine'].get('malice_threshold_high', 0.80)
        self.thresh_med = 0.50 # Hardcoded medium threshold
        
        # 3. Load Model (Crash if missing, as agreed)
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"[Inference] CRITICAL: Model file not found at {model_path}. Run train_model.py first!")
            
        print(f"[Inference] Loading model from {model_path}...")
        self.model = joblib.load(model_path)
        print("[Inference] Model loaded successfully.")

    def predict(self, feature_dict):

        vector = np.array([[
            feature_dict['mean_iat'],
            feature_dict['variance_iat'],
            feature_dict['skewness_iat']
        ]])
        
        #  probability of Class 1 (malicious)
        probability = self.model.predict_proba(vector)[0][1]
        
        # check severity
        if probability >= self.thresh_high:
            severity = "HIGH"
        elif probability >= self.thresh_med:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        return probability, severity

def run_inference(feature_queue, result_queue):
    # init Engine
    try:
        engine = InferenceEngine()
    except Exception as e:
        print(f"[Inference] Failed to start: {e}")
        return

    print("[Inference] Engine Active. Waiting for feature vectors...")
    
    while True:
        features = feature_queue.get()
        
        # prediction
        probability, severity = engine.predict(features)
        
        #  result for Dashboard
        result = {
            "timestamp": features.get('window_end'),
            "flow_key": features['flow_key'],
            "probability": float(probability),
            "severity": severity,
            "stats": features
        }
        
        # send to Main.py for broadcast
        result_queue.put(result)
        
        # logging High to console for debugging
        if severity == "HIGH":
            print(f"[ALERT] High Severity Detect! {features['flow_key']} (Prob: {probability:.2f})")
