import yaml
import numpy as np
from scipy.stats import skew
from collections import defaultdict
import multiprocessing
import os

class FlowTracker:
    def __init__(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, 'config.yaml')
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        self.max_window = config['engine']['max_window_size']
        self.inactivity_timeout = config['engine']['inactivity_timeout']
        
        self.flows = defaultdict(list)
        self.flow_last_seen = {}

    def process_packet(self, packet):

        if packet['dst_port'] == 443:
            # Outbound flow: Key is "DestIP:443"
            flow_key = f"{packet['dst_ip']}:443"
        elif packet['src_port'] == 443:
            # Inbound flow: Key is "SrcIP:443"
            flow_key = f"{packet['src_ip']}:443"
        else:
            return [] # Ignore non-HTTPS traffic

        current_time = packet['timestamp']
        

        self.flows[flow_key].append(current_time)
        self.flow_last_seen[flow_key] = current_time
        
        return self.check_expirations(current_time)

    def check_expirations(self, current_time):

        completed_flows = []
        keys_to_delete = []
        
        for flow_key, timestamps in self.flows.items():
            # --- RULE 3: Minimum 3 Packets ---
            if len(timestamps) < 3:
                continue
            
            # calculate durations
            time_active = timestamps[-1] - timestamps[0]
            time_since_last = current_time - self.flow_last_seen[flow_key]
            
            # timeout triggers ---
            is_full = len(timestamps) >= self.max_window
            is_expired = time_since_last >= self.inactivity_timeout
            
            if is_full or is_expired:
                features = self.extract_features(timestamps)
                if features:
                    features['flow_key'] = flow_key
                    features['window_end'] = timestamps[-1]
                    completed_flows.append(features)
                    
                    print(f"[Features] Extracted Flow: {flow_key} (Pkts: {len(timestamps)})")
                    
                keys_to_delete.append(flow_key)
                
        # cleanup mem
        for key in keys_to_delete:
            del self.flows[key]
            del self.flow_last_seen[key]
            
        return completed_flows

    def extract_features(self, timestamps):
        # calc IAT)
        iats = np.diff(timestamps)
        
        if len(iats) < 2: return None

        # Math for rf
        mean_iat = np.mean(iats)
        var_iat = np.var(iats)
        
        # zero variance (perfectly timed packets) crash
        if np.std(iats) > 0:
            skew_iat = skew(iats)
        else:
            skew_iat = 0.0
        
        return {
            "mean_iat": float(mean_iat),
            "variance_iat": float(var_iat),
            "skewness_iat": float(skew_iat),
            "packet_count": len(timestamps)
        }

def run_feature_engineering(packet_queue, feature_queue):
    tracker = FlowTracker()
    print("[Features] Engine Started. Waiting for flows...")
    
    while True:
        packet = packet_queue.get()
        completed_flows = tracker.process_packet(packet)
        
        for flow in completed_flows:
            feature_queue.put(flow)
