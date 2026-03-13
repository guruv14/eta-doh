import socket
import json
import yaml
import os
import multiprocessing

def run_ingestion(packet_queue):
    # load Config
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, 'config.yaml')
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    host = config['ingestion']['host']
    port = config['ingestion']['port']

    # binding Sockett
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        print(f"[Ingestion] Listening on {host}:{port}")
    except Exception as e:
        print(f"[Ingestion] CRITICAL ERROR: Could not bind port {port}. {e}")
        return

    packet_count = 0
    
    while True:
        try:
            # Buffer size 4096  standard _UDP
            data, addr = sock.recvfrom(4096)
            
            if not data:
                continue

            # Decode and Enqueue
            packet = json.loads(data.decode('utf-8'))
            packet_queue.put(packet)
            
            # periodic logging
            packet_count += 1
            if packet_count % 50 == 0:
                print(f"[Ingestion] Processed {packet_count} packets so far...")

        except json.JSONDecodeError:
            # Common with UDP packet fragmentation, just ignore
            continue
        except Exception as e:
            print(f"[Ingestion] Error: {e}")

if __name__ == "__main__":
    # Test block to run this alone
    q = multiprocessing.Queue()
    run_ingestion(q)
