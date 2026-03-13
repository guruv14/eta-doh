import socket
import json
import yaml

class MetadataExporter:
    def __init__(self, config_path='config.yaml'):
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        self.dest_ip = config['export']['destination_ip']
        self.dest_port = config['export']['destination_port']
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_metadata(self, metadata):
        try:
            payload = json.dumps(metadata).encode('utf-8')
            self.sock.sendto(payload, (self.dest_ip, self.dest_port))
        except Exception as e:
            print(f"Export error: {e}")
