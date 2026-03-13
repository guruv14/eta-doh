import socket
import struct
import time
import yaml
import sys
from exporter import MetadataExporter

GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"
CLEAR = "\033[H\033[J"

def load_config():
    try:
        with open('config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[{YELLOW}!{RESET}] Error: 'config.yaml' not found.")
        sys.exit(1)

def parse_packet(packet):
    eth_length = 14
    eth_header = packet[:eth_length]
    eth_data = struct.unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth_data[2])

    # ip protocol 8
    if eth_protocol == 8:
        ip_header = packet[eth_length:20+eth_length]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        # tcp ptoto 6
        if protocol == 6:
            t = eth_length + iph_length
            tcp_header = packet[t:t+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]

            # filter 443
            if source_port == 443 or dest_port == 443:
                return {
                    "timestamp": time.strftime('%H:%M:%S'),
                    "src_ip": s_addr,
                    "dst_ip": d_addr,
                    "src_port": source_port,
                    "dst_port": dest_port,
                    "length": len(packet)
                }
    return None

def main():
    config = load_config()
    interface = config['sensor']['interface']
    exporter = MetadataExporter()
    
    packet_count = 0
    start_time = time.time()

    try:
        # raw sock create
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))
    except PermissionError:
        print(f"[{YELLOW}!{RESET}] Execution requires {GREEN}sudo{RESET} privileges.")
        return
    except Exception as e:
        print(f"[{YELLOW}!{RESET}] Binding Error: {e}")
        return

    print(f"{BLUE}=== Packet Sensor Active ==={RESET}")
    print(f"Interface: {YELLOW}{interface}{RESET}")
    print(f"Exporter:  {YELLOW}{exporter.dest_ip}:{exporter.dest_port}{RESET}")
    print(f"Filtering: {GREEN}TCP/443 (HTTPS){RESET}")
    print("-" * 50)

    try:
        while True:
            packet = s.recvfrom(65565)[0]
            metadata = parse_packet(packet)
            
            if metadata:
                packet_count += 1

                exporter.send_metadata(metadata)
                
                ts = metadata['timestamp']
                src = f"{metadata['src_ip']}:{metadata['src_port']}"
                dst = f"{metadata['dst_ip']}:{metadata['dst_port']}"
                
                print(f"[{ts}] {BLUE}{src:21}{RESET} → {GREEN}{dst:21}{RESET} | {metadata['length']} bytes")

                if packet_count % 10 == 0:
                    elapsed = round(time.time() - start_time, 1)
                    sys.stdout.write(f"\r{YELLOW}Captured: {packet_count} packets ({elapsed}s elapsed){RESET}\n")

    except KeyboardInterrupt:
        print(f"\n{BLUE}=== Session Summary ==={RESET}")
        print(f"Total HTTPS Packets Captured: {packet_count}")
        print("Shutting down gracefully...")

if __name__ == "__main__":
    main()
