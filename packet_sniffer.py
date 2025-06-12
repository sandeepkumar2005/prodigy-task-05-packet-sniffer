from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = packet.proto

        print(f"📡 Packet: {src_ip} --> {dst_ip} | Protocol: {proto}")

        if packet.haslayer(TCP):
            print("🔹 TCP Payload:", bytes(packet[TCP].payload))
        elif packet.haslayer(UDP):
            print("🔹 UDP Payload:", bytes(packet[UDP].payload))
        print("-" * 60)

def main():
    print("📡 Packet Sniffer started... (Press Ctrl+C to stop)")
    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":
    main()
