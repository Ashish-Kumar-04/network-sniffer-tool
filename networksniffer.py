from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def process_packet(packet):
    print("\n" + "=" * 60)
    print("Packet Captured at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if IP in packet:
        ip_layer = packet[IP]
        print(f"[IP] {ip_layer.src} --> {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"[TCP] Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
            print("Payload:")
            print(bytes(tcp_layer.payload))

        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"[UDP] Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
            print("Payload:")
            print(bytes(udp_layer.payload))

        elif ICMP in packet:
            print("[ICMP] Type:", packet[ICMP].type)

    else:
        print("Non-IP packet detected.")

# Start sniffing (interface='eth0' or 'Wi-Fi' or 'en0' based on your OS)
print("Starting packet sniffer... Press Ctrl+C to stop.\n")
sniff(prn=process_packet, store=False)
