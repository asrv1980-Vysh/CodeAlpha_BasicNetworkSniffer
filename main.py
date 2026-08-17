from scapy.all import sniff, IP, TCP, UDP, ICMP


def process_packet(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        print("-" * 50)
        print("Source IP      :", source_ip)
        print("Destination IP :", destination_ip)
        print("Protocol       :", protocol)


print("Network Sniffer Started...")
print("Capturing packets...")

sniff(prn=process_packet, count=10)

print("Packet capturing completed.")