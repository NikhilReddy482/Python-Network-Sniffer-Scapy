from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Global variables
packet_count = 0
captured_packets = []

protocol_stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0
}

# Open log file
log_file = open("packet_log.txt", "w")


def process_packet(packet):
    global packet_count

    packet_count += 1
    captured_packets.append(packet)

    protocol = "OTHER"

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        protocol_stats[protocol] += 1

        # Color Selection
        if protocol == "TCP":
            color = Fore.GREEN
        elif protocol == "UDP":
            color = Fore.YELLOW
        elif protocol == "ICMP":
            color = Fore.CYAN
        else:
            color = Fore.WHITE

        packet_info = "\n" + "=" * 70 + "\n"
        packet_info += f"Packet Number      : {packet_count}\n"
        packet_info += f"Source IP          : {src_ip}\n"
        packet_info += f"Destination IP     : {dst_ip}\n"
        packet_info += f"Protocol           : {protocol}\n"

        # Ports
        if TCP in packet:
            packet_info += f"Source Port        : {packet[TCP].sport}\n"
            packet_info += f"Destination Port   : {packet[TCP].dport}\n"

        elif UDP in packet:
            packet_info += f"Source Port        : {packet[UDP].sport}\n"
            packet_info += f"Destination Port   : {packet[UDP].dport}\n"

        # Payload
        if Raw in packet:
            try:
                payload = packet[Raw].load
                packet_info += f"Payload Length     : {len(payload)} bytes\n"
                packet_info += f"Payload Preview    : {payload[:100]}\n"
            except:
                pass

        packet_info += "\nProtocol Statistics\n"
        packet_info += "-" * 25 + "\n"
        packet_info += f"TCP   : {protocol_stats['TCP']}\n"
        packet_info += f"UDP   : {protocol_stats['UDP']}\n"
        packet_info += f"ICMP  : {protocol_stats['ICMP']}\n"
        packet_info += f"OTHER : {protocol_stats['OTHER']}\n"

        print(color + packet_info + Style.RESET_ALL)

        # Write to log file
        log_file.write(packet_info)
        log_file.flush()


print("\n==============================")
print("      NETWORK SNIFFER")
print("==============================")

print("\nSelect Capture Mode")
print("1. TCP Only")
print("2. UDP Only")
print("3. ICMP Only")
print("4. All Traffic")

choice = input("\nEnter Choice: ")

if choice == "1":
    capture_filter = "tcp"
elif choice == "2":
    capture_filter = "udp"
elif choice == "3":
    capture_filter = "icmp"
else:
    capture_filter = ""

print("\nStarting Packet Capture...")
print("Press CTRL + C to stop\n")

try:

    if capture_filter:
        sniff(
            iface="eth0",
            filter=capture_filter,
            prn=process_packet,
            store=False
        )
    else:
        sniff(
            iface="eth0",
            prn=process_packet,
            store=False
        )

except KeyboardInterrupt:
    print("\nCapture stopped by user.")

finally:
    print("\nSaving files...")

    if len(captured_packets) > 0:
        wrpcap("capture.pcap", captured_packets)
        print("✓ capture.pcap saved")
