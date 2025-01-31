import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import time
from collections import defaultdict

CAPTURE_DURATION = 10
INTERFACE = "en0"


def capture_packets(duration=CAPTURE_DURATION):
    print(f"Starting packet capture on {INTERFACE} for {duration} seconds...")
    packets = scapy.sniff(iface=INTERFACE, timeout=duration)
    return packets


import numpy as np
import matplotlib.pyplot as plt

def analyze_packet_sizes(packets):
    total_bytes = 0
    total_packets = len(packets)
    packet_sizes = []

    for packet in packets:
        if IP in packet:
            total_bytes += len(packet)
            packet_sizes.append(len(packet))

    print(len(packets))
    print(len(packet_sizes))
    min_size = min(packet_sizes)
    max_size = max(packet_sizes)
    avg_size = np.mean(packet_sizes)

    # Save the histogram of packet sizes
    plt.hist(packet_sizes, bins=50)
    plt.title('Distribution of Packet Sizes')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.savefig('packet_size_distribution.png')  # Save as an image file

    # Save the metrics into a file
    with open("packet_metrics.txt", "w") as f:
        f.write(f"Total Bytes: {total_bytes}\n")
        f.write(f"Total Packets: {total_packets}\n")
        f.write(f"Min Packet Size: {min_size}\n")
        f.write(f"Max Packet Size: {max_size}\n")
        f.write(f"Avg Packet Size: {avg_size}\n")

    return total_bytes, total_packets, min_size, max_size, avg_size



def unique_src_dst_pairs(packets):
    unique_pairs = set()

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet or UDP in packet:
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport

                pair = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")

                unique_pairs.add(pair)

    with open("unique_pairs.txt", "w") as f:
        for pair in unique_pairs:
            f.write(f"{pair}\n")

    return unique_pairs


def flow_dictionaries_and_max_data(packets):
    src_flows = defaultdict(int)
    dst_flows = defaultdict(int)
    data_transferred = defaultdict(int)

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            src_flows[src_ip] += 1
            dst_flows[dst_ip] += 1

            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None

            if src_port and dst_port:
                flow_key = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
                data_transferred[flow_key] += len(packet)


    max_transfer_pair = max(data_transferred, key=data_transferred.get)
    max_transfer_data = data_transferred[max_transfer_pair]

    with open("flow_dicts_and_max_data.txt", "w") as f:
        f.write("Source Flows (IP -> Total Flows):\n")
        for ip, flows in src_flows.items():
            f.write(f"{ip} -> {flows}\n")


        f.write("\nDestination Flows (IP -> Total Flows):\n")
        for ip, flows in dst_flows.items():
            f.write(f"{ip} -> {flows}\n")


        f.write("\nSource-Destination Pair with the Most Data Transferred:\n")
        f.write(f"Pair: {max_transfer_pair}, Data Transferred: {max_transfer_data} bytes\n")



def capture_speed(packets, start_time):
    end_time = time.time()
    duration = end_time - start_time
    pps = len(packets) / duration  # packets per second
    total_bytes = sum(len(packet) for packet in packets)
    mbps = (total_bytes * 8) / (duration * 1e6)  # megabits per second

    # Save the speed metrics to a file
    with open("capture_speed.txt", "w") as f:
        f.write(f"Packets per second (pps): {pps}\n")
        f.write(f"Data rate (Mbps): {mbps}\n")

    return pps, mbps


if __name__ == "__main__":
    start_time = time.time()  # Start time for speed calculation
    packets = capture_packets(duration=CAPTURE_DURATION)  # Capture packets for the specified duration

    # Analyze the captured packets
    analyze_packet_sizes(packets)
    unique_src_dst_pairs(packets)
    flow_dictionaries_and_max_data(packets)
    capture_speed(packets, start_time)