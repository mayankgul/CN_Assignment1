import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import time
from collections import defaultdict
import sympy

CAPTURE_DURATION = 60
INTERFACE = "en0"


def capture_packets(duration=CAPTURE_DURATION):
    """
    This function captures network packets using the Scapy library.

    Parameters:
    duration (int): The duration for which the packet capture should run in seconds.
                    The default value is the value of the global variable CAPTURE_DURATION.

    Returns:
    scapy.PacketList: A list of captured packets.

    The function prints a message indicating the start of the packet capture,
    captures packets using the Scapy sniff function, and returns the captured packets.
    """
    print(f"Starting packet capture on {INTERFACE} for {duration} seconds...")
    packets = scapy.sniff(iface=INTERFACE, timeout=duration)
    return packets


import numpy as np
import matplotlib.pyplot as plt

def analyze_packet_sizes(packets):
    """
    This function analyzes the size of packets in a given list of packets.

    Parameters:
    packets (scapy.PacketList): A list of network packets captured using the Scapy library.

    Returns:
    tuple: A tuple containing the total bytes, total packets, minimum packet size,
           maximum packet size, and average packet size.

    The function calculates the total bytes, total packets, minimum packet size,
    maximum packet size, and average packet size from the given packets. It also saves
    a histogram of packet sizes as an image file and the metrics into a text file.
    """
    total_bytes = 0
    total_packets = len(packets)
    packet_sizes = []

    for packet in packets:
        if IP in packet:
            total_bytes += len(packet)
            packet_sizes.append(len(packet))

    min_size = min(packet_sizes)
    max_size = max(packet_sizes)
    avg_size = np.mean(packet_sizes)

    plt.hist(packet_sizes, bins=50)
    plt.title('Distribution of Packet Sizes')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.savefig('packet_size_distribution.png')  # Sa

    with open("packet_metrics.txt", "w") as f:
        f.write(f"Total Bytes: {total_bytes}\n")
        f.write(f"Total Packets: {total_packets}\n")
        f.write(f"Min Packet Size: {min_size}\n")
        f.write(f"Max Packet Size: {max_size}\n")
        f.write(f"Avg Packet Size: {avg_size}\n")

    return total_bytes, total_packets, min_size, max_size, avg_size



def unique_src_dst_pairs(packets):
    """
    This function extracts unique source-destination pairs from a list of network packets.

    Parameters:
    packets (scapy.PacketList): A list of network packets captured using the Scapy library.

    Returns:
    set: A set of unique source-destination pairs represented as tuples in the format (src_ip:src_port, dst_ip:dst_port).
         Each pair is written to a text file named "unique_pairs.txt".

    The function iterates through each packet in the given list, extracts the source and destination IP addresses,
    and source and destination ports (if present). It then forms a tuple representing the pair and adds it to a set.
    Finally, it writes each unique pair to a text file named "unique_pairs.txt".
    """
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
    """
    This function analyzes the network traffic flow by counting the number of flows from source and destination IPs,
    and calculating the total data transferred for each flow.

    Parameters:
    packets (scapy.PacketList): A list of network packets captured using the Scapy library.

    Returns:
    None. The function writes the results to a text file named "flow_dicts_and_max_data.txt".

    The function iterates through each packet in the given list, extracts the source and destination IP addresses,
    and source and destination ports (if present). It then forms a tuple representing the flow key and updates the
    dictionaries 'src_flows', 'dst_flows', and 'data_transferred' accordingly. Finally, it writes the source flows,
    destination flows, and the source-destination pair with the most data transferred to a text file.
    """
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
    """
    Calculates the network capture speed in packets per second (pps) and megabits per second (Mbps).

    Parameters:
    packets (scapy.PacketList): A list of network packets captured using the Scapy library.
    start_time (float): The start time of the packet capture in seconds.

    Returns:
    tuple: A tuple containing the capture speed in packets per second (pps) and megabits per second (Mbps).

    The function calculates the duration of the packet capture, the number of packets per second (pps),
    and the data rate in megabits per second (Mbps). It then saves these metrics to a file named "capture_speed.txt".
    """
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


# PCAP questions

def question_1(packets):
    """
    This function processes a list of network packets and identifies specific TCP packets based on certain conditions.
    It then writes the source and destination IP addresses of these packets to a file.

    Parameters:
    packets (scapy.PacketList): A list of network packets captured using the Scapy library.

    Returns:
    None. The function writes the results to a file named "PCAP_question1".

    The function iterates through each packet in the given list. If the packet contains a TCP layer and the TCP flags
    indicate a 'Push' and 'Ack' (0x018), it checks if the sum of the source and destination ports equals 60303.
    If the condition is met, it writes the source and destination IP addresses of the packet to a file named "PCAP_question1".
    """

    with open("PCAP_question1", "w") as f:
        for packet in packets:
            if TCP in packet:
                if packet[TCP].flags == 0x018:
                    source_port = packet[TCP].sport
                    destination_port = packet[TCP].dport
                    if (source_port + destination_port) == 60303:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        f.write(f"Source IP: {src_ip}, Destination IP: {dst_ip}\n")


def question_2(packets):
    """
    This function processes a list of network packets and identifies specific TCP packets based on certain conditions.
    It then writes the source and destination IP addresses of these packets to a file.

    Parameters:
    packets (scapy.PacketList): A list of network packets captured using the Scapy library.

    Returns:
    None. The function writes the results to a file named "PCAP_question2".

    The function iterates through each packet in the given list. If the packet contains a TCP layer and the TCP flags
    indicate a 'Syn' (0x02), it checks if the source port is divisible by 11 and the sequence number is greater than 100000.
    If the condition is met, it writes the source and destination IP addresses of the packet to a file named "PCAP_question2".
    Additionally, it counts the number of matching packets and writes the total count at the end of the file.
    """
    with open("PCAP_question2", "w") as f:
        count = 0
        for packet in packets:
            if TCP in packet and packet[TCP].flags == 0x02:
                source_port = packet[TCP].sport
                sequence_number = packet[TCP].seq
                if source_port % 11 == 0 and sequence_number > 100000:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    f.write(f"Source IP: {src_ip}, Destination IP: {dst_ip}\n")
                    count += 1

        f.write(f"Total matching packets: {count}\n")


def question_3(packets):
    """
    This function processes a list of network packets and identifies specific TCP packets based on certain conditions.
    It then writes the source and destination IP addresses of these packets to a file.

    Parameters:
    packets (scapy.PacketList): A list of network packets captured using the Scapy library.

    Returns:
    None. The function writes the results to a file named "PCAP_question3".

    The function iterates through each packet in the given list. If the packet contains a TCP layer,
    the source IP address starts with '18.234', the source port is a prime number, and the destination port is divisible by 11,
    it writes the source and destination IP addresses of the packet to a file named "PCAP_question3".
    Additionally, it counts the number of matching packets and writes the total count at the end of the file.
    """
    with open("PCAP_question3", "w") as f:
        count = 0
        for packet in packets:
            if TCP in packet:
                src_ip = packet[IP].src
                if src_ip.startswith('18.234'):
                    source_port = packet[TCP].sport
                    destination_port = packet[TCP].dport
                    if sympy.isprime(source_port) and destination_port % 11 == 0:
                        f.write(f"Source IP: {src_ip}, Destination IP: {packet[IP].dst}\n")
                        count += 1

        f.write(f"Total matching packets: {count}\n")


def question_4(packets):
    """
    This function processes a list of network packets and identifies a specific TCP packet based on certain conditions.
    It then writes the details of this packet to a file.

    Parameters:
    packets (scapy.PacketList): A list of network packets captured using the Scapy library.

    Returns:
    None. The function writes the results to a file named "PCAP_question4".

    The function iterates through each packet in the given list. If the packet contains a TCP layer,
    the sum of the sequence number and acknowledgment number equals 2512800625, and the checksum ends with '70',
    it writes the details of the packet (source and destination IP addresses, source and destination ports,
    sequence number, and acknowledgment number) to a file named "PCAP_question4".
    """
    with open("PCAP_question4", "w") as f:
        for packet in packets:
            if TCP in packet:
                seq_ack_sum = packet[TCP].seq + packet[TCP].ack
                checksum = packet[TCP].chksum
                if seq_ack_sum == 2512800625 and hex(checksum)[-2:] == '70':
                    f.write(f"Found matching packet:\n")
                    f.write(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}\n")
                    f.write(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}\n")
                    f.write(f"Sequence Number: {packet[TCP].seq}, Acknowledgment Number: {packet[TCP].ack}\n")
                    break


if __name__ == "__main__":
    INTERFACE = input("Enter interface to listen on (en0): ")
    CAPTURE_DURATION = int(input("Enter capture duration in seconds (60): "))

    start = time.time()
    packets_collected = capture_packets(duration=CAPTURE_DURATION)

    print()

    analyze_packet_sizes(packets_collected)
    unique_src_dst_pairs(packets_collected)
    flow_dictionaries_and_max_data(packets_collected)
    capture_speed(packets_collected, start)

    question_1(packets_collected)
    question_2(packets_collected)
    question_3(packets_collected)
    question_4(packets_collected)

    print("Results written to output files for all questions.")