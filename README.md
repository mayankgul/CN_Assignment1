# Network Packet Analyzer

This script captures and analyzes network packets using Scapy, extracts useful insights, and answers specific PCAP-related questions.

## Features
- Captures network packets for a specified duration.
- Analyzes packet sizes and generates a histogram.
- Identifies unique source-destination pairs with ports.
- Tracks network flows and identifies the pair with the most data transferred.
- Measures packet capture speed in packets per second (PPS) and Mbps.
- Answers specific PCAP-related questions based on TCP flags, port conditions, and checksum values.

## Requirements
- Python 3.7

## Installation and Setup

### 1. Clone the Repository
```sh
git clone https://github.com/mayankgul/CN_Assignment1
cd CN_Assignment1
```

### 2. Install dependencies
```sh
pip install -r requirements.txt
```


## Running the program

### 1. Turn off your internet connection

### 2. Find out active network interface

    Run the ifconfig command in your terminal to view list of all network interfaces.
    Find out the interface which is active.

### 3. Run the python program

```sh
python main.py
```

Specify the interface which you found out in the previous step (default en0.
Also, specify the capture duration in seconds (default 60).

### 4. Start tcpreplay

```sh
tcpreplay -i <active_interface> <path_to_pcap_file>
```

Note that the PCAP file is not included in the repository due to the large size. The file 7.pcap has been used to formulate the results here.