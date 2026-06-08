# Network Sniffer using Python and Scapy

## Overview

This project is a Python-based Network Sniffer developed using the Scapy library on Kali Linux. The tool captures and analyzes network packets in real time, providing insights into network traffic, communication protocols, source and destination addresses, ports, and packet payloads.

The project was developed as part of a Cyber Security internship to understand network monitoring, packet analysis, and the fundamentals of network protocols.

---

## Features

* Real-time packet capture
* Source and Destination IP extraction
* TCP, UDP, and ICMP protocol identification
* Source and Destination Port detection
* Payload inspection and analysis
* Live packet counting
* Protocol-wise traffic statistics
* Traffic filtering (TCP/UDP/ICMP)
* Packet logging to text files
* PCAP file generation for Wireshark analysis
* Color-coded terminal output
* Graceful termination with final statistics

---

## Technologies Used

* Python 3
* Scapy
* Colorama
* Kali Linux
* VMware Workstation
* Wireshark

---

## Project Workflow

1. Capture network packets from the selected network interface.
2. Extract source and destination IP addresses.
3. Identify communication protocols.
4. Analyze transport layer ports.
5. Inspect packet payloads.
6. Maintain protocol statistics.
7. Log packet details into a file.
8. Export captured traffic into a PCAP file.
9. Analyze exported packets using Wireshark.

---

## Learning Outcomes

* Understanding of TCP/IP networking
* Packet structure analysis
* Network traffic monitoring
* Protocol identification
* Cybersecurity fundamentals
* Packet capture and inspection techniques
* Network troubleshooting concepts

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Run the Program

```bash
sudo python3 sniffer.py
```

---

## Output Files

| File           | Description                                |
| -------------- | ------------------------------------------ |
| packet_log.txt | Stores captured packet information         |
| capture.pcap   | Packet capture file for Wireshark analysis |

---

## Future Enhancements

* GUI-based dashboard
* Intrusion Detection Features
* Suspicious Traffic Detection
* Real-time Traffic Visualization
* Email Alert System
* Machine Learning-based Traffic Classification

---

## Author

**Nikhil Reddy**

Cyber Security Intern | Computer Science & Engineering Student
