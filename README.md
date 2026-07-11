# CodeAlpha Network Sniffer

A Python-based network packet sniffer built for the CodeAlpha Cybersecurity Internship (Task 1). Captures live network traffic, parses packet headers, previews payload data, logs everything to CSV, and prints a protocol breakdown summary.

## Features

- Live packet capture using `scapy`
- Parses IP, TCP, UDP, and ICMP headers
- Displays source/destination IPs, ports, and TCP flags
- Previews payload data (shows plaintext for unencrypted protocols like HTTP, and demonstrates how HTTPS/TLS traffic appears as unreadable ciphertext)
- Logs every captured packet to a CSV file for later analysis
- Prints a summary of protocol distribution after capture completes

## Requirements

- Python 3.7+
- `scapy` library
- Linux (or macOS) — raw packet capture requires root privileges

## Installation

```bash
pip install scapy
```

## Usage

Run with root privileges (required for raw socket access):

```bash
sudo python3 network_sniffer.py
```

The script captures 30 packets by default (configurable via `PACKET_COUNT` in the script), then stops and prints a summary.

## Output

**Terminal output** (live, per packet):
```
[+] 2026-07-11 16:32:29 | 192.168.64.4 -> 34.223.124.45 | TCP | 58934->80 | S
```

**CSV log** (`captured_packets.csv`), with columns:

| Column | Description |
|---|---|
| timestamp | When the packet was captured |
| src_ip / dst_ip | Source and destination IP addresses |
| protocol | TCP, UDP, or ICMP |
| src_port / dst_port | Source and destination ports (TCP/UDP only) |
| flags | TCP connection flags, or ICMP type/code |
| payload_preview | First 80 bytes of payload data, decoded where possible |

**Summary** (printed after capture ends):
```
========================================
CAPTURE SUMMARY
========================================
Total packets captured: 30
  TCP: 18 packets (60.0%)
  UDP: 6 packets (20.0%)
  ICMP: 6 packets (20.0%)
========================================
Full log saved to: captured_packets.csv
```

## What I learned

- How the TCP three-way handshake (SYN → SYN-ACK → ACK) and connection teardown (FIN-ACK / RST) work in practice
- The difference between connection-oriented TCP and connectionless UDP
- Why HTTPS/TLS payloads appear as unreadable ciphertext, while plain HTTP payloads are fully readable — a direct illustration of why encryption matters
- How DNS resolution (UDP port 53) precedes almost every outbound connection
- Practical use of `scapy` for packet parsing and header extraction

## Disclaimer

This tool is for educational purposes only. Only capture traffic on networks you own or have explicit permission to monitor.

## Author

Built as part of the CodeAlpha Cybersecurity Internship.
