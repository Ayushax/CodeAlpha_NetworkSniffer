"""
Basic Network Sniffer
CodeAlpha Cybersecurity Internship - Task 1

Captures live network traffic, parses packet headers (IP, TCP, UDP, ICMP),
previews payload data, logs everything to CSV, and prints a summary.
"""

import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# ---------- Configuration ----------
CSV_FILE = "captured_packets.csv"
PACKET_COUNT = 30  # how many packets to capture before stopping

# ---------- Tracking state ----------
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
total_packets = 0


def setup_csv():
    """Create the CSV file and write the header row before capture starts."""
    with open(CSV_FILE, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "src_ip", "dst_ip", "protocol",
            "src_port", "dst_port", "flags", "payload_preview"
        ])


def get_payload_preview(packet):
    """Extract a short, safe-to-print preview of the packet's data, if any."""
    if Raw not in packet:
        return ""
    payload = packet[Raw].load
    try:
        preview = payload.decode('utf-8', errors='replace')[:80]
        return preview.replace('\n', ' ').replace('\r', '').replace(',', ';')
    except Exception:
        return str(payload[:40])


def handle_packet(packet):
    """Callback run by scapy for every captured packet."""
    global total_packets

    if IP not in packet:
        return  # skip non-IP traffic (e.g. ARP)

    ip_layer = packet[IP]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip, dst_ip = ip_layer.src, ip_layer.dst
    proto, sport, dport, flags = "OTHER", "", "", ""

    if TCP in packet:
        tcp_layer = packet[TCP]
        proto = "TCP"
        sport, dport = tcp_layer.sport, tcp_layer.dport
        flags = str(tcp_layer.flags)
    elif UDP in packet:
        udp_layer = packet[UDP]
        proto = "UDP"
        sport, dport = udp_layer.sport, udp_layer.dport
    elif ICMP in packet:
        icmp_layer = packet[ICMP]
        proto = "ICMP"
        flags = f"type={icmp_layer.type},code={icmp_layer.code}"

    payload_preview = get_payload_preview(packet)

    stats[proto] += 1
    total_packets += 1

    print(f"[+] {timestamp} | {src_ip} -> {dst_ip} | {proto} | {sport}->{dport} | {flags}")

    with open(CSV_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, dst_ip, proto, sport, dport, flags, payload_preview])


def print_summary():
    """Print protocol breakdown once capture finishes."""
    print("\n" + "=" * 40)
    print("CAPTURE SUMMARY")
    print("=" * 40)
    print(f"Total packets captured: {total_packets}")
    for proto, count in stats.items():
        if count > 0:
            pct = (count / total_packets) * 100
            print(f"  {proto}: {count} packets ({pct:.1f}%)")
    print("=" * 40)
    print(f"Full log saved to: {CSV_FILE}")


if __name__ == "__main__":
    setup_csv()
    print(f"Logging to {CSV_FILE} ... capturing {PACKET_COUNT} packets.")
    sniff(prn=handle_packet, count=PACKET_COUNT)
    print_summary()
