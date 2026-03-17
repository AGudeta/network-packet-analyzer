from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import json
from datetime import datetime
import atexit
import socket

# Storage for tracking traffic
port_tracker = defaultdict(set)
packet_counter = defaultdict(int)
last_reset = time.time()
alerts = []
alerted_ips = set()

SUS_PORTS = {23, 4444, 6667, 1337, 31337}
WHITELIST = {
    "142.250.177.78",    # Google
}
PORT_SCAN_THRESHOLD = 10
HIGH_TRAFFIC_THRESHOLD = 1000
RESET_INTERVAL = 60
def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip
def analyze_packet(packet):
    global last_reset

    # Reset counters every 60 sec
    if time.time() - last_reset > RESET_INTERVAL:
        port_tracker.clear()
        packet_counter.clear()
        last_reset = time.time()
        print("\n[INFO] Counters reset\n")

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        # Count packets per source IP
        packet_counter[src] += 1

        if TCP in packet:
            port = packet[TCP].dport
            port_tracker[src].add(port)
            print(f"TCP | {src} -> {dst} | Port: {port}")

        elif UDP in packet:
            port = packet[UDP].dport
            print(f"UDP | {src} -> {dst} | Port: {port}")

        # Detection 1: Port scan
        if len(port_tracker[src]) >= PORT_SCAN_THRESHOLD and src not in WHITELIST and src not in alerted_ips:
            alerted_ips.add(src)
            alert = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "PORT SCAN",
                "src": src,
                "hostname": resolve_ip(src),
                "details": f"Hit {len(port_tracker[src])} ports"
            }
            alerts.append(alert)
            print(f"PORT SCAN DETECTED | {resolve_ip(src)} {src} hit {len(port_tracker[src])} ports\n")

        # Detection 2: High traffic
        if packet_counter[src] >= HIGH_TRAFFIC_THRESHOLD and src not in WHITELIST and src not in alerted_ips:
            alerted_ips.add(src)
            alert = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "HIGH TRAFFIC",
                "src": src,
                "hostname": resolve_ip(src),
                "details": f"Sent {packet_counter[src]} packets"
            }
            alerts.append(alert)
            print(f"\n🚨 HIGH TRAFFIC DETECTED |{resolve_ip(src)} ({src}) sent {packet_counter[src]} packets\n")
        # Detection 3: Suspicious port
        if TCP in packet and packet[TCP].dport in SUS_PORTS:
            alert = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "SUSPICIOUS PORT",
                "src": src,
                "hostname": resolve_ip(src),
                "details": f"Hit port {packet[TCP].dport}"
            }
            alerts.append(alert)
            print(f"SUSPICIOUS PORT | {resolve_ip(src)} ({src}) -> {dst} | Port: {packet[TCP].dport}\n")


def save_alerts():
  end_time = datetime.now()
  duration = int(end_time.timestamp() - last_reset)
  top_talker = max(packet_counter, key=packet_counter.get) if packet_counter else "N/A"
  top_talker_count = packet_counter[top_talker] if packet_counter else 0
  total_packets = sum(packet_counter.values())

  summary = {
      "session_end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
      "duration_seconds": duration,
      "total_packets_captured": total_packets,
      "total_alerts": len(alerts),
      "top_talker": top_talker,
      "top_talker_packets": top_talker_count,
      "alerts": alerts
  }
  with open("alerts.json", "w") as f:
    json.dump(summary, f, indent=4)

    print(f"""Session Summary:
        Duration:          {duration} seconds
        Packets captured:  {total_packets}
        Alerts fired:      {len(alerts)}
        Top talker:        {top_talker} ({top_talker_count} packets)
        Alerts saved to:   alerts.json """)


atexit.register(save_alerts)

print("Starting packet capture... Press CTRL+C to stop")
sniff(prn=analyze_packet, store=False)