# NetworkTrafficAnalyser - Save basic packet info to CSV
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv

CSV_FILE = "packets.csv"

# create CSV with headers
with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["time", "src_ip", "dst_ip", "protocol"])

def capture_packet(pkt):                        
    if IP in pkt:
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            pkt[IP].src,
            pkt[IP].dst,
            proto,
        ]
        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
        print(row)  # quick feedback in terminal

print("📦 Capturing 50 packets and saving to packets.csv ...")
# You can narrow it down, e.g. filter="tcp or udp" or "tcp port 80"
sniff(prn=capture_packet, count=50)
print("✅ Done. Open packets.csv to view.")
