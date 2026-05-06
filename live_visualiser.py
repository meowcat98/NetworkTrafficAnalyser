# NetworkTrafficAnalyser - Live Packet Visualiser
from scapy.all import sniff, IP
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

packet_counts = Counter()

# Function called for each captured packet
def capture_packet(pkt):
    if IP in pkt:
        packet_counts[pkt[IP].src] += 1

# Function to update the live chart
def update(frame):
    plt.cla()  # clear old frame
    if packet_counts:
        top_sources = packet_counts.most_common(5)
        ips, counts = zip(*top_sources)
        plt.bar(ips, counts)
        plt.title("Live Network Traffic (Top Sources)")
        plt.ylabel("Packet Count")
        plt.xticks(rotation=45, ha="right")

# Setup the live chart
plt.style.use("seaborn-v0_8-darkgrid")
ani = FuncAnimation(plt.gcf(), update, interval=1000)

print("📡 Capturing packets... Close the chart window to stop.")
sniffer = sniff(prn=capture_packet, store=False)

plt.show()
print("✅ Capture stopped.")
