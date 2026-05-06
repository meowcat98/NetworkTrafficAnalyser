# NetworkTrafficAnalyser - Simple Analysis & Charts
import csv
from collections import Counter
import matplotlib.pyplot as plt

CSV_FILE = "packets.csv"

# Count protocols and IPs
protocols = Counter()
sources = Counter()
destinations = Counter()

with open(CSV_FILE, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        protocols[row["protocol"]] += 1
        sources[row["src_ip"]] += 1
        destinations[row["dst_ip"]] += 1

# Print summary
print("\nProtocol counts:", dict(protocols))
print("\nTop 5 sources:")
for ip, count in sources.most_common(5): print(f"  {ip:>16} - {count}")
print("\nTop 5 destinations:")
for ip, count in destinations.most_common(5): print(f"  {ip:>16} - {count}")

# Make charts
plt.figure()
plt.bar(protocols.keys(), protocols.values())
plt.title("Protocol Distribution")
plt.savefig("protocol_chart.png")

plt.figure()
ips, counts = zip(*sources.most_common(5))
plt.bar(ips, counts)
plt.title("Top 5 Source IPs")
plt.xticks(rotation=45)
plt.savefig("sources_chart.png")

print("\n✅ Charts saved: protocol_chart.png and sources_chart.png")
