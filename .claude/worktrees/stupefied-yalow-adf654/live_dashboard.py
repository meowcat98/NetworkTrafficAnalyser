"""Network Traffic Visualiser and Analyzer
Author: Your Name (Student ID: 12345678)
University of Brighton
Module: CI601 The Computing Project
Date: 2026-03-10
Version: 1.0

This module implements a live network traffic dashboard intended for
educational purposes as part of the CI601 Computing Project. It captures
packets, applies filters, detects anomalies, and renders an interactive
matplotlib-based dashboard.

Dependencies:
    * Python 3.8+
    * scapy
    * matplotlib
    * psutil (optional, for performance metrics)

Installation:
    pip install scapy matplotlib psutil

Configuration:
    The behaviour is controlled by a JSON config file (default:
    config.json). See `validate_config` for structure and defaults.

Usage example:
    python live_dashboard.py --config custom_config.json
"""

# ---------- standard library imports ----------
import argparse
import csv
import json
import logging
import os
import re
import shutil
import time
from collections import Counter, deque, defaultdict
from datetime import datetime

# ---------- third-party imports ----------
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.patheffects as pe
from matplotlib.animation import FuncAnimation
from matplotlib.ticker import FuncFormatter
import numpy as np
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from scapy.arch.windows import get_windows_if_list
from scapy.utils import PcapWriter
try:
    import winsound
except ImportError:
    winsound = None

# ---------- local imports ----------
# (none at present)

# ---------- Logging setup ----------
logger = logging.getLogger("NetworkTrafficAnalyser")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
file_handler = logging.FileHandler('network_analyser.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


# theme colors - define both dark and light palettes
THEMES = {
    'dark': {
        'DARK_BG': "#0a0e27",
        'CARD_BG': "#151b28",
        'CARD_BG_ALPHA': 0.85,
        'CARD_BORDER': "#2a3f5f",
        'TEXT_COLOR': "#eeeeee",
        'ACCENT1': "#00d4ff",
        'ACCENT2': "#0066ff",
        'ACCENT3': "#00ff88",
        'ALERT_BG': "#2e001e",
    },
    'light': {
        'DARK_BG': "#ffffff",
        'CARD_BG': "#f0f0f0",
        'CARD_BG_ALPHA': 0.9,
        'CARD_BORDER': "#cccccc",
        'TEXT_COLOR': "#1a1a1a",
        'ACCENT1': "#0088cc",
        'ACCENT2': "#003399",
        'ACCENT3': "#00aa44",
        'ALERT_BG': "#ffe6e6",
    }
}

# default theme
current_theme = 'dark'

# shortcut to get current theme colors
def get_theme():
    return THEMES[current_theme]

# legacy names for compatibility
DARK_BG = THEMES['dark']['DARK_BG']
CARD_BG = THEMES['dark']['CARD_BG']
CARD_BG_ALPHA = THEMES['dark']['CARD_BG_ALPHA']
CARD_BORDER = THEMES['dark']['CARD_BORDER']
TEXT_COLOR = THEMES['dark']['TEXT_COLOR']
ACCENT1 = THEMES['dark']['ACCENT1']
ACCENT2 = THEMES['dark']['ACCENT2']
ACCENT3 = THEMES['dark']['ACCENT3']
ALERT_BG = THEMES['dark']['ALERT_BG']

# ---------- Command Line Arguments (MUST be before config load) ----------
parser = argparse.ArgumentParser(description='Network Traffic Analyzer with Advanced Filtering')
parser.add_argument('--config', default='config.json', help='Path to configuration file')
parser.add_argument('--interface', help='Override interface from config')
parser.add_argument('--duration', type=int, help='Capture duration in seconds')
parser.add_argument('--no-filters', action='store_true', help='Disable packet filters')
args = parser.parse_args()

# ---------- Configuration Management ----------
DEFAULT_CONFIG = {
    "capture": {
        "interface": "auto",
        "bpf_filter": "ip and not broadcast",
        "packet_limit": None,
        "duration_seconds": None
    },
    "filters": {
        "enabled": True,
        "ip_whitelist": [],
        "ip_blacklist": [],
        "port_whitelist": [],
        "port_blacklist": [],
        "port_range_min": 1,
        "port_range_max": 65535,
        "protocols": ["TCP", "UDP", "ICMP"],
        "min_packet_size": 0,
        "max_packet_size": 65535
    },
    "alerts": {
        "enabled": True,
        "port_scan_threshold": 15,
        "high_pps_threshold": 150,
        "alert_cooldown_seconds": 30,
        "suspicious_ports": [23, 135, 139, 445, 1433, 3389, 5900],
        "sound_enabled": True
    },
    "export": {
        "csv_enabled": True,
        "pcap_enabled": True,
        "csv_path": "live_packets.csv",
        "pcap_path": "live_capture.pcap",
        "alert_log_path": "security_alerts.log"
    },
    "display": {
        "window_width": 16,
        "window_height": 9,
        "update_interval_ms": 1000,
        "max_history_seconds": 30
    }
}


def validate_config(config):
    """Validate and sanitize a configuration dictionary.

    Missing sections or keys will be filled from ``DEFAULT_CONFIG`` and
    invalid values will be corrected or removed. Warnings are emitted via
    the logger so the user can correct their configuration file.
    """
    changed = False
    # ensure top-level sections exist
    for section, defaults in DEFAULT_CONFIG.items():
        if section not in config or not isinstance(config[section], dict):
            logger.warning(f"Missing config section '{section}', using defaults")
            config[section] = defaults.copy()
            changed = True
        else:
            for key, defval in defaults.items():
                if key not in config[section]:
                    logger.warning(f"Missing key '{key}' in section '{section}', using default {defval}")
                    config[section][key] = defval
                    changed = True
    # validate ports and IP lists
    filters = config.get("filters", {})
    ip_regex = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    for list_name in ("ip_whitelist", "ip_blacklist"):
        lst = filters.get(list_name, [])
        for ip in lst.copy():
            if not ip_regex.match(ip):
                logger.warning(f"Malformed IP address '{ip}' in {list_name}; removing")
                lst.remove(ip)
                changed = True
    for list_name in ("port_whitelist", "port_blacklist"):
        lst = filters.get(list_name, [])
        for port in lst.copy():
            if not isinstance(port, int) or port < 1 or port > 65535:
                logger.warning(f"Invalid port '{port}' in {list_name}; removing")
                lst.remove(port)
                changed = True
    # ensure port ranges are sensible
    minp = filters.get("port_range_min", 1)
    maxp = filters.get("port_range_max", 65535)
    if not (1 <= minp <= 65535):
        logger.warning("Invalid port_range_min; resetting to 1")
        filters["port_range_min"] = 1
        changed = True
    if not (1 <= maxp <= 65535):
        logger.warning("Invalid port_range_max; resetting to 65535")
        filters["port_range_max"] = 65535
        changed = True
    if minp > maxp:
        logger.warning("port_range_min greater than max; swapping values")
        filters["port_range_min"], filters["port_range_max"] = maxp, minp
        changed = True
    # duration value sanity
    cap = config.get("capture", {})
    dur = cap.get("duration_seconds")
    if dur is not None and (not isinstance(dur, (int, float)) or dur <= 0):
        logger.warning("Invalid duration_seconds; disabling capture duration")
        cap["duration_seconds"] = None
        changed = True
    if changed:
        logger.info("Configuration validation applied corrections.")
    return config

def load_config(config_file="config.json"):
    """Load configuration from JSON file, creating it if necessary.

    The returned dictionary is guaranteed to contain all required keys and
    will be passed through :func:`validate_config` to enforce correct types
    and sensible ranges. Any issues are logged and defaults are used where
    appropriate.
    """
    if not os.path.exists(config_file):
        logger.info(f"Config file not found, creating default at {config_file}")
        try:
            with open(config_file, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write default config: {e}")
        return validate_config(DEFAULT_CONFIG.copy())

    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        logger.info(f"Loaded configuration from: {config_file}")
        config = validate_config(config)
        return config
    except Exception as e:
        logger.error(f"Error loading config '{config_file}': {e}. Using defaults.")
        return validate_config(DEFAULT_CONFIG.copy())

def log_event(event_type, message):
    """Print a formatted timestamped console event."""
    print(f"[{time.strftime('%H:%M:%S')}] {event_type} {message}")


# Load configuration (default path; re-loaded with CLI args when run directly)
CONFIG = load_config()

# ---------- helpers ----------
def short_ip(ip: str) -> str:
    """Return a possibly truncated/beautified representation of an IP.

    The current implementation is a no-op but the function exists to make
    later changes easier (e.g. mapping private address ranges).
    """
    return ip

def kfmt(x, _):
    """Formatter for large numbers with thousands separators.

    Used by matplotlib tick formatters. Silently returns the original value
    if conversion fails.
    """
    try:
        return f"{int(x):,}"
    except Exception:
        return str(x)

def format_bytes(bytes_val):
    """Convert a byte count into a human-readable string with units.

    :param bytes_val: number of bytes
    :returns: string like "1.23 MB"
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} TB"


def console_action(message):
    """Print a timestamped console confirmation for demo actions."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")


def timestamped_path(base_path, timestamp, prefix=None):
    """Build a timestamped file path next to the original export target."""
    directory = os.path.dirname(base_path)
    stem, ext = os.path.splitext(os.path.basename(base_path))
    if prefix:
        stem = prefix
    filename = f"{stem}_{timestamp}{ext}"
    return os.path.join(directory, filename) if directory else filename


def reset_runtime_state(clear_alert_state=False):
    """Reset dashboard counters and history deques back to an empty state."""
    global packet_counter, filtered_counter, processed_counter, total_bytes, bytes_counter
    global start_time, last_time, last_update_time, prev_source_data, prev_dest_data, prev_port_data
    global alert_display_index, fade_phase

    source_counts.clear()
    dest_counts.clear()
    protocol_counts.clear()
    port_counts.clear()

    pps_history.clear()
    mbps_history.clear()
    stat_history['total_packets'].clear()
    stat_history['avg_pps'].clear()

    packet_counter = 0
    filtered_counter = 0
    processed_counter = 0
    total_bytes = 0
    bytes_counter = 0

    now = time.time()
    start_time = now
    last_time = now
    last_update_time = now

    prev_source_data = {}
    prev_dest_data = {}
    prev_port_data = {}

    if clear_alert_state:
        alerts.clear()
        ip_port_tracker.clear()
        ip_packet_rate.clear()
        alert_cooldown.clear()
        alert_display_index = 0
        fade_phase = 0.0


def export_current_data():
    """Snapshot the live CSV and PCAP exports with timestamped filenames."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    exported = []
    log_event("💾", "User action: Data EXPORTED")

    if CONFIG['export']['csv_enabled'] and csv_f and os.path.exists(CSV_PATH):
        try:
            csv_f.flush()
            if hasattr(csv_f, "fileno"):
                try:
                    os.fsync(csv_f.fileno())
                except Exception:
                    pass
            csv_export_path = timestamped_path(CSV_PATH, timestamp)
            shutil.copyfile(CSV_PATH, csv_export_path)
            exported.append(csv_export_path)
        except Exception as e:
            logger.error(f"Failed to export CSV snapshot: {e}")

    if CONFIG['export']['pcap_enabled'] and os.path.exists(PCAP_PATH):
        try:
            pcap_export_path = timestamped_path(PCAP_PATH, timestamp)
            shutil.copyfile(PCAP_PATH, pcap_export_path)
            exported.append(pcap_export_path)
        except Exception as e:
            logger.error(f"Failed to export PCAP snapshot: {e}")

    return exported


def save_screenshot():
    """Save the current dashboard figure to the screenshots directory."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs("screenshots", exist_ok=True)
    screenshot_path = os.path.join("screenshots", f"dashboard_{timestamp}.png")
    fig.savefig(screenshot_path, dpi=150, bbox_inches="tight")
    return screenshot_path


def apply_packet_filter(pkt) -> bool:
    """Return ``True`` if ``pkt`` passes all configured filters.

    Filters include IP/port whitelists/blacklists, protocol whitelist, and
    packet size limits. If filtering is disabled in the configuration, the
    function always returns ``True``.

    The logic is intentionally verbose for teaching purposes; students can
    trace how each clause contributes to the final decision.
    """
    if not CONFIG['filters']['enabled']:
        return True
    if IP not in pkt:
        return False

    filters = CONFIG['filters']
    src = pkt[IP].src
    dst = pkt[IP].dst
    pkt_size = len(pkt)

    # IP whitelist: packet must have either src/dst in list
    if filters['ip_whitelist']:
        if src not in filters['ip_whitelist'] and dst not in filters['ip_whitelist']:
            logger.debug(f"Packet from {src}->{dst} rejected: not in IP whitelist")
            return False

    # IP blacklist: reject if either endpoint in blacklist
    if filters['ip_blacklist']:
        if src in filters['ip_blacklist'] or dst in filters['ip_blacklist']:
            logger.debug(f"Packet from {src}->{dst} rejected: blacklisted IP")
            return False

    proto = "OTHER"
    sport = None
    dport = None

    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"

    if proto not in filters['protocols']:
        logger.debug(f"Packet protocol {proto} not in allowed list")
        return False

    # port-based checks only apply if sport/dport are present
    if sport or dport:
        if filters['port_whitelist']:
            if sport not in filters['port_whitelist'] and dport not in filters['port_whitelist']:
                logger.debug(f"Packet ports {sport}/{dport} not in whitelist")
                return False

        if filters['port_blacklist']:
            if sport in filters['port_blacklist'] or dport in filters['port_blacklist']:
                logger.debug(f"Packet ports {sport}/{dport} in blacklist")
                return False

        if sport:
            if sport < filters['port_range_min'] or sport > filters['port_range_max']:
                logger.debug(f"Source port {sport} out of range")
                return False
        if dport:
            if dport < filters['port_range_min'] or dport > filters['port_range_max']:
                logger.debug(f"Dest port {dport} out of range")
                return False

    if pkt_size < filters['min_packet_size'] or pkt_size > filters['max_packet_size']:
        logger.debug(f"Packet size {pkt_size} outside allowed bounds")
        return False

    return True

# ---------- choose interface ----------
IFACE_GUID = r"\Device\NPF_{4D0D7188-9E1C-40E6-8E89-948FFC10A9A6}"
IFACE_FRIENDLY = None

def pick_iface():
    """Attempt to choose a sensible network interface on Windows.

    The function scans ``get_windows_if_list`` for an interface with an
    IPv4 address, skipping virtual adapters. Wireless interfaces are
    preferred over Ethernet. The first suitable interface becomes the
    fallback choice.

    :returns: interface name string or ``None`` if not found.
    """
    preferred, fallback = None, None
    try:
        for i in get_windows_if_list():
            name = (i.get("name", "") + " " + i.get("description", "")).lower()
            ips = i.get("ips") or []
            # ignore interfaces without IPv4 or with link-local/loopback
            has_ipv4 = any((ip.count(".") == 3) and not ip.startswith(("127.", "169.254.", "0.")) for ip in ips)
            if not has_ipv4:
                continue
            if any(bad in name for bad in ("virtualbox", "vmware", "loopback", "host-only")):
                continue
            # prefer wireless
            if "wi-fi" in name or "wlan" in name:
                return i["name"]
            if "ethernet" in name:
                fallback = i["name"]
            if preferred is None:
                preferred = i["name"]
        return fallback or preferred
    except Exception as e:
        logger.error(f"Error enumerating network interfaces: {e}")
        return None

IFACE = IFACE_GUID or IFACE_FRIENDLY or pick_iface()
if CONFIG['capture']['interface'] != "auto":
    IFACE = CONFIG['capture']['interface']
if args.interface:
    IFACE = args.interface

if not IFACE:
    logger.error("No network interface found or specified. Run as administrator and verify interfaces.")
else:
    logger.info(f"Using interface: {IFACE}")

# ---------- counters / state ----------
source_counts = Counter()
dest_counts = Counter()
protocol_counts = Counter()
port_counts = Counter()

pps_history = deque(maxlen=CONFIG['display']['max_history_seconds'])
mbps_history = deque(maxlen=CONFIG['display']['max_history_seconds'])  # ✅ bandwidth graph

# history for stats cards (used for trend arrows/percent)
stat_history = {
    'total_packets': deque(maxlen=30),
    'avg_pps': deque(maxlen=30),
    'health_score': deque(maxlen=30),
    # we already have mbps_history for data rate
}

last_time = time.time()
packet_counter = 0
filtered_counter = 0
processed_counter = 0  # total packets seen by the sniffer (including filtered)
total_bytes = 0
peak_pps = 0.0

bytes_counter = 0  # ✅ bytes counted in the last 1-second window
start_time = time.time()

# performance metrics are tracked elsewhere in the dashboard state

SERVICE = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
}

SUSPICIOUS_PORTS_INFO = {
    23: "Telnet - Unencrypted remote access",
    135: "Windows RPC - Often exploited",
    139: "NetBIOS - File sharing vulnerability",
    445: "SMB - Ransomware target",
    1433: "MSSQL - Database service exposure",
    3389: "RDP - Remote desktop access",
    5900: "VNC - Remote control service",
}

# ---------- Anomaly Detection ----------
ip_port_tracker = defaultdict(set)
ip_packet_rate = defaultdict(list)
alerts = deque(maxlen=10)
alert_cooldown = {}
last_alert_time = 0.0


def register_alert(timestamp, short_message, full_message):
    """Record a newly triggered alert and mark its arrival time."""
    global last_alert_time
    alerts.append({
        "timestamp": timestamp,
        "short": short_message,
        "full": full_message,
    })
    last_alert_time = timestamp
    if "PORT SCAN" in short_message:
        log_event("⚠️", f"ALERT: PORT SCAN detected from {short_message.split(': ', 1)[1].split(' → ')[0]}")
    elif "TRAFFIC ALERT" in short_message:
        src = short_message.split(': ', 1)[1].split(' → ')[0]
        pps_text = short_message.split('→ ')[1].replace(' pps', '')
        log_event("⚠️", f"ALERT: HIGH TRAFFIC from {src} ({pps_text} pps)")
    elif "PORT ALERT" in short_message:
        src = short_message.split(': ', 1)[1].split(' → ')[0]
        dst = short_message.split('→ ')[1].split(' ')[0]
        log_event("⚠️", f"ALERT: SUSPICIOUS PORT access from {src} to {dst}")


def play_alert_sound():
    """Play a short attention-getting beep for a fresh security alert."""
    if not CONFIG['alerts'].get('sound_enabled', True):
        return
    if winsound is None:
        print("[WARNING] Alert sound failed (winsound not available)")
        return
    try:
        winsound.Beep(1000, 200)
    except Exception:
        print("[WARNING] Alert sound failed (winsound not available)")


def format_port_scan_alert(src_ip, unique_ports):
    short_message = f"⚠️ PORT SCAN: {src_ip} → {unique_ports} ports"
    full_message = (
        "⚠️ SECURITY ALERT: Potential port scan detected\n"
        f"Source: {src_ip}\n"
        f"Activity: {unique_ports} unique ports contacted in 5 seconds\n"
        "Risk: This behavior may indicate network reconnaissance\n"
        "Action: Investigate source device for unauthorized scanning tools"
    )
    return short_message, full_message


def format_high_traffic_alert(src_ip, pps, threshold):
    short_message = f"⚠️ TRAFFIC ALERT: {src_ip} → {pps:.0f} pps"
    full_message = (
        "⚠️ TRAFFIC ALERT: Abnormal packet rate detected\n"
        f"Source: {src_ip}\n"
        f"Rate: {pps:.0f} packets/second (threshold: {threshold} pps)\n"
        "Risk: May indicate bandwidth abuse, DDoS, or data exfiltration\n"
        "Action: Monitor for sustained high traffic patterns"
    )
    return short_message, full_message


def format_suspicious_port_alert(src_ip, dst_port):
    port_desc = SUSPICIOUS_PORTS_INFO.get(dst_port, SERVICE.get(dst_port, "Unknown service"))
    short_message = f"⚠️ PORT ALERT: {src_ip} → {dst_port}"
    full_message = (
        "⚠️ PORT ALERT: Connection to high-risk service\n"
        f"Source: {src_ip}\n"
        f"Port: {dst_port} ({port_desc})\n"
        "Risk: Legacy protocol vulnerable to interception\n"
        "Action: Verify legitimate use or block unencrypted protocols"
    )
    return short_message, full_message


def check_anomalies(src_ip, dst_port, timestamp):
    """Perform basic anomaly detection on packet metadata.

    Three checks are currently implemented:
    1. **Port scan detection** - if a single source IP touches more than
       ``port_scan_threshold`` unique destination ports within one session.
    2. **High packet rate** - if a source sends more than
       ``high_pps_threshold`` packets in one second.
    3. **Suspicious port access** - if a packet targets a port in the
       ``suspicious_ports`` list.

    Alerts are rate-limited using ``alert_cooldown_seconds`` to avoid
    flooding. When an alert fires it is appended to the ``alerts`` deque and
    a log entry is emitted.
    """
    if not CONFIG['alerts']['enabled']:
        return

    current_time = time.time()
    alert_config = CONFIG['alerts']

    # port scan: track unique destination ports per source IP
    if dst_port:
        ip_port_tracker[src_ip].add(dst_port)
        if len(ip_port_tracker[src_ip]) > alert_config['port_scan_threshold']:
            alert_key = f"port_scan_{src_ip}"
            last_alert = alert_cooldown.get(alert_key, 0)
            if current_time - last_alert > alert_config['alert_cooldown_seconds']:
                short_msg, full_msg = format_port_scan_alert(src_ip, len(ip_port_tracker[src_ip]))
                register_alert(timestamp, short_msg, full_msg)
                play_alert_sound()
                alert_cooldown[alert_key] = current_time
                logger.warning(full_msg)

    # high packets-per-second from a single IP
    ip_packet_rate[src_ip].append(timestamp)
    ip_packet_rate[src_ip] = [t for t in ip_packet_rate[src_ip] if timestamp - t <= 1.0]
    current_pps = len(ip_packet_rate[src_ip])

    if current_pps > alert_config['high_pps_threshold']:
        alert_key = f"high_pps_{src_ip}"
        last_alert = alert_cooldown.get(alert_key, 0)
        if current_time - last_alert > alert_config['alert_cooldown_seconds']:
            short_msg, full_msg = format_high_traffic_alert(src_ip, current_pps, alert_config['high_pps_threshold'])
            register_alert(timestamp, short_msg, full_msg)
            play_alert_sound()
            alert_cooldown[alert_key] = current_time
            logger.warning(full_msg)

    # suspicious port access (e.g. known malware or admin ports)
    if dst_port in alert_config['suspicious_ports']:
        alert_key = f"suspicious_{src_ip}_{dst_port}"
        last_alert = alert_cooldown.get(alert_key, 0)
        if current_time - last_alert > alert_config['alert_cooldown_seconds']:
            short_msg, full_msg = format_suspicious_port_alert(src_ip, dst_port)
            register_alert(timestamp, short_msg, full_msg)
            play_alert_sound()
            alert_cooldown[alert_key] = current_time
            logger.warning(full_msg)

# ---------- persistence ----------
session_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
CSV_PATH = timestamped_path(CONFIG['export']['csv_path'], session_timestamp)
PCAP_PATH = timestamped_path(CONFIG['export']['pcap_path'], session_timestamp)
ALERT_LOG = timestamped_path(CONFIG['export']['alert_log_path'], session_timestamp)

for path in (CSV_PATH, PCAP_PATH, ALERT_LOG):
    parent_dir = os.path.dirname(path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

console_action(f"💾 Exporting to: {os.path.basename(CSV_PATH)}")
console_action(f"💾 Exporting to: {os.path.basename(PCAP_PATH)}")
console_action(f"💾 Exporting to: {os.path.basename(ALERT_LOG)}")

csv_f = None
csv_w = None
pcap_w = None

if CONFIG['export']['csv_enabled']:
    csv_f = open(CSV_PATH, "a", newline="", encoding="utf-8")
    csv_w = csv.writer(csv_f)
    csv_w.writerow(["time", "src", "dst", "proto", "sport", "dport", "len"])

if CONFIG['export']['pcap_enabled']:
    pcap_w = PcapWriter(PCAP_PATH, append=True, sync=True)

# ---------- packet handler ----------
def capture_packet(pkt):
    """Callback executed by the sniffer for every packet seen.

    This function applies filtering rules, updates global counters used by
    the dashboard, writes to CSV/PCAP if enabled and forwards traffic to the
    anomaly detector. Packets that fail the filter are counted and discarded.

    :param pkt: scapy packet object
    """
    global packet_counter, filtered_counter, total_bytes, bytes_counter, processed_counter

    if not capturing:
        return

    timestamp = time.time()

    # every packet that arrives is 'processed' even if filtered out
    processed_counter += 1

    if not apply_packet_filter(pkt):
        filtered_counter += 1
        return

    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        pkt_len = len(pkt)

        source_counts[src] += 1
        dest_counts[dst] += 1

        total_bytes += pkt_len
        bytes_counter += pkt_len  # ✅ count bytes in current 1s window

        if TCP in pkt:
            protocol_counts["TCP"] += 1
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            protocol_counts["UDP"] += 1
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            protocol_counts["ICMP"] += 1
            proto = "ICMP"
            sport, dport = "", ""
        else:
            protocol_counts["Other"] += 1
            proto, sport, dport = "OTHER", "", ""

        if isinstance(dport, int):
            svc = SERVICE.get(dport, str(dport))
            port_counts[svc] += 1
            check_anomalies(src, dport, timestamp)

        if csv_w:
            try:
                csv_w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), src, dst, proto, sport, dport, pkt_len])
            except Exception as e:
                logger.error(f"Failed to write CSV row: {e}")

        if pcap_w:
            try:
                pcap_w.write(pkt)
            except Exception as e:
                logger.error(f"Failed to write pcap: {e}")

        packet_counter += 1
        if packet_counter in (100, 1000, 10000):
            log_event("📊", f"Milestone: {packet_counter:,} packets captured")

# ---------- styling ----------
# apply universal rcParams for dark theme
plt.rcParams.update({
    "figure.facecolor": DARK_BG,
    "axes.facecolor": CARD_BG,
    "savefig.facecolor": DARK_BG,
    "axes.edgecolor": "#444",
    "axes.labelcolor": TEXT_COLOR,
    "xtick.color": TEXT_COLOR,
    "ytick.color": TEXT_COLOR,
    "text.color": TEXT_COLOR,
    "axes.titlesize": 10,
    "axes.titleweight": "bold",
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "figure.titlesize": 14,
    "legend.facecolor": CARD_BG,
    "legend.edgecolor": "#444",
    "grid.color": "#444",
    "grid.alpha": 0.3,
})
# seaborn style may override some colours so we set it first then adjust constants
try:
    plt.style.use("dark_background")
except Exception:
    pass

# helper to make each subplot look like a card

def style_card(ax, theme_colors=None):
    if theme_colors is None:
        theme_colors = get_theme()
    # set background with alpha for slight transparency
    ax.patch.set_facecolor(theme_colors['CARD_BG'])
    ax.patch.set_alpha(theme_colors['CARD_BG_ALPHA'])
    # rounded corners and border
    try:
        ax.patch.set_boxstyle("round", pad=0.3, rounding_size=0.05)
    except Exception:
        pass
    for spine in ax.spines.values():
        spine.set_edgecolor(theme_colors['CARD_BORDER'])
        spine.set_linewidth(1)
    ax.title.set_color(theme_colors['TEXT_COLOR'])
    ax.title.set_ha("center")
    ax.xaxis.label.set_color(theme_colors['TEXT_COLOR'])
    ax.yaxis.label.set_color(theme_colors['TEXT_COLOR'])
    ax.tick_params(colors=theme_colors['TEXT_COLOR'])
    # add subtle glow by using path effect on spine and patch edge
    glow = [pe.withStroke(linewidth=3, foreground="#000000", alpha=0.3)]
    ax.patch.set_path_effects(glow)
    # reduce internal plotting area to create padding
    pos = ax.get_position()
    ax.set_position([pos.x0 + 0.02*pos.width,
                     pos.y0 + 0.02*pos.height,
                     pos.width * 0.96,
                     pos.height * 0.96])

plt.rcParams.update({"figure.autolayout": False})

# ---------- Animation State Tracking ----------
# store previous data for smooth transitions
prev_source_data = {}
prev_dest_data = {}
prev_port_data = {}
last_update_time = time.time()
alert_display_index = 0  # cycle through multiple alerts
fade_phase = 0.0  # for fade transitions between alerts

def get_animation_progress(frame_time, last_update):
    """Calculate how far into the current 1-second animation we are (0.0 to 1.0)"""
    elapsed = frame_time - last_update
    progress = min(elapsed / 1.0, 1.0)  # cap at 1.0 (1 second)
    return progress

def interpolate_value(old_val, new_val, progress):
    """Smoothly interpolate between old and new values"""
    if old_val is None:
        return new_val
    return old_val + (new_val - old_val) * progress

def get_card_shimmer_alpha(update_time):
    """Subtle shimmer effect on card borders during updates (very subtle)"""
    shimmer = 0.3 + 0.1 * np.sin(update_time * 6)  # 6 Hz shimmer
    return shimmer

def hex_to_rgba(hex_color, alpha=1.0):
    """Convert hex color to RGBA tuple"""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16)/255.0 for i in (0,2,4)) + (alpha,)


def calculate_health_score(current_pps, runtime_seconds):
    """Calculate a simple 0-100 network health score."""
    score = 100.0

    recent_alerts = sum(1 for alert in alerts if time.time() - alert["timestamp"] <= 60)
    score -= recent_alerts * 20

    if current_pps > 100:
        score -= 10

    if current_pps < 1 and runtime_seconds > 30:
        score -= 5

    total_packets = sum(source_counts.values()) + filtered_counter
    if total_packets > 0:
        filtered_ratio = filtered_counter / total_packets
        if filtered_ratio > 0.10:
            score -= 5

    if protocol_counts:
        proto_total = sum(protocol_counts.values())
        if proto_total > 0:
            top_proto_ratio = max(protocol_counts.values()) / proto_total
            if top_proto_ratio > 0.95:
                score -= 10

    return max(0, min(100, int(round(score))))


def get_health_label(score):
    """Return the health label and color for a score."""
    if score >= 80:
        return "Excellent", "#00ff88"
    if score >= 60:
        return "Good", "#ffaa00"
    if score >= 40:
        return "Fair", "#ff9500"
    return "Poor", "#ff3333"


def tooltip_bbox(theme):
    """Return shared tooltip styling."""
    return dict(
        boxstyle="round,pad=0.35",
        facecolor=hex_to_rgba(theme["CARD_BG"], 0.9),
        edgecolor=theme["CARD_BORDER"],
        linewidth=1,
    )


def ensure_hover_annotation(ax):
    """Create or move the shared hover annotation onto the active axes."""
    global hover_annot, hover_annot_ax
    if hover_annot is None or hover_annot_ax is not ax:
        if hover_annot is not None:
            try:
                hover_annot.remove()
            except Exception:
                pass
        theme = get_theme()
        hover_annot = ax.annotate(
            "",
            xy=(0, 0),
            xytext=(12, 12),
            textcoords="offset points",
            bbox=tooltip_bbox(theme),
            color="white",
            fontsize=9,
            visible=False,
            zorder=200,
        )
        hover_annot_ax = ax
    return hover_annot


def show_hover_annotation(ax, text, xy):
    """Display the shared hover annotation at a position."""
    annot = ensure_hover_annotation(ax)
    theme = get_theme()
    annot.set_text(text)
    annot.xy = xy
    annot.get_bbox_patch().set(facecolor=hex_to_rgba(theme["CARD_BG"], 0.9), edgecolor=theme["CARD_BORDER"], linewidth=1)
    annot.get_text().set_color("white")
    annot.get_text().set_fontsize(9)
    annot.set_visible(True)
    fig.canvas.draw_idle()


def hide_hover_annotation():
    """Hide the shared hover annotation."""
    if hover_annot is not None:
        hover_annot.set_visible(False)
        fig.canvas.draw_idle()


def get_capture_status_style():
    """Return the capture-state badge label and color."""
    if capture_state == "PAUSED":
        return "🟡 PAUSED", "#ffaa00"
    if capture_state == "STOPPED":
        return "🔴 STOPPED", "#ff3333"
    return "🟢 CAPTURING", "#00ff88"

# ---------- rendering ----------
reset_flash_until = 0.0
about_overlay_visible = False

def reset_statistics():
    """Clear live counters without stopping packet capture."""
    global reset_flash_until, tooltip_state
    reset_runtime_state(clear_alert_state=True)
    reset_flash_until = time.time() + 1.0
    tooltip_state["pinned"] = False
    console_action("🔄 Statistics RESET - Counters cleared, capture continues")
    log_event("🔄", "User action: Statistics RESET")

def update(_frame):
    global packet_counter, bytes_counter, last_time, last_update_time, prev_source_data, prev_dest_data, prev_port_data, peak_pps, reset_flash_until, about_overlay_visible
    # reset tooltip target list each cycle
    bar_collections.clear()
    try:
        # get current theme colors
        theme = get_theme()
        now = time.time()
        elapsed = now - last_time
        pps = packet_counter / max(elapsed, 1e-6)
        mbps = (bytes_counter * 8) / (elapsed * 1_000_000)  # ✅ Mbps

        pps_history.append(pps)
        mbps_history.append(mbps)
        peak_pps = max(peak_pps, pps)

        packet_counter = 0
        bytes_counter = 0
        last_time = now

        # debug log
        # print(f"update called (elapsed={elapsed:.2f})")

        # clear figure and reset background using current theme
        plt.clf()
        fig = plt.gcf()
        fig.patch.set_facecolor(theme['DARK_BG'])
    except Exception as e:
        print("update error start", e)
        import traceback; traceback.print_exc()
        return

    runtime = now - start_time
    runtime_str = f"{int(runtime//3600):02d}:{int((runtime%3600)//60):02d}:{int(runtime%60):02d}"
    total_packets = sum(source_counts.values())
    avg_pps = total_packets / max(runtime, 1)

    filter_status = "ON" if CONFIG['filters']['enabled'] else "OFF"
    status_text, status_color = get_capture_status_style()
    health_score = calculate_health_score(pps, runtime)
    stat_history['health_score'].append(health_score)
    health_label, health_color = get_health_label(health_score)
    if len(stat_history['health_score']) > 1:
        prev_health = stat_history['health_score'][-2]
        if health_score > prev_health + 2:
            health_trend = "↑"
        elif health_score < prev_health - 2:
            health_trend = "↓"
        else:
            health_trend = "→"
    else:
        health_trend = "→"

    if len(stat_history['health_score']) == 1 or abs(health_score - stat_history['health_score'][-2]) >= 5:
        console_action(f"🛡️ Network Health: {health_score}/100 ({health_label}) {health_trend}")
    # Reserve significant top space for clean header layout
    fig.subplots_adjust(left=0.05, right=0.97, top=0.68, bottom=0.10, hspace=0.62, wspace=0.42)

    # gradient header rectangle behind title/stats - spans full header height
    ax_gradient = fig.add_axes([0, 0.75, 1, 0.25], zorder=0)
    ax_gradient.axis('off')
    grad = np.linspace(0,1,256)
    grad = np.vstack((grad,grad))
    ax_gradient.imshow(grad, aspect='auto', cmap=plt.get_cmap('Blues'),
                       extent=[0,1,0,1], alpha=0.15)

    title_text = "🔄 RESETTING..." if time.time() < reset_flash_until else "🔒 Live Network Traffic Dashboard"
    fig.text(
        0.015,
        0.958,
        title_text,
        ha='left',
        va='center',
        fontsize=12.0,
        weight='bold',
        color=theme['TEXT_COLOR'],
        transform=fig.transFigure,
        zorder=30,
    )
    fig.text(
        0.38,
        0.958,
        f"Filters: {filter_status}",
        ha='left',
        va='center',
        fontsize=8.5,
        weight='bold',
        color=theme['TEXT_COLOR'],
        transform=fig.transFigure,
        zorder=30,
        bbox=dict(
            boxstyle='round,pad=0.18',
            facecolor=theme['CARD_BG'],
            edgecolor=theme['CARD_BORDER'],
            linewidth=0.8,
            alpha=0.90,
        ),
    )
    fig.text(
        0.985,
        0.958,
        status_text,
        ha='right',
        va='center',
        fontsize=8.5,
        weight='bold',
        color=status_color,
        transform=fig.transFigure,
        zorder=30,
        bbox=dict(
            boxstyle='round,pad=0.18',
            facecolor=status_color,
            edgecolor=status_color,
            linewidth=0.8,
            alpha=0.25,
        ),
    )

    # stats cards with status, trends, and sparklines
    # update history deques for trend calculations
    stat_history['total_packets'].append(total_packets)
    stat_history['avg_pps'].append(avg_pps)

    card_width = 0.162
    card_height = 0.088
    card_y = 0.80
    # compute network health score (drawing deferred until after cards)
    health = 100
    health -= min(avg_pps / 2, 50)
    health -= len(alerts) * 10
    health -= min(len(ip_port_tracker) * 2, 20)
    health = max(0, min(100, health))
    if health >= 80:
        health_color = theme['ACCENT3']
    elif health >= 50:
        health_color = "#ffaa00"
    else:
        health_color = "#ff3333"
    card_xs = [0.03, 0.22, 0.41, 0.60, 0.79]
    # include numeric value for trend computations where applicable
    card_defs = [
        ("🕒 Uptime", runtime_str, None, None, None, theme['ACCENT1']),
        ("📦 Total", f"{total_packets:,} pkts", stat_history['total_packets'], None, total_packets, theme['ACCENT2']),
        ("⚡ PPS", f"{avg_pps:.2f}", stat_history['avg_pps'], pps_history, avg_pps, theme['ACCENT3']),
        ("💾 Data", f"{format_bytes(total_bytes)}", mbps_history, mbps_history, mbps_history[-1] if mbps_history else 0, theme['ACCENT1']),
        ("🛡️ Health", f"{health_score}/100", stat_history['health_score'], stat_history['health_score'], health_score, health_color),
    ]

    # draw each card using its own axes
    try:
        for idx, (label, value, hist_queue, spark_data, numeric_val, accent_color) in enumerate(card_defs):
            x0 = card_xs[idx]
            ax_card = fig.add_axes([x0, card_y, card_width, card_height], zorder=3)
            ax_card.axis('off')
            # background rectangle
            rect = plt.Rectangle((0,0),1,1, transform=ax_card.transAxes,
                                 facecolor=theme['CARD_BG'], alpha=theme['CARD_BG_ALPHA'],
                                 edgecolor=theme['CARD_BORDER'], linewidth=1)
            ax_card.add_patch(rect)

            # determine status dot color (green by default, red if metric falling)
            status_color = accent_color
            if numeric_val is not None and hist_queue and len(hist_queue) > 1:
                prev_val = hist_queue[-2]
                if prev_val != 0 and numeric_val < prev_val:
                    status_color = 'red'

            # status dot
            ax_card.text(0.05, 0.6, '●', color=status_color,
                         fontsize=12, ha='center', va='center', transform=ax_card.transAxes)
            # icon + label
            ax_card.text(0.12, 0.75, label, color=theme['TEXT_COLOR'],
                         fontsize=8, transform=ax_card.transAxes)
            # main value
            ax_card.text(0.12, 0.45, value, color=theme['TEXT_COLOR'],
                         fontsize=11, weight='bold', transform=ax_card.transAxes)
            # trend arrow and percentage
            pct = 0
            arrow = '→'
            arrow_color = theme['TEXT_COLOR']
            if numeric_val is not None and hist_queue and len(hist_queue) > 1:
                prev_val = hist_queue[-2]
                if prev_val != 0:
                    pct = (numeric_val - prev_val) / prev_val * 100
                if numeric_val > prev_val:
                    arrow = '↑'
                    arrow_color = 'green'
                elif numeric_val < prev_val:
                    arrow = '↓'
                    arrow_color = 'green'
            ax_card.text(0.7, 0.5, f"{arrow}{pct:+.0f}%", color=arrow_color,
                         fontsize=8, transform=ax_card.transAxes)
            # sparkline
            if spark_data is not None:
                # small inset axes inside card
                spark_ax = fig.add_axes([x0+card_width*0.5, card_y+0.05, card_width*0.45, card_height*0.3], zorder=4)
                spark_ax.plot(list(spark_data), color=accent_color, linewidth=1)
                spark_ax.axis('off')
    except Exception as e:
        print("error drawing cards", e)
        import traceback; traceback.print_exc()
    # vertical dividers
    for x in card_xs[1:]:
        fig.add_artist(plt.Line2D([x-0.02,x-0.02],[card_y, card_y+card_height],
                                  color=theme['CARD_BORDER'], linewidth=1, alpha=0.6))

    # draw health gauge now that cards are in place
    hb_ax = fig.add_axes([0.01, card_y+card_height+0.01, 0.18, 0.03], facecolor='none', zorder=4)
    hb_ax.barh(0, health/100, color=health_color)
    hb_ax.axis('off')
    fig.text(0.01, card_y+card_height+0.01, f"Network Health: {int(health)}/100", ha='left', va='bottom', fontsize=9, color=health_color)

    # divider separator between header and charts
    fig.lines = [ln for ln in fig.lines if not (ln.get_ydata()[0] == 0.80)]
    fig.add_artist(plt.Line2D([0.05,0.95],[card_y-0.025,card_y-0.025], color=theme['CARD_BORDER'], linewidth=1.5, alpha=0.45))


    # 2x3 grid
    ax1 = plt.subplot(2, 3, 1)
    ax1.set_title("📊 Top 5 Source IPs")
    style_card(ax1, theme)
    # apply subtle shimmer to card border
    shimmer = get_card_shimmer_alpha(now)
    for spine in ax1.spines.values():
        spine.set_edgecolor(theme['CARD_BORDER'])
        spine.set_alpha(shimmer)
    if source_counts:
        top5 = source_counts.most_common(5)
        ip_labels = [short_ip(ip) for ip, _ in top5]
        y_positions = list(range(len(ip_labels)))
        
        # smooth interpolation for bar heights
        anim_progress = get_animation_progress(now, last_update_time)
        interpolated_counts = []
        for ip, count in top5:
            old_count = prev_source_data.get(ip, count)
            interp = interpolate_value(old_count, count, anim_progress)
            interpolated_counts.append(interp)
        
        # fade in effect for new IPs
        colors = []
        for ip, count in top5:
            was_present = ip in prev_source_data
            alpha = 1.0 if was_present else (0.6 + 0.4 * anim_progress)
            colors.append(hex_to_rgba(theme['ACCENT1'], alpha))
        
        bars1 = ax1.barh(y_positions, interpolated_counts, height=0.7, color=colors)
        ax1.set_yticks(y_positions)
        ax1.set_yticklabels(ip_labels, fontsize=8)
        ax1.invert_yaxis()
        ax1.xaxis.set_major_formatter(FuncFormatter(kfmt))
        ax1.grid(axis='x', linestyle='--', alpha=0.4)
        # record for hover tooltips
        bar_collections.append(('h', ax1, bars1, ip_labels))
    ax1.set_xlabel("Packets")

    ax2 = plt.subplot(2, 3, 2)
    ax2.set_title("📈 Top 5 Destination IPs")
    style_card(ax2, theme)
    # apply subtle shimmer to card border
    for spine in ax2.spines.values():
        spine.set_edgecolor(theme['CARD_BORDER'])
        spine.set_alpha(shimmer)
    if dest_counts:
        top5 = dest_counts.most_common(5)
        ip_labels = [short_ip(ip) for ip, _ in top5]
        y_positions = list(range(len(ip_labels)))
        
        # smooth interpolation for bar heights
        anim_progress = get_animation_progress(now, last_update_time)
        interpolated_counts = []
        for ip, count in top5:
            old_count = prev_dest_data.get(ip, count)
            interp = interpolate_value(old_count, count, anim_progress)
            interpolated_counts.append(interp)
        
        # fade in effect for new IPs
        colors = []
        for ip, count in top5:
            was_present = ip in prev_dest_data
            alpha = 1.0 if was_present else (0.6 + 0.4 * anim_progress)
            colors.append(hex_to_rgba(theme['ACCENT2'], alpha))
        
        bars2 = ax2.barh(y_positions, interpolated_counts, height=0.7, color=colors)
        ax2.set_yticks(y_positions)
        ax2.set_yticklabels(ip_labels,fontsize=8)
        ax2.invert_yaxis()
        ax2.xaxis.set_major_formatter(FuncFormatter(kfmt))
        ax2.grid(axis='x', linestyle='--', alpha=0.4)
        bar_collections.append(('h', ax2, bars2, ip_labels))
    ax2.set_xlabel("Packets")

    ax3 = plt.subplot(2, 3, 3)
    ax3.set_title("⚠️ Protocol Distribution")
    style_card(ax3, theme)
    # apply subtle shimmer to card border
    for spine in ax3.spines.values():
        spine.set_edgecolor(theme['CARD_BORDER'])
        spine.set_alpha(shimmer)
    if protocol_counts:
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())
        colors = [theme['ACCENT1'], theme['ACCENT2'], theme['ACCENT3']][: len(counts)]
        wedges, texts, autotexts = ax3.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90, colors=colors,
                textprops={'color': theme['TEXT_COLOR'], 'fontsize':9})
        # move labels to legend on right
        ax3.legend(wedges, protocols, title="Protocols", loc="center left", bbox_to_anchor=(1,0,0.5,1), fontsize=8)
        for at in autotexts:
            at.set_color(theme['TEXT_COLOR'])
            at.set_size(8)

    ax4 = plt.subplot(2, 3, 4)
    ax4.set_title("📊 Packets/sec + Bandwidth (Mbps)")
    style_card(ax4, theme)
    # apply subtle shimmer to card border
    for spine in ax4.spines.values():
        spine.set_edgecolor(theme['CARD_BORDER'])
        spine.set_alpha(shimmer)
    ax4.grid(True, linestyle='--', alpha=0.4)
    ax4.set_xlabel("Time (s)")
    ax4.set_ylabel("Packets/sec")
    if pps_history:
        line1, = ax4.plot(list(pps_history), linewidth=2, color=theme['ACCENT1'])
        line1.set_path_effects([pe.Stroke(linewidth=4, foreground='#000', alpha=0.3)])
        ax4.set_ylim(0, max(max(pps_history)*1.2, 10))
    ax4b = ax4.twinx()
    ax4b.set_ylabel("Mbps")
    if mbps_history:
        line2, = ax4b.plot(list(mbps_history), linewidth=2.5, linestyle='--', color=theme['ACCENT3'])
        line2.set_path_effects([pe.Stroke(linewidth=4, foreground='#000', alpha=0.3)])
        ax4b.set_ylim(0, max(max(mbps_history)*1.2, 1))
    for spine in ax4b.spines.values():
        spine.set_edgecolor(theme['CARD_BORDER'])

    ax5 = plt.subplot(2, 3, 5)
    ax5.set_title("📊 Top Services (dest ports)")
    style_card(ax5, theme)
    # apply subtle shimmer to card border
    for spine in ax5.spines.values():
        spine.set_edgecolor(theme['CARD_BORDER'])
        spine.set_alpha(shimmer)
    if port_counts:
        svcs, cnts = zip(*port_counts.most_common(5))
        anim_progress = get_animation_progress(now, last_update_time)
        
        # smooth interpolation for bar heights
        interpolated_cnts = []
        for svc, cnt in zip(svcs, cnts):
            old_cnt = prev_port_data.get(svc, cnt)
            interp = interpolate_value(old_cnt, cnt, anim_progress)
            interpolated_cnts.append(interp)
        
        # fade in effect for new services
        colors = []
        for svc, cnt in zip(svcs, cnts):
            was_present = svc in prev_port_data
            alpha = 1.0 if was_present else (0.6 + 0.4 * anim_progress)
            colors.append(hex_to_rgba(theme['ACCENT3'], alpha))
        
        bars5 = ax5.bar(range(len(svcs)), interpolated_cnts, color=colors)
        ax5.set_xticks(range(len(svcs)))
        ax5.set_xticklabels(svcs, rotation=45, ha='right', fontsize=8)
        ax5.yaxis.set_major_formatter(FuncFormatter(kfmt))
        ax5.grid(axis='y')
        bar_collections.append(('v', ax5, bars5, svcs))
    ax5.set_ylabel("Packets")

    ax6 = plt.subplot(2, 3, 6)
    ax6.set_title("⚠️ Recent Security Alerts", color=theme['ACCENT3'])
    style_card(ax6, theme)
    # apply subtle shimmer to card border
    for spine in ax6.spines.values():
        spine.set_edgecolor(theme['CARD_BORDER'])
        spine.set_alpha(shimmer)
    ax6.axis('off')
    try:
        if alerts:
            # cycle through alerts if multiple
            global alert_display_index, fade_phase
            if len(alerts) > 1:
                alert_display_index = (alert_display_index + 1) % len(alerts)

            alert = alerts[alert_display_index]
            t = alert["timestamp"]
            alert_text = f"{datetime.fromtimestamp(t).strftime('%H:%M:%S')}\n{alert['short']}"

            # keep the subtle fade for the panel itself
            fade_phase = (fade_phase + 0.1) % 1.0

            newest_alert_time = last_alert_time or alerts[-1][0]
            alert_age = now - newest_alert_time
            fresh_alert = alert_age < 5.0
            pulsing_alert = alert_age < 3.0

            if pulsing_alert:
                pulse_step = int(alert_age / 0.3)
                pulse_on = (pulse_step + int(_frame or 0)) % 2 == 0
                pulse_color = "#ff0000" if pulse_on else "#aa0000"
                face_color = hex_to_rgba(pulse_color, 0.95)
                edge_color = hex_to_rgba(pulse_color, 1.0)
                border_width = 3
                box_alpha = None
            else:
                face_color = theme['ALERT_BG']
                edge_color = hex_to_rgba("#aa0000", 0.9)
                border_width = 2
                box_alpha = 0.6 + 0.4 * (0.5 + 0.5*np.sin(fade_phase * np.pi * 2))

            bbox_kwargs = dict(
                boxstyle='round',
                facecolor=face_color,
                edgecolor=edge_color,
                linewidth=border_width,
            )
            if box_alpha is not None:
                bbox_kwargs['alpha'] = box_alpha

            ax6.text(
                0.05,
                0.95,
                alert_text,
                transform=ax6.transAxes,
                fontsize=7,
                verticalalignment='top',
                family='monospace',
                color=theme['TEXT_COLOR'],
                bbox=bbox_kwargs,
            )
            # badge
            ax6.text(0.95, 0.95, '⚠️ ALERT', color='#ff3333', fontsize=7, ha='right', va='top', transform=ax6.transAxes)
            if fresh_alert:
                ax6.text(
                    0.95,
                    0.83,
                    '🔴 NEW',
                    color='#ffffff',
                    fontsize=6,
                    ha='right',
                    va='top',
                    transform=ax6.transAxes,
                    bbox=dict(
                        boxstyle='round,pad=0.2',
                        facecolor='#aa0000',
                        edgecolor='#ff0000',
                        linewidth=1,
                    ),
                )
        else:
            ax6.text(0.5, 0.5, "No alerts detected\n✓ System normal",
                     transform=ax6.transAxes, fontsize=9, ha='center', va='center',
                     color=theme['ACCENT3'], weight='bold')
    except Exception as e:
        print("error drawing alerts", e)
        import traceback; traceback.print_exc()

    # Leave extra top space so the suptitle + header don't overlap with plots
    # include space at bottom for the session summary, controls and footer
    plt.tight_layout(rect=[0.02, 0.15, 0.98, 0.78])

    session_text = (
        f"Session: {sum(source_counts.values()):,} pkts captured | "
        f"{filtered_counter:,} filtered | {len(alerts)} alert{'s' if len(alerts) != 1 else ''} | "
        f"Duration: {runtime_str} | "
        f"Avg: {avg_pps:.1f} pps | "
        f"Peak: {peak_pps:.0f} pps | "
        f"Data: {format_bytes(total_bytes)}"
    )
    fig.text(
        0.5,
        0.042,
        session_text,
        ha='center',
        va='center',
        fontsize=8,
        color=hex_to_rgba(theme['TEXT_COLOR'], 0.7),
        transform=fig.transFigure,
        zorder=20,
        bbox=dict(
            boxstyle='round,pad=0.25',
            facecolor=hex_to_rgba(theme['CARD_BG'], 0.5),
            edgecolor=theme['CARD_BORDER'],
            linewidth=0.8,
            alpha=0.85,
        ),
    )

    controls_text = "Controls: [P] Pause/Resume | [C] Clear | [S] Screenshot | [E] Export | [R] Reset | [T] Theme | [Q] Quit"
    fig.text(
        0.5,
        0.018,
        controls_text,
        ha='center',
        va='center',
        fontsize=8,
        color=hex_to_rgba(theme['TEXT_COLOR'], 0.6),
        transform=fig.transFigure,
        zorder=20,
        bbox=dict(
            boxstyle='round,pad=0.25',
            facecolor=theme['CARD_BG'],
            edgecolor=theme['CARD_BORDER'],
            linewidth=0.8,
            alpha=0.9,
        ),
    )

    # timestamp footer
    footer_text = f"Last updated: {datetime.now().strftime('%H:%M:%S')}"
    fig.text(
        0.985,
        0.008,
        footer_text,
        ha='right',
        va='bottom',
        fontsize=7.5,
        color=hex_to_rgba(theme['TEXT_COLOR'], 0.40),
        transform=fig.transFigure,
        zorder=20,
    )

    if about_overlay_visible:
        overlay_ax = fig.add_axes([0.14, 0.16, 0.72, 0.62], zorder=100)
        overlay_ax.set_facecolor(hex_to_rgba(theme['DARK_BG'], 0.92))
        for spine in overlay_ax.spines.values():
            spine.set_edgecolor(theme['CARD_BORDER'])
            spine.set_linewidth(2)
        overlay_ax.set_xticks([])
        overlay_ax.set_yticks([])
        overlay_ax.set_xlim(0, 1)
        overlay_ax.set_ylim(0, 1)

        overlay_text = (
            "═══════════════════════════════════════\n"
            "NETWORK TRAFFIC VISUALISER v1.0\n"
            "═══════════════════════════════════════\n"
            "Created by: Shannan Farrall\n"
            "Student ID: 23827528\n"
            "Institution: University of Brighton\n"
            "Module: CI601 The Computing Project\n"
            "═══════════════════════════════════════\n"
            "FEATURES\n"
            "═══════════════════════════════════════\n"
            "✓ Real-time packet capture & analysis\n"
            "✓ Security anomaly detection\n"
            "• Port scan detection\n"
            "• High traffic alerting\n"
            "• Suspicious port monitoring\n"
            "✓ Six-panel visualization dashboard\n"
            "✓ Configurable filtering system\n"
            "✓ CSV & PCAP export capabilities\n"
            "✓ Dark/Light theme toggle\n"
            "✓ Professional UI design\n"
            "═══════════════════════════════════════\n"
            "TECHNOLOGIES\n"
            "═══════════════════════════════════════\n"
            "Python 3.x\n"
            "Scapy (Packet capture)\n"
            "Matplotlib (Visualization)\n"
            "NumPy (Data processing)\n"
            "═══════════════════════════════════════\n"
            "Press A again or any other key to close"
        )
        overlay_ax.text(
            0.5,
            0.5,
            overlay_text,
            ha='center',
            va='center',
            fontsize=10,
            family='monospace',
            color='#ffffff',
            transform=overlay_ax.transAxes,
            bbox=dict(
                boxstyle='round,pad=0.6',
                facecolor=hex_to_rgba(theme['DARK_BG'], 0.35),
                edgecolor=theme['CARD_BORDER'],
                linewidth=1.5,
            ),
        )
    
    # ---------- Update animation state for next frame ----------
    # save current state for smooth interpolation in next frame
    if source_counts:
        prev_source_data = {ip: count for ip, count in source_counts.most_common(5)}
    if dest_counts:
        prev_dest_data = {ip: count for ip, count in dest_counts.most_common(5)}
    if port_counts:
        prev_port_data = {svc: count for svc, count in port_counts.most_common(5)}
    # update timer for next interpolation
    if elapsed >= 1:
        last_update_time = now

if __name__ == '__main__':
    CONFIG = load_config(args.config)
    log_event("⚙️", f"Configuration loaded: {args.config}")
    log_event("🔍", f"Filters: {'ENABLED' if CONFIG['filters']['enabled'] else 'DISABLED'}")
    if args.no_filters:
        CONFIG['filters']['enabled'] = False
        logger.info("CLI override: packet filters disabled")
    if args.duration:
        CONFIG['capture']['duration_seconds'] = args.duration
        logger.info(f"CLI override: duration set to {args.duration}s")

    # ---------- run ----------
    fig = plt.figure(figsize=(CONFIG['display']['window_width'], CONFIG['display']['window_height']))
    fig.patch.set_facecolor(DARK_BG)

    # global structures for hover tooltips on charts
    bar_collections = []  # list of tuples (orientation, ax, bars, labels)
    hover_annot = None
    hover_annot_ax = None
    tooltip_state = {"pinned": False}

    # global placeholders for sniffer/control state
    sniffer = None
    capturing = False
    capture_state = "CAPTURING"

    # Allow closing the dashboard with 'q' or 'escape' key
    def _on_key(event):
        global current_theme, capturing, capture_state, about_overlay_visible
        try:
            key = (event.key or "").lower()
            if about_overlay_visible and key != 'a':
                about_overlay_visible = False
                fig.canvas.draw_idle()
                return
            if key in ('q', 'escape'):
                plt.close(fig)
            elif key == 'a':
                about_overlay_visible = not about_overlay_visible
                fig.canvas.draw_idle()
            elif key == 't':
                current_theme = 'light' if current_theme == 'dark' else 'dark'
                console_action(f"🌅 Theme switched to: {current_theme.upper()}")
                fig.canvas.draw_idle()
            elif key == 'p':
                capturing = not capturing
                capture_state = "PAUSED" if not capturing else "CAPTURING"
                console_action("⏸️  Capture PAUSED" if not capturing else "▶️  Capture RESUMED")
                try:
                    fig.canvas.draw_idle()
                except Exception:
                    pass
            elif key == 'c':
                reset_runtime_state(clear_alert_state=True)
                console_action("🔄 Data CLEARED - Starting fresh")
                try:
                    fig.canvas.draw_idle()
                except Exception:
                    pass
            elif key == 'r':
                reset_statistics()
                try:
                    fig.canvas.draw_idle()
                except Exception:
                    pass
            elif key == 's':
                screenshot_path = save_screenshot()
                console_action(f"📸 Screenshot saved: {screenshot_path}")
            elif key == 'e':
                exported = export_current_data()
                if exported:
                    exported_names = [os.path.basename(path) for path in exported]
                    if any(name.startswith("live_packets_") for name in exported_names):
                        console_action(f"💾 Exported CSV: {next(name for name in exported_names if name.startswith('live_packets_'))}")
                    if any(name.startswith("live_capture_") for name in exported_names):
                        console_action(f"💾 Exported PCAP: {next(name for name in exported_names if name.startswith('live_capture_'))}")
                    if any(name.startswith("security_alerts_") for name in exported_names):
                        console_action(f"💾 Exported Alerts: {next(name for name in exported_names if name.startswith('security_alerts_'))}")
                else:
                    console_action("💾 Data export skipped - no live files available")
        except Exception:
            pass

    fig.canvas.mpl_connect('key_press_event', _on_key)

    # attach hover callback once; callback will reference bar_collections
    annotations = {}

    def _on_hover(event):
        if event.inaxes is None:
            hide_hover_annotation()
            return

        theme = get_theme()
        ax = event.inaxes

        for orient, a, bars, labels in bar_collections:
            if a is not ax:
                continue
            for i, bar in enumerate(bars):
                contains, _ = bar.contains(event)
                if not contains:
                    continue

                count = int(round(bar.get_width() if orient == "h" else bar.get_height()))
                label = labels[i] if labels and i < len(labels) else ""
                total = sum(source_counts.values()) if a is ax1 else sum(dest_counts.values()) if a is ax2 else sum(port_counts.values())
                pct = (count / total * 100.0) if total else 0.0

                if a is ax1 or a is ax2:
                    text = f"IP: {label} | Packets: {count:,} ({pct:.1f}% of total)"
                else:
                    if label in SERVICE.values() or label.isdigit():
                        text = f"Port {label}: {count:,} packets"
                    else:
                        text = f"{label}: {count:,} packets"

                show_hover_annotation(a, text, (event.xdata, event.ydata))
                return

        if ax is ax3 and protocol_counts:
            for wedge, proto, count in zip(ax.patches, protocol_counts.keys(), protocol_counts.values()):
                contains, _ = wedge.contains(event)
                if contains:
                    total = sum(protocol_counts.values())
                    pct = (count / total * 100.0) if total else 0.0
                    show_hover_annotation(ax, f"{proto}: {count:,} packets ({pct:.1f}%)", (event.xdata, event.ydata))
                    return

        if ax is ax4 and (pps_history or mbps_history):
            if event.xdata is not None:
                idx = int(round(event.xdata))
                idx = max(0, min(idx, max(len(pps_history), len(mbps_history)) - 1))
                if idx < len(pps_history) or idx < len(mbps_history):
                    pps_val = pps_history[idx] if idx < len(pps_history) else 0.0
                    mbps_val = mbps_history[idx] if idx < len(mbps_history) else 0.0
                    show_hover_annotation(ax, f"Time: {idx}s | PPS: {pps_val:.2f} | Bandwidth: {mbps_val:.2f} Mbps", (event.xdata, event.ydata))
                    return

        if ax is ax5 and port_counts:
            for i, bar in enumerate(ax.patches):
                if not hasattr(bar, "get_x"):
                    continue
                contains, _ = bar.contains(event)
                if contains:
                    svcs = list(port_counts.most_common(5))
                    if i < len(svcs):
                        svc, cnt = svcs[i]
                        show_hover_annotation(ax, f"Port {svc}: {cnt:,} packets", (event.xdata, event.ydata))
                        return

        if ax is ax6 and alerts:
            for txt in ax.texts:
                if "ALERT" in txt.get_text() or "No alerts detected" in txt.get_text():
                    continue
                contains, _ = txt.contains(event)
                if contains:
                    latest = alerts[alert_display_index] if alerts else None
                    if latest:
                        show_hover_annotation(ax, latest["full"], (event.xdata, event.ydata))
                        return

        hide_hover_annotation()

    fig.canvas.mpl_connect("motion_notify_event", _on_hover)
    # Tooltips are implemented with matplotlib annotations so they work silently
    # even when mplcursors is unavailable.



    BPF = CONFIG['capture']['bpf_filter']

    ani = FuncAnimation(plt.gcf(), update, interval=CONFIG['display']['update_interval_ms'],
                        blit=False, cache_frame_data=False)

    print("\n" + "="*60)
    print("🔒 Network Traffic Analyzer - Enhanced Security Monitoring")
    print("="*60)
    print(f"📊 Interface: {IFACE}")
    print(f"⚙️  Configuration: {args.config}")
    print(f"🔍 Packet Filters: {'ENABLED' if CONFIG['filters']['enabled'] else 'DISABLED'}")
    print(f"⚠️  Anomaly Detection: {'ENABLED' if CONFIG['alerts']['enabled'] else 'DISABLED'}")
    print(f"📝 Logging: CSV={CONFIG['export']['csv_enabled']}, PCAP={CONFIG['export']['pcap_enabled']}")
    print("="*60)
    print("Close the dashboard window to stop capture.\n")

    try:
        sniffer = AsyncSniffer(prn=capture_packet, store=False, iface=IFACE, filter=BPF)
        sniffer.start()
        capturing = True
        log_event("🟢", f"Packet capture STARTED on interface: {IFACE}")
    except Exception as e:
        print(f"⚠️  BPF filter failed: {e}")
        print("Retrying without BPF filter...")
        sniffer = AsyncSniffer(prn=capture_packet, store=False, iface=IFACE)
        sniffer.start()
        capturing = True
        log_event("🟢", f"Packet capture STARTED on interface: {IFACE}")

    try:
        # optional stop after duration
        dur = CONFIG['capture'].get('duration_seconds')
        if dur:
            plt.show(block=False)
            t0 = time.time()
            while plt.fignum_exists(plt.gcf().number) and (time.time() - t0) < dur:
                plt.pause(0.1)
            plt.close()
        else:
            plt.show()
    finally:
        capture_state = "STOPPED"
        log_event("🔴", "Packet capture STOPPED")
        try: sniffer.stop()
        except Exception: pass

        try:
            if csv_f:
                csv_f.flush()
                csv_f.close()
        except Exception: pass

        try:
            if pcap_w:
                pcap_w.close()
        except Exception: pass

        if alerts and ALERT_LOG:
            with open(ALERT_LOG, 'a', encoding="utf-8") as f:
                f.write(f"\n=== Session ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
                for alert in alerts:
                    f.write(f"{datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}\n{alert['full']}\n\n")

        print("\n" + "="*60)
        print("✅ Capture Session Summary")
        print("="*60)
        print(f"📊 Total packets captured: {sum(source_counts.values()):,}")
        print(f"🚫 Total packets filtered: {filtered_counter:,}")
        print(f"💾 Total data transferred: {format_bytes(total_bytes)}")
        print(f"⚠️  Security alerts triggered: {len(alerts)}")
        print(f"📝 Data saved to:")
        if CONFIG['export']['csv_enabled']:
            print(f"   - CSV: {CSV_PATH}")
        if CONFIG['export']['pcap_enabled']:
            print(f"   - PCAP: {PCAP_PATH}")
        if alerts:
            print(f"   - Alerts: {ALERT_LOG}")
        print("="*60)
        runtime = time.time() - start_time
        runtime_str = f"{int(runtime//3600):02d}:{int((runtime%3600)//60):02d}:{int(runtime%60):02d}"
        session_summary = f"Session Summary: {sum(source_counts.values()):,} packets | {len(alerts)} alert{'s' if len(alerts) != 1 else ''} | {runtime_str} duration"
        log_event("📊", session_summary)
