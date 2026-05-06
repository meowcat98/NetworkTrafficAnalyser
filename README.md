# Network Traffic Visualiser

A Python-based educational tool that captures live network traffic and visualises key patterns in real time to support basic network monitoring and cybersecurity learning.

**Author:** Shannan Farrall  
**Student ID:** 23827528  
**Module:** CI601 The Computing Project  
**Institution:** University of Brighton

---

## Overview

**Network Traffic Visualiser** is a lightweight network analysis dashboard designed for learning and demonstration. It captures packets from a selected network interface and converts them into live, interpretable visualisations and security-oriented summaries.

This project was developed for an academic context (CI601) with the aim of:
- demonstrating core packet analysis concepts (protocols, endpoints, services)
- supporting beginner-friendly cybersecurity investigation workflows
- encouraging ethical, controlled testing (synthetic traffic and lab networks)

**Target users**
- Cybersecurity / networking students
- Beginners learning about protocols and traffic behaviour
- Educators demonstrating packet capture and baseline anomaly detection

---

## Key Features

- Real-time packet capture and visualisation
- Protocol distribution analysis (TCP / UDP / ICMP)
- Anomaly detection, including:
  - potential port scans
  - high traffic / high packets-per-second (PPS)
  - traffic to suspicious ports
- Configurable filtering system (IP, port, protocol filters)
- Security alerts with a cooldown system (reduces repeated notifications)
- CSV and PCAP export functionality
- Dark theme dashboard with 6 visualisation panels

---

## Requirements

- **Python:** 3.8+
- **Administrator/root privileges:** Required to capture packets from network interfaces using raw sockets (packet sniffing typically needs elevated privileges).
- **Supported operating systems:**
  - Windows 10/11 (recommended for this submission)
  - Linux (should work with root permissions)
  - macOS (may work, but interface naming and permissions can vary)

---

## Installation

1. **Clone or download** this project folder to your machine.

2. (Recommended) Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   ```

   **Windows (PowerShell):**
   ```bash
   .\.venv\Scripts\Activate.ps1
   ```

   **Windows (cmd):**
   ```bat
   .venv\Scripts\activate
   ```

   **Linux/macOS:**
   ```bash
   source .venv/bin/activate
   ```

3. Install Python dependencies:

   ```bash
   pip install -r requirements.txt --break-system-packages
   ```

   Notes:
   - `--break-system-packages` is sometimes required on Debian/Ubuntu-based systems due to Python packaging restrictions.
   - On Windows, this flag is typically not needed, but it is safe to include for consistency with the module brief.

4. Run the dashboard with elevated privileges:
   - **Windows:** run Terminal/PowerShell as *Administrator*
   - **Linux:** use `sudo`
   - **macOS:** use `sudo` (if supported)

---

## Quick Start

### Run the live dashboard

```bash
python live_dashboard.py
```

### Stop the dashboard

- Press `Ctrl + C` in the terminal running the program.

### Run with a custom configuration file (example)

If your script supports a config file argument, a common pattern is:

```bash
python live_dashboard.py --config config.json
```

If no argument is supported, edit `config.json` directly (see below).

---

## Configuration

Project settings are stored in `config.json`.

Common settings you may want to change include:
- **interface**: the network interface name to capture from (e.g., Wi‑Fi / Ethernet)
- **filters**:
  - IP allow/deny lists
  - port filters
  - protocol filters (TCP/UDP/ICMP)
- **alert thresholds**:
  - port scan sensitivity (e.g., number of unique ports in a time window)
  - PPS / bandwidth thresholds
  - suspicious ports list

See: `config.json` for the full set of options.

---

## Dashboard Layout (6 Panels)

The dashboard uses a dark theme and shows six primary panels to support rapid interpretation of network behaviour.

### 1) Top 5 Source IPs
Shows the most active source IP addresses observed in the capture window.  
**Why it’s useful:** helps identify the “loudest” talkers generating traffic into the network interface.

### 2) Top 5 Destination IPs
Shows the most frequent destination IP addresses.  
**Why it’s useful:** reveals where traffic is going (local services, gateways, external hosts).

### 3) Protocol Distribution
A breakdown of observed protocol counts (TCP / UDP / ICMP).  
**Why it’s useful:** quickly indicates the overall traffic mix and highlights unusual spikes (e.g., sudden ICMP activity).

### 4) Packets/sec + Bandwidth (Mbps)
Time-series view of packet rate and estimated bandwidth.  
**Why it’s useful:** supports detection of bursts, floods, and sustained high-throughput activity.

### 5) Top Services (Destination Ports)
Shows the most common destination ports (services) being used.  
**Why it’s useful:** highlights typical service usage (e.g., 80/443) and surfaces unexpected ports.

### 6) Recent Security Alerts
Lists recent alerts triggered by detection rules.  
**Why it’s useful:** provides actionable security signals without requiring manual log inspection.

---

## Understanding Alerts

Alerts are designed to be simple, educational indicators rather than definitive intrusion detection outcomes.

### What triggers alerts
Typical triggers include:
- **Port scans:** a source contacting many distinct destination ports within a short time window.
- **High PPS / high traffic:** sustained or burst packet rates exceeding a defined threshold.
- **Suspicious ports:** traffic to or from ports commonly associated with risky or unexpected services (configurable).

### Cooldown system
To avoid repeated alerts for the same condition:
- when an alert fires, a **cooldown timer** is applied
- matching alerts within the cooldown period are suppressed or rate-limited
- this keeps the dashboard readable during sustained events

### What to do if you see an alert
- Confirm whether the traffic is expected (e.g., updates, legitimate scans in a lab)
- Check the **Top Source IPs**, **Top Services**, and **PPS/Bandwidth** panels for context
- Export evidence (CSV/PCAP) for offline review if needed

---

## Troubleshooting

### Permission denied / access errors
**Cause:** packet capture often requires elevated permissions.  
**Fix:**
- Windows: run Terminal/PowerShell as **Administrator**
- Linux/macOS: run with `sudo python live_dashboard.py`

### No suitable device found / interface errors
**Cause:** the configured interface name does not match a real interface on the machine.  
**Fix:**
- update the interface setting in `config.json`
- confirm you are connected (Wi‑Fi/Ethernet)
- try another interface name appropriate for your OS

### Module import errors (e.g., scapy not found)
**Cause:** dependencies not installed or wrong Python environment selected.  
**Fix:**
- install requirements:

  ```bash
  pip install -r requirements.txt --break-system-packages
  ```

- verify you are using the correct interpreter / virtual environment.

---

## Output Files

The tool generates files for logging, evidence capture, and reporting:

- `live_packets.csv` — packet log (structured rows for analysis)
- `live_capture.pcap` — packet capture file (open in Wireshark)
- `security_alerts.log` — alert history
- `network_analyser.log` — system log (errors, runtime messages)

---

## Project Structure

Typical key files in this repository:

```text
NetworkTrafficAnalyser/
├─ live_dashboard.py          # Main entry point: live capture + dashboard UI
├─ live_visualiser.py         # Visualisation components / plotting helpers
├─ main.py                    # Alternative entry / orchestration (if used)
├─ analyse_csv.py             # Offline CSV analysis helper
├─ pdf_report_generator.py    # Generates a PDF report from capture data
├─ config.json                # User configuration (interface, filters, thresholds)
├─ requirements.txt           # Python dependencies
├─ test_analyzer.py           # Tests for analysis components
├─ test_live_dashboard.py     # Tests for live dashboard logic (where feasible)
├─ live_packets.csv           # Output (generated)
├─ live_capture.pcap          # Output (generated)
└─ security_alerts.log        # Output (generated)
```

---

## Testing

Testing was carried out using **synthetic / self-generated traffic only**, to comply with ethical requirements and avoid monitoring real users.

Examples of controlled tests included:
- basic web browsing to generate HTTP/HTTPS flows
- ping tests to generate ICMP traffic
- local service connections to create predictable TCP/UDP patterns
- intentional, authorised scan-like behaviour in a lab environment (if applicable)

Unit tests (where feasible) are provided in:
- `test_analyzer.py`
- `test_live_dashboard.py`

Run tests with:

```bash
python -m unittest
```

---

## Academic Context

This project was developed for **CI601 The Computing Project** at the **University of Brighton**.

- **Educational use only**
- Not intended for production network monitoring or incident response
- Users must ensure they have authorisation to capture traffic on any network

---

## Future Improvements (Optional)

Potential enhancements for a future iteration:
- improved detection logic (time-windowed baselining, statistical thresholds)
- DNS / HTTP host extraction and enrichment
- per-interface selection UI and auto-discovery
- improved cross-platform support and packaging
- additional export formats and structured reporting templates

---

## License / Use

This repository is submitted for academic assessment. Any reuse should credit the author and remain within ethical and authorised environments.
