# Network Traffic Visualiser

The Network Traffic Visualiser is a Python application that captures live network packets and presents the data through real-time graphs, with the aim of making traffic behaviour easier to interpret without requiring expert-level protocol knowledge. It was developed for CI601 The Computing Project at the University of Brighton and is aimed at students and others new to network analysis.

**Author:** Shannan Farrall (Student ID: 23827528)
**Module:** CI601 The Computing Project
**Institution:** University of Brighton

## Requirements

The application requires Python 3.8 or later, the Python libraries listed in `requirements.txt`, and Npcap installed on Windows for raw packet capture. Administrator privileges are required to access the network interface.

## Installation and running

Install the Python dependencies with `pip install -r requirements.txt` and ensure Npcap is installed on Windows. To run the dashboard, open a terminal as Administrator, navigate to the project folder, and run `python live_dashboard.py`. The dashboard window will open and begin capturing live traffic within a few seconds. Press Q or Escape to quit.

## Configuration

Application settings are stored in `config.json`. Interface selection, alert thresholds, packet filters and export paths can all be adjusted without changing the source code. A full configuration reference is provided in Appendix C of the project report.

## Output files

During a capture session the application writes timestamped CSV, PCAP and security alert log files to the project folder, alongside a runtime log in `network_analyser.log`. The PCAP files can be opened directly in Wireshark for further inspection.

## Academic context

This project was submitted for CI601 The Computing Project at the University of Brighton. It is intended for educational use only and should not be used to monitor traffic on networks without explicit authorisation.
