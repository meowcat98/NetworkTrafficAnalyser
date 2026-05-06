"""Traffic generation script for Network Traffic Visualiser demos.

Usage:
    python generate_traffic.py normal
    python generate_traffic.py scan
    python generate_traffic.py spike

Modes:
    normal - simulate typical web browsing traffic
    scan   - simulate port scanning activity
    spike  - generate high packet rate traffic
"""

import socket
import sys
import time
import urllib.request
from urllib.error import URLError, HTTPError


NORMAL_SITES = [
    "https://www.google.com",
    "https://github.com",
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://www.microsoft.com",
    "https://www.cloudflare.com",
]


def log(message: str) -> None:
    print(message, flush=True)


def normal_traffic() -> None:
    """Simulate normal web browsing traffic for about 30 seconds."""
    log("[NORMAL MODE] Simulating web browsing...")
    end_time = time.time() + 30
    index = 0

    while time.time() < end_time:
        url = NORMAL_SITES[index % len(NORMAL_SITES)]
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        log(f"[NORMAL MODE] Requesting {host}...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as response:
                response.read(1024)
        except (HTTPError, URLError, socket.timeout, OSError) as exc:
            log(f"[NORMAL MODE] Request failed for {host}: {exc}")
        except KeyboardInterrupt:
            log("\n[NORMAL MODE] Stopped by user.")
            return

        index += 1
        time.sleep(1.5)

    log("[NORMAL MODE] Demo complete.")


def port_scan_simulation() -> None:
    """Simulate port scanning against localhost ports 1-50."""
    log("[SCAN MODE] Port scanning localhost ports 1-50...")
    end_time = time.time() + 10
    port = 1

    while time.time() < end_time and port <= 50:
        log(f"[SCAN MODE] Probing 127.0.0.1:{port}...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.15)
                sock.connect(("127.0.0.1", port))
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        except KeyboardInterrupt:
            log("\n[SCAN MODE] Stopped by user.")
            return

        port += 1
        time.sleep(0.1)

    log("[SCAN MODE] Demo complete.")


def traffic_spike() -> None:
    """Generate a rapid burst of UDP packets for about 15 seconds."""
    log("[SPIKE MODE] Generating traffic spike (200+ pps)...")
    end_time = time.time() + 15
    target = ("127.0.0.1", 9999)
    payload = b"x" * 1400
    sent = 0

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            while time.time() < end_time:
                start = time.time()
                for _ in range(25):
                    try:
                        sock.sendto(payload, target)
                        sent += 1
                    except OSError as exc:
                        log(f"[SPIKE MODE] UDP send error: {exc}")
                        break
                elapsed = time.time() - start
                if elapsed < 0.125:
                    time.sleep(0.125 - elapsed)
    except KeyboardInterrupt:
        log("\n[SPIKE MODE] Stopped by user.")
        return

    log(f"[SPIKE MODE] Demo complete. Sent approximately {sent} packets.")


def usage() -> None:
    log("Usage: python generate_traffic.py [normal|scan|spike]")


def main() -> int:
    if len(sys.argv) != 2:
        usage()
        return 1

    mode = sys.argv[1].strip().lower()

    try:
        if mode == "normal":
            normal_traffic()
        elif mode == "scan":
            port_scan_simulation()
        elif mode == "spike":
            traffic_spike()
        else:
            usage()
            return 1
    except KeyboardInterrupt:
        log("\nStopped by user.")
        return 130

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
