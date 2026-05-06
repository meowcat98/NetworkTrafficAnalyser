"""
Unit tests for NetworkTrafficAnalyser core functions.
Tests packet filtering, byte formatting, and anomaly detection logic.
Run: python test_live_dashboard.py
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Prevent argparse from processing test runner arguments
sys.argv = ['test_live_dashboard.py']

# Now import the module under test
import live_dashboard


class TestByteFormatting(unittest.TestCase):
    """Tests for format_bytes() function."""

    def test_bytes_single_byte(self):
        """Test formatting single byte."""
        self.assertEqual(live_dashboard.format_bytes(1), "1.00 B")

    def test_bytes_kilobytes(self):
        """Test formatting kilobytes."""
        self.assertEqual(live_dashboard.format_bytes(1024), "1.00 KB")

    def test_bytes_megabytes(self):
        """Test formatting megabytes."""
        self.assertEqual(live_dashboard.format_bytes(1024**2), "1.00 MB")

    def test_bytes_gigabytes(self):
        """Test formatting gigabytes."""
        self.assertEqual(live_dashboard.format_bytes(1024**3), "1.00 GB")

    def test_bytes_terabytes(self):
        """Test formatting terabytes."""
        self.assertEqual(live_dashboard.format_bytes(1024**4), "1.00 TB")

    def test_bytes_zero(self):
        """Test formatting zero bytes."""
        self.assertEqual(live_dashboard.format_bytes(0), "0.00 B")

    def test_bytes_fractional(self):
        """Test formatting with fractional values."""
        result = live_dashboard.format_bytes(1536)
        self.assertIn("1.50", result)
        self.assertIn("KB", result)


class TestPacketFiltering(unittest.TestCase):
    """Tests for apply_packet_filter() function."""

    def setUp(self):
        """Set up test fixtures."""
        # Save original config and restore after each test
        self.original_config = live_dashboard.CONFIG.copy()

    def tearDown(self):
        """Restore original config after test."""
        live_dashboard.CONFIG.update(self.original_config)

    def test_filters_disabled(self):
        """Test that function returns True when filters are disabled."""
        live_dashboard.CONFIG['filters']['enabled'] = False
        # Mock a packet without IP layer
        pkt = Mock()
        pkt.__contains__ = Mock(return_value=False)
        result = live_dashboard.apply_packet_filter(pkt)
        self.assertTrue(result)

    def test_no_ip_layer(self):
        """Test that non-IP packets are rejected when filters enabled."""
        live_dashboard.CONFIG['filters']['enabled'] = True
        pkt = Mock()
        pkt.__contains__ = Mock(return_value=False)  # No IP layer
        result = live_dashboard.apply_packet_filter(pkt)
        self.assertFalse(result)

    def test_ip_whitelist_allow(self):
        """Test IP whitelist allows matching IPs."""
        live_dashboard.CONFIG['filters']['enabled'] = True
        live_dashboard.CONFIG['filters']['ip_whitelist'] = ['192.168.1.1']
        live_dashboard.CONFIG['filters']['ip_blacklist'] = []
        live_dashboard.CONFIG['filters']['port_whitelist'] = []
        live_dashboard.CONFIG['filters']['port_blacklist'] = []
        live_dashboard.CONFIG['filters']['protocols'] = ['TCP', 'UDP', 'ICMP']
        live_dashboard.CONFIG['filters']['port_range_min'] = 1 
        live_dashboard.CONFIG['filters']['port_range_max'] = 65535
        live_dashboard.CONFIG['filters']['min_packet_size'] = 0
        live_dashboard.CONFIG['filters']['max_packet_size'] = 65535

        # Create mock packet with IP and TCP layers
        from scapy.all import IP, TCP
        pkt = Mock()
        pkt.__contains__ = Mock(side_effect=lambda x: x in (IP, TCP))
        pkt.__getitem__ = Mock()
        pkt.__len__ = Mock(return_value=100)
        pkt[IP].src = '192.168.1.1'
        pkt[IP].dst = '10.0.0.1'
        pkt[TCP].sport = 12345
        pkt[TCP].dport = 80

        result = live_dashboard.apply_packet_filter(pkt)
        self.assertTrue(result)

    def test_ip_whitelist_reject(self):
        """Test IP whitelist rejects non-matching IPs."""
        live_dashboard.CONFIG['filters']['enabled'] = True
        live_dashboard.CONFIG['filters']['ip_whitelist'] = ['192.168.1.1']
        live_dashboard.CONFIG['filters']['ip_blacklist'] = []
        live_dashboard.CONFIG['filters']['port_whitelist'] = []
        live_dashboard.CONFIG['filters']['port_blacklist'] = []
        live_dashboard.CONFIG['filters']['protocols'] = ['TCP', 'UDP', 'ICMP']
        live_dashboard.CONFIG['filters']['port_range_min'] = 1
        live_dashboard.CONFIG['filters']['port_range_max'] = 65535
        live_dashboard.CONFIG['filters']['min_packet_size'] = 0
        live_dashboard.CONFIG['filters']['max_packet_size'] = 65535

        from scapy.all import IP
        pkt = Mock()
        pkt.__contains__ = Mock(side_effect=lambda x: x == IP)
        pkt.__getitem__ = Mock()
        pkt.__len__ = Mock(return_value=100)
        pkt[IP].src = '10.0.0.1'
        pkt[IP].dst = '10.0.0.2'

        result = live_dashboard.apply_packet_filter(pkt)
        self.assertFalse(result)

    def test_ip_blacklist_reject(self):
        """Test IP blacklist rejects matching IPs."""
        live_dashboard.CONFIG['filters']['enabled'] = True
        live_dashboard.CONFIG['filters']['ip_whitelist'] = []
        live_dashboard.CONFIG['filters']['ip_blacklist'] = ['192.168.1.1']
        live_dashboard.CONFIG['filters']['port_whitelist'] = []
        live_dashboard.CONFIG['filters']['port_blacklist'] = []
        live_dashboard.CONFIG['filters']['protocols'] = ['TCP', 'UDP', 'ICMP']
        live_dashboard.CONFIG['filters']['port_range_min'] = 1
        live_dashboard.CONFIG['filters']['port_range_max'] = 65535
        live_dashboard.CONFIG['filters']['min_packet_size'] = 0
        live_dashboard.CONFIG['filters']['max_packet_size'] = 65535

        from scapy.all import IP
        pkt = Mock()
        pkt.__contains__ = Mock(side_effect=lambda x: x == IP)
        pkt.__getitem__ = Mock()
        pkt.__len__ = Mock(return_value=100)
        pkt[IP].src = '192.168.1.1'
        pkt[IP].dst = '10.0.0.1'

        result = live_dashboard.apply_packet_filter(pkt)
        self.assertFalse(result)


class TestAnomalyDetection(unittest.TestCase):
    """Tests for check_anomalies() function."""

    def setUp(self):
        """Set up test fixtures."""
        # Clear alerts and trackers
        live_dashboard.alerts.clear()
        live_dashboard.alert_cooldown.clear()
        live_dashboard.ip_port_tracker.clear()
        live_dashboard.ip_packet_rate.clear()
        # Save original config
        self.original_config = live_dashboard.CONFIG.copy()

    def tearDown(self):
        """Clean up after test."""
        live_dashboard.alerts.clear()
        live_dashboard.alert_cooldown.clear()
        live_dashboard.ip_port_tracker.clear()
        live_dashboard.ip_packet_rate.clear()
        live_dashboard.CONFIG.update(self.original_config)

    def test_anomaly_detection_disabled(self):
        """Test no alerts when anomaly detection disabled."""
        live_dashboard.CONFIG['alerts']['enabled'] = False
        initial_count = len(live_dashboard.alerts)
        live_dashboard.check_anomalies('192.168.1.1', 80, None)
        self.assertEqual(len(live_dashboard.alerts), initial_count)

    def test_port_scan_detection(self):
        """Test port scan detection triggers alert."""
        live_dashboard.CONFIG['alerts']['enabled'] = True
        live_dashboard.CONFIG['alerts']['port_scan_threshold'] = 5
        live_dashboard.CONFIG['alerts']['alert_cooldown_seconds'] = 0

        src_ip = '192.168.1.100'
        current_time = 1000.0
        for port in range(1, 7):
            live_dashboard.check_anomalies(src_ip, port, current_time + port * 0.01)

        alert_found = any('PORT SCAN' in alert['short'] for alert in live_dashboard.alerts)
        self.assertTrue(alert_found)

    def test_high_pps_detection(self):
        """Test high packets-per-second detection."""
        live_dashboard.CONFIG['alerts']['enabled'] = True
        live_dashboard.CONFIG['alerts']['high_pps_threshold'] = 5
        live_dashboard.CONFIG['alerts']['alert_cooldown_seconds'] = 0

        src_ip = '192.168.1.50'
        current_time = 1000.0
        for i in range(7):
            live_dashboard.check_anomalies(src_ip, 80, current_time + i*0.01)

        alert_found = any('TRAFFIC ALERT' in alert['short'] for alert in live_dashboard.alerts)
        self.assertTrue(alert_found)

    def test_suspicious_port_detection(self):
        """Test suspicious port detection."""
        live_dashboard.CONFIG['alerts']['enabled'] = True
        live_dashboard.CONFIG['alerts']['alert_cooldown_seconds'] = 0

        src_ip = '192.168.1.75'
        suspicious_port = 23  # TELNET
        current_time = 1000.0
        live_dashboard.check_anomalies(src_ip, suspicious_port, current_time)

        alert_found = any('PORT ALERT' in alert['short'] for alert in live_dashboard.alerts)
        self.assertTrue(alert_found)


class TestConfiguration(unittest.TestCase):
    """Tests for configuration loading and validation."""

    def test_config_loaded(self):
        """Test that configuration is loaded."""
        self.assertIsNotNone(live_dashboard.CONFIG)
        self.assertIn('capture', live_dashboard.CONFIG)
        self.assertIn('filters', live_dashboard.CONFIG)
        self.assertIn('alerts', live_dashboard.CONFIG)

    def test_config_has_required_keys(self):
        """Test that config has all required sections."""
        required_sections = ['capture', 'filters', 'alerts', 'export', 'display']
        for section in required_sections:
            self.assertIn(section, live_dashboard.CONFIG)

    def test_filters_enabled_by_default(self):
        """Test that filters are enabled by default."""
        self.assertTrue(live_dashboard.CONFIG['filters']['enabled'])

    def test_alerts_enabled_by_default(self):
        """Test that alerts are enabled by default."""
        self.assertTrue(live_dashboard.CONFIG['alerts']['enabled'])


class TestConstants(unittest.TestCase):
    """Tests for theme and color constants."""

    def test_theme_colors_defined(self):
        """Test that theme color constants are defined."""
        self.assertEqual(live_dashboard.DARK_BG, "#0a0e27")
        self.assertEqual(live_dashboard.TEXT_COLOR, "#eeeeee")

    def test_accent_colors_defined(self):
        """Test that accent colors are defined."""
        self.assertIsNotNone(live_dashboard.ACCENT1)
        self.assertIsNotNone(live_dashboard.ACCENT2)
        self.assertIsNotNone(live_dashboard.ACCENT3)


if __name__ == '__main__':
    # Run all tests with verbose output
    unittest.main(verbosity=2)
