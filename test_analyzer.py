"""
Unit tests for NetworkTrafficAnalyser core functions.
Tests packet filtering, byte formatting, and color constants.

Run:  python test_analyzer.py
"""

import unittest
import sys

# Prevent argparse from processing during import
sys.argv = ['test_analyzer.py']

from live_dashboard import (
    format_bytes, CONFIG, DARK_BG, TEXT_COLOR, ACCENT1, ACCENT2, ACCENT3, kfmt
)


class TestByteFormatting(unittest.TestCase):
    """Test format_bytes() function."""

    def test_single_byte(self):
        """Test formatting single byte."""
        self.assertEqual(format_bytes(1), "1.00 B")

    def test_kilobytes(self):
        """Test formatting kilobytes."""
        result = format_bytes(1024)
        self.assertIn("1.00", result)
        self.assertIn("KB", result)

    def test_megabytes(self):
        """Test formatting megabytes."""
        result = format_bytes(1024**2)
        self.assertIn("1.00", result)
        self.assertIn("MB", result)

    def test_zero(self):
        """Test formatting zero bytes."""
        self.assertEqual(format_bytes(0), "0.00 B")

    def test_fractional(self):
        """Test formatting fractional KB."""
        result = format_bytes(1536)
        self.assertIn("1.50", result)
        self.assertIn("KB", result)


class TestConfiguration(unittest.TestCase):
    """Test configuration is properly loaded."""

    def test_config_exists(self):
        """Test CONFIG object exists."""
        self.assertIsNotNone(CONFIG)

    def test_required_sections(self):
        """Test all required config sections exist."""
        required = ['capture', 'filters', 'alerts', 'export', 'display']
        for section in required:
            self.assertIn(section, CONFIG, f"Missing section: {section}")

    def test_filters_enabled(self):
        """Test filters enabled by default."""
        self.assertTrue(CONFIG['filters']['enabled'])

    def test_alerts_enabled(self):
        """Test alerts enabled by default."""
        self.assertTrue(CONFIG['alerts']['enabled'])

    def test_display_settings(self):
        """Test display config has required keys."""
        display = CONFIG.get('display', {})
        self.assertIn('window_width', display)
        self.assertIn('window_height', display)
        self.assertIn('update_interval_ms', display)


class TestThemeColors(unittest.TestCase):
    """Test theme and color constants."""

    def test_dark_bg_color(self):
        """Test dark background color."""
        self.assertEqual(DARK_BG, "#0a0e27")

    def test_text_color(self):
        """Test text color."""
        self.assertEqual(TEXT_COLOR, "#eeeeee")

    def test_accent_colors(self):
        """Test accent colors are defined."""
        self.assertIsNotNone(ACCENT1)
        self.assertIsNotNone(ACCENT2)
        self.assertIsNotNone(ACCENT3)
        # Verify they're hex colors
        self.assertTrue(ACCENT1.startswith('#'))
        self.assertTrue(ACCENT2.startswith('#'))
        self.assertTrue(ACCENT3.startswith('#'))


class TestNumberFormatter(unittest.TestCase):
    """Test kfmt number formatter."""

    def test_thousands(self):
        """Test formatting thousands."""
        self.assertEqual(kfmt(1000, None), "1,000")

    def test_millions(self):
        """Test formatting millions."""
        self.assertEqual(kfmt(1000000, None), "1,000,000")

    def test_zero(self):
        """Test formatting zero."""
        self.assertEqual(kfmt(0, None), "0")

    def test_small_number(self):
        """Test formatting small number."""
        self.assertEqual(kfmt(42, None), "42")


class TestServicePorts(unittest.TestCase):
    """Test service port mappings."""

    def test_service_dict_exists(self):
        """Test SERVICE dictionary is accessible."""
        from live_dashboard import SERVICE
        self.assertIsNotNone(SERVICE)
        self.assertIsInstance(SERVICE, dict)

    def test_common_services(self):
        """Test known service ports are mapped."""
        from live_dashboard import SERVICE
        self.assertEqual(SERVICE[22], "SSH")
        self.assertEqual(SERVICE[80], "HTTP")
        self.assertEqual(SERVICE[443], "HTTPS")
        self.assertEqual(SERVICE[53], "DNS")


class TestAnomalyDetection(unittest.TestCase):
    """Test anomaly detection configuration and thresholds."""

    def test_port_scan_threshold_exists(self):
        self.assertIn('port_scan_threshold', CONFIG['alerts'])

    def test_high_pps_threshold_exists(self):
        self.assertIn('high_pps_threshold', CONFIG['alerts'])

    def test_thresholds_are_positive(self):
        self.assertGreater(CONFIG['alerts']['port_scan_threshold'], 0)
        self.assertGreater(CONFIG['alerts']['high_pps_threshold'], 0)

    def test_suspicious_ports_configured(self):
        self.assertIn('suspicious_ports', CONFIG['alerts'])
        self.assertIsInstance(CONFIG['alerts']['suspicious_ports'], list)


class TestFilterLogic(unittest.TestCase):
    """Test packet filter configuration logic."""

    def test_filter_config_has_required_keys(self):
        required = ['enabled', 'ip_whitelist', 'ip_blacklist', 'port_whitelist', 'port_blacklist']
        for key in required:
            self.assertIn(key, CONFIG['filters'])

    def test_port_range_is_valid(self):
        self.assertGreaterEqual(CONFIG['filters']['port_range_min'], 1)
        self.assertLessEqual(CONFIG['filters']['port_range_max'], 65535)
        self.assertLessEqual(
            CONFIG['filters']['port_range_min'],
            CONFIG['filters']['port_range_max']
        )

    def test_protocols_list_contains_expected(self):
        protocols = CONFIG['filters']['protocols']
        self.assertIn('TCP', protocols)
        self.assertIn('UDP', protocols)


if __name__ == '__main__':
    # Run tests with verbosity
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*60)
    if result.wasSuccessful():
        print("✅ All tests passed!")
    else:
        print(f"❌ {len(result.failures)} failures, {len(result.errors)} errors")
    print("="*60)
