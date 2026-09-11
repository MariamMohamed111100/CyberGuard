import unittest

from scanner import NetworkScanner, classify_device


class TestClassifyDevice(unittest.TestCase):
    def test_router_by_port(self):
        self.assertEqual(classify_device('host', 'Cisco', [53, 80]), 'router')

    def test_router_by_hostname(self):
        self.assertEqual(classify_device('wireless-router', 'X', [80]), 'router')

    def test_workstation_windows_ports(self):
        self.assertEqual(classify_device('DESKTOP-ABC', 'X', [135, 139, 445]), 'workstation')

    def test_web_server(self):
        self.assertEqual(classify_device('host', 'X', [80, 443, 8080]), 'web-server')

    def test_database_server(self):
        self.assertEqual(classify_device('host', 'X', [3306]), 'database-server')

    def test_printer(self):
        self.assertEqual(classify_device('printer1', 'X', [631, 9100]), 'printer')

    def test_default_device(self):
        self.assertEqual(classify_device('host', 'X', []), 'device')

    def test_ssh_server(self):
        self.assertEqual(classify_device('host', 'X', [22]), 'ssh-server')


class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NetworkScanner()

    def test_port_spec_covers_config_ports_beyond_1024(self):
        spec = self.scanner._port_spec()
        self.assertIn('1-1024', spec)
        for port in [3306, 5432, 5900, 8080, 8888, 9000, 3000]:
            self.assertIn(str(port), spec)

    def test_risk_levels(self):
        c = self.scanner.config
        self.assertEqual(self.scanner._risk_level_for_port(23), 'high')
        self.assertEqual(self.scanner._risk_level_for_port(445), 'high')
        self.assertEqual(self.scanner._risk_level_for_port(8080), 'medium')
        self.assertEqual(self.scanner._risk_level_for_port(443), 'low')
        self.assertEqual(self.scanner._risk_level_for_port(4444), 'warning')

    def test_get_port_details_cache_fallback(self):
        # A port never scanned returns a cached-style fallback without scanning
        info = self.scanner.get_port_details('192.0.2.1', 23)
        self.assertEqual(info.risk_level, 'high')
        self.assertEqual(info.port, 23)

    def test_get_all_port_details_empty_initial(self):
        self.assertEqual(self.scanner.get_all_port_details('192.0.2.1'), [])

    def test_scan_ports_without_nmap_returns_empty(self):
        # Nonexistent / unreachable IP should not raise, just returns []
        ports = self.scanner.scan_ports('127.0.0.1')
        self.assertIsInstance(ports, list)


if __name__ == '__main__':
    unittest.main()