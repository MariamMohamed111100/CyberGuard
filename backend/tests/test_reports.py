import unittest
from datetime import datetime

from models import Device
from reports import generate_html_report, generate_pdf_report


def dev(ip='10.0.0.1', mac='aa:bb:cc:dd:ee:ff', authorized=True):
    return Device(ip=ip, mac=mac, hostname='pc', vendor='VMware',
                  last_seen=datetime.now(), is_authorized=authorized,
                  open_ports=[22, 80], device_type='web-server').to_dict()


class TestReports(unittest.TestCase):
    def test_html_contains_device_data(self):
        html = generate_html_report([dev(), dev(authorized=False)])
        self.assertIn('CyberGuard', html)
        self.assertIn('10.0.0.1', html)
        self.assertIn('UNAUTHORIZED', html)
        self.assertIn('<html', html)

    def test_html_includes_history(self):
        html = generate_html_report([dev()], [{'scan_time': '2026-01-01T00:00:00',
                                               'device_count': 1,
                                               'unauthorized_count': 0}])
        self.assertIn('Scan History', html)
        self.assertIn('2026-01-01T00:00:00', html)

    def test_pdf_returns_bytes(self):
        data, err = generate_pdf_report([dev()],
                                        [{'scan_time': 'now', 'device_count': 1,
                                          'unauthorized_count': 0}])
        self.assertIsNone(err)
        self.assertTrue(data.startswith(b'%PDF'))


if __name__ == '__main__':
    unittest.main()