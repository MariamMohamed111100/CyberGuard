import unittest
from datetime import datetime

from models import Device
from diffing import compute_scan_diff


def dev(ip='10.0.0.1', mac='aa:bb:cc:dd:ee:ff', ports=None):
    return Device(
        ip=ip, mac=mac, hostname='h', vendor='v',
        last_seen=datetime.now(), is_authorized=True,
        open_ports=ports or [], device_type='device'
    )


class TestComputeScanDiff(unittest.TestCase):
    def test_identical_scans_produce_no_changes(self):
        prev = [dev(), dev(ip='10.0.0.2', mac='11:22:33:44:55:66')]
        curr = [dev(), dev(ip='10.0.0.2', mac='11:22:33:44:55:66')]
        diff = compute_scan_diff(prev, curr)
        self.assertEqual(diff['new'], [])
        self.assertEqual(diff['disappeared'], [])
        self.assertEqual(diff['ports_opened'], [])
        self.assertEqual(diff['ports_closed'], [])
        self.assertEqual(diff['unchanged'], 2)

    def test_new_device_detected(self):
        prev = [dev()]
        curr = [dev(), dev(ip='10.0.0.9', mac='aa:aa:aa:aa:aa:aa')]
        diff = compute_scan_diff(prev, curr)
        self.assertEqual(len(diff['new']), 1)
        self.assertEqual(diff['new'][0]['ip'], '10.0.0.9')

    def test_disappeared_device_detected(self):
        prev = [dev(), dev(ip='10.0.0.9', mac='aa:aa:aa:aa:aa:aa')]
        curr = [dev()]
        diff = compute_scan_diff(prev, curr)
        self.assertEqual(len(diff['disappeared']), 1)
        self.assertEqual(diff['disappeared'][0]['ip'], '10.0.0.9')

    def test_ports_opened_and_closed(self):
        prev = [dev(ports=[22, 80])]
        curr = [dev(ports=[22, 443, 8080])]
        diff = compute_scan_diff(prev, curr)
        self.assertEqual([p['port'] for p in diff['ports_opened']], [443, 8080])
        self.assertEqual([p['port'] for p in diff['ports_closed']], [80])

    def test_macs_normalized_when_matching(self):
        prev = [dev(mac='AA:BB:CC:DD:EE:FF', ports=[22])]
        curr = [dev(mac='aa:bb:cc:dd:ee:ff', ports=[22, 25])]
        diff = compute_scan_diff(prev, curr)
        self.assertEqual(diff['new'], [])
        self.assertEqual([p['port'] for p in diff['ports_opened']], [25])

    def test_dict_inputs_supported(self):
        prev = [{'ip': '10.0.0.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'open_ports': [22]}]
        curr = [{'ip': '10.0.0.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'open_ports': []}]
        diff = compute_scan_diff(prev, curr)
        self.assertEqual([p['port'] for p in diff['ports_closed']], [22])


if __name__ == '__main__':
    unittest.main()