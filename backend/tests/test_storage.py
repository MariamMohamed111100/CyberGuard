import os
import tempfile
import unittest
from datetime import datetime

from models import Device, SecurityAlert
from storage import Storage


def make_device(ip='10.0.0.1', mac='aa:bb:cc:dd:ee:ff', authorized=True, ports=None):
    return Device(
        ip=ip,
        mac=mac,
        hostname='host',
        vendor='Unknown',
        last_seen=datetime.now(),
        is_authorized=authorized,
        open_ports=ports or [],
        device_type='device'
    )


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.tmp_dir, 'test.db')
        self.store = Storage(self.db_file)

    def tearDown(self):
        self.store.close()
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
        os.rmdir(self.tmp_dir)

    def test_snapshot_roundtrip(self):
        now = datetime.now()
        self.store.save_snapshot(now, [make_device(), make_device(ip='10.0.0.2', authorized=False)])
        history = self.store.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['device_count'], 2)
        self.assertEqual(history[0]['unauthorized_count'], 1)
        last = self.store.get_last_snapshot()
        self.assertEqual(len(last), 2)
        self.assertEqual(last[0]['ip'], '10.0.0.1')

    def test_timeline_keeps_first_seen(self):
        now = datetime.now()
        dev = make_device()
        self.store.update_timeline([dev])
        timeline = self.store.get_timeline()
        self.assertEqual(timeline[0]['first_seen'], timeline[0]['last_seen'])

        import time as _t
        _t.sleep(0.01)
        self.store.update_timeline([make_device(mac='aa:bb:cc:dd:ee:ff')])
        timeline = self.store.get_timeline()
        self.assertEqual(timeline[0]['first_seen'][:19], now.isoformat()[:19])
        self.assertNotEqual(timeline[0]['first_seen'], timeline[0]['last_seen'])

    def test_detect_new_devices_before_update(self):
        dev = make_device(mac='11:22:33:44:55:66')
        self.assertEqual(len(self.store.detect_new_devices([dev])), 1)
        self.store.update_timeline([dev])
        self.assertEqual(len(self.store.detect_new_devices([dev])), 0)

    def test_arp_bindings_initial_insert(self):
        dev = make_device(ip='10.0.0.1', mac='aa:bb:cc:dd:ee:ff')
        changed = self.store.update_arp_bindings([dev])
        self.assertEqual(changed, [])
        bindings = self.store.get_arp_bindings()
        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0]['mac'], 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(bindings[0]['changes'], 0)

    def test_arp_binding_change_detected(self):
        dev1 = make_device(ip='10.0.0.1', mac='aa:bb:cc:dd:ee:ff')
        self.store.update_arp_bindings([dev1])
        dev2 = make_device(ip='10.0.0.1', mac='11:22:33:44:55:66')
        changed = self.store.update_arp_bindings([dev2])
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]['ip'], '10.0.0.1')
        self.assertEqual(changed[0]['old_mac'], 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(changed[0]['new_mac'], '11:22:33:44:55:66')
        self.assertEqual(changed[0]['changes'], 1)

    def test_arp_binding_change_mac_normalized(self):
        self.store.update_arp_bindings([make_device(ip='10.0.0.1', mac='AA:BB:CC:DD:EE:FF')])
        changed = self.store.update_arp_bindings([make_device(ip='10.0.0.1', mac='aa-bb-cc-dd-ee-ff')])
        self.assertEqual(changed, [])

    def test_arp_binding_stable_no_change(self):
        self.store.update_arp_bindings([make_device(ip='10.0.0.1')])
        changed = self.store.update_arp_bindings([make_device(ip='10.0.0.1')])
        self.assertEqual(changed, [])
        self.assertEqual(self.store.get_arp_bindings()[0]['changes'], 0)

    def test_last_two_snapshots(self):
        from datetime import datetime, timedelta
        self.store.save_snapshot(datetime.now() - timedelta(minutes=2), [make_device()])
        self.store.save_snapshot(datetime.now(), [make_device(), make_device(ip='10.0.0.2')])
        older, newer = self.store.get_last_two_snapshots()
        self.assertEqual(len(older), 1)
        self.assertEqual(len(newer), 2)

    def test_cves_roundtrip(self):
        self.store.save_cves('10.0.0.1', [
            {'port': 22, 'service': 'openssh', 'version': '8.2',
             'cves': [{'id': 'CVE-2021-0001', 'summary': 'ssh vuln', 'cvss': 9.1}]}
        ])
        rows = self.store.get_cves('10.0.0.1')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['cve_id'], 'CVE-2021-0001')
        self.assertEqual(rows[0]['cvss'], 9.1)

    def test_cves_replaced_on_resave(self):
        self.store.save_cves('10.0.0.1', [{'port': 22, 'service': 'openssh',
                                           'version': '1', 'cves': [{'id': 'CVE-A'}]}])
        self.store.save_cves('10.0.0.1', [{'port': 80, 'service': 'nginx',
                                           'version': '1', 'cves': [{'id': 'CVE-B'}]}])
        rows = self.store.get_cves('10.0.0.1')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['cve_id'], 'CVE-B')

    def test_os_roundtrip(self):
        self.store.save_os('10.0.0.1', 'Linux 2.6.32', 92)
        row = self.store.get_os('10.0.0.1')
        self.assertEqual(row['os_name'], 'Linux 2.6.32')
        self.assertEqual(row['accuracy'], 92)

    def test_os_expired_returned_none(self):
        from datetime import datetime, timedelta
        import sqlite3
        self.store.save_os('10.0.0.1', 'Windows 10', 90)
        # backdate it beyond the freshness window
        old = (datetime.now() - timedelta(hours=5)).isoformat()
        self.store._execute('UPDATE device_os SET checked_at=? WHERE ip=?',
                            (old, '10.0.0.1'))
        self.assertIsNone(self.store.get_os('10.0.0.1'))

    def test_alerts_roundtrip(self):
        alert = SecurityAlert(
            id='x1', type='high_risk_port', severity='high',
            message='test', timestamp=datetime.now(), device_ip='10.0.0.1')
        self.store.record_alerts([alert])
        loaded = self.store.load_recent_alerts()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]['type'], 'high_risk_port')

    def test_audit_roundtrip(self):
        self.store.audit('authorize', 'aa:bb:cc:dd:ee:ff', 'admin')
        self.store.audit('scan', '5 devices', 'system')
        log = self.store.get_audit_log()
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0]['action'], 'authorize')


if __name__ == '__main__':
    unittest.main()