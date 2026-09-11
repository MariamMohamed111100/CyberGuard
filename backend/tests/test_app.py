import os
import tempfile
import unittest

# Isolate tests from the developer's real .env and production DB state:
# force known credentials before the app module reads its config, otherwise
# login-based tests break whenever the user customizes ADMIN creds.
os.environ['ADMIN_USERNAME'] = 'admin'
os.environ['ADMIN_PASSWORD'] = 'admin'

import app as app_module

app = app_module.app


class TestApp(unittest.TestCase):
    def setUp(self):
        app.config.testing = True
        self.client = app.test_client()

        # Clear the production scans/alerts that _restore_initial_state()
        # loaded into module memory at import time.
        app_module.security_monitor.alerts = []
        app_module.current_devices = []
        app_module.current_alerts = []
        app_module.last_scan_time = None

        # Isolate the authorized-devices file from the real one
        self.tmp_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.tmp_dir, 'authorized_devices.json')
        app_module.db.authorized_devices_file = self.db_file
        app_module.db.load_authorized_devices()

        # Isolate the SQLite storage from the real one
        from storage import Storage
        self.old_storage = app_module.storage
        self.temp_db = os.path.join(self.tmp_dir, 'test.db')
        app_module.storage = Storage(self.temp_db)

        self.old_token = app_module.config.API_TOKEN
        app_module.config.API_TOKEN = 'test-token'

        self.old_devices = app_module.current_devices
        app_module.current_devices = []

    def tearDown(self):
        app_module.storage.close()
        app_module.storage = self.old_storage
        app_module.config.API_TOKEN = self.old_token
        app_module.current_devices = self.old_devices
        app_module.db.authorized_devices_file = os.path.join(app_module.DATA_DIR, 'authorized_devices.json')
        app_module.db.load_authorized_devices()
        for path in (self.db_file, self.temp_db):
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
        if os.path.exists(self.tmp_dir):
            try:
                os.rmdir(self.tmp_dir)
            except OSError:
                pass

    def test_health(self):
        res = self.client.get('/api/health')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['status'], 'healthy')

    def test_status_endpoint(self):
        res = self.client.get('/api/status')
        self.assertEqual(res.status_code, 200)
        self.assertIn('scan_in_progress', res.json)
        self.assertIn('subnet', res.json)
        self.assertIn('nmap_available', res.json)

    def test_devices_initial_empty(self):
        res = self.client.get('/api/devices')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['devices'], [])

    def test_alerts_initial_empty(self):
        res = self.client.get('/api/alerts')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['alerts'], [])

    def test_authorize_requires_token(self):
        res = self.client.post('/api/device/aa:bb:cc:dd:ee:ff/authorize', json={'ip': '10.0.0.2'})
        self.assertEqual(res.status_code, 401)

    def test_authorize_with_token(self):
        res = self.client.post(
            '/api/device/AA:BB:CC:DD:EE:FF/authorize',
            json={'ip': '10.0.0.2'},
            headers={'X-API-Token': 'test-token'}
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(app_module.db.is_device_authorized('aa:bb:cc:dd:ee:ff'))

    def test_unauthorize_with_bearer_token(self):
        app_module.db.add_authorized_device({'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '10.0.0.2'})
        res = self.client.post(
            '/api/device/AA:BB:CC:DD:EE:FF/unauthorize',
            headers={'Authorization': 'Bearer test-token'}
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(app_module.db.is_device_authorized('aa:bb:cc:dd:ee:ff'))

    def test_authorized_devices_listing(self):
        app_module.db.add_authorized_device({'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '10.0.0.2', 'hostname': 'x'})
        res = self.client.get('/api/authorized-devices')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json['devices']), 1)

    def test_unknown_device_ports_returns_404(self):
        res = self.client.get('/api/device/192.0.2.1/ports')
        self.assertEqual(res.status_code, 404)

    # ------------------------------------------------------------------ auth

    def test_me_anonymous(self):
        res = self.client.get('/api/me')
        self.assertIsNone(res.json['username'])

    def test_login_success(self):
        res = self.client.post('/api/login', json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['role'], 'admin')
        me = self.client.get('/api/me')
        self.assertEqual(me.json['username'], 'admin')
        self.assertEqual(me.json['role'], 'admin')

    def test_login_wrong_password(self):
        res = self.client.post('/api/login', json={'username': 'admin', 'password': 'wrong'})
        self.assertEqual(res.status_code, 401)

    def test_login_records_audit(self):
        self.client.post('/api/login', json={'username': 'admin', 'password': 'admin'})
        res = self.client.get('/api/audit', headers={'X-API-Token': 'test-token'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['audit'][-1]['action'], 'login')

    # ------------------------------------------------------------------ export

    def test_export_requires_auth(self):
        res = self.client.get('/api/export?format=csv')
        self.assertEqual(res.status_code, 401)
        res = self.client.get('/api/export?format=json')
        self.assertEqual(res.status_code, 401)

    def test_export_json_with_token(self):
        from models import Device
        from datetime import datetime
        app_module.current_devices = [Device(
            ip='10.0.0.2', mac='aa:bb:cc:dd:ee:ff', hostname='x', vendor='y',
            last_seen=datetime.now(), is_authorized=True, open_ports=[22, 80],
            device_type='web-server'
        )]
        res = self.client.get('/api/export?format=json', headers={'X-API-Token': 'test-token'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/json')
        self.assertIn(b'web-server', res.data)

    def test_export_csv_via_session(self):
        from models import Device
        from datetime import datetime
        app_module.current_devices = [Device(
            ip='10.0.0.2', mac='aa:bb:cc:dd:ee:ff', hostname='x', vendor='y',
            last_seen=datetime.now(), is_authorized=False, open_ports=[22],
            device_type='ssh-server'
        )]
        self.client.post('/api/login', json={'username': 'admin', 'password': 'admin'})
        res = self.client.get('/api/export?format=csv')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'text/csv')
        self.assertIn(b'ip', res.data)
        self.assertIn(b'ssh-server', res.data)

    def test_export_html(self):
        from models import Device
        from datetime import datetime
        app_module.current_devices = [Device(
            ip='10.0.0.2', mac='aa:bb:cc:dd:ee:ff', hostname='x', vendor='y',
            last_seen=datetime.now(), is_authorized=False, open_ports=[22],
            device_type='ssh-server'
        )]
        self.client.post('/api/login', json={'username': 'admin', 'password': 'admin'})
        res = self.client.get('/api/export?format=html')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'text/html')
        self.assertIn(b'CyberGuard', res.data)
        self.assertIn(b'10.0.0.2', res.data)

    def test_export_pdf(self):
        from models import Device
        from datetime import datetime
        app_module.current_devices = [Device(
            ip='10.0.0.2', mac='aa:bb:cc:dd:ee:ff', hostname='x', vendor='y',
            last_seen=datetime.now(), is_authorized=True, open_ports=[22],
            device_type='ssh-server'
        )]
        self.client.post('/api/login', json={'username': 'admin', 'password': 'admin'})
        res = self.client.get('/api/export?format=pdf')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/pdf')
        self.assertTrue(res.data.startswith(b'%PDF'))

    # ------------------------------------------------------------------ reports

    def test_history_endpoint_open(self):
        res = self.client.get('/api/history')
        self.assertEqual(res.status_code, 200)
        self.assertIn('history', res.json)

    def test_diff_endpoint_empty_until_two_scans(self):
        res = self.client.get('/api/diff')
        self.assertEqual(res.status_code, 200)
        self.assertIn('diff', res.json)
        self.assertIsNone(res.json['diff'])

    def test_diff_endpoint_after_two_scans(self):
        from models import Device
        from datetime import datetime

        def d(ip, mac):
            return Device(ip=ip, mac=mac, hostname='h', vendor='v',
                          last_seen=datetime.now(), is_authorized=True,
                          open_ports=[22], device_type='device')

        app_module.storage.save_snapshot(datetime.now(), [d('10.0.0.1', 'aa:bb:cc:dd:ee:ff')])
        app_module.storage.save_snapshot(datetime.now(), [
            d('10.0.0.1', 'aa:bb:cc:dd:ee:ff'),
            d('10.0.0.2', '11:22:33:44:55:66')
        ])
        res = self.client.get('/api/diff')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json['diff']['new']), 1)
        self.assertEqual(res.json['diff']['new'][0]['ip'], '10.0.0.2')

    def test_sniff_start_requires_auth(self):
        res = self.client.post('/api/sniff/start?duration=3')
        self.assertEqual(res.status_code, 401)

    def test_sniff_start_status_queue(self):
        self.client.post('/api/login', json={'username': 'admin', 'password': 'admin'})
        res = self.client.post('/api/sniff/start?duration=3')
        self.assertEqual(res.status_code, 200)
        self.assertIn(res.json['status'], ('sniff_started', 'sniff_in_progress'))
        self.assertEqual(self.client.get('/api/sniff/status').status_code, 200)

    def test_sniff_result_requires_auth(self):
        res = self.client.get('/api/sniff/result')
        self.assertEqual(res.status_code, 401)

    # ------------------------------------------------------------------ cves / os

    def test_cves_endpoint_unknown_device(self):
        res = self.client.get('/api/device/192.0.2.1/cves')
        self.assertEqual(res.status_code, 404)

    def test_cves_endpoint_with_lookup_patched(self):
        from models import Device
        from datetime import datetime
        app_module.current_devices = [Device(
            ip='10.0.0.2', mac='aa:bb:cc:dd:ee:ff', hostname='x', vendor='y',
            last_seen=datetime.now(), is_authorized=True, open_ports=[22],
            device_type='ssh-server'
        )]
        original = app_module.lookup_cves_for_device
        app_module.lookup_cves_for_device = lambda device, details: [{
            'port': 22, 'service': 'openssh', 'version': '8.2',
            'checked': True,
            'cves': [{'id': 'CVE-2021-0001', 'summary': 'ssh vuln', 'cvss': 9.1}],
        }]
        try:
            res = self.client.get('/api/device/10.0.0.2/cves')
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data['source'], 'live')
            self.assertEqual(data['cves'][0]['cve_id'], 'CVE-2021-0001')
            # second call served from the cache
            cached = self.client.get('/api/device/10.0.0.2/cves').get_json()
            self.assertEqual(cached['source'], 'cache')
        finally:
            app_module.lookup_cves_for_device = original

    def test_os_endpoint_patched(self):
        from models import Device
        from datetime import datetime
        app_module.current_devices = [Device(
            ip='10.0.0.2', mac='aa:bb:cc:dd:ee:ff', hostname='x', vendor='y',
            last_seen=datetime.now(), is_authorized=True, open_ports=[22],
            device_type='ssh-server'
        )]
        original = app_module.scanner.detect_os
        app_module.scanner.detect_os = lambda ip: {
            'os_name': 'Linux 3.10', 'accuracy': 85, 'method': 'nmap-os'}
        try:
            res = self.client.get('/api/device/10.0.0.2/os')
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data['os']['os_name'], 'Linux 3.10')
            self.assertEqual(data['source'], 'live')
            cached = self.client.get('/api/device/10.0.0.2/os').get_json()
            self.assertEqual(cached['source'], 'cache')
        finally:
            app_module.scanner.detect_os = original

    def test_status_includes_channels(self):
        res = self.client.get('/api/status')
        self.assertEqual(res.status_code, 200)
        channels = res.json['channels']
        self.assertEqual(set(channels.keys()), {'webhook', 'telegram', 'email'})
        self.assertIsInstance(channels['webhook'], bool)

    def test_os_endpoint_unknown_device(self):
        res = self.client.get('/api/device/192.0.2.1/os')
        self.assertEqual(res.status_code, 404)

    def test_audit_requires_auth(self):
        res = self.client.get('/api/audit')
        self.assertEqual(res.status_code, 401)

    def test_authorize_records_audit(self):
        res = self.client.post(
            '/api/device/AA:BB:CC:DD:EE:FF/authorize',
            json={'ip': '10.0.0.2'},
            headers={'X-API-Token': 'test-token'}
        )
        self.assertEqual(res.status_code, 200)
        audit = self.client.get('/api/audit', headers={'X-API-Token': 'test-token'}).json['audit']
        self.assertEqual(audit[-1]['action'], 'authorize')
        self.assertEqual(audit[-1]['actor'], 'api-token')

    def test_authorize_updates_cached_devices_immediately(self):
        from models import Device
        from datetime import datetime
        app_module.current_devices = [Device(
            ip='10.0.0.2',
            mac='AA:BB:CC:DD:EE:FF',
            hostname='x',
            vendor='y',
            last_seen=datetime.now(),
            is_authorized=False,
            open_ports=[]
        )]
        res = self.client.post(
            '/api/device/AA:BB:CC:DD:EE:FF/authorize',
            json={'ip': '10.0.0.2'},
            headers={'X-API-Token': 'test-token'}
        )
        self.assertEqual(res.status_code, 200)
        devices = self.client.get('/api/devices').get_json()['devices']
        self.assertTrue(devices[0]['is_authorized'])

    def test_unauthorize_updates_cached_devices_immediately(self):
        from models import Device
        from datetime import datetime
        app_module.current_devices = [Device(
            ip='10.0.0.2',
            mac='aa:bb:cc:dd:ee:ff',
            hostname='x',
            vendor='y',
            last_seen=datetime.now(),
            is_authorized=True,
            open_ports=[]
        )]
        app_module.db.add_authorized_device({'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '10.0.0.2'})
        res = self.client.post(
            '/api/device/AA:BB:CC:DD:EE:FF/unauthorize',
            headers={'X-API-Token': 'test-token'}
        )
        self.assertEqual(res.status_code, 200)
        devices = self.client.get('/api/devices').get_json()['devices']
        self.assertFalse(devices[0]['is_authorized'])


if __name__ == '__main__':
    unittest.main()