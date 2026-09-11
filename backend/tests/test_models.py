import os
import tempfile
import unittest

from models import Database, normalize_mac


class TestNormalizeMac(unittest.TestCase):
    def test_lowercases(self):
        self.assertEqual(normalize_mac('AA:BB:CC:DD:EE:FF'), 'aa:bb:cc:dd:ee:ff')

    def test_strips_whitespace(self):
        self.assertEqual(normalize_mac(' aa:BB:cc:dd:ee:ff '), 'aa:bb:cc:dd:ee:ff')

    def test_converts_dashes(self):
        self.assertEqual(normalize_mac('AA-BB-CC-DD-EE-FF'), 'aa:bb:cc:dd:ee:ff')

    def test_empty(self):
        self.assertEqual(normalize_mac(''), '')
        self.assertEqual(normalize_mac(None), '')

    def test_oui_prefix(self):
        self.assertEqual(normalize_mac('00:0C:29'), '00:0c:29')


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.tmp_dir, 'authorized_devices.json')
        self.db = Database(self.db_file)

    def tearDown(self):
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
        os.rmdir(self.tmp_dir)

    def test_default_path_is_under_data_dir(self):
        db = Database()
        self.assertTrue(os.path.join('data', 'authorized_devices.json') in db.authorized_devices_file)

    def test_add_and_check_case_insensitive(self):
        self.db.add_authorized_device({'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '10.0.0.5', 'hostname': 'test'})
        self.assertTrue(self.db.is_device_authorized('aa:bb:cc:dd:ee:ff'))
        self.assertTrue(self.db.is_device_authorized('aA:bB:cC:dD:eE:fF'))

    def test_remove_normalizes(self):
        self.db.add_authorized_device({'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '10.0.0.5'})
        self.db.remove_authorized_device('AA:BB:CC:DD:EE:FF')
        self.assertFalse(self.db.is_device_authorized('aa:bb:cc:dd:ee:ff'))

    def test_add_requires_mac(self):
        with self.assertRaises(ValueError):
            self.db.add_authorized_device({'ip': '10.0.0.5'})

    def test_missing_file_means_empty(self):
        self.assertEqual(self.db.authorized_devices, {})

    def test_persistence(self):
        self.db.add_authorized_device({'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '10.0.0.5'})
        reloaded = Database(self.db_file)
        self.assertTrue(reloaded.is_device_authorized('aa:bb:cc:dd:ee:ff'))

    def test_legacy_uppercase_keys_are_migrated_on_load(self):
        import json
        with open(self.db_file, 'w') as f:
            json.dump({
                '00:0C:29:XX:XX:XX': {'mac': '00:0C:29:XX:XX:XX', 'ip': '10.0.0.1', 'hostname': 'Main-Server'},
                'AA:BB:CC:DD:EE:FF': {'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '10.0.0.2', 'hostname': 'Admin-PC'}
            }, f)

        db = Database(self.db_file)
        # Legacy entries must be reachable with the canonical (lowercase) form
        self.assertTrue(db.is_device_authorized('00:0c:29:xx:xx:xx'))
        self.assertTrue(db.is_device_authorized('aa:bb:cc:dd:ee:ff'))

        # Removing via the canonical form must actually delete the legacy entry
        db.remove_authorized_device('AA:BB:CC:DD:EE:FF')
        self.assertFalse(db.is_device_authorized('aa:bb:cc:dd:ee:ff'))
        self.assertTrue(db.is_device_authorized('00:0c:29:xx:xx:xx'))

    def test_remove_legacy_uppercase_entry(self):
        import json
        with open(self.db_file, 'w') as f:
            json.dump({
                '00:0C:29:XX:XX:XX': {'mac': '00:0C:29:XX:XX:XX', 'ip': '10.0.0.1'}
            }, f)

        db = Database(self.db_file)
        db.remove_authorized_device('00:0C:29:XX:XX:XX')
        self.assertFalse(db.is_device_authorized('00:0c:29:xx:xx:xx'))
        self.assertEqual(db.authorized_devices, {})


if __name__ == '__main__':
    unittest.main()