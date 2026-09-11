import unittest
from datetime import datetime

from advisor import SecurityAdvisor
from models import Device, PortInfo


class SupportDeviceFactory:
    @staticmethod
    def make(ip='10.0.0.1', authorized=True, open_ports=None):
        return Device(
            ip=ip,
            mac='aa:bb:cc:dd:ee:ff',
            hostname='test',
            vendor='Unknown',
            last_seen=datetime.now(),
            is_authorized=authorized,
            open_ports=open_ports or []
        )


class TestSecurityAdvisor(unittest.TestCase):
    def setUp(self):
        self.advisor = SecurityAdvisor()

    def test_advice_order_preserved_and_deduped(self):
        device = SupportDeviceFactory.make(authorized=False, open_ports=[23])
        advice = self.advisor.get_advice_for_device(device, [PortInfo(23, 'telnet', 'open', '', 'high')])
        self.assertEqual(len(advice), len(set(advice)))
        self.assertEqual(len(advice), 5)

    def test_unauthorized_device_advice(self):
        device = SupportDeviceFactory.make(authorized=False)
        advice = self.advisor.get_advice_for_device(device, [])
        self.assertTrue(any('authorized' in a.lower() for a in advice))

    def test_score_full_defeated(self):
        devices = [SupportDeviceFactory.make(authorized=False) for _ in range(10)]
        report = self.advisor.generate_security_report(devices)
        self.assertEqual(report['security_score'], 0)
        self.assertEqual(report['risk_assessment'], 'critical')

    def test_score_low_when_clean(self):
        report = self.advisor.generate_security_report([SupportDeviceFactory.make()])
        self.assertEqual(report['security_score'], 100)
        self.assertEqual(report['risk_assessment'], 'low')

    def test_report_includes_recommendations(self):
        report = self.advisor.generate_security_report([])
        self.assertTrue(len(report['recommendations']) >= 2)


if __name__ == '__main__':
    unittest.main()