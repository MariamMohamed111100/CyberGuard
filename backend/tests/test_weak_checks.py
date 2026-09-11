import unittest

from models import Device
from datetime import datetime
import weak_checks


def make_device(ip='10.0.0.1', mac='aa:bb:cc:dd:ee:ff', ports=None):
    return Device(ip=ip, mac=mac, hostname='h', vendor='v',
                  last_seen=datetime.now(), is_authorized=True,
                  open_ports=ports or [], device_type='device')


class TestBuildDnsQuery(unittest.TestCase):
    def test_query_structure(self):
        q = weak_checks._build_dns_query('example.com')
        self.assertEqual(q[2:4], b'\x01\x00')  # opcode QUERY + RD flag
        self.assertEqual(len(q[12 + 12 + 1:]), 4)  # QTYPE + QCLASS tail


class TestRunWeakChecks(unittest.TestCase):
    def test_no_probes_without_relevant_ports(self):
        dev = make_device(ports=[80, 443])
        self.assertEqual(weak_checks.run_weak_service_checks([dev]), [])

    def test_ftp_anonymous_flagged(self):
        dev = make_device(ports=[21])
        weak_checks._check_ftp_anonymous = lambda ip: True
        res = weak_checks.run_weak_service_checks([dev])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['type'], 'weak_ftp_anonymous')
        self.assertEqual(res[0]['severity'], 'high')

    def test_open_recursive_dns_flagged(self):
        dev = make_device(ports=[53])
        weak_checks._probe_dns = lambda ip: {
            'rcode': 0, 'recursion_available': True, 'answers': 2}
        res = weak_checks.run_weak_service_checks([dev])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['type'], 'open_dns_recursion')

    def test_plain_dns_resolver_medium(self):
        dev = make_device(ports=[53])
        weak_checks._probe_dns = lambda ip: {
            'rcode': 0, 'recursion_available': False, 'answers': 0}
        res = weak_checks.run_weak_service_checks([dev])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['type'], 'open_dns_resolver')
        self.assertEqual(res[0]['severity'], 'medium')


if __name__ == '__main__':
    unittest.main()