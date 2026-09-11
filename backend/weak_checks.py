"""Weak-service probes run after a scan.

Currently checks:
  * Anonymous FTP login allowed (port 21)
  * Open / recursive DNS resolver (port 53)
"""
import socket
import struct
from typing import List, Dict

# Domestic DNS probe target - a hostname we do NOT control, used purely to see
# whether the server resolves arbitrary queries (recursion) or just refuses.
_PROBE_DOMAIN = 'test.cyberguard-security-probe.invalid'


def _build_dns_query(qname: str, qtype: int = 1) -> bytes:
    """Minimal DNS query (A record) with the recursion-desired flag set."""
    import random
    txid = random.randint(0, 0xFFFF)
    header = struct.pack('>HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    labels = b''.join(
        bytes([len(part)]) + part.encode('ascii', 'ignore')
        for part in qname.strip('.').split('.') if part
    )
    return header + labels + b'\x00' + struct.pack('>HH', qtype, 1)


def _probe_dns(ip: str, timeout: int = 3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_dns_query(_PROBE_DOMAIN), (ip, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
        if len(data) < 12:
            return None
        flags = struct.unpack('>H', data[2:4])[0]
        answers = struct.unpack('>H', data[6:8])[0]
        return {
            'rcode': flags & 0x000F,
            'recursion_available': bool(flags & 0x0080),
            'answers': answers,
        }
    except socket.timeout:
        return None
    except Exception:
        return None


def _check_ftp_anonymous(ip: str, port: int = 21, timeout: int = 4):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.recv(1024)  # banner
        sock.sendall(b'USER anonymous\r\n')
        sock.recv(1024)
        sock.sendall(b'PASS anonymous@example.com\r\n')
        reply = sock.recv(1024).decode('utf-8', 'ignore')
        sock.close()
        return '230' in reply or '331' in reply
    except Exception:
        return False


def run_weak_service_checks(devices: List) -> List[Dict]:
    """Probe devices with FTP/DNS ports open. Returns alert dicts."""
    findings = []

    for device in devices:
        ports = set(device.open_ports or [])
        ip = device.ip

        # FTP anonymous
        if 21 in ports:
            try:
                allowed = _check_ftp_anonymous(ip)
                if allowed:
                    findings.append({
                        'type': 'weak_ftp_anonymous',
                        'severity': 'high',
                        'message': f'FTP allows anonymous login on {ip}',
                        'device_ip': ip,
                    })
            except Exception:
                pass

        # DNS resolver probes
        if 53 in ports:
            probe = _probe_dns(ip)
            if probe and probe['rcode'] == 0:
                if probe['recursion_available'] and probe['answers'] > 0:
                    findings.append({
                        'type': 'open_dns_recursion',
                        'severity': 'high',
                        'message': (f'Open recursive DNS resolver on {ip} '
                                    f'(answers arbitrary queries)'),
                        'device_ip': ip,
                    })
                else:
                    findings.append({
                        'type': 'open_dns_resolver',
                        'severity': 'medium',
                        'message': f'Responding DNS resolver on {ip} (recursion disabled)',
                        'device_ip': ip,
                    })

    return findings