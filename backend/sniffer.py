"""Passive traffic sniffer (scapy). Captures packets for a short window and
summarizes protocols, top talkers and live bandwidth.

Packet capture needs Npcap installed and administrator privileges on Windows;
errors are captured instead of crashing the app.
"""
import threading
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import conf, sniff
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


_PROTO_NAMES = {
    1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6',
    47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF', 132: 'SCTP',
}


class TrafficSniffer:
    def __init__(self, iface=None, duration=15):
        self.iface = iface or self._default_iface()
        self.duration = min(120, max(3, int(duration)))
        self._lock = threading.Lock()
        self._reset()

    def _reset(self):
        self.protocols = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.talkers = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.total_packets = 0
        self.total_bytes = 0
        self.started_at = None
        self.finished = True
        self.error = None
        self._last_poll_time = 0.0
        self._last_poll_bytes = 0
        self._rate_bps = 0.0

    @staticmethod
    def _default_iface():
        if not SCAPY_AVAILABLE:
            return None
        try:
            # On Windows, conf.iface can be a NetworkInterface object -> str()
            return str(conf.iface)
        except Exception:
            return None

    def _collect(self, pkt):
        try:
            ip = pkt.getlayer('IP') or pkt.getlayer('IPv6')
            if ip is None:
                return
            length = len(pkt)
            proto = getattr(ip, 'proto', 0)
            name = _PROTO_NAMES.get(proto, 'other')
            src = getattr(ip, 'src', '')
            dst = getattr(ip, 'dst', '')

            tcp = pkt.getlayer('TCP')
            udp = pkt.getlayer('UDP')
            if tcp is not None:
                name = 'TCP'
                src = f'{src}:{getattr(tcp, "sport", "?")}'
                dst = f'{dst}:{getattr(tcp, "dport", "?")}'
            elif udp is not None:
                name = 'UDP'
                src = f'{src}:{getattr(udp, "sport", "?")}'
                dst = f'{dst}:{getattr(udp, "dport", "?")}'

            with self._lock:
                self.protocols[name]['packets'] += 1
                self.protocols[name]['bytes'] += length
                key = (src, dst)
                self.talkers[key]['packets'] += 1
                self.talkers[key]['bytes'] += length
                self.total_packets += 1
                self.total_bytes += length
        except Exception:
            pass

    def start(self):
        if not SCAPY_AVAILABLE:
            self.error = 'Scapy capture unavailable (install scapy + Npcap).'
            self.finished = True
            return
        self._reset()
        self.started_at = datetime.now()
        self.finished = False
        thread = threading.Thread(target=self._capture, daemon=True,
                                  name='cyberwatch-sniffer')
        thread.start()

    def _capture(self):
        try:
            sniff(iface=self.iface, prn=self._collect, store=0, timeout=self.duration)
        except PermissionError:
            self.error = ('Packet capture requires administrator privileges. '
                          'Relaunch the app as Administrator.')
        except OSError as e:
            self.error = (f'Capture failed ({e}). Install Npcap and make sure a '
                          f'valid interface is selected (SNIFF_IFACE).')
        except Exception as e:
            self.error = f'Capture failed: {e}'
        finally:
            with self._lock:
                self.finished = True

    def live(self) -> dict:
        """Live counters used while the capture is running."""
        with self._lock:
            now = time.time()
            dt = now - self._last_poll_time
            if 0.8 <= dt <= 30:
                self._rate_bps = (self.total_bytes - self._last_poll_bytes) / dt
            self._last_poll_time = now
            self._last_poll_bytes = self.total_bytes

            elapsed = now - (self.started_at.timestamp() if self.started_at else now)
            progress = min(1.0, elapsed / self.duration) if self.started_at else 0.0
            return {
                'in_progress': not self.finished,
                'finished': self.finished,
                'elapsed': round(elapsed, 1),
                'duration': self.duration,
                'progress': round(progress * 100, 1),
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'rate_bps': round(self._rate_bps, 1),
                'iface': self.iface,
                'error': self.error,
            }

    def result(self) -> dict:
        """Final summary after the capture finishes (or partial if still running)."""
        with self._lock:
            protocols = sorted(self.protocols.items(),
                               key=lambda kv: kv[1]['bytes'], reverse=True)
            protocols = [{'protocol': name, **stats} for name, stats in protocols]
            talkers = sorted(self.talkers.items(),
                             key=lambda kv: kv[1]['bytes'], reverse=True)[:10]
            talkers = [{'src': s, 'dst': d, **stats} for (s, d), stats in talkers]
            return {
                'finished': self.finished,
                'duration': self.duration,
                'started_at': self.started_at.isoformat() if self.started_at else None,
                'iface': self.iface,
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'protocols': protocols,
                'top_talkers': talkers,
                'error': self.error,
            }