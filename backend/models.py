from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any
import json
import os

# Absolute paths so the app works no matter what the current working directory is
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')

# Vercel (serverless) has a read-only project filesystem and an ephemeral
# /tmp directory. Point runtime data there so the demo/dashboard keeps working;
# it resets with each instance, which is expected for hosted demo mode.
if os.environ.get('VERCEL'):
    DATA_DIR = os.path.join('/tmp', 'cyberwatch')


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str
    vendor: str
    last_seen: datetime
    is_authorized: bool
    open_ports: List[int]
    device_type: str = 'device'

    def to_dict(self):
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'last_seen': self.last_seen.isoformat(),
            'is_authorized': self.is_authorized,
            'open_ports': self.open_ports,
            'device_type': self.device_type
        }


@dataclass
class PortInfo:
    port: int
    service: str
    state: str
    version: str
    risk_level: str

    def to_dict(self):
        return {
            'port': self.port,
            'service': self.service,
            'state': self.state,
            'version': self.version,
            'risk_level': self.risk_level
        }


@dataclass
class SecurityAlert:
    id: str
    type: str
    severity: str
    message: str
    timestamp: datetime
    device_ip: str = None

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'severity': self.severity,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'device_ip': self.device_ip
        }


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address to a canonical lowercase, colon-separated form."""
    if not mac:
        return ''
    value = mac.strip().lower().replace('-', ':').replace('.', '')
    # Accept both XX:XX:XX:XX:XX:XX and 24-bit OUI prefixes
    parts = [p for p in value.split(':') if p]
    return ':'.join(parts)


class Database:
    def __init__(self, authorized_devices_file: str = None):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.authorized_devices_file = (
            authorized_devices_file or os.path.join(DATA_DIR, 'authorized_devices.json')
        )
        self.load_authorized_devices()

    def load_authorized_devices(self):
        try:
            with open(self.authorized_devices_file, 'r') as f:
                loaded = json.load(f)
        except FileNotFoundError:
            self.authorized_devices = {}
            return
        except (ValueError, OSError):
            self.authorized_devices = {}
            return

        # Migrate any legacy (mixed-case / dashed) MAC keys to the canonical form
        normalized = {}
        changed = False
        for key, value in (loaded or {}).items():
            canonical = normalize_mac(key)
            if not canonical:
                continue
            if isinstance(value, dict):
                value['mac'] = canonical
            if canonical != key:
                changed = True
            normalized[canonical] = value
        self.authorized_devices = normalized
        if changed:
            self.save_authorized_devices()

    def save_authorized_devices(self):
        with open(self.authorized_devices_file, 'w') as f:
            json.dump(self.authorized_devices, f, indent=2)

    def is_device_authorized(self, mac: str) -> bool:
        canonical = normalize_mac(mac)
        if not canonical:
            return False
        return canonical in self.authorized_devices

    def add_authorized_device(self, device_info: dict):
        if 'mac' not in device_info or not device_info['mac']:
            raise ValueError('MAC address is required')
        canonical = normalize_mac(device_info['mac'])
        stored = dict(device_info)
        stored['mac'] = canonical
        self.authorized_devices[canonical] = stored
        self.save_authorized_devices()

    def remove_authorized_device(self, mac: str):
        canonical = normalize_mac(mac)
        if canonical in self.authorized_devices:
            del self.authorized_devices[canonical]
            self.save_authorized_devices()