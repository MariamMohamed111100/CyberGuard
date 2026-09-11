"""Scan-to-scan diffing: what changed between two scans.

Draws the difference between the most recent snapshot and the new scan:
new devices, disappeared devices and ports that opened/closed.
"""
from typing import Dict, List

try:
    from models import normalize_mac
except ImportError:
    from .models import normalize_mac


def _to_dict(device) -> dict:
    if hasattr(device, 'to_dict'):
        return device.to_dict()
    return dict(device)


def _key(d: dict) -> str:
    """Identify a device robustly: normalize the MAC, fall back to the IP."""
    mac = normalize_mac(d.get('mac', '') or '')
    return mac or (d.get('ip', '') or '')


def compute_scan_diff(prev_devices: list, curr_devices: list) -> Dict:
    """Compare two device lists and describe what changed.

    Returns:
        {
          'new':          [device dicts present now but not before],
          'disappeared':  [device dicts seen before but not now],
          'ports_opened': [{'ip','mac','port'}...],
          'ports_closed': [{'ip','mac','port'}...],
          'unchanged':    count of devices present in both scans
        }
    """
    prev = {_key(_to_dict(d)): _to_dict(d) for d in prev_devices}
    curr = {_key(_to_dict(d)): _to_dict(d) for d in curr_devices}

    prev_keys = set(prev)
    curr_keys = set(curr)

    new = [curr[k] for k in curr_keys - prev_keys]
    disappeared = [prev[k] for k in prev_keys - curr_keys]

    ports_opened = []
    ports_closed = []
    for key in prev_keys & curr_keys:
        prev_ports = set(prev[key].get('open_ports') or [])
        curr_ports = set(curr[key].get('open_ports') or [])
        ip = curr[key].get('ip', '')
        mac = curr[key].get('mac', '')
        for port in sorted(curr_ports - prev_ports):
            ports_opened.append({'ip': ip, 'mac': mac, 'port': port})
        for port in sorted(prev_ports - curr_ports):
            ports_closed.append({'ip': ip, 'mac': mac, 'port': port})

    return {
        'new': new,
        'disappeared': disappeared,
        'ports_opened': ports_opened,
        'ports_closed': ports_closed,
        'unchanged': len(prev_keys & curr_keys),
    }