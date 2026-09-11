"""Persistent SQLite storage for scan history, device timeline, alerts and audit logs.

Data survives server restarts (unlike the previous in-memory approach).
"""
import json
import os
import sqlite3
import threading
from datetime import datetime

try:
    from models import DATA_DIR, normalize_mac
except ImportError:
    from .models import DATA_DIR, normalize_mac


class Storage:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(DATA_DIR, 'cyberwatch.db')
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        with self._lock:
            cur = self._conn.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_time TEXT NOT NULL,
                    device_count INTEGER NOT NULL,
                    unauthorized_count INTEGER NOT NULL,
                    snapshot TEXT NOT NULL
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS device_timeline (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    is_authorized INTEGER
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT,
                    type TEXT,
                    severity TEXT,
                    message TEXT,
                    device_ip TEXT,
                    timestamp TEXT
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    action TEXT,
                    detail TEXT,
                    actor TEXT
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS arp_bindings (
                    ip TEXT PRIMARY KEY,
                    mac TEXT NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    changes INTEGER NOT NULL DEFAULT 0
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS device_cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    port INTEGER,
                    service TEXT,
                    version TEXT,
                    cve_id TEXT,
                    summary TEXT,
                    cvss REAL,
                    checked_at TEXT
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS device_os (
                    ip TEXT PRIMARY KEY,
                    os_name TEXT,
                    accuracy REAL,
                    method TEXT,
                    checked_at TEXT
                )
            ''')
            self._conn.commit()

    def _execute(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    # ------------------------------------------------------------------ history
    def save_snapshot(self, scan_time: datetime, devices: list):
        snapshot = json.dumps([d.to_dict() for d in devices], default=str)
        unauthorized = sum(1 for d in devices if not d.is_authorized)
        self._execute(
            'INSERT INTO history (scan_time, device_count, unauthorized_count, snapshot) VALUES (?,?,?,?)',
            (scan_time.isoformat(), len(devices), unauthorized, snapshot)
        )
        self._execute(
            'DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT 500)'
        )

    def get_history(self, limit: int = 200) -> list:
        rows = self._execute(
            'SELECT scan_time, device_count, unauthorized_count FROM history ORDER BY id DESC LIMIT ?',
            (limit,)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def get_last_snapshot(self) -> list:
        row = self._execute('SELECT snapshot FROM history ORDER BY id DESC LIMIT 1').fetchone()
        if not row:
            return []
        try:
            return json.loads(row['snapshot'])
        except (ValueError, TypeError):
            return []

    def get_last_two_snapshots(self) -> list:
        """Return the two most recent snapshots as [older, newer] ([] when missing)."""
        rows = self._execute(
            'SELECT snapshot FROM history ORDER BY id DESC LIMIT 2'
        ).fetchall()
        result = []
        for row in reversed(rows):
            try:
                result.append(json.loads(row['snapshot']))
            except (ValueError, TypeError):
                result.append([])
        return result

    # ------------------------------------------------------------- device timeline
    def update_timeline(self, devices: list):
        now = datetime.now().isoformat()
        for d in devices:
            self._execute('''
                INSERT INTO device_timeline
                    (mac, ip, hostname, vendor, device_type, first_seen, last_seen, is_authorized)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip=excluded.ip,
                    hostname=excluded.hostname,
                    vendor=excluded.vendor,
                    device_type=excluded.device_type,
                    last_seen=excluded.last_seen,
                    is_authorized=excluded.is_authorized
            ''', (
                normalize_mac(d.mac), d.ip, d.hostname,
                d.vendor, d.device_type, now, now,
                1 if d.is_authorized else 0
            ))

    def get_timeline(self) -> list:
        rows = self._execute(
            'SELECT * FROM device_timeline ORDER BY last_seen DESC'
        ).fetchall()
        return [dict(r) for r in rows]

    def detect_new_devices(self, devices: list) -> list:
        """Return devices that have never been seen before."""
        new_devices = []
        for d in devices:
            row = self._execute(
                'SELECT first_seen FROM device_timeline WHERE mac=?',
                (normalize_mac(d.mac),)
            ).fetchone()
            if row is None:
                new_devices.append(d)
        return new_devices

    # -------------------------------------------------------------- arp bindings
    def update_arp_bindings(self, devices: list, now=None):
        """Track IP -> MAC bindings over time.

        Returns a list of binding changes (possible ARP spoofing):
            {ip, old_mac, new_mac, changes, last_seen}
        """
        now = now or datetime.now()
        now_iso = now.isoformat()
        changed = []
        for d in devices:
            ip = (d.ip if hasattr(d, 'ip') else d.get('ip')) or ''
            mac = (d.mac if hasattr(d, 'mac') else d.get('mac')) or ''
            mac = normalize_mac(mac)
            if not ip or not mac:
                continue
            row = self._execute(
                'SELECT mac, changes, first_seen FROM arp_bindings WHERE ip=?', (ip,)
            ).fetchone()
            if row is None:
                self._execute(
                    'INSERT INTO arp_bindings (ip, mac, first_seen, last_seen, changes) VALUES (?,?,?,?,0)',
                    (ip, mac, now_iso, now_iso)
                )
            elif row['mac'] != mac:
                changes = row['changes'] + 1
                self._execute(
                    'UPDATE arp_bindings SET mac=?, last_seen=?, changes=? WHERE ip=?',
                    (mac, now_iso, changes, ip)
                )
                changed.append({
                    'ip': ip,
                    'old_mac': row['mac'],
                    'new_mac': mac,
                    'changes': changes,
                    'since': row['first_seen'],
                    'last_seen': now_iso
                })
            else:
                self._execute(
                    'UPDATE arp_bindings SET last_seen=? WHERE ip=?', (now_iso, ip)
                )
        return changed

    def get_arp_bindings(self) -> list:
        rows = self._execute(
            'SELECT * FROM arp_bindings ORDER BY last_seen DESC'
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ CVEs
    def save_cves(self, ip: str, results: list):
        """Replace all cached CVE rows for an IP."""
        self._execute('DELETE FROM device_cves WHERE ip=?', (ip,))
        now = datetime.now().isoformat()
        for group in results:
            for cve in group.get('cves', []):
                self._execute(
                    'INSERT INTO device_cves (ip, port, service, version, cve_id, summary, cvss, checked_at) '
                    'VALUES (?,?,?,?,?,?,?,?)',
                    (ip, group.get('port'), group.get('service'), group.get('version'),
                     cve.get('id', ''), cve.get('summary', '') or '',
                     cve.get('cvss'), now)
                )

    def get_cves(self, ip: str, max_age_hours: int = 24) -> list:
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        rows = self._execute(
            'SELECT cve_id, summary, cvss, port, service, version FROM device_cves '
            'WHERE ip=? AND checked_at>=? ORDER BY cvss DESC NULLS LAST LIMIT 200',
            (ip, cutoff.isoformat())
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ OS
    def save_os(self, ip: str, os_name: str, accuracy, method: str = 'nmap-os'):
        self._execute(
            'INSERT OR REPLACE INTO device_os (ip, os_name, accuracy, method, checked_at) '
            'VALUES (?,?,?,?,?)',
            (ip, os_name, accuracy, method, datetime.now().isoformat())
        )

    def get_os(self, ip: str, max_age_hours: int = 1):
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        row = self._execute(
            'SELECT * FROM device_os WHERE ip=? AND checked_at>=?',
            (ip, cutoff.isoformat())
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------ alerts
    def record_alerts(self, alerts: list):
        for a in alerts:
            self._execute(
                'INSERT INTO alerts (alert_id, type, severity, message, device_ip, timestamp) VALUES (?,?,?,?,?,?)',
                (a.id, a.type, a.severity, a.message, a.device_ip, a.timestamp.isoformat())
            )
        self._execute(
            'DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 500)'
        )

    def load_recent_alerts(self, limit: int = 100) -> list:
        rows = self._execute(
            'SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    # ------------------------------------------------------------------ audit log
    def audit(self, action: str, detail: str = '', actor: str = 'unknown'):
        self._execute(
            'INSERT INTO audit_log (timestamp, action, detail, actor) VALUES (?,?,?,?)',
            (datetime.now().isoformat(), action, detail, actor)
        )

    def get_audit_log(self, limit: int = 100) -> list:
        rows = self._execute(
            'SELECT * FROM audit_log ORDER BY id DESC LIMIT ?', (limit,)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def close(self):
        with self._lock:
            self._conn.close()