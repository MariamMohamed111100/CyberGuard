import hmac
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

from flask import Flask, Response, jsonify, request, send_file, send_from_directory, session

# Add the backend directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Now import your modules
try:
    from scanner import NetworkScanner, SecurityMonitor, classify_device
    from advisor import SecurityAdvisor
    from models import DATA_DIR, Database, Device, SecurityAlert, normalize_mac
    from storage import Storage
    from config import Config
    from diffing import compute_scan_diff
    from sniffer import TrafficSniffer, SCAPY_AVAILABLE
    from weak_checks import run_weak_service_checks
    from cve_lookup import lookup_cves_for_device
    from reports import generate_html_report, generate_pdf_report
except ImportError:
    from .scanner import NetworkScanner, SecurityMonitor, classify_device
    from .advisor import SecurityAdvisor
    from .models import DATA_DIR, Database, Device, SecurityAlert, normalize_mac
    from .storage import Storage
    from .config import Config
    from .diffing import compute_scan_diff
    from .sniffer import TrafficSniffer, SCAPY_AVAILABLE
    from .weak_checks import run_weak_service_checks
    from .cve_lookup import lookup_cves_for_device
    from .reports import generate_html_report, generate_pdf_report

app = Flask(__name__,
           static_folder='../frontend',
           static_url_path='')

config = Config()
app.secret_key = config.SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=8)

# Initialize components
scanner = NetworkScanner()
security_monitor = SecurityMonitor()
advisor = SecurityAdvisor()
db = Database()
storage = Storage()

# Store current scan data (guarded by a lock since threads write it)
state_lock = threading.Lock()
current_devices = []
current_alerts = []
scan_in_progress = False
last_scan_time = None
_monitor_started = False

# Traffic sniffer (lazily created)
sniffer = None
sniffer_lock = threading.Lock()


# ------------------------------------------------------------------ auth helpers
def _check_token():
    """Check the API token header (allows non-browser clients)."""
    expected = config.API_TOKEN or 'changeme'
    token = request.headers.get('X-API-Token') or ''
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth[len('Bearer '):]
    if not token or not hmac.compare_digest(token, expected):
        return False
    return True


def _is_authorized_request():
    return bool(session.get('user')) or _check_token()


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not _is_authorized_request():
            return jsonify({'error': 'login required'}), 401
        return f(*args, **kwargs)
    return wrapped


def _is_admin():
    return session.get('role') == 'admin' or _check_token()


def admin_required(f):
    """Admin (or API token) only."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not _is_authorized_request():
            return jsonify({'error': 'login required'}), 401
        if not _is_admin():
            return jsonify({'error': 'admin privileges required'}), 403
        return f(*args, **kwargs)
    return wrapped


def _actor():
    return session.get('user') or 'api-token'


def _role():
    return session.get('role') or ('admin' if _check_token() else 'anonymous')


def _mark_devices_authorized(mac, authorized):
    """Update the cached device objects so the UI reflects the change immediately."""
    canonical = normalize_mac(mac)
    with state_lock:
        for device in current_devices:
            if normalize_mac(device.mac) == canonical:
                device.is_authorized = authorized


def _notify_webhook(alerts):
    if not config.WEBHOOK_URL or not alerts:
        return
    try:
        import urllib.request
        payload = json.dumps({
            'source': 'cyberguard',
            'timestamp': datetime.now().isoformat(),
            'alerts': [a.to_dict() for a in alerts]
        }, default=str).encode('utf-8')
        req = urllib.request.Request(
            config.WEBHOOK_URL, data=payload,
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"Webhook notified: {resp.status}")
    except Exception as e:
        print(f"Webhook failed: {e}")


def _alerts_text(alerts, limit=10):
    lines = [f'CyberGuard: {len(alerts)} new alert(s)']
    for a in alerts[:limit]:
        lines.append(f'- [{a.severity.upper()}] {a.type}: {a.message}')
    return '\n'.join(lines)


def _notify_telegram(alerts):
    token = config.TELEGRAM_BOT_TOKEN
    chat_id = config.TELEGRAM_CHAT_ID
    if not token or not chat_id or not alerts:
        return
    try:
        import urllib.parse
        import urllib.request
        text = _alerts_text(alerts)
        payload = urllib.parse.urlencode(
            {'chat_id': chat_id, 'text': text}).encode('utf-8')
        url = f'https://api.telegram.org/bot{token}/sendMessage'
        req = urllib.request.Request(url, data=payload)
        with urllib.request.urlopen(req, timeout=8) as resp:
            print(f"Telegram notified: {resp.status}")
    except Exception as e:
        print(f"Telegram failed: {e}")


def _notify_email(alerts):
    if not config.EMAIL_SMTP_HOST or not config.EMAIL_TO or not alerts:
        return
    try:
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg['Subject'] = f'[CyberGuard] {len(alerts)} new security alert(s)'
        msg['From'] = config.EMAIL_FROM or config.EMAIL_SMTP_USER
        msg['To'] = config.EMAIL_TO
        msg.set_content(_alerts_text(alerts))
        with smtplib.SMTP(config.EMAIL_SMTP_HOST, config.EMAIL_SMTP_PORT, timeout=10) as srv:
            if config.EMAIL_USE_TLS:
                srv.starttls()
            if config.EMAIL_SMTP_USER:
                srv.login(config.EMAIL_SMTP_USER, config.EMAIL_SMTP_PASSWORD)
            srv.send_message(msg)
        print("Email alerted.")
    except Exception as e:
        print(f"Email failed: {e}")


def _notify_alerts(alerts):
    """Fan out new alerts to webhook, Telegram and/or email."""
    _notify_webhook(alerts)
    _notify_telegram(alerts)
    _notify_email(alerts)


# ------------------------------------------------------------------ core scan logic
def _run_scan_sync():
    """Run one scan, persist results and update the shared state. Thread-safe."""
    global current_devices, current_alerts, last_scan_time

    print("Starting network scan...")
    prev_snapshot = storage.get_last_snapshot()
    devices = scanner.scan_network()

    # Detect brand-new devices BEFORE updating the timeline
    new_devices = storage.detect_new_devices(devices)

    alerts = security_monitor.analyze_devices(devices)

    for device in new_devices:
        alerts.append(SecurityAlert(
            id=str(uuid.uuid4()),
            type='new_device',
            severity='medium',
            message=f'New device seen for the first time: {device.ip} ({device.mac})',
            timestamp=datetime.now(),
            device_ip=device.ip
        ))

    now = datetime.now()

    # ARP spoofing: an IP that answered with two distinct MACs in this scan
    for conflict in scanner.arp_conflicts:
        alerts.append(SecurityAlert(
            id=str(uuid.uuid4()),
            type='arp_spoofing',
            severity='high',
            message=(f'Possible ARP spoofing: {conflict["ip"]} answered with '
                     f'multiple MAC addresses ({", ".join(conflict["macs"])})'),
            timestamp=now,
            device_ip=conflict['ip']
        ))

    # ARP spoofing: an IP whose MAC binding changed vs what we last recorded
    for change in storage.update_arp_bindings(devices, now):
        alerts.append(SecurityAlert(
            id=str(uuid.uuid4()),
            type='arp_spoofing',
            severity='high',
            message=(f'ARP binding change for {change["ip"]}: '
                     f'{change["old_mac"]} -> {change["new_mac"]}'),
            timestamp=now,
            device_ip=change['ip']
        ))

    # Scan-to-scan diffing vs the previous snapshot
    scan_diff = compute_scan_diff(prev_snapshot, devices)
    for device in scan_diff['disappeared']:
        alerts.append(SecurityAlert(
            id=str(uuid.uuid4()),
            type='device_disappeared',
            severity='medium',
            message=(f'Device no longer responding: {device.get("ip", "")} '
                     f'({device.get("mac", "unknown")})'),
            timestamp=now,
            device_ip=device.get('ip', '')
        ))
    for entry in scan_diff['ports_opened']:
        alerts.append(SecurityAlert(
            id=str(uuid.uuid4()),
            type='port_opened',
            severity='medium',
            message=(f'New port {entry["port"]} opened on '
                     f'{entry["ip"]} ({entry["mac"]})'),
            timestamp=now,
            device_ip=entry['ip']
        ))
    for entry in scan_diff['ports_closed']:
        alerts.append(SecurityAlert(
            id=str(uuid.uuid4()),
            type='port_closed',
            severity='low',
            message=f'Port {entry["port"]} closed on {entry["ip"]}',
            timestamp=now,
            device_ip=entry['ip']
        ))

    # Weak-service probes (FTP anonymous, DNS open/recursive)
    weak_findings = []
    if config.WEAK_SERVICE_CHECKS:
        weak_findings = run_weak_service_checks(devices)
        for finding in weak_findings:
            alerts.append(SecurityAlert(
                id=str(uuid.uuid4()),
                type=finding['type'],
                severity=finding['severity'],
                message=finding['message'],
                timestamp=now,
                device_ip=finding['device_ip']
            ))
        if weak_findings:
            storage.audit('weak_check',
                          f'{len(weak_findings)} weak service(s) found', 'system')

    if new_devices:
        # Prepend the new-device alerts so they surface at the top of the list
        fresh_new = [a for a in alerts if a.type == 'new_device']
        security_monitor.alerts = (fresh_new + security_monitor.alerts)[:100]

    with state_lock:
        current_devices = devices
        current_alerts = alerts
        last_scan_time = now

    # Persist results
    storage.save_snapshot(now, devices)
    storage.update_timeline(devices)
    storage.record_alerts(alerts)
    storage.audit('scan', f'{len(devices)} devices found', 'system')
    _notify_alerts(alerts)

    print(f"Scan completed. Found {len(devices)} devices.")
    return devices


def _restore_initial_state():
    """Rebuild the last known scan + alerts after a restart from persisted data."""
    global current_devices, current_alerts, last_scan_time

    snapshot = storage.get_last_snapshot()
    restored = []
    for d in snapshot:
        try:
            restored.append(Device(
                ip=d.get('ip', ''),
                mac=d.get('mac', ''),
                hostname=d.get('hostname', 'Unknown'),
                vendor=d.get('vendor', 'Unknown'),
                last_seen=datetime.fromisoformat(d['last_seen']),
                is_authorized=bool(d.get('is_authorized')),
                open_ports=d.get('open_ports') or [],
                device_type=d.get('device_type', 'device')
            ))
        except (KeyError, ValueError, TypeError):
            continue

    restored_alerts = []
    for a in storage.load_recent_alerts():
        try:
            restored_alerts.append(SecurityAlert(
                id=a['alert_id'] or '',
                type=a['type'],
                severity=a['severity'],
                message=a['message'],
                timestamp=datetime.fromisoformat(a['timestamp']),
                device_ip=a['device_ip']
            ))
        except (KeyError, ValueError, TypeError):
            continue

    with state_lock:
        current_devices = restored
        current_alerts = restored_alerts
        security_monitor.alerts = restored_alerts
        last_scan_time = None


# ------------------------------------------------------------------ static / pages
@app.route('/')
def serve_landing():
    return send_from_directory(app.static_folder, 'landing.html')

@app.route('/login')
def serve_login():
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/dashboard')
@app.route('/dashboard/')
def serve_dashboard():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/dashboard/<path:path>')
def serve_dashboard_static(path):
    return send_from_directory(app.static_folder, path)

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)


# ------------------------------------------------------------------ auth routes
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password') or ''
    if (username == config.ADMIN_USERNAME
            and hmac.compare_digest(password, config.ADMIN_PASSWORD)):
        session.permanent = True
        session['user'] = username
        session['role'] = 'admin'
        storage.audit('login', f'{username} (admin)', username)
        return jsonify({'status': 'ok', 'username': username, 'role': 'admin'})
    storage.audit('login_failed', str(username), 'unknown')
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    user = session.pop('user', None)
    session.pop('role', None)
    if user:
        storage.audit('logout', user, user)
    return jsonify({'status': 'logged_out'})


@app.route('/api/me', methods=['GET'])
def me():
    return jsonify({'username': session.get('user'), 'role': session.get('role')})


# ------------------------------------------------------------------ scan / state
@app.route('/api/scan', methods=['GET'])
def scan_network():
    global scan_in_progress

    with state_lock:
        if scan_in_progress:
            return jsonify({'status': 'scan_in_progress'})
        scan_in_progress = True

    def perform_scan():
        global scan_in_progress
        try:
            _run_scan_sync()
        except Exception as e:
            print(f"Scan error: {e}")
        finally:
            with state_lock:
                scan_in_progress = False

    thread = threading.Thread(target=perform_scan)
    thread.daemon = True
    thread.start()

    return jsonify({'status': 'scan_started', 'message': 'Network scan initiated'})


@app.route('/api/status', methods=['GET'])
def scan_status():
    with state_lock:
        return jsonify({
            'scan_in_progress': scan_in_progress,
            'last_scan': last_scan_time.isoformat() if last_scan_time else None,
            'total_devices': len(current_devices),
            'total_alerts': len(current_alerts),
            'subnet': scanner.last_subnet,
            'gateway': scanner.detect_gateway(),
            'nmap_available': scanner.nmap_available,
            'autoscan': config.AUTOSCAN_ENABLED,
            'monitoring': _monitor_started,
            'sniffer_available': SCAPY_AVAILABLE,
            'channels': _configured_channels()
        })


def _configured_channels():
    """Which notification channels are enabled on the server."""
    return {
        'webhook': bool(config.WEBHOOK_URL),
        'telegram': bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID),
        'email': bool(config.EMAIL_SMTP_HOST and config.EMAIL_TO),
    }


@app.route('/api/devices', methods=['GET'])
def get_devices():
    with state_lock:
        devices_data = [device.to_dict() for device in current_devices]
    return jsonify({'devices': devices_data})


@app.route('/api/device/<ip>/ports', methods=['GET'])
def get_device_ports(ip):
    with state_lock:
        device = next((d for d in current_devices if d.ip == ip), None)
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    port_details = scanner.get_all_port_details(ip)
    return jsonify({'ports': [p.to_dict() for p in port_details]})


@app.route('/api/device/<ip>/cves', methods=['GET'])
def get_device_cves(ip):
    """CVEs for the services found on a device. Uses cached rows first,
    then falls back to the public cve.circl.lu API (network may be offline)."""
    with state_lock:
        device = next((d for d in current_devices if d.ip == ip), None)
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    cached = storage.get_cves(ip)
    if cached:
        storage.audit('cve_lookup', f'{ip} (cached)', _actor())
        return jsonify({'cves': cached, 'source': 'cache'})

    port_details = scanner.get_all_port_details(ip)
    results = lookup_cves_for_device(device, port_details)
    storage.save_cves(ip, results)
    storage.audit('cve_lookup', f'{ip} ({len(results)} service(s))', _actor())

    flattened = []
    for group in results:
        for cve in group['cves']:
            flattened.append({
                'port': group['port'], 'service': group['service'],
                'version': group['version'],
                'cve_id': cve.get('id', ''), 'summary': cve.get('summary', ''),
                'cvss': cve.get('cvss'),
            })
    return jsonify({'cves': flattened, 'source': 'live'})


@app.route('/api/device/<ip>/os', methods=['GET'])
def get_device_os(ip):
    """Fingerprint a device's OS with nmap -O (on demand, cached 1h)."""
    with state_lock:
        device = next((d for d in current_devices if d.ip == ip), None)
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    cached = storage.get_os(ip)
    if cached:
        return jsonify({'os': cached, 'source': 'cache'})

    result = scanner.detect_os(ip)
    if not result:
        return jsonify({'os': None, 'error': 'OS detection failed '
                                              '(nmap unavailable or host not reachable).'})
    storage.save_os(ip, result['os_name'], result['accuracy'])
    return jsonify({'os': result, 'source': 'live'})


@app.route('/api/device/<mac>/authorize', methods=['POST'])
@admin_required
def authorize_device(mac):
    try:
        data = request.json or {}
        device_info = {
            'mac': mac,
            'ip': data.get('ip'),
            'hostname': data.get('hostname'),
            'timestamp': datetime.now().isoformat()
        }
        db.add_authorized_device(device_info)
        _mark_devices_authorized(mac, True)
        storage.audit('authorize', f'{normalize_mac(mac)} {data.get("ip", "")}', _actor())
        return jsonify({'status': 'authorized'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/device/<mac>/unauthorize', methods=['POST'])
@admin_required
def unauthorize_device(mac):
    try:
        db.remove_authorized_device(mac)
        _mark_devices_authorized(mac, False)
        storage.audit('unauthorize', normalize_mac(mac), _actor())
        return jsonify({'status': 'unauthorized'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    # Return the accumulated list (last 100 alerts across scans)
    alerts_data = [alert.to_dict() for alert in security_monitor.alerts]
    return jsonify({'alerts': alerts_data})


@app.route('/api/advice/<ip>', methods=['GET'])
def get_advice(ip):
    with state_lock:
        device = next((d for d in current_devices if d.ip == ip), None)
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    port_details = scanner.get_all_port_details(ip)
    advice = advisor.get_advice_for_device(device, port_details)
    return jsonify({'advice': advice})


@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        system_stats = scanner.get_system_stats()
        with state_lock:
            report = advisor.generate_security_report(current_devices)
            total_devices = len(current_devices)
            total_alerts = len(current_alerts)
            last_scan = last_scan_time.isoformat() if last_scan_time else None

        return jsonify({
            'system': system_stats,
            'security_report': report,
            'last_scan': last_scan,
            'total_devices': total_devices,
            'total_alerts': total_alerts
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    try:
        interfaces = scanner.get_network_interfaces()
        return jsonify({'interfaces': interfaces, 'subnet': scanner.last_subnet})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/authorized-devices', methods=['GET'])
def get_authorized_devices():
    return jsonify({'devices': list(db.authorized_devices.values())})


# ------------------------------------------------------------------ reports
@app.route('/api/history', methods=['GET'])
def get_history():
    return jsonify({'history': storage.get_history()})


@app.route('/api/diff', methods=['GET'])
def get_scan_diff():
    """What changed between the two most recent scans (new/left/ports)."""
    snapshots = storage.get_last_two_snapshots()
    if len(snapshots) < 2:
        return jsonify({'diff': None,
                        'message': 'Need at least two scans to compute a diff.'})
    return jsonify({'diff': compute_scan_diff(snapshots[0], snapshots[1])})


@app.route('/api/audit', methods=['GET'])
@login_required
def get_audit():
    return jsonify({'audit': storage.get_audit_log()})


# ------------------------------------------------------------------ traffic sniffer
def _get_sniffer():
    global sniffer
    if sniffer is None:
        sniffer = TrafficSniffer(iface=config.SNIFF_IFACE or None,
                                 duration=15)
    return sniffer


@app.route('/api/sniff/start', methods=['POST'])
@admin_required
def sniff_start():
    with sniffer_lock:
        live = _get_sniffer().live()
        if live['in_progress']:
            return jsonify({'status': 'sniff_in_progress', 'live': live})

    try:
        duration = int(request.args.get('duration', 15))
    except (TypeError, ValueError):
        duration = 15
    duration = min(120, max(3, duration))

    global sniffer
    sniffer = TrafficSniffer(iface=config.SNIFF_IFACE or None, duration=duration)
    sniffer.start()
    storage.audit('sniff', f'started {duration}s capture', _actor())
    return jsonify({'status': 'sniff_started', 'duration': duration})


@app.route('/api/sniff/status', methods=['GET'])
def sniff_status():
    if sniffer is None:
        return jsonify({'live': None})
    return jsonify({'live': sniffer.live()})


@app.route('/api/sniff/result', methods=['GET'])
@login_required
def sniff_result():
    if sniffer is None:
        return jsonify({'result': None})
    return jsonify({'result': sniffer.result()})


@app.route('/api/export', methods=['GET'])
@login_required
def export_report():
    fmt = request.args.get('format', 'json').lower()
    with state_lock:
        devices = [d.to_dict() for d in current_devices]
    history = storage.get_history(limit=50)

    storage.audit('export', f'format={fmt}', _actor())

    if fmt == 'html':
        html = generate_html_report(devices, history)
        output = BytesIO(html.encode('utf-8'))
        output.seek(0)
        return send_file(output, mimetype='text/html', as_attachment=True,
                         download_name='cyberguard-report.html')

    if fmt == 'pdf':
        pdf, err = generate_pdf_report(devices, history)
        if err:
            return jsonify({'error': err}), 400
        output = BytesIO(pdf)
        output.seek(0)
        return send_file(output, mimetype='application/pdf', as_attachment=True,
                         download_name='cyberguard-report.pdf')

    if fmt == 'csv':
        import csv
        import io
        text = io.StringIO()
        fieldnames = ['ip', 'mac', 'hostname', 'vendor', 'device_type', 'is_authorized', 'open_ports', 'last_seen']
        writer = csv.DictWriter(text, fieldnames=fieldnames)
        writer.writeheader()
        for d in devices:
            row = {k: d.get(k, '') for k in fieldnames}
            row['open_ports'] = ' '.join(str(p) for p in d.get('open_ports') or [])
            writer.writerow(row)
        output = BytesIO(text.getvalue().encode('utf-8'))
        output.seek(0)
        return send_file(output, mimetype='text/csv', as_attachment=True,
                         download_name='cyberguard-report.csv')

    data = json.dumps({
        'generated': datetime.now().isoformat(),
        'device_count': len(devices),
        'devices': devices
    }, default=str, indent=2).encode('utf-8')
    output = BytesIO(data)
    output.seek(0)
    return send_file(output, mimetype='application/json', as_attachment=True,
                     download_name='cyberguard-report.json')


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'Cyber Security Monitor',
        'version': '2.1.0'
    })


# ------------------------------------------------------------------ continuous monitoring
def start_monitoring():
    """Background thread that keeps scanning even with no browser open."""
    global _monitor_started
    if not config.AUTOSCAN_ENABLED or _monitor_started:
        return
    _monitor_started = True

    def loop():
        interval = max(10, config.SCAN_INTERVAL)
        while True:
            time.sleep(interval)
            with state_lock:
                already = scan_in_progress
            if already:
                continue
            with state_lock:
                scan_in_progress = True
            try:
                _run_scan_sync()
            except Exception as e:
                print(f"Auto-scan error: {e}")
            finally:
                with state_lock:
                    scan_in_progress = False

    thread = threading.Thread(target=loop, daemon=True, name='cyberguard-monitor')
    thread.start()
    print(f"Continuous monitoring enabled (every {config.SCAN_INTERVAL}s).")


_restore_initial_state()

if __name__ == '__main__':
    # Ensure data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)

    start_monitoring()

    print("Starting Cyber Security Monitor...")
    print("Open http://localhost:5000 in your browser")
    app.run(debug=True, port=5000, host='0.0.0.0')