import ipaddress
import shutil
import socket
import uuid
from datetime import datetime
from typing import List, Dict, Any

# netifaces is a C-extension package; if it fails to build/install on a
# given host (e.g. some serverless build images), importing it used to
# crash this whole module at import time, taking the entire app down with
# it. Guard it the same way scapy already is below.
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    print("Warning: netifaces not available. Gateway/interface detection will be limited.")
    netifaces = None
    NETIFACES_AVAILABLE = False
import psutil
import nmap

# Try to use scapy for scanning, but have a fallback
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: scapy not available. Using fallback scanning methods.")
    SCAPY_AVAILABLE = False

# Simple import - we're in the same directory
try:
    from models import Device, PortInfo, SecurityAlert, Database, normalize_mac
    from config import Config
except ImportError:
    from .models import Device, PortInfo, SecurityAlert, Database, normalize_mac
    from .config import Config


def classify_device(hostname: str, vendor: str, open_ports: List[int]) -> str:
    """Classify a device by its hostname, vendor and open ports."""
    host = (hostname or '').lower()
    ports = set(open_ports or [])

    # Printers
    if ports & {515, 631, 9100}:
        return 'printer'
    # Routers / gateways
    if ('router' in host or 'gateway' in host or 'ap' == host
            or ports & {53, 1900}):
        return 'router'
    # Infrastructure servers
    if 53 in ports:
        return 'dns-server'
    if ports & {25, 110, 143, 587}:
        return 'mail-server'
    if ports & {3306, 5432, 1433}:
        return 'database-server'
    if 22 in ports:
        return 'ssh-server'
    if ports & {80, 443, 8080, 8000, 8443}:
        return 'web-server'
    # Windows file sharing -> workstation
    if ports & {135, 139, 445}:
        return 'workstation'
    # Media / IoT devices
    if ports & {8008, 8009} or 'chromecast' in host or 'tv' in host:
        return 'media-device'
    return 'device'


class NetworkScanner:
    def __init__(self):
        self.config = Config()
        self.db = Database()
        # Cache of PortInfo per IP, refreshed during the main scan
        self._port_details: Dict[str, List[PortInfo]] = {}
        self.last_subnet = None
        self.nmap_available = shutil.which('nmap') is not None
        try:
            # python-nmap's constructor itself shells out to `nmap -V` to
            # locate the binary and RAISES if it can't find one anywhere in
            # PATH. On hosts with no nmap installed (serverless platforms
            # like Vercel, for example) that exception used to happen here,
            # before self.nmap_available was even checked — which crashed
            # NetworkScanner() at import time and took the whole app down
            # with it, well before any of the "if not self.nmap_available"
            # guards further down ever got a chance to run.
            self.nm = nmap.PortScanner()
        except Exception:
            self.nm = None
            self.nmap_available = False
        if not self.nmap_available:
            print("Warning: nmap binary not found on this system. Port scanning will be disabled.")
        self._arp_conflicts: List[Dict] = []

    @property
    def arp_conflicts(self) -> List[Dict]:
        """IPs that answered with more than one distinct MAC in the last scan."""
        return list(self._arp_conflicts)

    def detect_gateway(self) -> str | None:
        """IP of the default IPv4 gateway (used by the topology map)."""
        try:
            default = netifaces.gateways().get('default', {})
            addr = default.get(netifaces.AF_INET, [None])[0]
            if not addr:
                for entry in netifaces.gateways().get(netifaces.AF_INET, []):
                    return entry[0]
            return addr
        except Exception:
            return None

    def get_network_interfaces(self) -> List[Dict]:
        """Get available network interfaces"""
        interfaces = []
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        if addr_info['addr'] != '127.0.0.1':
                            interfaces.append({
                                'name': iface,
                                'ip': addr_info['addr'],
                                'netmask': addr_info.get('netmask', ''),
                                'broadcast': addr_info.get('broadcast', '')
                            })
        except Exception as e:
            print(f"Error getting interfaces: {e}")
        return interfaces

    def _network_from_iface(self, iface: str) -> str | None:
        try:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                return None
            for a in addrs[netifaces.AF_INET]:
                ip = a.get('addr')
                netmask = a.get('netmask')
                if ip and netmask and ip != '127.0.0.1':
                    return str(ipaddress.IPv4Interface(f'{ip}/{netmask}').network)
        except Exception as e:
            print(f"Error computing network for {iface}: {e}")
        return None

    def detect_subnet(self) -> str | None:
        """Auto-detect the local subnet from routed network interfaces."""
        try:
            # Prefer the interface that owns the default IPv4 gateway
            gateways = netifaces.gateways()
            default = gateways.get('default', {})
            default_iface = default.get(netifaces.AF_INET, [None])[1]
            if default_iface:
                network = self._network_from_iface(default_iface)
                if network:
                    return network
            # Fallback: first usable non-loopback interface
            for iface in netifaces.interfaces():
                network = self._network_from_iface(iface)
                if network:
                    return network
        except Exception as e:
            print(f"Error detecting subnet: {e}")
        return None

    def resolve_subnet(self) -> str:
        if self.config.NETWORK_SUBNET:
            return self.config.NETWORK_SUBNET
        detected = self.detect_subnet()
        if detected:
            return detected
        print("Could not detect subnet automatically, defaulting to 192.168.1.0/24")
        return '192.168.1.0/24'

    def _port_spec(self) -> str:
        """Build an nmap port spec that covers common ports plus everything in config."""
        ports = set(range(1, 1025))
        ports.update(self.config.AUTHORIZED_PORTS.keys())
        ports.update(self.config.HIGH_RISK_PORTS)
        ports.update(self.config.WARNING_PORTS)
        extra = sorted(p for p in ports if p > 1024)
        spec = ['1-1024']
        if extra:
            spec.append(','.join(str(p) for p in extra))
        return ','.join(spec)

    def scan_network(self, subnet: str = None) -> List[Device]:
        """Scan network for devices"""
        subnet = subnet or self.resolve_subnet()
        self.last_subnet = subnet
        self._arp_conflicts = []

        # Reload the whitelist from disk before checking, so authorizations made
        # after this process started (via the API) are picked up.
        self.db.load_authorized_devices()

        print(f"Scanning network: {subnet}")
        devices = []

        if SCAPY_AVAILABLE:
            try:
                arp = ARP(pdst=subnet)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp

                result = srp(packet, timeout=3, verbose=0)[0]

                # IP -> MAC seen in this run, to spot one IP claiming two MACs
                seen_macs: Dict[str, str] = {}
                for sent, received in result:
                    ip = received.psrc
                    mac = normalize_mac(received.hwsrc)
                    if ip in seen_macs and seen_macs[ip] != mac:
                        self._arp_conflicts.append({
                            'ip': ip,
                            'macs': sorted({seen_macs[ip], mac})
                        })
                    else:
                        seen_macs[ip] = mac

                for sent, received in result:
                    ip = received.psrc
                    mac = normalize_mac(received.hwsrc)
                    if ip in seen_macs and seen_macs[ip] != mac:
                        continue
                    hostname = self.get_hostname(ip)
                    vendor = self.get_vendor_from_mac(mac)
                    authorized = self.db.is_device_authorized(mac)

                    # Scan ports once (single nmap pass, cached for later detail calls)
                    open_ports = self.scan_ports(ip)

                    device = Device(
                        ip=ip,
                        mac=mac,
                        hostname=hostname,
                        vendor=vendor,
                        last_seen=datetime.now(),
                        is_authorized=authorized,
                        open_ports=open_ports,
                        device_type=classify_device(hostname, vendor, open_ports)
                    )
                    devices.append(device)
            except Exception as e:
                print(f"ARP scan failed: {e}")
        else:
            # Scapy unavailable - fall back to nmap host discovery (no MACs available)
            print("Scapy not available. Using nmap fallback discovery.")
            devices = self._discover_with_nmap(subnet)

        return devices

    def _discover_with_nmap(self, subnet: str) -> List[Device]:
        devices = []
        if not self.nmap_available:
            print("nmap not available and scapy missing - scanning disabled.")
            return devices
        try:
            self.nm.scan(subnet, arguments='-sn -T4')
            for ip in self.nm.all_hosts():
                hostname = self.get_hostname(ip)
                open_ports = self.scan_ports(ip)
                device = Device(
                    ip=ip,
                    mac='unknown',
                    hostname=hostname,
                    vendor='Unknown',
                    last_seen=datetime.now(),
                    is_authorized=False,
                    open_ports=open_ports,
                    device_type=classify_device(hostname, 'Unknown', open_ports)
                )
                devices.append(device)
        except Exception as e:
            print(f"Nmap host discovery failed: {e}")
        return devices

    def get_hostname(self, ip: str) -> str:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return "Unknown"

    def get_vendor_from_mac(self, mac: str) -> str:
        # Simple vendor lookup based on the OUI prefix
        vendors = {
            '00:0C:29': 'VMware',
            '00:50:56': 'VMware',
            '00:1A:2B': 'Cisco',
            '00:1B:63': 'Netgear',
            '00:1E:65': 'Dell',
            '00:21:5A': 'HP',
            '00:24:54': 'Apple',
            '00:26:BB': 'Apple',
            '00:22:41': 'Microsoft',
            '00:23:DF': 'Intel',
            '00:25:BC': 'Samsung',
        }

        prefix = normalize_mac(mac)[:8]
        return vendors.get(prefix, 'Unknown')

    def _risk_level_for_port(self, port: int) -> str:
        if port in self.config.HIGH_RISK_PORTS:
            return 'high'
        if port in self.config.WARNING_PORTS:
            return 'medium'
        if port not in self.config.AUTHORIZED_PORTS:
            return 'warning'
        return 'low'

    def scan_ports(self, ip: str) -> List[int]:
        """Scan a device for open ports in a single nmap pass and cache the details."""
        if not self.nmap_available:
            return []

        open_ports = []
        details = []
        try:
            spec = self._port_spec()
            print(f"Scanning ports ({spec}) on {ip}...")
            self.nm.scan(ip, spec, arguments='-sT -Pn -T4 --open')

            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    for port in self.nm[ip][proto]:
                        info = self.nm[ip][proto][port]
                        if info.get('state') == 'open':
                            open_ports.append(port)
                            level = self._risk_level_for_port(port)
                            details.append(PortInfo(
                                port=port,
                                service=info.get('name', 'unknown'),
                                state=info.get('state', 'unknown'),
                                version=info.get('version', '') or '',
                                risk_level=level
                            ))
        except Exception as e:
            print(f"Port scan error for {ip}: {e}")

        self._port_details[ip] = details
        return sorted(open_ports)

    def get_port_details(self, ip: str, port: int) -> PortInfo:
        """Return cached details for a port. No on-demand re-scan (fast)."""
        cached = self._port_details.get(ip, [])
        for info in cached:
            if info.port == port:
                return info
        # Fallback detail if the port wasn't cached (e.g. device not re-scanned yet)
        return PortInfo(
            port=port,
            service='unknown',
            state='unknown',
            version='',
            risk_level=self._risk_level_for_port(port)
        )

    def get_all_port_details(self, ip: str) -> List[PortInfo]:
        """Return all cached port details for a device."""
        return self._port_details.get(ip, [])

    def detect_os(self, ip: str) -> Dict | None:
        """Fingerprint the OS of a single host with nmap -O. Never called during
        a normal scan (it is slow); used by the on-demand /api/device/<ip>/os."""
        if not self.nmap_available:
            return None
        try:
            self.nm.scan(ip, arguments='-O -Pn -T4 --osscan-guess')
            if ip not in self.nm.all_hosts():
                return None
            osmatch = self.nm[ip].get('osmatch') or []
            if osmatch:
                best = osmatch[0]
                return {
                    'os_name': best.get('name', 'Unknown'),
                    'accuracy': best.get('accuracy', 0),
                    'method': 'nmap-os'
                }
        except Exception as e:
            print(f"OS detection error for {ip}: {e}")
        return None

    def get_system_stats(self) -> Dict:
        """Get system statistics"""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_io': {
                    'bytes_sent': psutil.net_io_counters().bytes_sent,
                    'bytes_recv': psutil.net_io_counters().bytes_recv
                }
            }
        except Exception as e:
            print(f"Error getting system stats: {e}")
            return {
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_usage': 0,
                'network_io': {'bytes_sent': 0, 'bytes_recv': 0}
            }


class SecurityMonitor:
    def __init__(self):
        self.alerts = []
        self.config = Config()

    def analyze_devices(self, devices: List[Device]) -> List[SecurityAlert]:
        """Analyze devices for security issues"""
        alerts = []

        for device in devices:
            # Check for unauthorized devices
            if not device.is_authorized:
                alert = SecurityAlert(
                    id=str(uuid.uuid4()),
                    type='unauthorized_device',
                    severity='high',
                    message=f'Unauthorized device detected: {device.ip} ({device.mac})',
                    timestamp=datetime.now(),
                    device_ip=device.ip
                )
                alerts.append(alert)

            # Check for suspicious open ports
            for port in device.open_ports:
                if port in self.config.HIGH_RISK_PORTS:
                    alert = SecurityAlert(
                        id=str(uuid.uuid4()),
                        type='high_risk_port',
                        severity='high',
                        message=f'High risk port {port} open on {device.ip}',
                        timestamp=datetime.now(),
                        device_ip=device.ip
                    )
                    alerts.append(alert)

        # Keep only last 100 alerts
        self.alerts = (alerts + self.alerts)[:100]
        return alerts