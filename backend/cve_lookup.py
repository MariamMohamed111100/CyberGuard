"""CVE lookup against the public cve.circl.lu API.

Results are cached in memory and persisted in SQLite by the app, so already
checked devices stay fast even when the API is unreachable.
"""
import json
import threading
from datetime import datetime, timedelta
from urllib.parse import quote


try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError
except ImportError:  # pragma: no cover
    urlopen = None


_CACHE = {}
_CACHE_LOCK = threading.Lock()
_TTL = timedelta(hours=6)
_MAX_PER_PRODUCT = 200
_TIMEOUT = 8
USER_AGENT = 'cyberguard/2.1'


def _fetch_product_cves(product: str):
    if urlopen is None:
        return []
    url = f'https://cve.circl.lu/api/search/{quote(product.strip())}'
    try:
        req = Request(url, headers={'User-Agent': USER_AGENT})
        with urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode('utf-8', 'ignore'))
        if not isinstance(data, list):
            return []
        out = []
        for item in data[:_MAX_PER_PRODUCT]:
            cve = {
                'id': item.get('id', item.get('cve_id', '')),
                'summary': item.get('summary', ''),
                'cvss': item.get('cvss'),
                'last_modified': item.get('Modified') or item.get('last_modified'),
            }
            if cve['id']:
                out.append(cve)
        return out
    except (URLError, HTTPError, OSError, ValueError, KeyError):
        return []


def lookup_product_cves(product: str):
    """Cached lookup of all CVEs published for a product."""
    key = product.strip().lower()
    if not key:
        return []
    now = datetime.now()
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached and now - cached['ts'] < _TTL:
            return cached['cves']
    cves = _fetch_product_cves(product)
    with _CACHE_LOCK:
        _CACHE[key] = {'ts': now, 'cves': cves}
    return cves


def _clean_version(version: str) -> str:
    return (version or '').strip().split()[0].lower()


def _matches_version(cve, version: str):
    """Keep the CVE only when the reported version appears in its summary/id."""
    v = _clean_version(version)
    if not v or v in ('unknown',):
        return True
    haystack = (cve.get('summary') or '').lower()
    return v in haystack


def lookup_cves_for_device(device, port_details) -> list:
    """Look up CVEs for every port with a known product/version. Returns:
        [{port, service, version, checked, cves: [{id, summary, cvss}]}]
    """
    results = []
    seen_products = set()
    for info in port_details:
        service = (info.service or '').strip().lower()
        version = (info.version or '').strip()
        if not service or service in ('unknown', 'tcpwrapped', 'filtered'):
            continue
        product = _service_to_product(service)
        if not product or product in seen_products:
            continue
        seen_products.add(product)
        cves = lookup_product_cves(product)
        if version:
            cves = [c for c in cves if _matches_version(c, version)]
        cves = sorted(cves, key=lambda c: c.get('cvss') or 0, reverse=True)[:10]
        results.append({
            'port': info.port,
            'service': service,
            'version': version,
            'checked': True,
            'cves': cves,
        })
    return results


def _service_to_product(service: str) -> str:
    """Map common nmap service names to product names the CVE API understands."""
    mapping = {
        'http': 'nginx', 'https': 'nginx', 'http-proxy': 'squid',
        'ssl/http': 'apache', 'ssl/https': 'apache',
        'openssh': 'openssh', 'ssh': 'openssh',
        'mysql': 'mysql', 'postgresql': 'postgresql',
        'smtp': 'exim', 'dns': 'bind',
        'ftp': 'vsftpd', 'telnet': 'tcp_wrappers',
        'ms-wbt-server': 'microsoft-remote-desktop',
    }
    key = service.lower()
    return mapping.get(key, key)