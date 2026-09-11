# Cyber Security Monitor & Tracker

A LAN network-monitoring web application that discovers devices, scans open ports,
detects rogue (unauthorized) devices, and provides security alerts and recommendations
through a single-page dashboard.

## Features

### Network Monitoring
- Real-time network device discovery (ARP scan via Scapy, nmap fallback)
- Automatic subnet detection from the machine's network interfaces
- Port scanning and service detection (covers ports 1-1024 + configured high-risk ports)
- MAC address vendor identification (simple OUI table)
- Device authorization management

### Security Features
- Rogue device detection against a whitelist of authorized MACs
- **New device detection** — devices seen for the first time raise their own alert
- **ARP spoofing detection** — an IP answering with two distinct MACs, or an IP whose
  MAC binding changed since the last scan, raises a high-severity alert
- **Scan-to-scan diffing** — new devices, devices that disappeared, and ports that
  opened/closed between consecutive scans (alerts + a diff panel in Reports)
- High-risk port identification (23, 21, 139, 445, 135, 3389)
- **Weak-service checks** — lightweight probes after each scan flag anonymous FTP
  logins and open DNS resolvers/recursion
- **CVE lookups** — on-demand `CVE Search` per device (cve.circl.lu public API) with
  live + cached results shown in the device modal
- **OS detection** — on-demand `nmap -O` fingerprinting per device (cached 1h)
- **Dashboard authentication** — a single `admin` account with full control; the
  dashboard itself is browsable read-only without logging in
- Security alerts and browser notifications
- **Optional alert channels** — webhook, Telegram bot and SMTP email are delivered
  when their environment variables are set
- **Persistent audit log** of logins, authorize/unauthorize, scans, weak checks and exports
- Automated security recommendations (device-level and per-port advice)
- **Device classification** (router / web-server / workstation / printer / ...)
- Security score / risk assessment computed on the backend

### Continuous Monitoring
- **Background scanning** keeps running even when no browser is open (scheduler)
- **SQLite persistence** — scan snapshots, device timeline, ARP bindings, alerts and
  audit log survive server restarts
- Scan history chart (devices & unauthorized devices over time)
- **Topology map** — canvas drawing of devices around the gateway, color-coded by
  authorization status
- **Traffic sniffer** — short passive captures (Scapy) with protocol breakdown, top
  talkers and live bandwidth while the capture runs
- CSV / JSON / HTML / PDF report export
- **Dark mode** and **Arabic/English** interface toggles (AR labels + RTL-safe layout)

### Dashboard
- Modern, responsive interface
- Stats cards (devices, alerts, ports, security score)
- Charts (device authorization donut, port-risk bar chart, history line chart)
- **Network Topology** section with an interactive Canvas map
- Device details modal, per-port details and advice, plus **CVE lookup** and **OS
  detection** buttons
- Authorized-device management panel (admin only)
- **Notifications settings** panel showing which channels (webhook/Telegram/email)
  are configured server-side
- Login screen, Reports section with export buttons, audit log viewer, scan-diff
  panel and the traffic sniffer

## Installation

### Prerequisites
- Python 3.8+ (project developed on 3.14)
- [Nmap](https://nmap.org/download.html) installed and on your `PATH`
- On Windows, run the shell _as Administrator_ so Scapy/nmap can perform ARP and socket scans

### Backend Setup
1. Clone the repository
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/macOS
   source .venv/bin/activate
   ```
3. Install Python dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
4. Create the environment file:
   ```bash
   cp .env.example .env        # Windows: copy .env.example .env
   ```
   Set a strong `API_TOKEN` — this is required to authorize/unauthorize devices from the UI.
5. Run the application:
   ```bash
   python run.py
   ```
6. Open http://localhost:5000 in your browser.

> The server binds to `0.0.0.0`, so it is reachable from other devices on the LAN.
> The first time you authorize a device you will be asked to enter the `API_TOKEN`.

## API Endpoints

| Method | Path                          | Description                                    | Auth |
| ------ | ----------------------------- | ---------------------------------------------- | ---- |
| GET    | `/api/health`                 | Health check                                   | No   |
| GET    | `/api/scan`                   | Start a network scan (background)              | No   |
| GET    | `/api/status`                 | Scan status, subnet, gateway, channels         | No   |
| GET    | `/api/devices`                | List last scanned devices                      | No   |
| GET    | `/api/device/<ip>/ports`      | Cached open-port details for a device          | No   |
| GET    | `/api/device/<ip>/cves`       | Known CVEs for a device (cache then live API)  | Yes  |
| GET    | `/api/device/<ip>/os`         | Detect OS via `nmap -O` (cached)               | Yes  |
| GET    | `/api/advice/<ip>`            | Security advice for a device                   | No   |
| GET    | `/api/alerts`                 | Accumulated alerts (last 100)                  | No   |
| GET    | `/api/stats`                  | System stats + security report                 | No   |
| GET    | `/api/interfaces`             | Network interfaces                             | No   |
| GET    | `/api/authorized-devices`     | List authorized devices                        | No   |
| GET    | `/api/history`                | Scan history for the trend chart               | No   |
| GET    | `/api/diff`                   | Changes between the two most recent scans      | No   |
| GET    | `/api/sniff/status`           | Live sniffer counters (in-progress capture)    | No   |
| POST   | `/api/sniff/start?duration=N` | Start a passive capture (3-120s)               | Yes  |
| GET    | `/api/sniff/result`           | Latest capture summary (protocols/talkers)     | Yes  |
| GET    | `/api/me`                     | Current session user                           | No   |
| POST   | `/api/login`                  | Session login                                 | No   |
| POST   | `/api/logout`                 | Session logout                                | No   |
| GET    | `/api/audit`                  | Audit log (last 100)                           | Yes  |
| GET    | `/api/export?format=csv\|json\|html\|pdf` | Download the scan report            | Yes  |
| POST   | `/api/device/<mac>/authorize` | Add device to the whitelist                    | Yes (admin) |
| POST   | `/api/device/<mac>/unauthorize` | Remove device from the whitelist             | Yes (admin) |

Auth token is sent via the `X-API-Token` header or `Authorization: Bearer <token>`.
Browser users log in via the dashboard login screen (session cookie).

## Configuration (`.env`)

| Variable        | Default       | Description                                       |
| --------------- | ------------- | ------------------------------------------------- |
| `SECRET_KEY`    | demo value    | Flask secret key (set a random value in production) |
| `SCAN_INTERVAL` | `60`          | Seconds between continuous background scans       |
| `NETWORK_SUBNET`| auto-detect  | Target CIDR, e.g. `192.168.1.0/24`                 |
| `API_TOKEN`     | `changeme`    | Token accepted for authorize/unauthorize/export   |
| `ADMIN_USERNAME`| `admin`       | Dashboard login username                          |
| `ADMIN_PASSWORD`| `admin`       | Dashboard login password (change it!)             |
| `AUTOSCAN_ENABLED`| `true`      | Enable the continuous background scanner          |
| `WEBHOOK_URL`   | *(empty)*     | Optional URL that receives new alerts as JSON POST|
| `TELEGRAM_BOT_TOKEN` | *(empty)* | Optional Telegram bot token for alerts          |
| `TELEGRAM_CHAT_ID` | *(empty)*  | Optional Telegram chat id for alerts             |
| `EMAIL_SMTP_HOST` | *(empty)*   | Optional SMTP host for email alerts              |
| `EMAIL_SMTP_PORT` | `587`       | SMTP port (TLS when `EMAIL_USE_TLS=true`)        |
| `EMAIL_SMTP_USER` | *(empty)*   | SMTP username                                    |
| `EMAIL_SMTP_PASSWORD` | *(empty)* | SMTP password / app password                    |
| `EMAIL_FROM`    | *(empty)*     | From address of alert emails                     |
| `EMAIL_TO`      | *(empty)*     | Recipient of alert emails                        |
| `EMAIL_USE_TLS` | `true`        | Enable `STARTTLS` when sending                  |
| `WEAK_SERVICE_CHECKS` | `true` | Run FTP/DNS weak-service probes after a scan    |
| `SNIFF_IFACE`   | *(empty)*     | Interface used by the traffic sniffer (auto if empty) |

## Default Login

For development the default credentials are `admin` / `admin`.
**Change them via `ADMIN_USERNAME` / `ADMIN_PASSWORD` before exposing the tool.**

## Data Storage

- Authorized devices: `data/authorized_devices.json` (MACs are normalized).
- Scan history, device timeline, alerts and audit log:
  `data/cyberwatch.db` (SQLite). Data survives restarts.

## Running Tests

```bash
python -m unittest discover -s backend/tests -t backend
```

## Known Limitations

- Vendor identification uses a tiny built-in OUI table (does not query a full OUI database).
- Port scanning is `-sT` (TCP connect) so it works without raw sockets, but is slower on large networks.
- nmap fallback discovery (when Scapy is unavailable) cannot report MAC addresses, so those
  devices cannot be authorized until Scapy is available.
- The traffic sniffer needs the machine to run with administrator privileges and Npcap
  installed; otherwise the capture reports a clear error instead of crashing.
- CVE lookups call the public `cve.circl.lu` API, so they need internet access; results
  for both the live lookup and the SQLite cache are capped and sorted by CVSS score.
- OS detection runs `nmap -O` on demand and can take tens of seconds per device.