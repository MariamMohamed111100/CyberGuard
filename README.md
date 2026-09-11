<p align="center">
  <img src="https://img.shields.io/badge/status-alive%20%26%20watching-brightgreen" alt="Status">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/interface-AR%20%2F%20EN-orange" alt="i18n">
  <img src="https://img.shields.io/badge/dark%20mode-true-yellow" alt="Dark mode">
  <img src="https://img.shields.io/badge/tests-92%20passing-success" alt="Tests">
  <img src="https://img.shields.io/badge/made_with-%F0%9F%8D%8A-purple" alt="Made with 🍊">
</p>

<h1 align="center">👁️ CyberGuard</h1>

<p align="center">
  <b>Your LAN's paranoid roommate.</b><br>
  It never sleeps, it scans everything, and it <i>will</i> tell on you the moment a strange device joins your network.
</p>

<blockquote align="center">
  A self-hosted LAN security monitor: device discovery · port scanning · rogue-device detection ·<br>
  CVE lookup · OS fingerprinting · Telegram/Email/Webhook alerts · pretty dashboard 🌐
</blockquote>

---

## ✨ Why CyberGuard?

Most home routers give you a flat list of IPs and call it a day. CyberGuard actually **cares**:

- 🔍 **Finds every device** on your network (ARP/Scapy + nmap fallback, subnet auto-detected)
- 🚨 **Calls the cops on rogues** — any MAC not on your whitelist becomes a high-severity alert
- 🕵️ **Smells ARP spoofing** — one IP, two MACs? Sus.
- 🔁 **Diffs every scan** — new device? Gone device? New port open? You'll know.
- 💥 **CVE lookup** per device (live API + smart cache)
- 🤖 **OS fingerprinting** via `nmap -O` on demand
- 📬 **Alerts wherever you are**: Telegram bot, SMTP email, or a webhook (Slack/Discord/ntfy)
- 📊 **Beautiful dashboard** in **English or Arabic**, with **dark mode** — because security at 3AM deserves nice colors
- 📁 **Exports**: CSV, JSON, HTML, PDF — ready for your compliance report
- 🐍 **SQLite persistence** — your data survives restarts, like a trauma survivor

---

## 🚀 Quickstart (60 seconds)

```bash
# 1. Clone & enter
git clone https://github.com/<you>/cyberwatch.git && cd cyberwatch

# 2. Virtual env
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux / macOS

# 3. Dependencies
pip install -r backend/requirements.txt

# 4. Config
copy .env.example .env        # Windows
cp .env.example .env          # Linux / macOS
# then edit .env and set a strong API_TOKEN

# 5. Run
python run.py
```

Open **http://localhost:5000** 🔗 — seriously, do it.

> ⚠️ **Windows:** run from an **Administrator** shell so Scapy/nmap can sniff & scan.
> Install [Nmap](https://nmap.org/download.html) if it isn't on your `PATH` yet.

---

## 🔐 First Login

### 👑 Single Admin Account

| Default creds     | Powers                                                       |
| ----------------- | ------------------------------------------------------------ |
| `admin` / `admin` | Everything: scan, sniff, whitelist, exports, audit           |

**Please** set `ADMIN_USERNAME` / `ADMIN_PASSWORD` (or add them to `.env`) before exposing it to the world. Your network will thank you.

---

## 📬 Alerting That Actually Reaches You

Set a few env vars, get alerts on your phone. Yes, your phone.

| Channel      | What you need                                                        |
| ------------ | -------------------------------------------------------------------- |
| 📡 Webhook   | `WEBHOOK_URL` — any JSON endpoint (ntfy.sh, Slack, Discord...)       |
| ✈️ Telegram  | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` (say hi to @BotFather)     |
| 📧 Email     | `EMAIL_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_TO` + `_FROM`|

Everything is **best-effort & independent**: if Telegram is down, email still flies.
The dashboard even shows which channels are live, with one-click persistence of your preferences. 🧠

Full `.env` reference → see [Configuration](docs/README.md#configuration-env).

---

## 🧭 Features Tour

### 📡 Network Monitoring
- Auto subnet detection from your machine's interfaces
- Device discovery — ARP scan via Scapy, nmap fallback when raw sockets aren't available
- Port scanning (1–1024 + high-risk list) with service detection
- MAC → vendor identification (built-in OUI table)
- Device classification: router, workstation, printer, web-server... 🖨️

### 🛡️ Security Arsenal
- Rogue (unauthorized) device alarms
- New-device detection on first sight
- ARP-spoofing / IP-binding-change detection
- Scan-to-scan diffing (new/gone devices, ports opened/closed)
- Weak-service probes: anonymous FTP, open DNS resolvers 🦠
- On-demand **CVE lookup** and **OS fingerprinting** per device
- Security score, risk assessment, per-port + per-device advice
- Single-admin auth + persistent **audit log**

### 🤖 Continuous Monitoring
- Background scheduler keeps scanning with **no browser open**
- SQLite storage: snapshots, timeline, alerts, audit — restart-proof
- Scan-history chart 📈, live traffic sniffer 🚦, topology map 🗺️

### 🎨 Dashboard
- Stats cards, donut/bar/line charts (Chart.js)
- Interactive topology canvas with colors by authorization status
- Device modal with ports, advice, CVE & OS buttons
- **Arabic/English** toggle + **dark/light** theme — saved in localStorage
- Guests see the dashboard read-only (no account needed); the admin signs in for the full controls

---

## 🔌 API (short story)

A bunch of `/api/*` JSON endpoints: health, scan, devices, alerts, stats, cves, os,
export... The full table with auth flags lives in the [docs](docs/README.md#api-endpoints).

```bash
curl http://localhost:5000/api/health
# → {"status":"healthy","service":"Cyber Security Monitor","version":"2.1.0"}
```

---

## 🧪 Running Tests

```bash
python -m unittest discover -s backend/tests -t backend
# Ran 92 tests … OK ✅
```

---

## 🗂️ Layout

```
cyberwatch/
├── run.py                # 🚀 entrypoint
├── backend/
│   ├── app.py            # Flask app + all routes
│   ├── scanner.py        # discovery, ports, analyzer
│   ├── cve_lookup.py     # CVE API + layered cache
│   ├── weak_checks.py    # FTP / DNS probes
│   ├── reports.py        # HTML / PDF exports
│   ├── sniffer.py        # passive traffic capture
│   ├── diffing.py        # scan-to-scan diffing
│   └── tests/            # 92 tests, all green
├── frontend/
│   ├── index.html        # dark-mode, i18n dashboard
│   ├── css/              # style + modern redesign layer
│   └── js/               # app, charts, i18n, notifications
├── docs/README.md        # 📚 deep-dive docs (API table, .env reference)
└── .env.example          # config template
```

---

## 🛠️ Tech Stack

| Layer      | Tools                                                          |
| ---------- | -------------------------------------------------------------- |
| Backend    | Python · Flask · Scapy · python-nmap · psutil · reportlab      |
| Storage    | SQLite (+ JSON whitelist)                                      |
| Frontend   | Vanilla JS · Chart.js · Font Awesome · hand-rolled CSS magic   |
| Notify     | HTTP webhooks · python-telegram-bot style calls · SMTP         |

---

## ⚠️ Friendly Legal Corner

This tool is for **monitoring networks you own** or have permission to scan.
With great scanning power comes great responsibility. Please don't be the villain in someone's audit log. 🦹

---

## 🩹 Known Limitations & Fair Confessions

- OUI table is tiny — vendor names may say "Unknown" sometimes. It's not you, it's us.
- Full port scan is TCP-connect (`-sT`), slower on huge networks but no raw sockets needed.
- Without Scapy, nmap fallback can't see MACs → those devices can't be whitelisted yet.
- The sniffer needs **admin + Npcap** on Windows; otherwise it fails gracefully, like a gentleman.
- CVE lookups need public internet (cve.circl.lu); results are cached & CVSS-sorted.
- `nmap -O` is slow by design — it's called only on demand.

More honest confessions → [Known Limitations](docs/README.md#known-limitations).

---

<p align="center">
  Made with ☕, ~90% caffeine and a healthy dose of <code>sudo</code>.<br>
  Security is a journey — CyberGuard just makes it prettier. 🛰️
</p>