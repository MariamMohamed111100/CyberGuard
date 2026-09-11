# 🚀 Deployment Guide

CyberGuard can run in **two modes**. Pick the one that matches what you need:

| Mode | Hosting | Works |
| ---- | ------- | ----- |
| **☁️ Demo dashboard** | Vercel (serverless) | Login + roles, dashboard, charts, exports, i18n/dark mode, audit (per session) |
| **🏠 Full LAN monitor** | Your machine / VPS + Tunnel | Everything, including real scanning, sniffing, persistence |

---

## ☁️ Option A — Vercel demo dashboard

Vercel gives you a free public URL with HTTPS for showing off the product.

### What works / what does not

| Feature | On Vercel |
| ------- | --------- |
| Login (single admin) | ✅ |
| Dashboard, charts, topology UI | ✅ (networks stay empty) |
| CSV / JSON / HTML / PDF exports | ✅ |
| Arabic/English + dark mode | ✅ |
| **Guest view** (read-only browsing without logging in) | ✅ |
| Audit log of logins | ✅ (per instance session) |
| Device authorization UI | ⚠️ interactive but nothing to authorize |
| **Real LAN scanning** | ❌ no nmap, no raw sockets, no access to your LAN |
| **Sniffer / autoscan** | ❌ threads don't survive serverless |
| **Persistence** (SQLite) | ❌ `/tmp` is ephemeral on Vercel |

So: **perfect as a live demo of the UI, not for actual monitoring.**

### Steps

1. Push the project to GitHub (`.env`, `data/*`, `.venv/` are already gitignored).
2. Create a project on [vercel.com](https://vercel.com) → import the repo host "Other", framework: **Other** (the repo ships `vercel.json` + `api/index.py`, so no extra config).
3. Install the CLI (optional) and link:
   ```bash
   npm i -g vercel
   vercel
   ```
4. Set **Environment Variables** in Vercel → Project → Settings → Environment Variables:
   ```
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=<a strong password>
   API_TOKEN=<a long random string>
   SECRET_KEY=<a long random string>
   AUTOSCAN_ENABLED=false
   WEAK_SERVICE_CHECKS=false
   ```
   (Also add `TELEGRAM_*` / `EMAIL_*` / `WEBHOOK_URL` if you want the alert
   channels wired, though without scans there are no alerts to deliver.)
5. Deploy:
   ```bash
   vercel --prod
   ```
6. Open the generated URL and log in with the admin credentials you set.

> Vercel is **read-only** on the project filesystem, so `models.py` redirects
> runtime data to `/tmp/cyberwatch` when it detects the `VERCEL` env var.

---

## 🏠 Option B — Full LAN monitoring over a tunnel

Run the app on a machine **inside the network you monitor** (Windows admin is
best for Scapy + sniffer) and expose it safely.

1. Start it like always:
   ```bash
   python run.py        # binds http://0.0.0.0:5000
   ```

2. **Cloudflare Tunnel** (recommended - free, no open ports):
   ```bash
   # quick try (no account needed)
   cloudflared tunnel --url http://localhost:5000

   # or a named tunnel with a fixed hostname
   cloudflared tunnel create cyberwatch
   cloudflared tunnel route dns cyberwatch <your-subdomain>.trycloudflare.com
   cloudflared tunnel run cyberwatch
   ```
   Wrap the login page with a free Cloudflare Access policy for an extra lock.

3. **ngrok** (quick alternative):
   ```bash
   ngrok http 5000
   ```

4. **Tailscale / WireGuard** — even better: don't expose anything public, just
   reach the dashboard over your private network.

### Security checklist before exposing to the internet

- [ ] `ADMIN_PASSWORD` is **not** `admin` anymore
- [ ] `API_TOKEN` and `SECRET_KEY` are long random strings
- [ ] `.env` stays out of git (`.gitignore` covers it)
- [ ] Prefer a tunnel + Access policy over port-forwarding
- [ ] Disable `AUTOSCAN_ENABLED` if the machine isn't powerful enough

---

## ⚙️ Environment reference

Full table of every `.env`/Vercel variable → [docs/README.md](README.md#configuration-env).