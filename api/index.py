"""Vercel serverless entrypoint.

Vercel imports the Flask WSGI `app` from this module and routes every URL
through it (see `vercel.json`). Env vars (ADMIN_*, REVIEWER_*, API_TOKEN,
SECRET_KEY, Telegram/Email/webhook...) are injected from the Vercel project
settings, not from a .env file.

Serverless notes:
- The filesystem is read-only except /tmp, and /tmp is ephemeral: runtime
  data (authorized devices, SQLite history) resets between instances. That is
  fine for a hosted demo dashboard.
- Real LAN scanning needs nmap / raw sockets / background threads that cannot
  exist on Vercel, so scan/sniff endpoints simply stay empty there. Use the
  full deployment (`python run.py` on the LAN, exposed via Cloudflare Tunnel
  or similar) for real monitoring - see docs/DEPLOY.md.
"""
import os
import sys

# Make the backend package importable (Vercel runs functions from the repo root).
_BACKEND = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from app import app  # noqa: E402  (the WSGI app Vercel expects)