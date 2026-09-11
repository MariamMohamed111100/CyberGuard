import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'cyber-security-monitor-secret-key')
    SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', '60'))  # seconds
    # Leave net_subnet empty to auto-detect from the machine's network interfaces
    NETWORK_SUBNET = os.getenv('NETWORK_SUBNET', '')
    API_TOKEN = os.getenv('API_TOKEN', 'changeme')

    # Dashboard authentication
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')

    # Continuous monitoring: keeps scanning in the background even without a browser open
    AUTOSCAN_ENABLED = os.getenv('AUTOSCAN_ENABLED', 'true').lower() in ('1', 'true', 'yes')

    # Optional webhook that receives a JSON payload whenever a scan raises new alerts
    WEBHOOK_URL = os.getenv('WEBHOOK_URL', '').strip()

    # Telegram alert channel (both required to enable)
    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '').strip()
    TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '').strip()

    # Email alert channel (SMTP host + recipient required to enable)
    EMAIL_SMTP_HOST = os.getenv('EMAIL_SMTP_HOST', '').strip()
    EMAIL_SMTP_PORT = int(os.getenv('EMAIL_SMTP_PORT', '587'))
    EMAIL_SMTP_USER = os.getenv('EMAIL_SMTP_USER', '').strip()
    EMAIL_SMTP_PASSWORD = os.getenv('EMAIL_SMTP_PASSWORD', '').strip()
    EMAIL_FROM = os.getenv('EMAIL_FROM', '').strip()
    EMAIL_TO = os.getenv('EMAIL_TO', '').strip()
    EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'true').lower() in ('1', 'true', 'yes')

    # Run weak-service probes (FTP anonymous login, open DNS resolver) during scans
    WEAK_SERVICE_CHECKS = os.getenv('WEAK_SERVICE_CHECKS', 'true').lower() in ('1', 'true', 'yes')

    # Interface used by the traffic sniffer; leave empty for auto-selection
    SNIFF_IFACE = os.getenv('SNIFF_IFACE', '').strip()

    # Security thresholds
    HIGH_RISK_PORTS = [23, 21, 139, 445, 135, 3389]
    WARNING_PORTS = [8080, 8888, 9000, 3000]

    AUTHORIZED_PORTS = {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        53: 'DNS',
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        3389: 'RDP',
        5900: 'VNC'
    }