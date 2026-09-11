"""Security report generation: self-contained HTML and a PDF built with reportlab."""
from datetime import datetime


def _port_text(device) -> str:
    ports = device.get('open_ports') or []
    if not ports:
        return 'None'
    return ', '.join(str(p) for p in ports)


def _sorted_devices(devices) -> list:
    return sorted(devices, key=lambda d: (d.get('is_authorized'), str(d.get('ip', ''))))


# ------------------------------------------------------------------ HTML
def generate_html_report(devices, history=None, generated=None) -> str:
    generated = generated or datetime.now()
    total = len(devices)
    unauthorized = sum(1 for d in devices if not d.get('is_authorized'))

    rows = []
    for d in _sorted_devices(devices):
        status = ('Authorized' if d.get('is_authorized') else 'UNAUTHORIZED')
        rows.append(f'''
            <tr>
                <td>{_esc(d.get('ip', ''))}</td>
                <td>{_esc(d.get('mac', 'unknown'))}</td>
                <td>{_esc(d.get('hostname') or 'Unknown')}</td>
                <td>{_esc(d.get('vendor') or '')}</td>
                <td>{_esc(d.get('device_type') or '')}</td>
                <td>{_esc(_port_text(d))}</td>
                <td class="{('ok' if d.get('is_authorized') else 'bad')}">{status}</td>
            </tr>''')

    hist_rows = ''
    for p in (history or []):
        hist_rows += (f'<tr><td>{_esc(p.get("scan_time", ""))}</td>'
                      f'<td>{p.get("device_count", 0)}</td>'
                      f'<td>{p.get("unauthorized_count", 0)}</td></tr>')

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CyberGuard Security Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 2rem; color: #1f2937; }}
  h1 {{ color: #1d4ed8; border-bottom: 3px solid #1d4ed8; padding-bottom: .4rem; }}
  .meta {{ color: #6b7280; margin-bottom: 1.5rem; }}
  .cards {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
  .card {{ flex: 1; border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; }}
  .card h3 {{ margin: 0 0 .4rem; font-size: .8rem; color: #6b7280; }}
  .card .num {{ font-size: 1.6rem; font-weight: 700; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: .5rem; }}
  th, td {{ border: 1px solid #e5e7eb; padding: .45rem .6rem; font-size: .85rem; text-align: left; }}
  th {{ background: #f3f4f6; }}
  .ok {{ color: #047857; font-weight: 600; }}
  .bad {{ color: #b91c1c; font-weight: 700; }}
  h2 {{ margin-top: 2rem; color: #374151; }}
</style>
</head>
<body>
  <h1>CyberGuard Security Report</h1>
  <div class="meta">Generated: {generated.isoformat() if hasattr(generated, 'isoformat') else generated}</div>
  <div class="cards">
    <div class="card"><h3>Devices</h3><div class="num">{total}</div></div>
    <div class="card"><h3>Unauthorized</h3><div class="num">{unauthorized}</div></div>
    <div class="card"><h3>Open Ports</h3><div class="num">{sum(len(d.get('open_ports') or []) for d in devices)}</div></div>
  </div>
  <h2>Devices</h2>
  <table>
    <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>Type</th><th>Open Ports</th><th>Status</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="7">No devices scanned.</td></tr>'}</tbody>
  </table>
  <h2>Scan History</h2>
  <table>
    <thead><tr><th>Time</th><th>Devices</th><th>Unauthorized</th></tr></thead>
    <tbody>{hist_rows or '<tr><td colspan="3">No history yet.</td></tr>'}</tbody>
  </table>
</body>
</html>'''


# ------------------------------------------------------------------ PDF
def generate_pdf_report(devices, history=None, generated=None):
    """Returns (bytes, None) on success, (None, error_string) when reportlab
    is not installed."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                        Table, TableStyle)
    except ImportError:
        return None, ('PDF generation requires the "reportlab" package. '
                      'Run: pip install reportlab')

    from io import BytesIO
    generated = generated or datetime.now()

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4),
                            leftMargin=15*mm, rightMargin=15*mm,
                            topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    title = styles['Title']
    item = styles['BodyText']
    story = [
        Paragraph('CyberGuard Security Report', title),
        Paragraph(f'Generated: {generated.isoformat()}', item),
        Spacer(1, 5*mm),
        Paragraph(f'Total devices: {len(devices)} | '
                  f'Unauthorized: {sum(1 for d in devices if not d.get("is_authorized"))} | '
                  f'Open ports: {sum(len(d.get("open_ports") or []) for d in devices)}', item),
        Spacer(1, 3*mm),
    ]

    headers = ['IP', 'MAC', 'Hostname', 'Vendor', 'Type', 'Open Ports', 'Status']
    rows = [headers]
    for d in _sorted_devices(devices):
        rows.append([
            str(d.get('ip', '')),
            str(d.get('mac', 'unknown')),
            str(d.get('hostname') or 'Unknown'),
            str(d.get('vendor') or ''),
            str(d.get('device_type') or ''),
            _port_text(d),
            'Authorized' if d.get('is_authorized') else 'UNAUTHORIZED',
        ])
    t = Table(rows, repeatRows=1)
    t.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#d1d5db')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
         [colors.white, colors.HexColor('#f9fafb')]),
        ('TEXTCOLOR', (6, 1), (6, -1), colors.HexColor('#b91c1c')),
    ]))
    story.append(Paragraph('Devices', styles['Heading2']))
    story.append(t)
    story.append(Spacer(1, 5*mm))

    history = history or []
    if history:
        hrows = [['Time', 'Devices', 'Unauthorized']]
        for p in history:
            hrows.append([str(p.get('scan_time', '')), str(p.get('device_count', 0)),
                          str(p.get('unauthorized_count', 0))])
        ht = Table(hrows, repeatRows=1)
        ht.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#d1d5db')),
        ]))
        story.append(Paragraph('Scan History', styles['Heading2']))
        story.append(ht)

    doc.build(story)
    return buf.getvalue(), None


# ------------------------------------------------------------------ helpers
def _esc(value) -> str:
    return (str(value).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;'))