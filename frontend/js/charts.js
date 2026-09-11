// Charts for the security dashboard (Chart.js from CDN)
let deviceChart = null;
let riskChart = null;
let historyChart = null;

const HIGH_RISK_PORTS = [23, 21, 139, 445, 135, 3389];
const WARNING_PORTS = [8080, 8888, 9000, 3000];

function ct(key, vars) {
    return window.i18n ? window.i18n.t(key, vars) : key;
}

function isDarkTheme() {
    return document.documentElement.dataset.theme === 'dark';
}

function chartTextColor() {
    return isDarkTheme() ? '#e5e7eb' : '#1f2937';
}

function portRiskLevel(port) {
    if (HIGH_RISK_PORTS.includes(port)) return 'high';
    if (WARNING_PORTS.includes(port)) return 'medium';
    return 'low';
}

function renderCharts(devices = [], alerts = []) {
    if (typeof Chart === 'undefined') return;

    const authorized = (devices || []).filter(d => d.is_authorized).length;
    const unauthorized = (devices || []).length - authorized;
    const textColor = chartTextColor();

    // Devices: authorized vs unauthorized (donut)
    const deviceCtx = document.getElementById('chart-devices');
    if (deviceCtx) {
        if (deviceChart) deviceChart.destroy();
        deviceChart = new Chart(deviceCtx, {
            type: 'doughnut',
            data: {
                labels: [ct('charts.authorized'), ct('charts.unauthorized')],
                datasets: [{
                    data: [authorized, unauthorized],
                    backgroundColor: ['#10b981', '#dc2626'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: textColor, usePointStyle: true } }
                }
            }
        });
    }

    // Port risk distribution (bar)
    const riskCounts = { high: 0, medium: 0, low: 0 };
    (devices || []).forEach(device => {
        (device.open_ports || []).forEach(port => {
            riskCounts[portRiskLevel(port)] += 1;
        });
    });

    const riskCtx = document.getElementById('chart-risk');
    if (riskCtx) {
        if (riskChart) riskChart.destroy();
        riskChart = new Chart(riskCtx, {
            type: 'bar',
            data: {
                labels: [ct('charts.highRisk'), ct('charts.mediumRisk'), ct('charts.lowRisk')],
                datasets: [{
                    label: ct('charts.openPorts'),
                    data: [riskCounts.high, riskCounts.medium, riskCounts.low],
                    backgroundColor: ['#dc2626', '#f59e0b', '#10b981'],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { ticks: { color: textColor } },
                    y: { beginAtZero: true, ticks: { color: textColor, precision: 0 } }
                }
            }
        });
    }
}

window.renderCharts = renderCharts;

function renderHistoryChart(points = []) {
    if (typeof Chart === 'undefined') return;
    const ctx = document.getElementById('chart-history');
    if (!ctx) return;

    const textColor = chartTextColor();

    const labels = points.map((p, i) => {
        try {
            return new Date(p.scan_time).toLocaleString(
                window.i18n && window.i18n.getLang && window.i18n.getLang() === 'ar' ? 'ar-EG' : 'en-US',
                { hour: '2-digit', minute: '2-digit' }
            );
        } catch (e) {
            return `#${i + 1}`;
        }
    });

    if (historyChart) historyChart.destroy();

    if (!points || points.length === 0) {
        historyChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    borderColor: '#2563eb',
                    fill: false
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
        return;
    }

    historyChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: ct('charts.devices'),
                    data: points.map(p => p.device_count),
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.15)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 3
                },
                {
                    label: ct('charts.unauthorized'),
                    data: points.map(p => p.unauthorized_count),
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.1)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: textColor, usePointStyle: true } }
            },
            scales: {
                x: { ticks: { color: textColor, maxTicksLimit: 12 } },
                y: { beginAtZero: true, ticks: { color: textColor, precision: 0 } }
            }
        }
    });
}

window.renderHistoryChart = renderHistoryChart;

// ---------------------------------------------------------------- topology map
function renderTopology(devices = [], gateway = null) {
    const canvas = document.getElementById('topology-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;
    const dark = isDarkTheme();

    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = dark ? '#0b1220' : '#f8fafc';
    ctx.fillRect(0, 0, W, H);

    const cx = W / 2;
    const cy = H / 2;

    // faint radar rings
    ctx.strokeStyle = dark ? 'rgba(96, 165, 250, 0.16)' : 'rgba(37, 99, 235, 0.12)';
    ctx.lineWidth = 1;
    [90, 150, 210].forEach(r => {
        ctx.beginPath();
        ctx.arc(cx, cy, r + 90, 0, Math.PI * 2);
        ctx.stroke();
    });

    // gateway drawn after the ring
    drawTopologyNode(ctx, cx, cy, gateway || ct('topology.gateway'), '#2563eb', '#ffffff', true);

    const list = devices || [];
    if (!list.length) {
        ctx.fillStyle = dark ? '#94a3b8' : '#64748b';
        ctx.font = '13px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(ct('topology.runScanMap'), cx, H - 30);
        return;
    }

    const radius = Math.min(W, H) / 2 - 80;
    const n = list.length;
    const angleStep = (Math.PI * 2) / n;
    const start = -Math.PI / 2;

    const positions = list.map((device, i) => {
        const angle = start + angleStep * i;
        const x = cx + Math.cos(angle) * radius;
        const y = cy + Math.sin(angle) * radius;
        return { device, x, y };
    });

    // edges first (under the nodes)
    positions.forEach(({ device, x, y }) => {
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(x, y);
        ctx.strokeStyle = device.is_authorized ? 'rgba(16, 185, 129, 0.45)' : 'rgba(220, 38, 38, 0.5)';
        ctx.lineWidth = device.is_authorized ? 1.5 : 2.5;
        if (!device.is_authorized) ctx.setLineDash([5, 4]);
        ctx.stroke();
        ctx.setLineDash([]);
    });

    // nodes
    positions.forEach(({ device, x, y }) => {
        drawTopologyNode(
            ctx, x, y,
            device.ip,
            device.is_authorized ? '#10b981' : '#dc2626',
            '#ffffff',
            false,
            device.hostname
        );
    });
}

function drawTopologyNode(ctx, x, y, label, fill, textColor, isGateway, subLabel) {
    const r = isGateway ? 26 : 20;
    const dark = isDarkTheme();
    // highlight halo for the gateway
    if (isGateway) {
        ctx.beginPath();
        ctx.arc(x, y, r + 8, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(37, 99, 235, 0.15)';
        ctx.fill();
    }
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fillStyle = fill;
    ctx.fill();
    ctx.strokeStyle = dark ? 'rgba(226, 232, 240, 0.25)' : 'rgba(15, 23, 42, 0.2)';
    ctx.lineWidth = 1;
    ctx.stroke();

    ctx.fillStyle = textColor;
    ctx.font = isGateway ? 'bold 15px Inter, sans-serif' : 'bold 12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(isGateway ? 'R' : 'D', x, y + 1);

    ctx.fillStyle = dark ? '#cbd5e1' : '#1e293b';
    ctx.font = '11px Inter, sans-serif';
    ctx.textBaseline = 'top';
    ctx.fillText(label, x, y + r + 5);
    if (subLabel) {
        const text = String(subLabel);
        ctx.fillStyle = dark ? '#94a3b8' : '#64748b';
        ctx.font = '10px Inter, sans-serif';
        ctx.fillText(text.length > 14 ? text.slice(0, 13) + '…' : text, x, y + r + 18);
    }
}

window.renderTopology = renderTopology;