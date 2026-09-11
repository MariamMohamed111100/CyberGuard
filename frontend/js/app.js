// Main application JavaScript
class SecurityMonitorApp {
    constructor() {
        this.apiBaseUrl = '/api';
        this.autoScanInterval = null;
        this.autoScanEnabled = false;
        this.currentDevicePorts = {};
        this.role = 'admin';

        this.initializeApp();
    }

    t(key, vars) {
        return window.i18n ? window.i18n.t(key, vars) : key;
    }

    initializeApp() {
        this.updateCurrentTime();
        setInterval(() => this.updateCurrentTime(), 1000);

        this.bindEvents();
        this.initAuth();
        this.initFunEffects();

        // Load system stats every 10 seconds
        setInterval(() => this.loadSystemStats(), 10000);
    }

    // Small, purely-cosmetic interaction layer: button ripples, scroll-reveal
    // for cards/sections, and a nav "scroll-spy" that highlights the section
    // currently in view. None of this touches app state/data.
    initFunEffects() {
        const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

        // Keep --header-offset in sync with the header's real rendered
        // height. The header wraps to multiple lines on narrow viewports
        // (and its content changes with language/login state), so a fixed
        // CSS px guess here is what previously caused toast notifications
        // to render underneath/behind the header instead of below it.
        const header = document.querySelector('.header');
        if (header) {
            const updateHeaderOffset = () => {
                const rect = header.getBoundingClientRect();
                document.documentElement.style.setProperty('--header-offset', `${Math.max(0, rect.bottom)}px`);
            };
            updateHeaderOffset();
            window.addEventListener('resize', updateHeaderOffset);
            if ('ResizeObserver' in window) {
                new ResizeObserver(updateHeaderOffset).observe(header);
            }
        }

        // Ripple effect on any .btn click
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('.btn');
            if (!btn) return;
            if (reduced) return;
            const rect = btn.getBoundingClientRect();
            const ripple = document.createElement('span');
            const size = Math.max(rect.width, rect.height);
            ripple.className = 'ripple';
            ripple.style.width = ripple.style.height = `${size}px`;
            ripple.style.left = `${e.clientX - rect.left - size / 2}px`;
            ripple.style.top = `${e.clientY - rect.top - size / 2}px`;
            btn.appendChild(ripple);
            ripple.addEventListener('animationend', () => ripple.remove(), { once: true });
        });

        // Scroll-reveal for cards / sections
        const revealTargets = document.querySelectorAll('.card, .chart-card, .content-section');
        if (reduced || !('IntersectionObserver' in window)) {
            revealTargets.forEach(el => el.classList.add('cw-visible'));
        } else {
            revealTargets.forEach(el => el.classList.add('reveal-on-scroll'));
            const revealObserver = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('cw-visible');
                        revealObserver.unobserve(entry.target);
                    }
                });
            }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
            revealTargets.forEach(el => revealObserver.observe(el));
        }

        // Nav scroll-spy: highlight the sidebar link for the section in view
        const navLinks = Array.from(document.querySelectorAll('.nav-menu a[href^="#"]'));
        if (navLinks.length && 'IntersectionObserver' in window) {
            const sections = navLinks
                .map(link => document.getElementById(link.getAttribute('href').slice(1)))
                .filter(Boolean);
            const setActive = (id) => {
                navLinks.forEach(link => {
                    link.parentElement.classList.toggle('active', link.getAttribute('href') === `#${id}`);
                });
            };
            const spyObserver = new IntersectionObserver((entries) => {
                const visible = entries.filter(en => en.isIntersecting);
                if (visible.length) {
                    visible.sort((a, b) => b.intersectionRatio - a.intersectionRatio);
                    setActive(visible[0].target.id);
                }
            }, { threshold: [0.2, 0.5, 0.8], rootMargin: '-15% 0px -55% 0px' });
            sections.forEach(sec => spyObserver.observe(sec));
        }
    }

    escapeHtml(value) {
        return String(value ?? '').replace(/[&<>"']/g, c => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        })[c]);
    }

    getApiToken() {
        return localStorage.getItem('cw_api_token') || '';
    }

    setApiToken() {
        const token = prompt('Enter the API token (set API_TOKEN in .env on the server):');
        if (token) {
            localStorage.setItem('cw_api_token', token.trim());
            return token.trim();
        }
        return null;
    }

    async apiFetch(path, options = {}) {
        const headers = new Headers(options.headers || {});
        const token = this.getApiToken();
        if (token) {
            headers.set('X-API-Token', token);
        }
        options.headers = headers;
        const response = await fetch(`${this.apiBaseUrl}${path}`, options);
        return response;
    }

    bindEvents() {
        // Scan buttons
        document.getElementById('scan-btn').addEventListener('click', () => this.startScan());
        document.getElementById('auto-scan-btn').addEventListener('click', () => this.toggleAutoScan());
        document.getElementById('refresh-devices').addEventListener('click', () => this.loadDevices());
        document.getElementById('close-port-details').addEventListener('click', () => this.hidePortDetails());

        // Close modal
        document.querySelector('.close-modal').addEventListener('click', () => this.hideModal());
        document.getElementById('device-modal').addEventListener('click', (e) => {
            if (e.target === document.getElementById('device-modal')) {
                this.hideModal();
            }
        });

        // Event delegation for dynamically built buttons (avoids inline JS / XSS)
        document.getElementById('devices-body').addEventListener('click', (e) => {
            const btn = e.target.closest('button[data-action]');
            if (!btn) return;
            const { action, ip, mac } = btn.dataset;
            if (action === 'details') this.showDeviceDetails(ip);
            else if (action === 'ports') this.showPortDetails(ip);
            else if (action === 'authorize') this.authorizeDevice(mac, ip, btn);
            else if (action === 'unauthorize') this.unauthorizeDevice(mac);
        });

        document.getElementById('device-modal-body').addEventListener('click', (e) => {
            const btn = e.target.closest('button[data-action]');
            if (!btn) return;
            const { action, ip, mac } = btn.dataset;
            if (action === 'ports') this.showPortDetails(ip);
            else if (action === 'authorize') this.authorizeDevice(mac, ip);
            else if (action === 'unauthorize') this.unauthorizeDevice(mac);
            else if (action === 'cves') this.loadDeviceCves(ip);
            else if (action === 'os') this.detectDeviceOs(ip);
        });

        document.getElementById('ports-body').addEventListener('click', (e) => {
            const btn = e.target.closest('button[data-action]');
            if (!btn) return;
            if (btn.dataset.action === 'advice') {
                this.getPortAdvice(parseInt(btn.dataset.port, 10), btn.dataset.service);
            }
        });

        // Click on port badge opens the port details view
        document.getElementById('devices-body').addEventListener('click', (e) => {
            const badge = e.target.closest('.port-badge');
            if (!badge) return;
            this.showPortDetails(badge.dataset.ip, parseInt(badge.dataset.port, 10));
        });

        // Sidebar "Ports" nav: open the (hidden-by-default) Port Details section
        document.querySelectorAll('.nav-menu a[href="#ports"]').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                this.closeSidebar();
                const candidates = (this.lastDevices || []).filter(d => d.open_ports && d.open_ports.length);
                if (candidates.length) {
                    this.showPortDetails(candidates[0].ip);
                } else {
                    document.getElementById('selected-device-ip').textContent = '';
                    document.getElementById('ports-body').innerHTML = `
                        <tr>
                            <td colspan="6" class="text-center">
                                <div class="no-data">
                                    <i class="fas fa-info-circle"></i>
                                    <p>${this.escapeHtml(this.t('ports.noOpenPorts'))}</p>
                                </div>
                            </td>
                        </tr>`;
                    document.getElementById('ports').style.display = 'block';
                    document.getElementById('ports').scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });

        // Auth
        document.getElementById('logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('login-btn').addEventListener('click', () => {
            window.location.href = '/login';
        });

        // Export buttons
        document.getElementById('export-csv').addEventListener('click', () => this.exportReport('csv'));
        document.getElementById('export-json').addEventListener('click', () => this.exportReport('json'));
        document.getElementById('export-html').addEventListener('click', () => this.exportReport('html'));
        document.getElementById('export-pdf').addEventListener('click', () => this.exportReport('pdf'));

        // Sniffer
        document.getElementById('sniff-start').addEventListener('click', () => this.startSniff());

        // Responsive sidebar
        const sidebarToggle = document.getElementById('sidebar-toggle');
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => this.toggleSidebar());
        }
        const sidebarOverlay = document.getElementById('sidebar-overlay');
        if (sidebarOverlay) {
            sidebarOverlay.addEventListener('click', () => this.closeSidebar());
        }
        document.querySelectorAll('.nav-menu a').forEach(link => {
            link.addEventListener('click', () => this.closeSidebar());
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closeSidebar();
        });
    }

    toggleSidebar() {
        document.querySelector('.app-container').classList.toggle('sidebar-open');
    }

    closeSidebar() {
        document.querySelector('.app-container').classList.remove('sidebar-open');
    }

    animateNumber(el, value) {
        if (!el || value === el.cwLastValue) return;
        el.cwLastValue = value;
        if (typeof value !== 'number' || Number.isNaN(value)) { el.textContent = value; return; }
        const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (reduced) { el.textContent = value; return; }
        const start = performance.now();
        const from = 0;
        const duration = 500;
        const step = (now) => {
            const p = Math.min((now - start) / duration, 1);
            const ease = 1 - Math.pow(1 - p, 3);
            el.textContent = Math.round(from + (value - from) * ease);
            if (p < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    }

    async initAuth() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/me`);
            const data = await response.json();
            if (data.username) {
                this.setLoggedIn(data.username, data.role || 'admin');
            } else {
                this.setGuest();
            }
        } catch (error) {
            console.error('Auth check error:', error);
            this.setGuest();
        }
    }

    setGuest() {
        this.role = 'guest';
        this.currentUser = null;
        this.applyRole();
        document.getElementById('user-name').textContent = this.t('header.guest');
        const loginBtn = document.getElementById('login-btn');
        if (loginBtn) loginBtn.style.display = 'inline-block';
        this.loadInitialData();
        this.loadReports();
    }

    setLoggedIn(username, role) {
        this.role = role || 'admin';
        this.currentUser = username;
        this.applyRole();
        document.getElementById('user-name').textContent = username;
        document.getElementById('logout-btn').style.display = 'inline-block';
        const loginBtn = document.getElementById('login-btn');
        if (loginBtn) loginBtn.style.display = 'none';
        this.loadInitialData();
        this.loadReports();
    }

    locale() {
        return window.i18n && window.i18n.getLang && window.i18n.getLang() === 'ar' ? 'ar-EG' : 'en-US';
    }

    async refreshAll() {
        this.applyRole();
        const nameEl = document.getElementById('user-name');
        if (nameEl) {
            nameEl.textContent = this.role === 'admin' ? (this.currentUser || '') : this.t('header.guest');
        }
        this.updateCurrentTime();
        if (window.i18n) window.i18n.applyStatic();
        if (this.lastDevices) {
            this.displayDevices(this.lastDevices);
            this.updateStats(this.lastDevices);
            if (window.renderCharts) window.renderCharts(this.lastDevices);
            if (window.renderTopology) window.renderTopology(this.lastDevices, this.gateway || null);
        } else {
            this.loadDevices();
        }
        this.loadAlerts();
        this.loadSystemStats();
        this.loadAuthorizedDevices();
        this.loadReports();
    }

    applyRole() {
        const isAdmin = this.role === 'admin';
        const isLoggedIn = this.role === 'admin';
        document.body.dataset.role = this.role || 'guest';
        document.querySelectorAll('.admin-only').forEach(el => {
            el.classList.toggle('hidden', !isAdmin);
        });
        document.querySelectorAll('.login-required').forEach(el => {
            el.classList.toggle('hidden', !isLoggedIn);
        });
    }

    async logout() {
        try {
            await fetch(`${this.apiBaseUrl}/logout`, { method: 'POST', credentials: 'include' });
        } catch (error) {
            console.error('Logout error:', error);
        }
        window.location.href = '/dashboard';
    }

    exportReport(format) {
        const a = document.createElement('a');
        a.href = `${this.apiBaseUrl}/export?format=${format}`;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }

    async loadReports() {
        this.loadHistory();
        this.loadScanDiff();
        this.loadSniffStatus();
    }

    async loadScanDiff() {
        const container = document.getElementById('scan-diff');
        try {
            const response = await fetch(`${this.apiBaseUrl}/diff`);
            const data = await response.json();
            const diff = data.diff;
            if (!diff) {
                container.innerHTML = `
                    <div class="no-data">
                        <i class="fas fa-info-circle"></i>
                        <p>${this.escapeHtml(this.t('rec.runTwoScans'))}</p>
                    </div>
                `;
                return;
            }
            const blocks = [];
            if (diff.new.length) {
                blocks.push(this.diffBlock(this.t('rec.newDevices'), 'success', diff.new.map(d =>
                    `${this.escapeHtml(d.hostname || this.t('common.unknown'))} (${this.escapeHtml(d.ip)})`)));
            }
            if (diff.disappeared.length) {
                blocks.push(this.diffBlock(this.t('rec.devicesGone'), 'warning', diff.disappeared.map(d =>
                    `${this.escapeHtml(d.hostname || this.t('common.unknown'))} (${this.escapeHtml(d.ip)})`)));
            }
            if (diff.ports_opened.length) {
                blocks.push(this.diffBlock(this.t('rec.portsOpened'), 'danger', diff.ports_opened.map(e =>
                    this.t('rec.portOn', { 0: this.escapeHtml(e.port), 1: this.escapeHtml(e.ip) }))));
            }
            if (diff.ports_closed.length) {
                blocks.push(this.diffBlock(this.t('rec.portsClosed'), 'info', diff.ports_closed.map(e =>
                    this.t('rec.portOn', { 0: this.escapeHtml(e.port), 1: this.escapeHtml(e.ip) }))));
            }
            if (!blocks.length) {
                container.innerHTML = `
                    <div class="no-data">
                        <i class="fas fa-check-circle"></i>
                        <p>${this.escapeHtml(this.t('rec.noChanges'))}</p>
                    </div>
                `;
            } else {
                container.innerHTML = blocks.join('');
            }
        } catch (error) {
            console.error('Error loading scan diff:', error);
        }
    }

    diffBlock(title, tone, items) {
        return `
            <div class="diff-group diff-${tone}">
                <div class="diff-title"><i class="fas fa-${tone === 'danger' ? 'exclamation-triangle' :
                    tone === 'success' ? 'plus-circle' :
                    tone === 'warning' ? 'minus-circle' : 'info-circle'}"></i>
                    ${title} (${items.length})</div>
                <ul class="diff-items">${items.map(i => `<li>${i}</li>`).join('')}</ul>
            </div>
        `;
    }

    async loadSniffStatus() {
        if (!window.app || !document.getElementById('sniff-live')) return;
        try {
            const response = await fetch(`${this.apiBaseUrl}/sniff/status`);
            const data = await response.json();
            const live = data.live;
            if (live && live.in_progress) {
                this.renderSniffLive(live);
                if (!this.sniffPolling) {
                    this.sniffPolling = true;
                    this.pollSniff();
                }
            } else if (live && live.finished && live.total_packets > 0 && !this.sniffPolling) {
                document.getElementById('sniff-result').innerHTML = '';
            }
        } catch (error) {
            console.error('Error loading sniff status:', error);
        }
    }

    async startSniff() {
        const duration = document.getElementById('sniff-duration').value;
        const btn = document.getElementById('sniff-start');
        btn.disabled = true;
        btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${this.escapeHtml(this.t('rec.capturing'))}`;
        document.getElementById('sniff-result').innerHTML = '';
        document.getElementById('sniff-live').style.display = 'block';
        document.getElementById('sniff-note').style.display = 'block';

        const doRequest = () => fetch(`${this.apiBaseUrl}/sniff/start?duration=${duration}`, { method: 'POST' });

        let response = await doRequest();
        if (response.status === 401 && this.getApiToken()) {
            response = await doRequest();
        }
        const data = await response.json().catch(() => ({}));

        if (response.status === 401) {
            this.showToast(this.t('toast.authRequired'), this.t('toast.loginToView'), 'error');
            btn.disabled = false;
            btn.innerHTML = `<i class="fas fa-play"></i> ${this.escapeHtml(this.t('rec.startCapture'))}`;
            return;
        }
        if (data.status === 'sniff_in_progress') {
            this.showToast(this.t('toast.scanAlreadyRunning'), this.t('toast.scanInProgress'), 'info');
        } else {
            this.showToast(this.t('rec.trafficSniffer'), this.t('rec.captureFor', { 0: this.escapeHtml(duration) }), 'info');
        }

        this.sniffPolling = true;
        this.lastSniffToast = false;
        this.pollSniff(duration);
    }

    async pollSniff() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/sniff/status`);
            const data = await response.json();
            const live = data.live;
            if (!live || live.finished) {
                this.sniffPolling = false;
                this.finishSniff();
                return;
            }
            this.renderSniffLive(live);
        } catch (e) {
            // transient error - keep polling
        } finally {
            if (this.sniffPolling) {
                setTimeout(() => this.pollSniff(), 1000);
            }
        }
    }

    renderSniffLive(live) {
        const packets = document.getElementById('sniff-packets');
        const bytes = document.getElementById('sniff-bytes');
        const rate = document.getElementById('sniff-rate');
        const progress = document.getElementById('sniff-progress');
        if (packets) packets.textContent = live.total_packets.toLocaleString();
        if (bytes) bytes.textContent = this.formatBytes(live.total_bytes);
        if (rate) rate.textContent = this.formatBits(live.rate_bps) + '/s';
        if (progress) progress.style.width = `${live.progress}%`;
    }

    formatBytes(n) {
        if (!n) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        let i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
        return `${n.toFixed(1)} ${units[i]}`;
    }

    formatBits(bytesPerSec) {
        const bits = bytesPerSec * 8;
        if (bits >= 1000000) return `${(bits / 1000000).toFixed(2)} Mbps`;
        if (bits >= 1000) return `${(bits / 1000).toFixed(1)} Kbps`;
        return `${bits.toFixed(0)} bps`;
    }

    async finishSniff() {
        const btn = document.getElementById('sniff-start');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fas fa-play"></i> ${this.escapeHtml(this.t('rec.startCapture'))}`;
        }
        try {
            const response = await fetch(`${this.apiBaseUrl}/sniff/result`);
            if (response.status === 401) {
                this.showToast(this.t('toast.authRequired'), this.t('toast.loginToView'), 'error');
                return;
            }
            const data = await response.json();
            this.renderSniffResult(data.result);
            if (data.result && data.result.error) {
                this.showToast(this.t('rec.trafficSniffer'), data.result.error, 'warning');
            }
        } catch (error) {
            console.error('Error loading sniff result:', error);
        }
    }

    renderSniffResult(result) {
        const container = document.getElementById('sniff-result');
        if (!result) {
            container.innerHTML = `
                <div class="no-data"><i class="fas fa-info-circle"></i>
                    <p>${this.escapeHtml(this.t('rec.noResults'))}</p></div>
            `;
            return;
        }
        if (result.error && !result.total_packets) {
            container.innerHTML = `
                <div class="sniff-error"><i class="fas fa-exclamation-circle"></i>
                    ${this.escapeHtml(result.error)}</div>
            `;
            return;
        }
        const t = (k, v) => this.t(k, v);
        const protoRows = (result.protocols || []).map(p => `
            <tr>
                <td><strong>${this.escapeHtml(p.protocol)}</strong></td>
                <td>${p.packets.toLocaleString()}</td>
                <td>${this.formatBytes(p.bytes)}</td>
            </tr>
        `).join('');
        const talkerRows = (result.top_talkers || []).map(tl => `
            <tr>
                <td><code>${this.escapeHtml(tl.src)}</code></td>
                <td><i class="fas fa-arrow-right"></i> <code>${this.escapeHtml(tl.dst)}</code></td>
                <td>${tl.packets.toLocaleString()}</td>
                <td>${this.formatBytes(tl.bytes)}</td>
            </tr>
        `).join('');
        container.innerHTML = `
            <div class="sniff-summary">
                <span>${this.escapeHtml(t('rec.sniffCaptured', {
                    0: result.total_packets.toLocaleString(),
                    1: this.formatBytes(result.total_bytes),
                    2: (result.iface || 'auto'),
                    3: result.duration
                }))}</span>
            </div>
            <div class="sniff-tables">
                <div>
                    <h4>${this.escapeHtml(t('rec.protocols'))}</h4>
                    <table class="sniff-table">
                        <thead><tr><th>${this.escapeHtml(t('rec.protocols'))}</th><th>${this.escapeHtml(t('rec.packets'))}</th><th>${this.escapeHtml(t('rec.bytes'))}</th></tr></thead>
                        <tbody>${protoRows || `<tr><td colspan="3">${this.escapeHtml(t('rec.noTraffic'))}</td></tr>`}</tbody>
                    </table>
                </div>
                <div>
                    <h4>${this.escapeHtml(t('rec.topTalkers'))}</h4>
                    <table class="sniff-table">
                        <thead><tr><th>${this.escapeHtml(t('rec.source'))}</th><th></th><th>${this.escapeHtml(t('rec.destination'))}</th><th>${this.escapeHtml(t('rec.packets'))}</th><th>${this.escapeHtml(t('rec.bytes'))}</th></tr></thead>
                        <tbody>${talkerRows || `<tr><td colspan="5">${this.escapeHtml(t('rec.noTraffic'))}</td></tr>`}</tbody>
                    </table>
                </div>
            </div>
        `;
    }

    async loadHistory() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/history`);
            const data = await response.json();
            if (window.renderHistoryChart) {
                window.renderHistoryChart(data.history || []);
            }
        } catch (error) {
            console.error('Error loading history:', error);
        }
    }

    updateCurrentTime() {
        const now = new Date();
        document.getElementById('current-time').textContent =
            now.toLocaleString(this.locale(), {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
    }

    async loadInitialData() {
        await Promise.all([
            this.loadDevices(),
            this.loadAlerts(),
            this.loadSystemStats(),
            this.loadAuthorizedDevices(),
            this.loadScanStatus()
        ]);
    }

    async startScan() {
        const scanBtn = document.getElementById('scan-btn');
        const originalText = scanBtn.innerHTML;

        scanBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${this.escapeHtml(this.t('rec.capturing'))}`;
        scanBtn.disabled = true;

        try {
            const response = await fetch(`${this.apiBaseUrl}/scan`);
            const data = await response.json();

            if (data.status === 'scan_in_progress') {
                this.showToast(this.t('toast.scanAlreadyRunning'), this.t('toast.scanInProgress'), 'info');
                scanBtn.innerHTML = originalText;
                scanBtn.disabled = false;
                return;
            }

            if (data.status === 'scan_started') {
                this.showToast(this.t('toast.scanStarted'), this.t('toast.scanInitiated'), 'info');
            }

            // Poll for actual scan completion instead of guessing a fixed delay
            await this.waitForScanComplete();
            await Promise.all([
                this.loadDevices(),
                this.loadAlerts(),
                this.loadSystemStats(),
                this.loadScanStatus(),
                this.loadHistory(),
                this.loadScanDiff()
            ]);
            this.showToast(this.t('toast.scanComplete'), this.t('toast.scanFinished'), 'success');
        } catch (error) {
            console.error('Scan error:', error);
            this.showToast(this.t('toast.scanFailed'), this.t('toast.scanFailedMsg'), 'error');
        } finally {
            scanBtn.innerHTML = originalText;
            scanBtn.disabled = false;
        }
    }

    async waitForScanComplete(timeoutMs = 300000) {
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
            try {
                const response = await fetch(`${this.apiBaseUrl}/status`);
                const status = await response.json();
                if (!status.scan_in_progress) return;
            } catch (e) {
                // ignore transient errors and keep polling
            }
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }

    async loadScanStatus() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/status`);
            const status = await response.json();
            if (status.last_scan) {
                document.getElementById('last-scan-time').textContent =
                    new Date(status.last_scan).toLocaleString(this.locale());
            } else {
                document.getElementById('last-scan-time').textContent = this.t('nav.neverScanned');
            }
            const subnetEl = document.getElementById('current-subnet');
            if (subnetEl) {
                subnetEl.textContent = status.subnet ? this.t('nav.subnet', { 0: status.subnet }) : this.t('nav.subnetDetecting');
            }
            this.gateway = status.gateway || null;
            this.snifferAvailable = !!status.sniffer_available;
        } catch (error) {
            console.error('Error loading scan status:', error);
        }
    }

    toggleAutoScan() {
        const autoScanBtn = document.getElementById('auto-scan-btn');

        if (this.autoScanEnabled) {
            clearInterval(this.autoScanInterval);
            this.autoScanInterval = null;
            this.autoScanEnabled = false;
            autoScanBtn.innerHTML = '<i class="fas fa-sync-alt"></i>';
            autoScanBtn.title = this.t('header.autoScan');
            autoScanBtn.classList.remove('scanning');
            this.showToast(this.t('toast.autoScanOff'), this.t('toast.autoScanOffMsg'), 'info');
        } else {
            this.autoScanEnabled = true;
            autoScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
            autoScanBtn.title = this.t('header.autoScan');
            autoScanBtn.classList.add('scanning');

            // Start scan immediately
            this.startScan();

            // Then scan every 60 seconds
            this.autoScanInterval = setInterval(() => this.startScan(), 60000);

            this.showToast(this.t('toast.autoScanOn'), this.t('toast.autoScanOnMsg'), 'success');
        }
    }

    async loadDevices() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/devices`);
            const data = await response.json();

            this.lastDevices = data.devices || [];
            this.displayDevices(this.lastDevices);
            this.updateStats(this.lastDevices);
            if (window.renderCharts) window.renderCharts(this.lastDevices);
            if (window.renderTopology) window.renderTopology(this.lastDevices, this.gateway || null);
        } catch (error) {
            console.error('Error loading devices:', error);
            this.showToast(this.t('toast.loadFailed'), this.t('toast.unableLoadDevices'), 'error');
        }
    }

    displayDevices(devices) {
        const tbody = document.getElementById('devices-body');
        tbody.innerHTML = '';
        const isAdmin = this.role === 'admin';

        if (!devices || devices.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center">
                        <div class="no-data">
                            <i class="fas fa-search"></i>
                            <p>${this.escapeHtml(this.t('devices.noDevices'))}</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        devices.forEach(device => {
            const row = document.createElement('tr');
            const ip = this.escapeHtml(device.ip);
            const mac = this.escapeHtml(device.mac);
            const hostname = this.escapeHtml(device.hostname || this.t('common.unknown'));
            const vendor = this.escapeHtml(device.vendor);

            const ports = device.open_ports && device.open_ports.length > 0
                ? device.open_ports.map(port =>
                    `<span class="port-badge ${this.isRiskyPort(port) ? 'risky' : ''}" data-ip="${ip}" data-port="${port}">
                        ${port}
                     </span>`
                  ).join(' ')
                : `<span class="text-muted">${this.escapeHtml(this.t('devices.none'))}</span>`;

            const authorizeBtn = isAdmin
                ? (!device.is_authorized
                    ? `<button class="action-btn" data-action="authorize" data-ip="${ip}" data-mac="${mac}" title="${this.escapeHtml(this.t('modal.authorizeDevice'))}">
                         <i class="fas fa-check"></i>
                       </button>`
                    : `<button class="action-btn danger" data-action="unauthorize" data-mac="${mac}" title="${this.escapeHtml(this.t('modal.unauthorizeDevice'))}">
                         <i class="fas fa-times"></i>
                       </button>`)
                : '';

            row.innerHTML = `
                <td>
                    <span class="${device.is_authorized ? 'status-authorized' : 'status-unauthorized'}">
                        <i class="fas fa-${device.is_authorized ? 'check-circle' : 'exclamation-triangle'}"></i>
                        ${device.is_authorized ? this.escapeHtml(this.t('status.authorized')) : this.escapeHtml(this.t('status.unauthorized'))}
                    </span>
                </td>
                <td><strong>${ip}</strong></td>
                <td><code>${mac}</code></td>
                <td>${hostname}</td>
                <td>${vendor}${device.device_type ? ` <small class="device-type-badge">${this.escapeHtml(device.device_type)}</small>` : ''}</td>
                <td>${ports}</td>
                <td>
                    <div class="action-buttons">
                        <button class="action-btn" data-action="details" data-ip="${ip}" title="${this.escapeHtml(this.t('modal.deviceDetails'))}">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="action-btn" data-action="ports" data-ip="${ip}" title="${this.escapeHtml(this.t('ports.portDetails'))}">
                            <i class="fas fa-plug"></i>
                        </button>
                        ${authorizeBtn}
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    isRiskyPort(port) {
        const highRiskPorts = [23, 21, 139, 445, 135, 3389];
        const warningPorts = [8080, 8888, 9000, 3000];
        return highRiskPorts.includes(port) || warningPorts.includes(port);
    }

    async showDeviceDetails(ip) {
        const devices = await this.fetchDevices();
        const device = devices.find(d => d.ip === ip);

        if (device) {
            const advice = await this.fetchAdvice(ip);
            const escIp = this.escapeHtml(device.ip);
            const escMac = this.escapeHtml(device.mac);
            const escHostname = this.escapeHtml(device.hostname || this.t('common.unknown'));
            const escVendor = this.escapeHtml(device.vendor);
            const isAdmin = this.role === 'admin';

            const body = document.getElementById('device-modal-body');
            body.innerHTML = `
                <div class="device-details">
                    <div class="detail-row">
                        <span class="detail-label">${this.escapeHtml(this.t('modal.ipAddress'))}</span>
                        <span class="detail-value">${escIp}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">${this.escapeHtml(this.t('modal.macAddress'))}</span>
                        <span class="detail-value">${escMac}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">${this.escapeHtml(this.t('modal.hostname'))}</span>
                        <span class="detail-value">${escHostname}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">${this.escapeHtml(this.t('modal.vendor'))}</span>
                        <span class="detail-value">${escVendor}${device.device_type ? ` <small class="device-type-badge">${this.escapeHtml(device.device_type)}</small>` : ''}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">${this.escapeHtml(this.t('modal.status'))}</span>
                        <span class="${device.is_authorized ? 'status-authorized' : 'status-unauthorized'}">
                            ${device.is_authorized ? this.escapeHtml(this.t('status.authorized')) : this.escapeHtml(this.t('status.unauthorized'))}
                        </span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">${this.escapeHtml(this.t('modal.lastSeen'))}</span>
                        <span class="detail-value">${new Date(device.last_seen).toLocaleString(this.locale())}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">${this.escapeHtml(this.t('modal.openPorts'))}</span>
                        <span class="detail-value">
                            ${device.open_ports && device.open_ports.length > 0
                                ? device.open_ports.map(p => this.escapeHtml(p)).join(', ')
                                : this.escapeHtml(this.t('devices.none'))}
                        </span>
                    </div>

                    ${advice.length > 0 ? `
                        <div class="security-advice">
                            <h4>${this.escapeHtml(this.t('modal.securityRec'))}</h4>
                            <ul>
                                ${advice.map(item => `<li>${this.escapeHtml(item)}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}

                    <div class="detail-row modal-tool-row">
                        <button class="btn btn-sm" data-action="cves" data-ip="${escIp}">
                            <i class="fas fa-bug"></i> ${this.escapeHtml(this.t('modal.viewCves'))}
                        </button>
                        <button class="btn btn-sm" data-action="os" data-ip="${escIp}">
                            <i class="fas fa-desktop"></i> ${this.escapeHtml(this.t('modal.detectOs'))}
                        </button>
                    </div>
                    <div class="modal-sub-area" id="device-cves-area"></div>
                    <div class="modal-sub-area" id="device-os-area"></div>

                    <div class="modal-actions">
                        <button class="btn btn-primary" data-action="ports" data-ip="${escIp}">
                            <i class="fas fa-plug"></i> ${this.escapeHtml(this.t('modal.viewPortDetails'))}
                        </button>
                        ${isAdmin ? (!device.is_authorized
                            ? `<button class="btn btn-success" data-action="authorize" data-mac="${escMac}" data-ip="${escIp}">
                                 <i class="fas fa-check"></i> ${this.escapeHtml(this.t('modal.authorizeDevice'))}
                               </button>`
                            : `<button class="btn btn-danger" data-action="unauthorize" data-mac="${escMac}">
                                 <i class="fas fa-times"></i> ${this.escapeHtml(this.t('modal.unauthorizeDevice'))}
                               </button>`)
                        : ''}
                    </div>
                </div>
            `;

            this.showModal();
        }
    }

    async loadDeviceCves(ip) {
        const area = document.getElementById('device-cves-area');
        if (!area) return;
        area.innerHTML = `
            <div class="no-data"><i class="fas fa-spinner fa-spin"></i>
                <p>${this.escapeHtml(this.t('modal.checkingCves'))}</p></div>
        `;
        try {
            const response = await fetch(`${this.apiBaseUrl}/device/${encodeURIComponent(ip)}/cves`);
            if (response.status === 404) {
                area.innerHTML = '';
                return;
            }
            const data = await response.json();
            const rows = data.cves || [];
            if (!rows.length) {
                area.innerHTML = `
                    <div class="no-data"><i class="fas fa-thumbs-up"></i>
                        <p>${this.escapeHtml(this.t('modal.noCves'))}</p></div>
                `;
                return;
            }
            const sourceLabel = this.escapeHtml(this.t(data.source === 'live' ? 'modal.live' : 'modal.cache'));
            const html = rows.map(c => `
                <tr>
                    <td><code>${this.escapeHtml(c.cve_id)}</code></td>
                    <td>${this.escapeHtml(c.port)}</td>
                    <td>${this.escapeHtml(c.service)}</td>
                    <td>${this.escapeHtml(c.version || '-')}</td>
                    <td>${c.cvss != null ? this.escapeHtml(c.cvss) : '-'}</td>
                    <td>${this.escapeHtml(c.summary || '')}</td>
                </tr>
            `).join('');
            area.innerHTML = `
                <div class="cve-header">
                    <strong><i class="fas fa-bug"></i> ${this.escapeHtml(this.t('modal.viewCves'))}</strong>
                    <span class="source-badge">${sourceLabel}</span>
                </div>
                <table class="cve-table">
                    <thead><tr>
                        <th>${this.escapeHtml(this.t('cve.id'))}</th>
                        <th>${this.escapeHtml(this.t('cve.port'))}</th>
                        <th>${this.escapeHtml(this.t('cve.service'))}</th>
                        <th>${this.escapeHtml(this.t('cve.version'))}</th>
                        <th>${this.escapeHtml(this.t('cve.cvss'))}</th>
                        <th>${this.escapeHtml(this.t('cve.summary'))}</th>
                    </tr></thead>
                    <tbody>${html}</tbody>
                </table>
            `;
        } catch (error) {
            console.error('Error loading CVEs:', error);
            area.innerHTML = '';
        }
    }

    async detectDeviceOs(ip) {
        const area = document.getElementById('device-os-area');
        if (!area) return;
        area.innerHTML = `
            <div class="no-data"><i class="fas fa-spinner fa-spin"></i>
                <p>${this.escapeHtml(this.t('modal.detectingOs'))}</p></div>
        `;
        try {
            const response = await fetch(`${this.apiBaseUrl}/device/${encodeURIComponent(ip)}/os`);
            if (response.status === 404) {
                area.innerHTML = '';
                return;
            }
            const data = await response.json();
            const os = data.os;
            if (!os || !os.os_name) {
                area.innerHTML = `
                    <div class="no-data"><i class="fas fa-question-circle"></i>
                        <p>${this.escapeHtml(this.t('modal.osUnknown'))}</p></div>
                `;
                return;
            }
            const sourceLabel = this.escapeHtml(this.t(data.source === 'live' ? 'modal.live' : 'modal.cache'));
            area.innerHTML = `
                <div class="os-result">
                    <i class="fas fa-tv"></i>
                    <span class="os-acc">${this.escapeHtml(this.t('modal.osResult', { 0: os.os_name, 1: os.accuracy || 0 }))}</span>
                    <span class="source-badge">${sourceLabel}</span>
                </div>
            `;
        } catch (error) {
            console.error('Error detecting OS:', error);
            area.innerHTML = '';
        }
    }

    async showPortDetails(ip, specificPort = null) {
        try {
            document.getElementById('selected-device-ip').textContent = ip;

            const response = await fetch(`${this.apiBaseUrl}/device/${encodeURIComponent(ip)}/ports`);
            const data = await response.json();

            const tbody = document.getElementById('ports-body');
            tbody.innerHTML = '';

            if (data.ports && data.ports.length > 0) {
                data.ports
                    .filter(port => !specificPort || port.port === specificPort)
                    .forEach(port => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td><strong>${this.escapeHtml(port.port)}</strong></td>
                            <td>${this.escapeHtml(port.service)}</td>
                            <td>
                                <span class="status-${port.state === 'open' ? 'authorized' : 'unauthorized'}">
                                    ${this.escapeHtml(port.state)}
                                </span>
                            </td>
                            <td>${this.escapeHtml(port.version || this.t('ports.unknown'))}</td>
                            <td>
                                <span class="risk-${this.escapeHtml(port.risk_level)}">
                                    ${this.escapeHtml(port.risk_level.toUpperCase())}
                                </span>
                            </td>
                            <td>
                                <button class="btn btn-sm" data-action="advice" data-port="${port.port}" data-service="${this.escapeHtml(port.service)}">
                                    <i class="fas fa-lightbulb"></i> Advice
                                </button>
                            </td>
                        `;
                        tbody.appendChild(row);
                    });

                document.getElementById('ports').style.display = 'block';
                document.getElementById('ports').scrollIntoView({ behavior: 'smooth', block: 'start' });

                if (specificPort) {
                    const port = data.ports.find(p => p.port === specificPort);
                    this.getPortAdvice(specificPort, port ? port.service : '');
                }
            } else {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="text-center">
                            <div class="no-data">
                                <i class="fas fa-info-circle"></i>
                                <p>${this.escapeHtml(this.t('ports.noOpenPorts'))}</p>
                            </div>
                        </td>
                    </tr>
                `;
                document.getElementById('ports').style.display = 'block';
                document.getElementById('ports').scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        } catch (error) {
            console.error('Error loading port details:', error);
            this.showToast(this.t('toast.error'), this.t('toast.portDetailsError'), 'error');
        }
    }

    hidePortDetails() {
        document.getElementById('ports').style.display = 'none';
    }

    async authorizeDevice(mac, ip, btn = null) {
        const doRequest = async () => {
            const response = await this.apiFetch(
                `/device/${encodeURIComponent(mac)}/authorize`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, hostname: 'Unknown' })
                }
            );
            return response;
        };

        let response = await doRequest();
        if (response.status === 401) {
            const token = this.setApiToken();
            if (!token) return;
            response = await doRequest();
        }

        if (response.ok) {
            this.showToast(this.t('toast.deviceAuthorized'), this.t('toast.deviceAuthorizedMsg'), 'success');
            this.loadDevices();
            this.loadAlerts();
            this.loadAuthorizedDevices();
        } else if (response.status === 401) {
            this.showToast(this.t('toast.authRequired'), this.t('toast.invalidToken'), 'error');
        } else {
            this.showToast(this.t('toast.error'), this.t('toast.unableAuthorize'), 'error');
        }
    }

    async unauthorizeDevice(mac) {
        const doRequest = async () => {
            const response = await this.apiFetch(
                `/device/${encodeURIComponent(mac)}/unauthorize`,
                { method: 'POST' }
            );
            return response;
        };

        let response = await doRequest();
        if (response.status === 401) {
            const token = this.setApiToken();
            if (!token) return;
            response = await doRequest();
        }

        if (response.ok) {
            this.showToast(this.t('toast.deviceUnauthorized'), this.t('toast.deviceUnauthorizedMsg'), 'warning');
            this.loadDevices();
            this.loadAlerts();
            this.loadAuthorizedDevices();
        } else if (response.status === 401) {
            this.showToast(this.t('toast.authRequired'), this.t('toast.invalidToken'), 'error');
        } else {
            this.showToast(this.t('toast.error'), this.t('toast.unableUnauthorize'), 'error');
        }
    }

    async loadAlerts() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/alerts`);
            const data = await response.json();

            this.displayAlerts(data.alerts);
            this.updateAlertStats(data.alerts);
        } catch (error) {
            console.error('Error loading alerts:', error);
        }
    }

    displayAlerts(alerts) {
        const container = document.getElementById('alerts-list');

        if (!alerts || alerts.length === 0) {
            container.innerHTML = `
                <div class="no-data">
                    <i class="fas fa-check-circle"></i>
                    <p>${this.escapeHtml(this.t('alerts.noAlerts'))}</p>
                </div>
            `;
            return;
        }

        container.innerHTML = alerts.map(alert => `
            <div class="alert-item">
                <div class="alert-header">
                    <div class="alert-title">
                        <i class="fas fa-${alert.severity === 'high' ? 'exclamation-triangle text-danger' : 'exclamation-circle text-warning'}"></i>
                        ${this.escapeHtml(alert.type.replace('_', ' ').toUpperCase())}
                    </div>
                    <div class="alert-time">${new Date(alert.timestamp).toLocaleTimeString()}</div>
                </div>
                <div class="alert-message">${this.escapeHtml(alert.message)}</div>
                ${alert.device_ip ? `<div class="alert-device">${this.escapeHtml(this.t('alerts.device', { 0: alert.device_ip }))}</div>` : ''}
            </div>
        `).join('');
    }

    async loadSystemStats() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/stats`);
            const data = await response.json();

            if (data.system) {
                document.getElementById('cpu-usage').textContent = data.system.cpu_percent.toFixed(1);
                document.getElementById('memory-usage').textContent = data.system.memory_percent.toFixed(1);
            }

            if (data.security_report) {
                this.updateSecurityScore(data.security_report);
            }
        } catch (error) {
            console.error('Error loading system stats:', error);
        }
    }

    updateStats(devices) {
        const totalDevices = devices.length;
        const unauthorizedDevices = devices.filter(d => !d.is_authorized).length;
        const totalPorts = devices.reduce((sum, device) => sum + (device.open_ports?.length || 0), 0);
        const riskyPorts = devices.reduce((sum, device) => {
            return sum + (device.open_ports?.filter(port => this.isRiskyPort(port)).length || 0);
        }, 0);

        this.animateNumber(document.getElementById('total-devices'), totalDevices);
        document.getElementById('unauthorized-devices').textContent = this.t('stats.unauthorizedCount', { 0: unauthorizedDevices });
        this.animateNumber(document.getElementById('total-ports'), totalPorts);
        document.getElementById('risky-ports').textContent = this.t('stats.riskyPorts', { 0: riskyPorts });
    }

    updateAlertStats(alerts) {
        const totalAlerts = alerts.length;
        const highAlerts = alerts.filter(a => a.severity === 'high').length;

        this.animateNumber(document.getElementById('total-alerts'), totalAlerts);
        document.getElementById('high-alerts').textContent = this.t('stats.highRisk', { 0: highAlerts });
        document.getElementById('alerts-count').textContent = totalAlerts;
    }

    updateSecurityScore(report) {
        const scoreElement = document.getElementById('security-score');
        const riskLevelElement = document.getElementById('risk-level');

        // Use the backend-computed score/risk so frontend and backend agree
        const score = report.security_score ?? 100;
        const riskLevel = report.risk_assessment ?? 'low';
        const cssLevel = ['critical', 'high', 'medium', 'low'].includes(riskLevel) ? riskLevel : 'low';

        scoreElement.textContent = score;
        scoreElement.className = `security-score-display ${cssLevel}`;
        riskLevelElement.textContent = riskLevel.toUpperCase();
        riskLevelElement.className = `risk-${cssLevel}`;
    }

    async fetchDevices() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/devices`);
            const data = await response.json();
            return data.devices || [];
        } catch (error) {
            return [];
        }
    }

    async fetchAdvice(ip) {
        try {
            const response = await fetch(
                `${this.apiBaseUrl}/advice/${encodeURIComponent(ip)}`
            );
            const data = await response.json();
            return data.advice || [];
        } catch (error) {
            return [];
        }
    }

    async getPortAdvice(port, service) {
        const advice = {
            22: [
                "Use SSH key authentication instead of passwords",
                "Change default SSH port (22) to a non-standard port",
                "Implement fail2ban to prevent brute force attacks",
                "Disable root login over SSH"
            ],
            23: [
                "Telnet transmits passwords in clear text - DISABLE IMMEDIATELY",
                "Use SSH instead for secure remote access",
                "If Telnet is absolutely necessary, restrict to specific IPs"
            ],
            80: [
                "Redirect HTTP to HTTPS",
                "Implement security headers (HSTS, CSP)",
                "Use a Web Application Firewall (WAF)",
                "Regularly update web server software"
            ],
            443: [
                "Use strong TLS configurations (TLS 1.2+)",
                "Regular SSL certificate renewal",
                "Implement HSTS (HTTP Strict Transport Security)",
                "Disable weak ciphers and protocols"
            ],
            3389: [
                "Restrict RDP access to specific IP addresses",
                "Use Network Level Authentication (NLA)",
                "Consider using VPN instead of open RDP",
                "Implement account lockout policies"
            ]
        };

        const portAdvice = advice[port] || [
            "Regularly update the service running on this port",
            "Restrict access to necessary IP addresses only",
            "Monitor for unusual traffic on this port",
            "Consider closing if not essential"
        ];

        this.showToast(`${this.escapeHtml(this.t('ports.portDetails'))} ${port} (${this.escapeHtml(service)})`, portAdvice[0], 'info');

        // Display all advice in security recommendations section
        const adviceContainer = document.getElementById('security-advice');
        adviceContainer.innerHTML = `
            <div class="advice-item">
                <h4>${this.escapeHtml(this.t('rec.adviceForPort', { 0: port, 1: service }))}</h4>
                <ul>
                    ${portAdvice.map(item => `<li>${this.escapeHtml(item)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    async loadAuthorizedDevices() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/authorized-devices`);
            const data = await response.json();
            this.displayAuthorizedDevices(data.devices || []);
        } catch (error) {
            console.error('Error loading authorized devices:', error);
        }
    }

    displayAuthorizedDevices(devices) {
        const container = document.getElementById('authorized-devices-list');
        if (!container) return;
        const isAdmin = this.role === 'admin';

        if (!devices || devices.length === 0) {
            container.innerHTML = `
                <div class="no-data">
                    <i class="fas fa-info-circle"></i>
                    <p>No authorized devices configured yet.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = devices.map(device => `
            <div class="authorized-device">
                <div class="authorized-device-info">
                    <strong>${this.escapeHtml(device.hostname || 'Unknown')}</strong>
                    <span>${this.escapeHtml(device.ip || '')}</span>
                    <code>${this.escapeHtml(device.mac)}</code>
                </div>
                ${isAdmin ? `
                <button class="btn btn-sm btn-danger" data-action="unauthorize" data-mac="${this.escapeHtml(device.mac)}">
                    <i class="fas fa-times"></i> Remove
                </button>` : ''}
            </div>
        `).join('');

        // Wire up remove buttons
        container.querySelectorAll('button[data-action="unauthorize"]').forEach(btn => {
            btn.addEventListener('click', () => this.unauthorizeDevice(btn.dataset.mac));
        });
    }

    showModal() {
        document.getElementById('device-modal').style.display = 'flex';
    }

    hideModal() {
        document.getElementById('device-modal').style.display = 'none';
    }

    showToast(title, message, type = 'info') {
        const toastContainer = document.querySelector('.toast-container') || this.createToastContainer();

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-icon">
                <i class="fas fa-${type === 'success' ? 'check-circle' :
                    type === 'error' ? 'exclamation-circle' :
                    type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
            </div>
            <div class="toast-content">
                <div class="toast-title">${this.escapeHtml(title)}</div>
                <div class="toast-message">${this.escapeHtml(message)}</div>
            </div>
            <button class="toast-close" type="button" aria-label="Dismiss">
                <span aria-hidden="true">&times;</span>
            </button>
            <div class="toast-progress"></div>
        `;

        toastContainer.appendChild(toast);

        // --- Robust close handling -------------------------------------
        // Previously this relied on an inline onclick="this.parentElement.remove()"
        // attribute, which could silently fail to fire (or fire on the wrong
        // element after re-renders) and left toasts stuck on screen forever.
        // We now bind a real listener, guard against double-firing, and always
        // fall back to a hard removal even if the CSS exit animation never runs
        // (e.g. reduced-motion users, or the tab being backgrounded).
        const DURATION = 5000;
        let remaining = DURATION;
        let startedAt = Date.now();
        let timer = null;

        const dismiss = () => {
            if (toast.dataset.closing === 'true') return;
            toast.dataset.closing = 'true';
            clearTimeout(timer);
            toast.classList.add('toast-closing');
            toast.addEventListener('animationend', () => toast.remove(), { once: true });
            // Hard fallback in case the animation never fires.
            setTimeout(() => {
                if (toast.parentElement) toast.remove();
            }, 400);
        };

        const scheduleAutoDismiss = () => {
            startedAt = Date.now();
            timer = setTimeout(dismiss, remaining);
            const progressEl = toast.querySelector('.toast-progress');
            if (progressEl) progressEl.style.animationPlayState = 'running';
        };

        const pauseAutoDismiss = () => {
            clearTimeout(timer);
            remaining = Math.max(0, remaining - (Date.now() - startedAt));
            const progressEl = toast.querySelector('.toast-progress');
            if (progressEl) progressEl.style.animationPlayState = 'paused';
        };

        toast.querySelector('.toast-close').addEventListener('click', dismiss);
        toast.addEventListener('mouseenter', pauseAutoDismiss);
        toast.addEventListener('mouseleave', scheduleAutoDismiss);

        const progressEl = toast.querySelector('.toast-progress');
        if (progressEl) progressEl.style.animationDuration = `${DURATION}ms`;
        scheduleAutoDismiss();

        return toast;
    }

    createToastContainer() {
        const container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
        return container;
    }
}

// Initialize the app when DOM is loaded
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new SecurityMonitorApp();
    window.app = app; // Make app available globally for onclick handlers
});