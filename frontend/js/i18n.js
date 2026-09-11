// Internationalization (EN/AR) + theme toggle for CyberGuard
(function () {
    'use strict';

    const dict = {
        en: {
            'nav.dashboard': 'Dashboard',
            'nav.devices': 'Devices',
            'nav.topology': 'Topology',
            'nav.ports': 'Ports',
            'nav.alerts': 'Alerts',
            'nav.reports': 'Reports',
            'nav.systemStatus': 'System Status',
            'nav.monitoringActive': 'Monitoring Active',
            'nav.neverScanned': 'Never scanned',
            'nav.subnet': 'Subnet: {0}',
            'nav.subnetDetecting': 'Subnet: detecting...',

            'header.securityDashboard': 'Security Dashboard',
            'header.scanNetwork': 'Scan Network',
            'header.autoScan': 'Auto Scan',
            'header.logout': 'Logout',
            'header.login': 'Login',
            'header.guest': 'Guest',

            'stats.devices': 'Devices',
            'stats.alerts': 'Alerts',
            'stats.openPorts': 'Open Ports',
            'stats.securityScore': 'Security Score',
            'stats.unauthorizedCount': '{0} unauthorized',
            'stats.highRisk': '{0} high risk',
            'stats.riskyPorts': '{0} risky',
            'stats.noData': 'No data',

            'charts.deviceAuth': 'Device Authorization',
            'charts.portRisk': 'Port Risk Distribution',
            'charts.authorized': 'Authorized',
            'charts.unauthorized': 'Unauthorized',
            'charts.highRisk': 'High Risk',
            'charts.mediumRisk': 'Medium Risk',
            'charts.lowRisk': 'Low Risk',
            'charts.openPorts': 'Open ports',
            'charts.devices': 'Devices',

            'topology.networkTopology': 'Network Topology',
            'topology.gateway': 'Gateway',
            'topology.runScanMap': 'Run a network scan to populate the map',

            'devices.networkDevices': 'Network Devices',
            'devices.refresh': 'Refresh',
            'devices.status': 'Status',
            'devices.ipAddress': 'IP Address',
            'devices.macAddress': 'MAC Address',
            'devices.hostname': 'Hostname',
            'devices.vendor': 'Vendor',
            'devices.openPorts': 'Open Ports',
            'devices.actions': 'Actions',
            'devices.none': 'None',
            'devices.noDevices': 'No devices found. Run a network scan to discover devices.',

            'common.unknown': 'Unknown',

            'status.authorized': 'Authorized',
            'status.unauthorized': 'Unauthorized',

            'alerts.securityAlerts': 'Security Alerts',
            'alerts.noAlerts': 'No security alerts detected',
            'alerts.device': 'Device: {0}',

            'ports.portDetails': 'Port Details',
            'ports.port': 'Port',
            'ports.service': 'Service',
            'ports.state': 'State',
            'ports.version': 'Version',
            'ports.riskLevel': 'Risk Level',
            'ports.advice': 'Advice',
            'ports.noOpenPorts': 'No open ports found for this device.',
            'ports.unknown': 'Unknown',

            'rec.securityRecommendations': 'Security Recommendations',
            'rec.runScanForAdvice': 'Run a network scan to get security recommendations',
            'rec.scanHistory': 'Scan History',
            'rec.scanDiff': 'Scan-to-Scan Changes',
            'rec.runTwoScans': 'Run at least two scans to see what changed between them.',
            'rec.noChanges': 'No changes between the last two scans.',
            'rec.newDevices': 'New devices',
            'rec.devicesGone': 'Devices gone',
            'rec.portsOpened': 'Ports opened',
            'rec.portsClosed': 'Ports closed',
            'rec.portOn': 'Port {0} on {1}',
            'rec.exportReport': 'Export Report',
            'rec.exportCSV': 'Export CSV',
            'rec.exportJSON': 'Export JSON',
            'rec.exportHTML': 'Export HTML',
            'rec.exportPDF': 'Export PDF',
            'rec.trafficSniffer': 'Traffic Sniffer',
            'rec.sec': '{0} seconds',
            'rec.startCapture': 'Start Capture',
            'rec.capturing': 'Capturing...',
            'rec.packets': 'Packets',
            'rec.bytes': 'Bytes',
            'rec.rate': 'Rate',
            'rec.sniffNote': 'Capturing traffic requires administrator privileges and Npcap on Windows.',
            'rec.protocols': 'Protocols',
            'rec.topTalkers': 'Top Talkers',
            'rec.source': 'Source',
            'rec.destination': 'Destination',
            'rec.noTraffic': 'No traffic captured',
            'rec.noResults': 'No capture results yet.',
            'rec.captureFor': 'Capturing traffic for {0}s.',
            'rec.sniffCaptured': 'Captured {0} packets ({1}) on {2} over {3}s',

            'login.title': 'Welcome Back',
            'login.subtitle': 'Sign in to access your security dashboard',
            'login.username': 'Username',
            'login.password': 'Password',
            'login.invalid': 'Invalid credentials',
            'login.login': 'Sign In',
            'login.signingIn': 'Signing in...',
            'login.invalidToast': 'Invalid username or password.',
            'login.backHome': 'Back to Home',
            'login.welcome': 'Welcome, {0}',

            'landing.brand': 'CyberGuard',
            'landing.tagline': 'Your LAN\'s paranoid roommate',
            'landing.signIn': 'Sign In',
            'landing.getStarted': 'Launch Dashboard',
            'landing.badge': 'Live LAN monitoring',
            'landing.headline': 'Know every device on your network.',
            'landing.headlineAccent': 'Before they know you.',
            'landing.subtitle': 'CyberGuard stays up all night watching your LAN. Spotting rogue devices, open ports, and CVEs before they become headlines.',
            'landing.startFree': 'Open the Dashboard',
            'landing.watchDemo': 'How it works',
            'landing.trustedBy': 'Runs on a Raspberry Pi, a VPS, or that dusty laptop in the closet',
            'landing.devices': 'Devices tracked',
            'landing.alerts': 'Threats flagged',
            'landing.ports': 'Ports mapped',
            'landing.uptime': 'Uptime',
            'landing.scanSeconds': 'sec scan cycle',
            'landing.selfHosted': 'self-hosted',
            'landing.reportFormats': 'report formats',
            'landing.languages': 'languages',

            'landing.featuresTitle': 'Superpowers, included',
            'landing.featuresSubtitle': 'No plugins, no cloud, no setup theater. Just open the dashboard',
            'landing.f1.title': 'Continuous Scanning',
            'landing.f1.desc': 'Auto-discovers devices every 60 seconds using ARP plus an nmap fallback.',
            'landing.f2.title': 'Rogue Detection',
            'landing.f2.desc': 'Alerts you the second an unknown device, ARP spoof, or binding change appears.',
            'landing.f3.title': 'CVE Lookups',
            'landing.f3.desc': 'One-click vulnerability check per device with smart layered caching.',
            'landing.f4.title': 'OS Fingerprinting',
            'landing.f4.desc': 'Identifies the OS behind each IP with accuracy scores, cached for an hour.',
            'landing.f5.title': 'Multi-Channel Alerts',
            'landing.f5.desc': 'Telegram, Email (SMTP), and Webhooks. Delivered in parallel, best-effort.',
            'landing.f6.title': 'Professional Reports',
            'landing.f6.desc': 'Export CSV, JSON, HTML, or PDF with charts and advice baked in.',
            'landing.f7.title': 'AR/EN + Dark Mode',
            'landing.f7.desc': 'Full RTL support, instant language switch, persistent theme.',
            'landing.f8.title': 'Role-Based Access',
            'landing.f8.desc': 'Single admin account with full control. Session-based secure authentication.',

            'landing.stepsTitle': 'From clueless to covered',
            'landing.stepsSubtitle': 'Three moves and your network stops being a mystery',
            'landing.step1.title': 'Discover',
            'landing.step1.desc': 'ARP scan + nmap fallback maps every device, MAC, and open port on your LAN.',
            'landing.step2.title': 'Detect',
            'landing.step2.desc': 'Rogue devices, ARP spoofing, and port changes light up the alerts panel instantly.',
            'landing.step3.title': 'Protect',
            'landing.step3.desc': 'Authorize trusted hardware, look up CVEs, and export printable reports.',

            'landing.ctaTitle': 'Stop asking \'what\'s on my WiFi?\'',
            'landing.ctaSubtitle': 'Self-hosted. Private. Runs on a Raspberry Pi or a small VPS.',
            'landing.ctaButton': 'Open the Dashboard',
            'landing.ctaNote': 'No account needed to look. Sign in only when you want to manage.',

            'landing.footerDesc': 'The friend that watches your network at 3 AM so you can sleep.',
            'landing.product': 'Product',
            'landing.features': 'Features',
            'landing.dashboard': 'Dashboard',

            'lp.about.title': 'About CyberGuard',
            'lp.about.body': 'CyberGuard started with a question: why does network security need a PhD, a VPN subscription, and a weekend of YAML? So we built a self-hosted watchdog that scans your LAN on its own schedule, spots what changed, and tells you what matters in plain words.',
            'lp.about.c1': '0 cloud servers',
            'lp.about.c2': '60 sec scan cycles',
            'lp.about.c3': '1 dashboard',
            'lp.security.title': 'Security posture',
            'lp.security.body': 'Everything runs on your machine. Scans stay inside your LAN, the admin dashboard lives behind a signed session, and nothing phones home. If a feature needs admin rights, it asks for them; if it does not, it leaves your privileges alone.',
            'lp.security.c1': 'Session-based auth',
            'lp.security.c2': 'No telemetry',
            'lp.security.c3': 'Local SQLite only',
            'lp.privacy.title': 'Privacy promise',
            'lp.privacy.body': 'There is no data to sell, because nothing ever leaves home. The dashboard holds device IPs, MACs and ports for your own eyes only, and your preferences live in your browser, not on a server.',
            'lp.privacy.c1': 'Data stays local',
            'lp.privacy.c2': 'Anonymous usage',
            'lp.privacy.c3': 'The log is yours',
            'lp.docs.copyHint': 'Copy the clone command',
            'lp.docs.title': 'Quick start',
            'lp.docs.body': 'Self-hosted in one command. No accounts to create, no cloud to sync.',
            'lp.docs.c1': 'Self-hosted',
            'lp.docs.c2': 'No cloud',
            'lp.docs.c3': 'Open source',
            'landing.company': 'Company',
            'landing.about': 'About',
            'landing.security': 'Security',
            'landing.privacy': 'Privacy',
            'landing.resources': 'Resources',
            'landing.login': 'Login',
            'landing.github': 'GitHub',
            'landing.docs': 'Docs',
            'landing.backHome': 'Back to Home',
            'landing.copyright': '© 2026 CyberGuard. Self-hosted. Open source.',
            'landing.builtWith': 'Built with Python · Flask · Nmap · coffee'
            ,

            'modal.deviceDetails': 'Device Details',
            'modal.ipAddress': 'IP Address:',
            'modal.macAddress': 'MAC Address:',
            'modal.hostname': 'Hostname:',
            'modal.vendor': 'Vendor:',
            'modal.status': 'Status:',
            'modal.lastSeen': 'Last Seen:',
            'modal.openPorts': 'Open Ports:',
            'modal.securityRec': 'Security Recommendations:',
            'modal.viewPortDetails': 'View Port Details',
            'modal.authorizeDevice': 'Authorize Device',
            'modal.unauthorizeDevice': 'Unauthorize Device',
            'modal.viewCves': 'Known CVEs',
            'modal.detectOs': 'Detect OS',
            'modal.checkingCves': 'Checking for known CVEs...',
            'modal.noCves': 'No known CVEs found for this device.',
            'modal.detectingOs': 'Detecting operating system...',
            'modal.osResult': 'OS Detection: {0} (accuracy {1}%)',
            'modal.osMethod': 'via {0}',
            'modal.osUnknown': 'Operating system could not be identified.',
            'modal.live': 'live',
            'modal.cache': 'cache',
            'modal.fromCache': ' (from {0})',

            'cve.id': 'CVE',
            'cve.port': 'Port',
            'cve.service': 'Service',
            'cve.version': 'Version',
            'cve.cvss': 'CVSS',
            'cve.summary': 'Summary',
            'cve.notChecked': 'not checked',

            'toast.loggedIn': 'Logged in',
            'toast.loginFailed': 'Login failed',
            'toast.loggedOut': 'Logged out',
            'toast.signedOut': 'You have been signed out.',
            'toast.scanAlreadyRunning': 'Scan already running',
            'toast.scanInProgress': 'A previous scan is still in progress.',
            'toast.scanStarted': 'Scan started',
            'toast.scanInitiated': 'Network scan has been initiated. This may take a few moments.',
            'toast.scanComplete': 'Scan complete',
            'toast.scanFinished': 'Network scan finished successfully.',
            'toast.scanFailed': 'Scan failed',
            'toast.scanFailedMsg': 'Unable to start network scan. Please try again.',
            'toast.autoScanOn': 'Auto scan enabled',
            'toast.autoScanOnMsg': 'Network will be scanned automatically every 60 seconds.',
            'toast.autoScanOff': 'Auto scan disabled',
            'toast.autoScanOffMsg': 'Automatic scanning has been disabled.',
            'toast.authRequired': 'Auth required',
            'toast.loginToView': 'Please log in to view.',
            'toast.deviceAuthorized': 'Device authorized',
            'toast.deviceAuthorizedMsg': 'Device has been added to authorized list.',
            'toast.deviceUnauthorized': 'Device unauthorized',
            'toast.deviceUnauthorizedMsg': 'Device has been removed from authorized list.',
            'toast.error': 'Error',
            'toast.unableAuthorize': 'Unable to authorize device.',
            'toast.unableUnauthorize': 'Unable to unauthorize device.',
            'toast.invalidToken': 'Please provide a valid API token.',
            'toast.loadFailed': 'Load failed',
            'toast.unableLoadDevices': 'Unable to load device information.',
            'toast.portDetailsError': 'Unable to load port details.',
            'toast.exporting': 'Exporting report...'
        },

        ar: {
            'nav.dashboard': 'الرئيسية',
            'nav.devices': 'الأجهزة',
            'nav.topology': 'الطوبولوجيا',
            'nav.ports': 'المنافذ',
            'nav.alerts': 'التنبيهات',
            'nav.reports': 'التقارير',
            'nav.systemStatus': 'حالة النظام',
            'nav.monitoringActive': 'المراقبة نشطة',
            'nav.neverScanned': 'لم يتم الفحص بعد',
            'nav.subnet': 'الشبكة: {0}',
            'nav.subnetDetecting': 'الشبكة: جارٍ الكشف...',

            'header.securityDashboard': 'لوحة الأمان',
            'header.scanNetwork': 'فحص الشبكة',
            'header.autoScan': 'الفحص التلقائي',
            'header.logout': 'تسجيل الخروج',
            'header.login': 'تسجيل الدخول',
            'header.guest': 'ضيف',

            'stats.devices': 'الأجهزة',
            'stats.alerts': 'التنبيهات',
            'stats.openPorts': 'المنافذ المفتوحة',
            'stats.securityScore': 'درجة الأمان',
            'stats.unauthorizedCount': '{0} غير مصرح به',
            'stats.highRisk': '{0} خطر مرتفع',
            'stats.riskyPorts': '{0} خطر',
            'stats.noData': 'لا توجد بيانات',

            'charts.deviceAuth': 'ترخيص الأجهزة',
            'charts.portRisk': 'توزيع مخاطر المنافذ',
            'charts.authorized': 'مصرح به',
            'charts.unauthorized': 'غير مصرح به',
            'charts.highRisk': 'خطر مرتفع',
            'charts.mediumRisk': 'خطر متوسط',
            'charts.lowRisk': 'خطر منخفض',
            'charts.openPorts': 'المنافذ المفتوحة',
            'charts.devices': 'الأجهزة',

            'topology.networkTopology': 'طوبولوجيا الشبكة',
            'topology.gateway': 'البوابة',
            'topology.runScanMap': 'شغّل فحصًا للشبكة لملء الخريطة',

            'devices.networkDevices': 'أجهزة الشبكة',
            'devices.refresh': 'تحديث',
            'devices.status': 'الحالة',
            'devices.ipAddress': 'عنوان IP',
            'devices.macAddress': 'عنوان MAC',
            'devices.hostname': 'اسم الجهاز',
            'devices.vendor': 'الشركة المصنعة',
            'devices.openPorts': 'المنافذ المفتوحة',
            'devices.actions': 'إجراءات',
            'devices.none': 'لا يوجد',
            'devices.noDevices': 'لا توجد أجهزة. شغّل فحصًا للشبكة لاكتشاف الأجهزة.',

            'common.unknown': 'غير معروف',

            'status.authorized': 'مصرح به',
            'status.unauthorized': 'غير مصرح به',

            'alerts.securityAlerts': 'تنبيهات الأمان',
            'alerts.noAlerts': 'لا توجد تنبيهات أمنية',
            'alerts.device': 'الجهاز: {0}',

            'ports.portDetails': 'تفاصيل المنافذ',
            'ports.port': 'المنفذ',
            'ports.service': 'الخدمة',
            'ports.state': 'الحالة',
            'ports.version': 'الإصدار',
            'ports.riskLevel': 'مستوى الخطر',
            'ports.advice': 'نصيحة',
            'ports.noOpenPorts': 'لا توجد منافذ مفتوحة على هذا الجهاز.',
            'ports.unknown': 'غير معروف',

            'rec.securityRecommendations': 'توصيات الأمان',
            'rec.runScanForAdvice': 'شغّل فحصًا للشبكة للحصول على توصيات الأمان',
            'rec.scanHistory': 'سجل الفحص',
            'rec.scanDiff': 'التغييرات بين الفحوصات',
            'rec.runTwoScans': 'شغّل فحصين على الأقل لمعرفة ما تغير بينهما.',
            'rec.noChanges': 'لا توجد تغييرات بين آخر فحصين.',
            'rec.newDevices': 'أجهزة جديدة',
            'rec.devicesGone': 'أجهزة اختفت',
            'rec.portsOpened': 'منافذ فُتحت',
            'rec.portsClosed': 'منافذ أُغلقت',
            'rec.portOn': 'المنفذ {0} على {1}',
            'rec.exportReport': 'تصدير التقرير',
            'rec.exportCSV': 'تصدير CSV',
            'rec.exportJSON': 'تصدير JSON',
            'rec.exportHTML': 'تصدير HTML',
            'rec.exportPDF': 'تصدير PDF',
            'rec.trafficSniffer': 'مراقب الحركة',
            'rec.sec': '{0} ثانية',
            'rec.startCapture': 'بدء الالتقاط',
            'rec.capturing': 'جارٍ الالتقاط...',
            'rec.packets': 'الرزم',
            'rec.bytes': 'البايت',
            'rec.rate': 'المعدل',
            'rec.sniffNote': 'التقاط الحركة يتطلب صلاحيات مسؤول و Npcap على ويندوز.',
            'rec.protocols': 'البروتوكولات',
            'rec.topTalkers': 'أكثر المتحدثين',
            'rec.source': 'المصدر',
            'rec.destination': 'الوجهة',
            'rec.noTraffic': 'لا توجد حركة تم التقاطها',
            'rec.noResults': 'لا توجد نتائج التقاط بعد.',
            'rec.captureFor': 'جارٍ التقاط الحركة لمدة {0} ثانية.',
            'rec.sniffCaptured': 'تم التقاط {0} رزمة ({1}) على {2} خلال {3} ثانية',

            'login.title': 'مرحبًا بعودتك',
            'login.subtitle': 'سجّل الدخول للوصول إلى لوحة تحكم الأمان',
            'login.username': 'اسم المستخدم',
            'login.password': 'كلمة المرور',
            'login.invalid': 'بيانات دخول غير صحيحة',
            'login.login': 'تسجيل الدخول',
            'login.signingIn': 'جارٍ تسجيل الدخول...',
            'login.invalidToast': 'اسم مستخدم أو كلمة مرور غير صحيحة.',
            'login.backHome': 'العودة للرئيسية',
            'login.welcome': 'مرحبًا، {0}',

            'landing.brand': 'CyberGuard',
            'landing.tagline': 'رفيقك الملول على شبكتك',
            'landing.signIn': 'تسجيل الدخول',
            'landing.getStarted': 'افتح اللوحة',
            'landing.badge': 'مراقبة LAN مباشرة',
            'landing.headline': 'اعرف كل جهاز على شبكتك.',
            'landing.headlineAccent': 'قبل ما هو يبضن عليك.',
            'landing.subtitle': 'CyberGuard ساهر على شبكتك في نص الليل. يلمّح على أي جهاز غريب، منفذ مفتوح، أو ثغرة قبل ما تبقى عنوان خبر.',
            'landing.startFree': 'افتح اللوحة',
            'landing.watchDemo': 'إزاي بيمشي؟',
            'landing.trustedBy': 'شغال على Raspberry Pi، VPS، أو اللابتوب المغبّر في الأوضة',
            'landing.devices': 'جهاز متابع',
            'landing.alerts': 'تهديد متبلّغ عنه',
            'landing.ports': 'منفذ متكشف',
            'landing.uptime': 'وقت التشغيل',
            'landing.scanSeconds': 'ثانية لدورة الفحص',
            'landing.selfHosted': 'استضافة ذاتية',
            'landing.reportFormats': 'صيغ تقرير',
            'landing.languages': 'لغات',

            'landing.featuresTitle': 'قوى خارقة.. من غير إعدادات',
            'landing.featuresSubtitle': 'من غير بلجنات، من غير سحابة، من غير وجع راس. افتح اللوحة وبس',
            'landing.f1.title': 'فحص مستمر',
            'landing.f1.desc': 'يكتشف الأجهزة تلقائيًا كل 60 ثانية عبر ARP مع بديل nmap.',
            'landing.f2.title': 'كشف الدخلاء',
            'landing.f2.desc': 'ينبّهك في نفس اللحظة لما يظهر جهاز غريب أو هجوم spoofing.',
            'landing.f3.title': 'بحث CVE',
            'landing.f3.desc': 'فحص ثغرات بضغطة زر لكل جهاز مع كاش ذكي متعدد الطبقات.',
            'landing.f4.title': 'تعرّف نظام التشغيل',
            'landing.f4.desc': 'يكتشف النظام وراء كل عنوان IP مع نسبة دقة، مخزّن لمدة ساعة.',
            'landing.f5.title': 'تنبيهات متعددة القنوات',
            'landing.f5.desc': 'Telegram والإيميل (SMTP) وWebhooks. تتوصّل بالتوازي بأفضل جهد.',
            'landing.f6.title': 'تقارير احترافية',
            'landing.f6.desc': 'صدّر CSV أو JSON أو HTML أو PDF مع الرسوم والنصائح.',
            'landing.f7.title': 'عربي/إنجليزي + وضع داكن',
            'landing.f7.desc': 'دعم RTL كامل وتبديل لغة فوري وثيم محفوظ.',
            'landing.f8.title': 'تحكم في الصلاحيات',
            'landing.f8.desc': 'حساب مدير واحد بتحكم كامل. تسجيل دخول آمن بجلسات موقعة.',

            'landing.stepsTitle': 'من ضايع.. لمغطّى',
            'landing.stepsSubtitle': 'تلات خطوات وشبكتك توقف تكون لغز',
            'landing.step1.title': 'اكتشف',
            'landing.step1.desc': 'فحص ARP مع بديل nmap يرسّم كل جهاز وعنوان MAC ومنفذ مفتوح على الـ LAN.',
            'landing.step2.title': 'اكشف',
            'landing.step2.desc': 'الأجهزة الغريبة وARP spoofing وتغيرات المنافذ بتشغّل التنبيهات فورًا.',
            'landing.step3.title': 'احمي',
            'landing.step3.desc': 'رخّص الأجهزة الموثوقة، دوّر على CVE، وصدّر تقارير جاهزة للطباعة.',

            'landing.ctaTitle': 'بطل تسأل \'إيه الحاجات الموصلة على الواي فاي؟\'',
            'landing.ctaSubtitle': 'استضافة ذاتية. خصوصي. شغال على Raspberry Pi أو VPS صغير.',
            'landing.ctaButton': 'افتح اللوحة',
            'landing.ctaNote': 'مفيش حساب المطلوب للتجربة. سجّل الدخول بس لما تقرر تدير.',

            'landing.footerDesc': 'الصاحب اللي بيسهر على شبكتك الساعة 3 الفجر عشان تنام مرتاح.',
            'landing.product': 'المنتج',
            'landing.features': 'المميزات',
            'landing.dashboard': 'لوحة التحكم',

            'lp.about.title': 'عن CyberGuard',
            'lp.about.body': 'CyberGuard بدأ بسؤال: ليه أمان الشبكات محتاج دكتوراه واشتراك VPN وآخر الأسبوع في ملفات إعدادات؟ فبنينا كلب حراسة شغال عندك أنت بس، بيفحص الشبكة بمزاجه، يلاحظ أي تغيير، ويقولهالك بكلام واضح.',
            'lp.about.c1': '0 سيرفرات سحابة',
            'lp.about.c2': 'فحص كل 60 ثانية',
            'lp.about.c3': 'لوحة واحدة',
            'lp.security.title': 'الأمان عندنا',
            'lp.security.body': 'كل حاجة شغالة على جهازك. الفحص جوه شبكتك، لوحة المسؤول خلف جلسة موقّعة، ومفيش حاجة بتخرج برة البيت. اللي محتاج صلاحيات بناخده، واللي لأ مبنلمسهاش.',
            'lp.security.c1': 'دخول بجلسة موقّعة',
            'lp.security.c2': 'من غير تتبّع',
            'lp.security.c3': 'قاعدة بيانات محلية فقط',
            'lp.privacy.title': 'وعد الخصوصية',
            'lp.privacy.body': 'مفيش داتا تتباع، لأن مفيش داتا أصلاً بتخرج من البيت. اللوحة شايلة عناوين الأجهزة والمنافذ لعينيك أنت بس، وتفضيلاتك عايشة في المتصفح مش على سيرفر.',
            'lp.privacy.c1': 'البيانات قرب البيت',
            'lp.privacy.c2': 'استخدام مجهول',
            'lp.privacy.c3': 'السجل ملكك',
            'lp.docs.copyHint': 'انسخ أمر الاستنساخ',
            'lp.docs.title': 'ابدأ بسرعة',
            'lp.docs.body': 'استضافة ذاتية بأمر واحد. من غير حسابات تفتحها، ومن غير سحابة على مزاجها.',
            'lp.docs.c1': 'استضافة ذاتية',
            'lp.docs.c2': 'من غير سحابة',
            'lp.docs.c3': 'مصدر مفتوح',
            'landing.company': 'الشركة',
            'landing.about': 'عن المشروع',
            'landing.security': 'الأمان',
            'landing.privacy': 'الخصوصية',
            'landing.resources': 'موارد',
            'landing.login': 'تسجيل الدخول',
            'landing.github': 'GitHub',
            'landing.docs': 'التوثيق',
            'landing.backHome': 'العودة للرئيسية',
            'landing.copyright': '© 2026 CyberGuard. استضافة ذاتية. مفتوح المصدر.',
            'landing.builtWith': 'صُنع بـ Python · Flask · Nmap · قهوة'
            ,

            'modal.deviceDetails': 'تفاصيل الجهاز',
            'modal.ipAddress': 'عنوان IP:',
            'modal.macAddress': 'عنوان MAC:',
            'modal.hostname': 'اسم الجهاز:',
            'modal.vendor': 'الشركة المصنعة:',
            'modal.status': 'الحالة:',
            'modal.lastSeen': 'آخر ظهور:',
            'modal.openPorts': 'المنافذ المفتوحة:',
            'modal.securityRec': 'توصيات الأمان:',
            'modal.viewPortDetails': 'عرض تفاصيل المنافذ',
            'modal.authorizeDevice': 'الترخيص للجهاز',
            'modal.unauthorizeDevice': 'إلغاء ترخيص الجهاز',
            'modal.viewCves': 'ثغرات معروفة',
            'modal.detectOs': 'كشف نظام التشغيل',
            'modal.checkingCves': 'جارٍ البحث عن الثغرات المعروفة...',
            'modal.noCves': 'لا توجد ثغرات معروفة لهذا الجهاز.',
            'modal.detectingOs': 'جارٍ كشف نظام التشغيل...',
            'modal.osResult': 'نظام التشغيل: {0} (الدقة {1}%)',
            'modal.osMethod': 'عبر {0}',
            'modal.osUnknown': 'تعذّر تحديد نظام التشغيل.',
            'modal.live': 'مباشر',
            'modal.cache': 'مخزّن',
            'modal.fromCache': ' ({0})',

            'cve.id': 'الثغرة',
            'cve.port': 'المنفذ',
            'cve.service': 'الخدمة',
            'cve.version': 'الإصدار',
            'cve.cvss': 'CVSS',
            'cve.summary': 'الملخص',
            'cve.notChecked': 'لم يُفحص',

            'toast.loggedIn': 'تم تسجيل الدخول',
            'toast.loginFailed': 'فشل تسجيل الدخول',
            'toast.loggedOut': 'تم تسجيل الخروج',
            'toast.signedOut': 'لقد خرجت من الجلسة.',
            'toast.scanAlreadyRunning': 'الفحص قيد التشغيل بالفعل',
            'toast.scanInProgress': 'فحص سابق لا يزال قيد التنفيذ.',
            'toast.scanStarted': 'بدأ الفحص',
            'toast.scanInitiated': 'تم بدء فحص الشبكة. قد يستغرق الأمر لحظات.',
            'toast.scanComplete': 'اكتمل الفحص',
            'toast.scanFinished': 'انتهى فحص الشبكة بنجاح.',
            'toast.scanFailed': 'فشل الفحص',
            'toast.scanFailedMsg': 'تعذّر بدء فحص الشبكة. حاول مرة أخرى.',
            'toast.autoScanOn': 'تم تفعيل الفحص التلقائي',
            'toast.autoScanOnMsg': 'ستتم مراقبة الشبكة كل 60 ثانية.',
            'toast.autoScanOff': 'تم تعطيل الفحص التلقائي',
            'toast.autoScanOffMsg': 'تم تعطيل الفحص التلقائي.',
            'toast.authRequired': 'مطلوب تسجيل الدخول',
            'toast.loginToView': 'سجّل الدخول لعرض هذه الصفحة.',
            'toast.deviceAuthorized': 'تم ترخيص الجهاز',
            'toast.deviceAuthorizedMsg': 'تمت إضافة الجهاز إلى قائمة الأجهزة المصرح بها.',
            'toast.deviceUnauthorized': 'تم إلغاء ترخيص الجهاز',
            'toast.deviceUnauthorizedMsg': 'تمت إزالة الجهاز من قائمة الأجهزة المصرح بها.',
            'toast.error': 'خطأ',
            'toast.unableAuthorize': 'تعذّر ترخيص الجهاز.',
            'toast.unableUnauthorize': 'تعذّر إلغاء ترخيص الجهاز.',
            'toast.invalidToken': 'يرجى توفير رمز API صحيح.',
            'toast.loadFailed': 'فشل التحميل',
            'toast.unableLoadDevices': 'تعذّر تحميل بيانات الأجهزة.',
            'toast.portDetailsError': 'تعذّر تحميل تفاصيل المنافذ.',
            'toast.exporting': 'جارٍ تصدير التقرير...'
        }
    };

    function t(key, vars) {
        const table = dict[getLang()] || dict.en;
        let str = table[key] !== undefined ? table[key] : (dict.en[key] !== undefined ? dict.en[key] : key);
        if (vars) {
            Object.keys(vars).forEach(i => {
                str = str.replace(new RegExp('\\{' + i + '\\}', 'g'), vars[i]);
            });
        }
        return str;
    }

    function getLang() {
        return localStorage.getItem('cw_lang') || 'en';
    }

    function setLang(lang) {
        localStorage.setItem('cw_lang', lang === 'ar' ? 'ar' : 'en');
        applyStatic();
        document.documentElement.lang = getLang();
        const toggle = document.getElementById('lang-toggle');
        if (toggle) toggle.textContent = getLang() === 'ar' ? 'EN' : 'العربية';
        if (window.app && window.app.refreshAll) window.app.refreshAll();
    }

    function applyStatic() {
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const vars = (el.dataset.i18nVars || '').split(',').filter(Boolean);
            el.textContent = t(el.dataset.i18n, vars.length ? vars : undefined);
        });
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            el.placeholder = t(el.dataset.i18nPlaceholder);
        });
        document.querySelectorAll('[data-i18n-title]').forEach(el => {
            el.title = t(el.dataset.i18nTitle);
        });
    }

    // ---------------------------------------------------------------- theme
    function getTheme() {
        return localStorage.getItem('cw_theme') || 'light';
    }

    function applyTheme() {
        const theme = getTheme();
        document.documentElement.dataset.theme = theme;
        const toggle = document.getElementById('theme-toggle');
        if (toggle) {
            toggle.innerHTML = theme === 'dark'
                ? '<i class="fas fa-sun"></i>'
                : '<i class="fas fa-moon"></i>';
        }
        if (window.app) {
            if (window.renderCharts && document.getElementById('chart-devices')) {
                window.app.loadDevices();
            }
            if (window.renderTopology && document.getElementById('topology-canvas')) {
                if (window.app.gatewayHandle) window.renderTopology(window.app.lastDevices || [], window.app.gateway);
            }
        }
    }

    function toggleTheme() {
        localStorage.setItem('cw_theme', getTheme() === 'dark' ? 'light' : 'dark');
        applyTheme();
    }

    // ---------------------------------------------------------------- init
    document.addEventListener('DOMContentLoaded', () => {
        setLang(getLang());
        applyTheme();
        const themeBtn = document.getElementById('theme-toggle');
        if (themeBtn) themeBtn.addEventListener('click', toggleTheme);
        const langBtn = document.getElementById('lang-toggle');
        if (langBtn) langBtn.addEventListener('click', () => setLang(getLang() === 'ar' ? 'en' : 'ar'));
    });

    window.i18n = { t, getLang, setLang, applyStatic, toggleTheme, getTheme };
})();