package web

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phantom Grid - Security Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #343741;
            overflow-x: hidden;
        }

        /* Top Navigation Bar */
        .top-nav {
            background: #fff;
            border-bottom: 1px solid #d3dae6;
            padding: 0 24px;
            height: 56px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
            position: sticky;
            top: 0;
            z-index: 1000;
        }

        .top-nav-left {
            display: flex;
            align-items: center;
            gap: 24px;
        }

        .logo {
            font-size: 20px;
            font-weight: 600;
            color: #006bb4;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .nav-item {
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            color: #343741;
            transition: background 0.2s;
        }

        .nav-item:hover {
            background: #f0f4f8;
        }

        .nav-item.active {
            background: #e3f2fd;
            color: #006bb4;
            font-weight: 500;
        }

        .top-nav-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            background: #e8f5e9;
            border-radius: 16px;
            font-size: 12px;
            color: #2e7d32;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #4caf50;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }

        /* Main Container */
        .main-container {
            display: flex;
            min-height: calc(100vh - 56px);
        }

        /* Sidebar */
        .sidebar {
            width: 240px;
            background: #fff;
            border-right: 1px solid #d3dae6;
            padding: 24px 0;
            position: sticky;
            top: 56px;
            height: calc(100vh - 56px);
            overflow-y: auto;
        }

        .sidebar-section {
            padding: 0 16px;
            margin-bottom: 24px;
        }

        .sidebar-title {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #69707d;
            margin-bottom: 12px;
            padding: 0 8px;
        }

        .sidebar-item {
            padding: 10px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            color: #343741;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: background 0.2s;
            margin-bottom: 4px;
        }

        .sidebar-item:hover {
            background: #f0f4f8;
        }

        .sidebar-item.active {
            background: #e3f2fd;
            color: #006bb4;
            font-weight: 500;
        }

        .sidebar-item-icon {
            width: 20px;
            text-align: center;
        }

        /* Content Area */
        .content {
            flex: 1;
            padding: 24px;
            overflow-y: auto;
        }

        /* Page Header */
        .page-header {
            margin-bottom: 24px;
        }

        .page-title {
            font-size: 28px;
            font-weight: 600;
            color: #1a1c21;
            margin-bottom: 8px;
        }

        .page-subtitle {
            font-size: 14px;
            color: #69707d;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: #fff;
            border: 1px solid #d3dae6;
            border-radius: 8px;
            padding: 20px;
            transition: box-shadow 0.2s, transform 0.2s;
        }

        .stat-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }

        .stat-card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }

        .stat-card-title {
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #69707d;
        }

        .stat-card-icon {
            font-size: 20px;
        }

        .stat-card-value {
            font-size: 32px;
            font-weight: 600;
            color: #1a1c21;
            margin-bottom: 4px;
        }

        .stat-card-footer {
            font-size: 12px;
            color: #69707d;
        }

        .stat-card.danger .stat-card-value { color: #d32f2f; }
        .stat-card.warning .stat-card-value { color: #f57c00; }
        .stat-card.success .stat-card-value { color: #388e3c; }
        .stat-card.info .stat-card-value { color: #1976d2; }

        /* Panels */
        .panel {
            background: #fff;
            border: 1px solid #d3dae6;
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }

        .panel-header {
            padding: 16px 20px;
            border-bottom: 1px solid #d3dae6;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #fafbfc;
        }

        .panel-title {
            font-size: 16px;
            font-weight: 600;
            color: #1a1c21;
        }

        .panel-body {
            padding: 20px;
        }

        /* Log Container */
        .log-container {
            height: 600px;
            overflow-y: auto;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 12px;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 16px;
            border-radius: 4px;
        }

        .log-entry {
            margin-bottom: 8px;
            padding: 8px 12px;
            border-left: 3px solid transparent;
            border-radius: 3px;
            transition: background 0.2s;
            display: flex;
            gap: 12px;
        }

        .log-entry:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .log-entry.spa { border-left-color: #ffc107; }
        .log-entry.trap { border-left-color: #f44336; }
        .log-entry.stealth { border-left-color: #9c27b0; }
        .log-entry.system { border-left-color: #2196f3; }

        .log-timestamp {
            color: #858585;
            min-width: 180px;
        }

        .log-message {
            color: #d4d4d4;
            flex: 1;
        }

        /* Threat Gauge */
        .threat-gauge-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px;
        }

        .gauge-wrapper {
            position: relative;
            width: 200px;
            height: 200px;
            margin-bottom: 24px;
        }

        .gauge-value {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 48px;
            font-weight: 700;
            color: #1a1c21;
        }

        .gauge-label {
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            text-align: center;
        }

        .gauge-label.low { color: #388e3c; }
        .gauge-label.medium { color: #f57c00; }
        .gauge-label.high { color: #d32f2f; }

        /* System Info */
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }

        .info-item {
            padding: 12px;
            background: #fafbfc;
            border-radius: 4px;
            border: 1px solid #e4e7eb;
        }

        .info-label {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            color: #69707d;
            margin-bottom: 4px;
        }

        .info-value {
            font-size: 14px;
            font-weight: 500;
            color: #1a1c21;
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #f1f3f5;
        }

        ::-webkit-scrollbar-thumb {
            background: #c1c7cd;
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #a8b0b8;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .sidebar {
                width: 200px;
            }
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <!-- Top Navigation -->
    <div class="top-nav">
        <div class="top-nav-left">
            <div class="logo">
                <span>🛡️</span>
                <span>Phantom Grid</span>
            </div>
            <div class="nav-item active">Overview</div>
            <div class="nav-item">Security</div>
            <div class="nav-item">Analytics</div>
        </div>
        <div class="top-nav-right">
            <div class="status-badge">
                <div class="status-dot"></div>
                <span>ACTIVE</span>
            </div>
            <div style="font-size: 12px; color: #69707d;">
                <span id="uptime">00:00:00</span>
            </div>
        </div>
    </div>

    <!-- Main Container -->
    <div class="main-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-section">
                <div class="sidebar-title">Navigation</div>
                <div class="sidebar-item active">
                    <span class="sidebar-item-icon">📊</span>
                    <span>Dashboard</span>
                </div>
                <div class="sidebar-item">
                    <span class="sidebar-item-icon">🔐</span>
                    <span>SPA Authentication</span>
                </div>
                <div class="sidebar-item">
                    <span class="sidebar-item-icon">🎣</span>
                    <span>Honeypot Traps</span>
                </div>
                <div class="sidebar-item">
                    <span class="sidebar-item-icon">👻</span>
                    <span>Stealth Scans</span>
                </div>
            </div>
            <div class="sidebar-section">
                <div class="sidebar-title">System</div>
                <div class="sidebar-item">
                    <span class="sidebar-item-icon">⚙️</span>
                    <span>Settings</span>
                </div>
                <div class="sidebar-item">
                    <span class="sidebar-item-icon">📝</span>
                    <span>Logs</span>
                </div>
            </div>
        </div>

        <!-- Content Area -->
        <div class="content">
            <!-- Page Header -->
            <div class="page-header">
                <div class="page-title">Security Dashboard</div>
                <div class="page-subtitle">Real-time monitoring and threat detection</div>
            </div>

            <!-- Statistics Grid -->
            <div class="stats-grid">
                <div class="stat-card danger">
                    <div class="stat-card-header">
                        <div class="stat-card-title">Redirected</div>
                        <div class="stat-card-icon">🎣</div>
                    </div>
                    <div class="stat-card-value" id="redirected">0</div>
                    <div class="stat-card-footer">Connections to honeypot</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-card-header">
                        <div class="stat-card-title">Stealth Scans</div>
                        <div class="stat-card-icon">👻</div>
                    </div>
                    <div class="stat-card-value" id="stealth">0</div>
                    <div class="stat-card-footer">Blocked scans</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-card-header">
                        <div class="stat-card-title">OS Mutations</div>
                        <div class="stat-card-icon">🔄</div>
                    </div>
                    <div class="stat-card-value" id="os-mutations">0</div>
                    <div class="stat-card-footer">Fingerprint changes</div>
                </div>
                <div class="stat-card success">
                    <div class="stat-card-header">
                        <div class="stat-card-title">SPA Success</div>
                        <div class="stat-card-icon">🔐</div>
                    </div>
                    <div class="stat-card-value" id="spa-success">0</div>
                    <div class="stat-card-footer">Successful auths</div>
                </div>
                <div class="stat-card danger">
                    <div class="stat-card-header">
                        <div class="stat-card-title">SPA Failed</div>
                        <div class="stat-card-icon">✗</div>
                    </div>
                    <div class="stat-card-value" id="spa-failed">0</div>
                    <div class="stat-card-footer">Failed attempts</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-card-header">
                        <div class="stat-card-title">Egress Blocks</div>
                        <div class="stat-card-icon">🚫</div>
                    </div>
                    <div class="stat-card-value" id="egress-blocks">0</div>
                    <div class="stat-card-footer">DLP blocks</div>
                </div>
            </div>

            <!-- Main Content Grid -->
            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 24px;">
                <!-- Event Log Panel -->
                <div class="panel">
                    <div class="panel-header">
                        <div class="panel-title">Real-Time Event Log</div>
                    </div>
                    <div class="panel-body">
                        <div class="log-container" id="log-container"></div>
                    </div>
                </div>

                <!-- Right Sidebar -->
                <div>
                    <!-- Threat Level Panel -->
                    <div class="panel" style="margin-bottom: 24px;">
                        <div class="panel-header">
                            <div class="panel-title">Threat Level</div>
                        </div>
                        <div class="panel-body">
                            <div class="threat-gauge-container">
                                <div class="gauge-wrapper">
                                    <svg width="200" height="200" viewBox="0 0 200 200">
                                        <circle cx="100" cy="100" r="85" fill="none" stroke="#e4e7eb" stroke-width="12"/>
                                        <circle id="gauge-circle" cx="100" cy="100" r="85" fill="none" stroke="#388e3c" stroke-width="12" 
                                                stroke-dasharray="534" stroke-dashoffset="534" transform="rotate(-90 100 100)" stroke-linecap="round"/>
                                    </svg>
                                    <div class="gauge-value" id="threat-percent">0%</div>
                                </div>
                                <div class="gauge-label low" id="threat-label">LOW THREAT</div>
                            </div>
                        </div>
                    </div>

                    <!-- System Info Panel -->
                    <div class="panel">
                        <div class="panel-header">
                            <div class="panel-title">System Information</div>
                        </div>
                        <div class="panel-body">
                            <div class="info-grid">
                                <div class="info-item">
                                    <div class="info-label">Interface</div>
                                    <div class="info-value" id="interface">-</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">XDP Hook</div>
                                    <div class="info-value" style="color: #388e3c;">ACTIVE</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Uptime</div>
                                    <div class="info-value" id="uptime-sidebar">00:00:00</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const logContainer = document.getElementById('log-container');
        const statsEventSource = new EventSource('/api/events');
        const logsEventSource = new EventSource('/api/logs-stream');

        // Update statistics from SSE
        statsEventSource.onmessage = function(event) {
            const stats = JSON.parse(event.data);
            updateStats(stats);
        };

        // Update logs from SSE (real-time)
        logsEventSource.onmessage = function(event) {
            const newLogs = JSON.parse(event.data);
            if (Array.isArray(newLogs) && newLogs.length > 0) {
                newLogs.forEach(log => {
                    addLogEntry(log);
                });
            }
        };

        // Fetch initial logs
        fetchLogs();

        function updateStats(stats) {
            document.getElementById('redirected').textContent = formatNumber(stats.redirected || 0);
            document.getElementById('stealth').textContent = formatNumber(stats.stealth || 0);
            document.getElementById('os-mutations').textContent = formatNumber(stats.os_mutations || 0);
            document.getElementById('spa-success').textContent = formatNumber(stats.spa_success || 0);
            document.getElementById('spa-failed').textContent = formatNumber(stats.spa_failed || 0);
            document.getElementById('egress-blocks').textContent = formatNumber(stats.egress_blocks || 0);
            document.getElementById('interface').textContent = stats.interface || '-';
            document.getElementById('uptime').textContent = stats.uptime || '00:00:00';
            document.getElementById('uptime-sidebar').textContent = stats.uptime || '00:00:00';

            // Update threat level
            const totalThreats = (stats.redirected || 0) + (stats.stealth || 0);
            const threatLevel = Math.min(100, (totalThreats * 10) % 100);
            updateThreatGauge(threatLevel);
        }

        function formatNumber(num) {
            return num.toLocaleString();
        }

        function updateThreatGauge(percent) {
            const circle = document.getElementById('gauge-circle');
            const circumference = 2 * Math.PI * 85;
            const offset = circumference - (percent / 100) * circumference;
            circle.style.strokeDashoffset = offset;

            document.getElementById('threat-percent').textContent = percent + '%';

            let color = '#388e3c';
            let label = 'LOW THREAT';
            let labelClass = 'low';
            if (percent >= 70) {
                color = '#d32f2f';
                label = 'HIGH THREAT';
                labelClass = 'high';
            } else if (percent >= 30) {
                color = '#f57c00';
                label = 'MEDIUM THREAT';
                labelClass = 'medium';
            }

            circle.style.stroke = color;
            const labelEl = document.getElementById('threat-label');
            labelEl.textContent = label;
            labelEl.className = 'gauge-label ' + labelClass;
        }

        let displayedLogs = new Set();

        function fetchLogs() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(logs => {
                    logContainer.innerHTML = '';
                    displayedLogs.clear();
                    logs.slice(-200).reverse().forEach(log => {
                        addLogEntry(log);
                    });
                    logContainer.scrollTop = logContainer.scrollHeight;
                })
                .catch(err => {
                    console.error('Error fetching logs:', err);
                });
        }

        function addLogEntry(log) {
            // Create unique ID from timestamp + message
            const logId = log.timestamp + '|' + log.message;
            if (displayedLogs.has(logId)) {
                return; // Skip duplicate
            }
            displayedLogs.add(logId);

            const entry = document.createElement('div');
            entry.className = 'log-entry ' + getLogType(log.message);
            entry.innerHTML = '<span class="log-timestamp">[' + log.timestamp + ']</span>' +
                             '<span class="log-message">' + escapeHtml(log.message) + '</span>';
            
            // Insert at the end (newest at bottom)
            logContainer.appendChild(entry);
            
            // Keep only last 500 entries in DOM
            while (logContainer.children.length > 500) {
                const firstId = logContainer.children[0].textContent;
                displayedLogs.delete(firstId);
                logContainer.removeChild(logContainer.firstChild);
            }
            
            // Auto-scroll to bottom
            logContainer.scrollTop = logContainer.scrollHeight;
        }

        function getLogType(message) {
            const msg = message.toUpperCase();
            if (msg.includes('[SPA]')) return 'spa';
            if (msg.includes('[TRAP]')) return 'trap';
            if (msg.includes('[STEALTH]')) return 'stealth';
            return 'system';
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
`

func getHTMLTemplate() string {
	return htmlTemplate
}
