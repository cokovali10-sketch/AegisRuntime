//go:build linux

package api

import (
	"net/http"
	"time"
)

const DashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisRuntime - Live Audit Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-tertiary: #1a1a25;
            --accent-green: #00ff88;
            --accent-blue: #00aaff;
            --accent-red: #ff3366;
            --accent-yellow: #ffcc00;
            --text-primary: #e0e0e0;
            --text-secondary: #888899;
            --border-color: #2a2a35;
            --glow-green: 0 0 20px rgba(0, 255, 136, 0.3);
        }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }

        .status-bar {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 12px;
            font-family: 'JetBrains Mono', monospace;
        }

        .status-bar-left {
            display: flex;
            gap: 20px;
        }

        .status-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-label {
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .status-value {
            color: var(--accent-green);
            font-weight: 500;
        }

        .header {
            background: linear-gradient(180deg, var(--bg-secondary) 0%, var(--bg-primary) 100%);
            border-bottom: 1px solid var(--border-color);
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-title {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .header-title h1 {
            font-family: 'JetBrains Mono', monospace;
            font-size: 24px;
            font-weight: 700;
            color: var(--accent-green);
            text-shadow: var(--glow-green);
            letter-spacing: 3px;
        }

        .header-title .subtitle {
            font-size: 12px;
            color: var(--text-secondary);
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        .connection-status {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 15px;
            background: var(--bg-tertiary);
            border-radius: 20px;
            border: 1px solid var(--border-color);
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent-red);
            transition: background 0.3s ease;
        }

        .status-dot.connected {
            background: var(--accent-green);
            box-shadow: 0 0 10px var(--accent-green);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .status-text {
            font-size: 12px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .main-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            grid-template-rows: 1fr 1fr;
            gap: 15px;
            padding: 15px;
            height: calc(100vh - 140px);
        }

        .panel {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .panel-header {
            background: var(--bg-tertiary);
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .panel-title {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            font-weight: 600;
            color: var(--accent-green);
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        .panel-badge {
            font-size: 10px;
            padding: 3px 8px;
            background: rgba(0, 255, 136, 0.1);
            color: var(--accent-green);
            border-radius: 10px;
            font-family: 'JetBrains Mono', monospace;
        }

        .terminal-panel {
            grid-column: 1;
            grid-row: 1 / 3;
        }

        .graph-panel {
            grid-column: 2;
            grid-row: 1;
        }

        .events-panel {
            grid-column: 2;
            grid-row: 2;
        }

        .terminal-output {
            flex: 1;
            padding: 15px;
            overflow-y: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            line-height: 1.6;
            background: #000;
        }

        .terminal-line {
            white-space: pre-wrap;
            word-break: break-all;
        }

        .terminal-line .timestamp {
            color: var(--text-secondary);
        }

        .terminal-line .type {
            color: var(--accent-blue);
            font-weight: 500;
        }

        .terminal-line .message {
            color: var(--accent-green);
        }

        .terminal-line.error .message {
            color: var(--accent-red);
        }

        .terminal-line.warning .message {
            color: var(--accent-yellow);
        }

        .graph-container {
            flex: 1;
            padding: 10px;
            position: relative;
        }

        .graph-canvas {
            width: 100%;
            height: 100%;
        }

        .graph-legend {
            position: absolute;
            top: 15px;
            right: 15px;
            display: flex;
            flex-direction: column;
            gap: 5px;
            font-size: 10px;
            font-family: 'JetBrains Mono', monospace;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .legend-color {
            width: 12px;
            height: 3px;
            border-radius: 2px;
        }

        .events-list {
            flex: 1;
            padding: 10px;
            overflow-y: auto;
        }

        .event-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 10px;
            margin-bottom: 8px;
            background: var(--bg-tertiary);
            border-radius: 6px;
            border-left: 3px solid var(--accent-green);
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-10px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .event-item.severity-critical {
            border-left-color: var(--accent-red);
        }

        .event-item.severity-high {
            border-left-color: #ff6600;
        }

        .event-item.severity-medium {
            border-left-color: var(--accent-yellow);
        }

        .event-item.severity-low {
            border-left-color: var(--accent-green);
        }

        .event-severity {
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 6px;
            border-radius: 3px;
            text-transform: uppercase;
            white-space: nowrap;
        }

        .severity-critical .event-severity {
            background: rgba(255, 51, 102, 0.2);
            color: var(--accent-red);
        }

        .severity-high .event-severity {
            background: rgba(255, 102, 0, 0.2);
            color: #ff6600;
        }

        .severity-medium .event-severity {
            background: rgba(255, 204, 0, 0.2);
            color: var(--accent-yellow);
        }

        .severity-low .event-severity {
            background: rgba(0, 255, 136, 0.2);
            color: var(--accent-green);
        }

        .event-content {
            flex: 1;
            min-width: 0;
        }

        .event-title {
            font-size: 12px;
            font-weight: 500;
            margin-bottom: 3px;
            color: var(--text-primary);
        }

        .event-details {
            font-size: 10px;
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
        }

        .event-time {
            font-size: 10px;
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
            white-space: nowrap;
        }

        .footer {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: var(--bg-secondary);
            border-top: 1px solid var(--border-color);
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-secondary);
        }

        .footer-left {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .footer-brand {
            color: var(--accent-green);
            font-weight: 600;
            letter-spacing: 2px;
        }

        .terminal-output::-webkit-scrollbar,
        .events-list::-webkit-scrollbar {
            width: 6px;
        }

        .terminal-output::-webkit-scrollbar-track,
        .events-list::-webkit-scrollbar-track {
            background: var(--bg-primary);
        }

        .terminal-output::-webkit-scrollbar-thumb,
        .events-list::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 3px;
        }

        .terminal-output::-webkit-scrollbar-thumb:hover,
        .events-list::-webkit-scrollbar-thumb:hover {
            background: var(--text-secondary);
        }

        @media (max-width: 1200px) {
            .main-container {
                grid-template-columns: 1fr;
                grid-template-rows: auto;
                height: auto;
            }

            .terminal-panel {
                grid-column: 1;
                grid-row: auto;
                min-height: 400px;
            }

            .graph-panel,
            .events-panel {
                grid-column: 1;
                grid-row: auto;
                min-height: 300px;
            }
        }
    </style>
</head>
<body>
    <div class="status-bar">
        <div class="status-bar-left">
            <div class="status-item">
                <span class="status-label">Container:</span>
                <span class="status-value" id="container-id">--</span>
            </div>
            <div class="status-item">
                <span class="status-label">Uptime:</span>
                <span class="status-value" id="uptime">00:00:00</span>
            </div>
            <div class="status-item">
                <span class="status-label">Events/sec:</span>
                <span class="status-value" id="events-per-sec">0</span>
            </div>
            <div class="status-item">
                <span class="status-label">Memory:</span>
                <span class="status-value" id="memory-usage">0 MB</span>
            </div>
        </div>
        <div class="status-bar-right">
            <div class="status-item">
                <span class="status-label">Latency:</span>
                <span class="status-value" id="latency">-- ms</span>
            </div>
        </div>
    </div>

    <header class="header">
        <div class="header-title">
            <div>
                <h1>AEGISRUNTIME</h1>
                <div class="subtitle">LIVE AUDIT DASHBOARD</div>
            </div>
        </div>
        <div class="connection-status">
            <div class="status-dot" id="status-dot"></div>
            <span class="status-text" id="status-text">Disconnected</span>
        </div>
    </header>

    <main class="main-container">
        <div class="panel terminal-panel">
            <div class="panel-header">
                <span class="panel-title">System Output</span>
                <span class="panel-badge" id="line-count">0 lines</span>
            </div>
            <div class="terminal-output" id="terminal-output"></div>
        </div>

        <div class="panel graph-panel">
            <div class="panel-header">
                <span class="panel-title">Resource Monitor</span>
                <span class="panel-badge">Real-time</span>
            </div>
            <div class="graph-container">
                <canvas id="graph-canvas" class="graph-canvas"></canvas>
                <div class="graph-legend">
                    <div class="legend-item">
                        <div class="legend-color" style="background: #00aaff;"></div>
                        <span style="color: #00aaff;">CPU</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #00ff88;"></div>
                        <span style="color: #00ff88;">RAM</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #ffcc00;"></div>
                        <span style="color: #ffcc00;">PIDs</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="panel events-panel">
            <div class="panel-header">
                <span class="panel-title">Security Events</span>
                <span class="panel-badge" id="event-count">0 events</span>
            </div>
            <div class="events-list" id="events-list"></div>
        </div>
    </main>

    <footer class="footer">
        <div class="footer-left">
            <span class="footer-brand">AegisRuntime v1.0.0</span>
            <span>|</span>
            <span>Zero-Trust AI Sandbox</span>
        </div>
        <div>
            <span>Protocol: WebSocket</span>
        </div>
    </footer>

    <script>
        const CONFIG = {
            WS_URL: 'ws://localhost:8080/api/ws',
            RECONNECT_BASE_DELAY: 1000,
            RECONNECT_MAX_DELAY: 30000,
            MAX_TERMINAL_LINES: 500,
            MAX_EVENTS: 100,
            GRAPH_POINTS: 60,
            GRAPH_UPDATE_INTERVAL: 1000
        };

        const state = {
            ws: null,
            connected: false,
            reconnectAttempts: 0,
            reconnectTimeout: null,
            containerId: null,
            startTime: Date.now(),
            terminalLines: [],
            events: [],
            lineCount: 0,
            eventsPerSecond: 0,
            lastEventCount: 0,
            lastEventTime: Date.now(),
            graphData: {
                cpu: [],
                ram: [],
                pids: []
            }
        };

        function generateId() {
            return 'container-' + Math.random().toString(36).substr(2, 9);
        }

        function connect() {
            state.containerId = state.containerId || generateId();
            document.getElementById('container-id').textContent = state.containerId;

            try {
                state.ws = new WebSocket(CONFIG.WS_URL + '?container_id=' + state.containerId);

                state.ws.onopen = function() {
                    state.connected = true;
                    state.reconnectAttempts = 0;
                    updateConnectionStatus(true);
                    addTerminalLine('system', 'Connected to AegisRuntime Audit Stream');
                    console.log('[Aegis] WebSocket connected');
                };

                state.ws.onmessage = function(event) {
                    try {
                        const msg = JSON.parse(event.data);
                        handleMessage(msg);
                    } catch (e) {
                        console.error('[Aegis] Parse error:', e);
                    }
                };

                state.ws.onclose = function() {
                    state.connected = false;
                    updateConnectionStatus(false);
                    addTerminalLine('system', 'Connection lost. Attempting to reconnect...');
                    scheduleReconnect();
                };

                state.ws.onerror = function(error) {
                    console.error('[Aegis] WebSocket error:', error);
                    state.connected = false;
                    updateConnectionStatus(false);
                };
            } catch (e) {
                console.error('[Aegis] Connection failed:', e);
                scheduleReconnect();
            }
        }

        function scheduleReconnect() {
            if (state.reconnectTimeout) {
                clearTimeout(state.reconnectTimeout);
            }

            const delay = Math.min(
                CONFIG.RECONNECT_BASE_DELAY * Math.pow(2, state.reconnectAttempts),
                CONFIG.RECONNECT_MAX_DELAY
            );

            state.reconnectAttempts++;
            addTerminalLine('system', 'Reconnecting in ' + (delay / 1000).toFixed(1) + 's (attempt ' + state.reconnectAttempts + ')');

            state.reconnectTimeout = setTimeout(function() {
                connect();
            }, delay);
        }

        function handleMessage(msg) {
            switch (msg.type) {
                case 'syscall':
                    addTerminalLine('syscall', formatSyscall(msg));
                    break;
                case 'memory':
                    handleMemoryEvent(msg);
                    break;
                case 'network':
                    addTerminalLine('network', formatNetworkEvent(msg));
                    break;
                case 'security':
                    handleSecurityEvent(msg);
                    break;
                case 'system':
                    addTerminalLine('system', msg.data?.message || JSON.stringify(msg.data));
                    if (msg.data?.server_time) {
                        state.startTime = new Date(msg.data.server_time).getTime();
                    }
                    break;
                case 'pong':
                    const latency = Date.now() - (msg.data?.client_time || Date.now());
                    document.getElementById('latency').textContent = Math.max(0, latency) + ' ms';
                    break;
                default:
                    addTerminalLine('info', JSON.stringify(msg));
            }
        }

        function formatSyscall(msg) {
            const data = msg.data?.payload || msg.data;
            if (typeof data === 'string') return data;
            if (data?.name) {
                return '[' + (data.pid || '?') + '] ' + data.name + '(' + (data.args || '') + ') = ' + (data.result || '?');
            }
            return JSON.stringify(data);
        }

        function formatNetworkEvent(msg) {
            const data = msg.data?.payload || msg.data;
            if (typeof data === 'string') return data;
            if (data?.protocol && data?.port) {
                return '[NET] ' + data.protocol.toUpperCase() + ' ' + (data.direction || '→') + ' ' + data.port + ' ' + (data.remote || '');
            }
            return JSON.stringify(data);
        }

        function handleMemoryEvent(msg) {
            const data = msg.data?.payload || msg.data;
            if (data?.usage_mb) {
                document.getElementById('memory-usage').textContent = data.usage_mb.toFixed(1) + ' MB';
                updateGraph('ram', data.usage_mb);
            }
            if (data?.cpu_percent !== undefined) {
                updateGraph('cpu', data.cpu_percent);
            }
            if (data?.pids !== undefined) {
                updateGraph('pids', data.pids);
            }
            addTerminalLine('memory', typeof data === 'string' ? data : JSON.stringify(data));
        }

        function handleSecurityEvent(msg) {
            const data = msg.data?.payload || msg.data;
            const severity = data?.severity || 'low';
            const title = data?.title || data?.message || 'Security event';
            const details = data?.details || data?.description || '';

            addSecurityEvent(severity, title, details);
            addTerminalLine('security', '[' + severity.toUpperCase() + '] ' + title);
        }

        function addTerminalLine(type, message) {
            const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });
            const line = document.getElementById('terminal-output');
            const div = document.createElement('div');
            div.className = 'terminal-line ' + type;
            div.innerHTML = '<span class="timestamp">' + timestamp + '</span> ' +
                           '<span class="type">[' + type.toUpperCase() + ']</span> ' +
                           '<span class="message">' + escapeHtml(message) + '</span>';

            line.appendChild(div);
            state.terminalLines.push(div);
            state.lineCount++;

            while (state.terminalLines.length > CONFIG.MAX_TERMINAL_LINES) {
                const oldLine = state.terminalLines.shift();
                if (oldLine.parentNode) {
                    oldLine.parentNode.removeChild(oldLine);
                }
            }

            document.getElementById('line-count').textContent = state.lineCount + ' lines';
            line.scrollTop = line.scrollHeight;
        }

        function addSecurityEvent(severity, title, details) {
            const eventsList = document.getElementById('events-list');
            const div = document.createElement('div');
            div.className = 'event-item severity-' + severity;

            const time = new Date().toLocaleTimeString('en-US', { hour12: false });

            div.innerHTML = '<span class="event-severity">' + severity + '</span>' +
                           '<div class="event-content">' +
                           '<div class="event-title">' + escapeHtml(title) + '</div>' +
                           '<div class="event-details">' + escapeHtml(details) + '</div>' +
                           '</div>' +
                           '<span class="event-time">' + time + '</span>';

            eventsList.insertBefore(div, eventsList.firstChild);
            state.events.push(div);

            while (state.events.length > CONFIG.MAX_EVENTS) {
                const oldEvent = state.events.shift();
                if (oldEvent.parentNode) {
                    oldEvent.parentNode.removeChild(oldEvent);
                }
            }

            document.getElementById('event-count').textContent = Math.min(state.events.length, CONFIG.MAX_EVENTS) + ' events';
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function updateConnectionStatus(connected) {
            const dot = document.getElementById('status-dot');
            const text = document.getElementById('status-text');

            if (connected) {
                dot.classList.add('connected');
                text.textContent = 'Connected';
                text.style.color = '#00ff88';
            } else {
                dot.classList.remove('connected');
                text.textContent = 'Disconnected';
                text.style.color = '#ff3366';
            }
        }

        function updateStats() {
            const uptime = Math.floor((Date.now() - state.startTime) / 1000);
            const hours = Math.floor(uptime / 3600);
            const minutes = Math.floor((uptime % 3600) / 60);
            const seconds = uptime % 60;

            document.getElementById('uptime').textContent =
                String(hours).padStart(2, '0') + ':' +
                String(minutes).padStart(2, '0') + ':' +
                String(seconds).padStart(2, '0');

            const now = Date.now();
            const elapsed = (now - state.lastEventTime) / 1000;
            if (elapsed >= 1) {
                state.eventsPerSecond = Math.round(state.lineCount / Math.max(1, (now - state.startTime) / 1000));
                document.getElementById('events-per-sec').textContent = state.eventsPerSecond;
            }

            if (state.connected && state.ws?.readyState === WebSocket.OPEN) {
                state.ws.send(JSON.stringify({ type: 'ping', data: { client_time: Date.now() } }));
            }
        }

        function initGraph() {
            const canvas = document.getElementById('graph-canvas');
            const ctx = canvas.getContext('2d');

            function resize() {
                const container = canvas.parentElement;
                canvas.width = container.clientWidth - 20;
                canvas.height = container.clientHeight - 20;
            }

            resize();
            window.addEventListener('resize', resize);

            for (let i = 0; i < CONFIG.GRAPH_POINTS; i++) {
                state.graphData.cpu.push(Math.random() * 30 + 10);
                state.graphData.ram.push(Math.random() * 20 + 30);
                state.graphData.pids.push(Math.random() * 10 + 5);
            }

            drawGraph();
        }

        function updateGraph(type, value) {
            if (state.graphData[type]) {
                state.graphData[type].push(value);
                if (state.graphData[type].length > CONFIG.GRAPH_POINTS) {
                    state.graphData[type].shift();
                }
            }
            drawGraph();
        }

        function drawGraph() {
            const canvas = document.getElementById('graph-canvas');
            const ctx = canvas.getContext('2d');
            const width = canvas.width;
            const height = canvas.height;

            ctx.fillStyle = '#0a0a0f';
            ctx.fillRect(0, 0, width, height);

            ctx.strokeStyle = '#1a1a25';
            ctx.lineWidth = 1;

            for (let i = 0; i <= 10; i++) {
                const y = (height / 10) * i;
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(width, y);
                ctx.stroke();
            }

            for (let i = 0; i <= 10; i++) {
                const x = (width / 10) * i;
                ctx.beginPath();
                ctx.moveTo(x, 0);
                ctx.lineTo(x, height);
                ctx.stroke();
            }

            const datasets = [
                { data: state.graphData.cpu, color: '#00aaff', max: 100 },
                { data: state.graphData.ram, color: '#00ff88', max: 100 },
                { data: state.graphData.pids, color: '#ffcc00', max: 50 }
            ];

            datasets.forEach(function(dataset) {
                if (dataset.data.length < 2) return;

                ctx.strokeStyle = dataset.color;
                ctx.lineWidth = 2;
                ctx.beginPath();

                const step = width / (CONFIG.GRAPH_POINTS - 1);

                for (let i = 0; i < dataset.data.length; i++) {
                    const x = i * step;
                    const y = height - (dataset.data[i] / dataset.max) * height;

                    if (i === 0) {
                        ctx.moveTo(x, y);
                    } else {
                        ctx.lineTo(x, y);
                    }
                }

                ctx.stroke();

                const gradient = ctx.createLinearGradient(0, 0, 0, height);
                gradient.addColorStop(0, dataset.color + '33');
                gradient.addColorStop(1, dataset.color + '00');

                ctx.fillStyle = gradient;
                ctx.lineTo((dataset.data.length - 1) * step, height);
                ctx.lineTo(0, height);
                ctx.closePath();
                ctx.fill();
            });
        }

        function simulateDemoData() {
            if (!state.connected) return;

            const types = ['syscall', 'memory', 'network', 'security'];
            const type = types[Math.floor(Math.random() * types.length)];

            switch (type) {
                case 'syscall':
                    const syscalls = ['read', 'write', 'open', 'close', 'mmap', 'execve', 'socket', 'connect'];
                    const syscall = syscalls[Math.floor(Math.random() * syscalls.length)];
                    addTerminalLine('syscall', '[' + Math.floor(Math.random() * 10000) + '] ' + syscall + '() = ' + Math.floor(Math.random() * 4096));
                    break;

                case 'memory':
                    const usage = Math.random() * 80 + 20;
                    updateGraph('ram', usage);
                    document.getElementById('memory-usage').textContent = usage.toFixed(1) + ' MB';
                    break;

                case 'network':
                    const ports = [80, 443, 8080, 3000, 5432];
                    const port = ports[Math.floor(Math.random() * ports.length)];
                    addTerminalLine('network', '[NET] TCP → ' + port + ' (192.168.1.' + Math.floor(Math.random() * 255) + ')');
                    break;

                case 'security':
                    const events = [
                        { severity: 'low', title: 'Capability dropped', details: 'CAP_NET_RAW dropped for container' },
                        { severity: 'medium', title: 'Memory limit warning', details: 'Usage at 85% of limit' },
                        { severity: 'high', title: 'SECCOMP block', details: 'Blocked syscall: unshare' },
                        { severity: 'critical', title: 'Privilege escalation attempt', details: 'Unexpected setuid call' }
                    ];
                    const event = events[Math.floor(Math.random() * events.length)];
                    addSecurityEvent(event.severity, event.title, event.details);
                    break;
            }

            const cpu = Math.random() * 40 + 10;
            const pids = Math.random() * 15 + 5;
            updateGraph('cpu', cpu);
            updateGraph('pids', pids);
        }

        function init() {
            connect();
            initGraph();
            setInterval(updateStats, 1000);
            setInterval(function() {
                simulateDemoData();
            }, 1500);

            addTerminalLine('system', 'AegisRuntime Dashboard initialized');
            addTerminalLine('system', 'Connecting to audit stream...');
        }

        document.addEventListener('DOMContentLoaded', init);
    </script>
</body>
</html>`

func ServeDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-AegisRuntime-Version", "1.0.0")
	w.Write([]byte(DashboardHTML))
}

func ServeDashboardWithTimestamp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-AegisRuntime-Generated", time.Now().Format(time.RFC3339))
	w.Write([]byte(DashboardHTML))
}
