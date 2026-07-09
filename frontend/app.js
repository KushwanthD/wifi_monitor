/* ══════════════════════════════════════════════════════════════════════════
   WiFi Sentinel – app.js  (v30)
   All-in-one dashboard JS: agent polling, WebSocket, charts, tabs, toasts
   ══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ── Detect base URL ──────────────────────────────────────────────────────────
const BASE_URL = location.origin;

const WS_URL = BASE_URL.replace(/^http/, 'ws') + '/ws/monitor';

// ── Global state ─────────────────────────────────────────────────────────────
let activeAgentId    = localStorage.getItem('activeAgent') || null;
let agentPollTimer   = null;
let currentDevices   = [];
let selectedDevice   = null;
let whitelist        = [];
let blacklist        = [];
let scoreHistChart   = null;
let channelChart     = null;
let currentAlerts    = [];
let ws               = null;
let wsReconnectTimer = null;

// ── DOM shortcuts ─────────────────────────────────────────────────────────────
const $  = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

// ═══════════════════════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    setupTabs();
    setupAgentPanel();
    setupButtons();
    setupDeviceInspector();
    setupThreatFilters();
    connectWebSocket();
    loadWhitelistBlacklist();
    fetchOnlineAgents();
    fetchPublicIP();
    fetchAssets();
    setupReportExports();

    // Auto-restore previous agent session
    if (activeAgentId) {
        setTimeout(() => activateAgent(activeAgentId), 600);
    } else {
        updateBannerVisibility();
    }

    // Periodic fetch of online agents list every 15 s
    setInterval(fetchOnlineAgents, 15000);
});

function updateBannerVisibility() {
    const banner = $('local-status-banner');
    if (!banner) return;
    if (activeAgentId) {
        banner.classList.add('hidden');
    } else {
        banner.classList.remove('hidden');
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TABS
// ═══════════════════════════════════════════════════════════════════════════════
const TAB_META = {
    overview:  { title: 'Security Overview',      subtitle: 'Real-time threat intelligence & Wi-Fi security posture' },
    threats:   { title: 'Threat Center',          subtitle: 'Active security findings with contextual evidence & remediation' },
    assets:    { title: 'Wi-Fi Airspace',         subtitle: 'Detected networks, channel analysis & signal mapping' },
    devices:   { title: 'Subnet Devices',         subtitle: 'Network inventory, access controls & device inspector' },
    inventory:  { title: 'Asset Inventory',        subtitle: 'Managed device and access point expected state definitions' },
    compliance: { title: 'Compliance Center',       subtitle: 'CIS Benchmark checklist and wireless hardening criteria' },
    timeline:  { title: 'Security Timeline',      subtitle: 'Historical security events across all scans' },
    logs:      { title: 'Console Log',            subtitle: 'Live event stream & diagnostic output' },
};

function setupTabs() {
    $$('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
}

function switchTab(tab) {
    $$('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    $$('.tab-panel').forEach(p => p.classList.remove('active'));
    const panel = $(`panel-${tab}`);
    if (panel) panel.classList.add('active');
    $('page-title').textContent    = TAB_META[tab]?.title    || tab;
    $('page-subtitle').textContent = TAB_META[tab]?.subtitle || '';
    if (tab === 'inventory') fetchAssets();
    if (tab === 'compliance') fetchCompliance();
    lucide.createIcons();
}

// ═══════════════════════════════════════════════════════════════════════════════
// WEBSOCKET
// ═══════════════════════════════════════════════════════════════════════════════
function connectWebSocket() {
    if (ws) { try { ws.close(); } catch(e){} }
    clearTimeout(wsReconnectTimer);
    try {
        ws = new WebSocket(WS_URL);
        ws.onopen = () => {
            setWsStatus('online', 'Live feed connected');
            consoleLog('WebSocket connected to monitor.', 'info');
        };
        ws.onmessage = evt => {
            try {
                const msg = JSON.parse(evt.data);
                handleWsMessage(msg);
            } catch(e) {}
        };
        ws.onerror = () => {};
        ws.onclose = () => {
            setWsStatus('offline', 'Reconnecting…');
            wsReconnectTimer = setTimeout(connectWebSocket, 5000);
        };
    } catch(e) {
        wsReconnectTimer = setTimeout(connectWebSocket, 5000);
    }
}

function setWsStatus(state, text) {
    const dot = $('ws-dot');
    const txt = $('ws-status-text');
    if (dot) dot.className = 'ws-dot ' + state;
    if (txt) txt.textContent = text;
}

function handleWsMessage(msg) {
    if (msg.type === 'agent_update') {
        if (msg.agent_id === activeAgentId) {
            renderFullReport(msg);
            fetchCompliance();
        }
    } else if (msg.type === 'alert') {
        showToast(msg.title || 'Alert', msg.message, 'high');
        consoleLog(`[ALERT] ${msg.title}: ${msg.message}`, 'threat');
    } else if (msg.type === 'update') {
        // local mode broadcast
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGENT PANEL
// ═══════════════════════════════════════════════════════════════════════════════
function setupAgentPanel() {
    $('agent-connect-btn').addEventListener('click', () => {
        const id = $('agent-id-input').value.trim().toUpperCase();
        if (id) activateAgent(id);
    });
    $('agent-id-input').addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            const id = $('agent-id-input').value.trim().toUpperCase();
            if (id) activateAgent(id);
        }
    });
    $('agent-disconnect-btn').addEventListener('click', disconnectAgent);
}

function activateAgent(agentId) {
    activeAgentId = agentId.toUpperCase();
    localStorage.setItem('activeAgent', activeAgentId);
    $('agent-id-input').value = '';
    $('agent-active-badge').classList.remove('hidden');
    $('agent-active-text').textContent = activeAgentId;
    $('agent-input-group').style.display = 'none';

    consoleLog(`Agent connected: ${activeAgentId}`, 'info');
    pollAgent();
    clearInterval(agentPollTimer);
    agentPollTimer = setInterval(pollAgent, 8000);
    loadAgentTimeline(activeAgentId);
    fetchCompliance();
    updateBannerVisibility();
}

function disconnectAgent() {
    clearInterval(agentPollTimer);
    activeAgentId = null;
    localStorage.removeItem('activeAgent');
    $('agent-active-badge').classList.add('hidden');
    $('agent-input-group').style.display = 'flex';
    consoleLog('Agent disconnected.', 'warn');
    resetDashboard();
    fetchCompliance();
    updateBannerVisibility();
}

async function pollAgent() {
    if (!activeAgentId) return;
    try {
        const res = await fetch(`${BASE_URL}/api/agent/report/${activeAgentId}`);
        if (!res.ok) {
            if (res.status === 404) consoleLog(`No report yet for agent ${activeAgentId}`, 'warn');
            return;
        }
        const data = await res.json();
        renderFullReport({ agent_id: activeAgentId, ...data });
    } catch (e) {
        consoleLog(`Poll error: ${e.message}`, 'error');
    }
}

async function fetchOnlineAgents() {
    try {
        const res  = await fetch(`${BASE_URL}/api/agent/list`);
        const list = await res.json();
        const cont = $('online-agents-container');
        cont.innerHTML = '';
        list.forEach(id => {
            const chip = document.createElement('button');
            chip.className = 'online-agent-chip';
            chip.textContent = id;
            chip.addEventListener('click', () => activateAgent(id));
            cont.appendChild(chip);
        });
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RENDER FULL REPORT
// ═══════════════════════════════════════════════════════════════════════════════
function renderFullReport(data) {
    const wifi    = data.wifi    || {};
    const devices = data.devices || [];
    const scan    = data.wifi_scan || [];
    const score   = typeof data.security_score === 'number' ? data.security_score : 100;
    const alerts  = data.alerts  || [];
    const history = data.score_history || [];

    currentAlerts  = alerts;
    currentDevices = devices;

    renderScoreRing(score);
    renderKPIs(score, alerts, devices, scan);
    renderProfileCard(wifi);
    renderAlerts(alerts);
    renderScoreChart(history);
    renderAirspace(scan);
    renderDevices(devices);
    updateConnectionPill(wifi);
    updateThreatBadge(alerts);
    consoleLog(`[${activeAgentId}] Score: ${score} | Alerts: ${alerts.length} | Devices: ${devices.length} | Nearby: ${scan.length}`, 'ok');

    // Also reload persistent timeline alerts
    loadAgentTimeline(activeAgentId);
}

// ═══════════════════════════════════════════════════════════════════════════════
// KPIs
// ═══════════════════════════════════════════════════════════════════════════════
function renderKPIs(score, alerts, devices, scan) {
    $('kpi-score-val').textContent    = score + '%';
    $('kpi-threats-val').textContent  = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;
    $('kpi-devices-val').textContent  = devices.length;
    $('kpi-networks-val').textContent = scan.length;

    const kpiScore = $('kpi-score');
    if (kpiScore) {
        kpiScore.style.borderColor = score >= 80 ? 'rgba(34,197,94,0.3)'
            : score >= 60 ? 'rgba(234,179,8,0.3)' : 'rgba(239,68,68,0.3)';
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORE RING
// ═══════════════════════════════════════════════════════════════════════════════
function renderScoreRing(score) {
    const ring = $('ring-fill');
    const num  = $('score-num');
    const lbl  = $('score-label');
    const badge = $('score-grade-badge');
    const circumference = 314.16;

    if (!ring) return;
    const offset = circumference - (score / 100) * circumference;
    ring.style.strokeDashoffset = offset;
    ring.style.stroke = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : '#ef4444';
    num.textContent = score;

    let label, grade;
    if (score >= 90)      { label = 'Excellent – Hardened'; grade = 'A+'; }
    else if (score >= 80) { label = 'Good – Minor Risks'; grade = 'A'; }
    else if (score >= 70) { label = 'Fair – Attention Needed'; grade = 'B'; }
    else if (score >= 55) { label = 'Poor – Active Risks'; grade = 'C'; }
    else if (score >= 30) { label = 'Bad – Threats Detected'; grade = 'D'; }
    else                  { label = 'Critical – Immediate Action'; grade = 'F'; }

    lbl.textContent = label;
    if (badge) badge.textContent = 'Grade ' + grade;
    $('kpi-score-val').textContent = score + '%';
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE CARD
// ═══════════════════════════════════════════════════════════════════════════════
function renderProfileCard(wifi) {
    const set = (id, val) => { const el = $(id); if(el) el.textContent = val || '--'; };
    set('pr-ssid',    wifi.ssid);
    set('pr-bssid',   wifi.bssid);
    set('pr-auth',    wifi.authentication);
    set('pr-cipher',  wifi.cipher);
    set('pr-band',    [wifi.band, wifi.channel].filter(Boolean).join(' / ch'));
    set('pr-signal',  wifi.signal ? wifi.signal + '%' : '--');
    set('pr-radio',   wifi.radio_type);
    set('pr-mac',     wifi.mac_address);
    set('pr-rate',    wifi.receive_rate && wifi.transmit_rate
            ? `${wifi.receive_rate}↓ / ${wifi.transmit_rate}↑ Mbps` : '--');
    set('pr-level',   wifi.security_level);
    set('pr-adapter', wifi.description || wifi.interface_name);
    const hasPwd = wifi.password_protected === true ? '✅ Yes' : wifi.password_protected === false ? '🚫 No' : '--';
    set('pr-password',     hasPwd);
    set('pr-password-box', hasPwd);
    set('pr-enc',     wifi.encryption_strength);
    set('pr-status',  wifi.status);

    // Connection pill
    updateConnectionPill(wifi);
}

function updateConnectionPill(wifi) {
    const pill = $('conn-pill');
    const txt  = $('conn-pill-text');
    const icon = $('conn-pill-icon');
    if (!pill) return;
    if (wifi.ssid && wifi.status !== 'disconnected') {
        pill.classList.add('connected');
        txt.textContent = wifi.ssid;
        if (icon) icon.setAttribute('data-lucide', 'wifi');
    } else {
        pill.classList.remove('connected');
        txt.textContent = 'Disconnected';
        if (icon) icon.setAttribute('data-lucide', 'wifi-off');
    }
    lucide.createIcons();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALERTS
// ═══════════════════════════════════════════════════════════════════════════════
function renderAlerts(alerts) {
    const cont  = $('alerts-container');
    const badge = $('alert-count');
    if (!cont) return;

    if (!alerts.length) {
        cont.innerHTML = `
          <div class="empty-state">
            <i data-lucide="shield-check" class="empty-icon ok"></i>
            <p>No active threats detected.</p>
          </div>`;
        badge.textContent = '0';
        lucide.createIcons();
        renderThreatList(alerts);
        return;
    }

    badge.textContent = alerts.length;
    cont.innerHTML = alerts.map(a => `
      <div class="alert-item ${a.severity || 'info'}">
        <div class="alert-hdr">
          <span class="alert-sev-tag ${a.severity || 'info'}">${a.severity?.toUpperCase() || 'INFO'}</span>
          <span class="alert-category">${escHtml(a.category || '')}</span>
        </div>
        <div class="alert-msg">${escHtml(a.message || '')}</div>
      </div>`).join('');
    lucide.createIcons();

    // Also update Threat Center
    renderThreatList(alerts);
}

function renderThreatList(alerts, filterSev = 'all') {
    const list = $('threat-list');
    if (!list) return;

    const filtered = filterSev === 'all' ? alerts
        : alerts.filter(a => a.severity === filterSev);

    if (!filtered.length) {
        list.innerHTML = `<div class="empty-state">
            <i data-lucide="shield-check" class="empty-icon ok"></i>
            <p>${filterSev === 'all' ? 'No threats detected.' : 'No ' + filterSev + '-severity threats.'}</p>
          </div>`;
        lucide.createIcons();
        return;
    }

    list.innerHTML = filtered.map((a, i) => `
      <div class="threat-card ${a.severity || 'info'}" id="tc-${i}">
        <div class="threat-hdr">
          <div class="threat-hdr-left">
            <span class="threat-sev-dot"></span>
            <div>
              <div class="threat-cat">${escHtml(a.category || '')}</div>
              <div class="threat-ts">${a.ts ? fmtTime(a.ts) : 'Just now'}</div>
            </div>
          </div>
          <span class="alert-sev-tag ${a.severity}">${(a.severity || 'INFO').toUpperCase()}</span>
        </div>
        <div class="threat-msg">${escHtml(a.message || '')}</div>
        ${a.evidence && Object.keys(a.evidence).length ? `
          <details style="margin-top:8px;">
            <summary style="font-size:0.75rem;color:var(--text-muted);cursor:pointer;">Evidence</summary>
            <pre style="font-size:0.72rem;color:var(--text-secondary);margin-top:6px;white-space:pre-wrap;">${escHtml(JSON.stringify(a.evidence, null, 2))}</pre>
          </details>` : ''}
      </div>`).join('');
    lucide.createIcons();
}

function updateThreatBadge(alerts) {
    const critical = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;
    const badge = $('threat-badge');
    if (!badge) return;
    badge.textContent = critical;
    badge.classList.toggle('hidden', critical === 0);
}

function setupThreatFilters() {
    $$('.filter-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            $$('.filter-chip').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            renderThreatList(currentAlerts, chip.dataset.sev);
        });
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORE HISTORY CHART
// ═══════════════════════════════════════════════════════════════════════════════
function renderScoreChart(history) {
    const canvas = $('score-history-chart');
    if (!canvas) return;
    const labels = history.map(h => fmtTime(h.ts, true));
    const values = history.map(h => h.score);

    if (scoreHistChart) { scoreHistChart.destroy(); scoreHistChart = null; }

    scoreHistChart = new Chart(canvas, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Security Score',
                data: values,
                borderColor: '#22d3ee',
                backgroundColor: 'rgba(34,211,238,0.08)',
                borderWidth: 2,
                pointBackgroundColor: values.map(v =>
                    v >= 80 ? '#22c55e' : v >= 60 ? '#eab308' : '#ef4444'),
                pointRadius: 4,
                tension: 0.4,
                fill: true,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: {
                backgroundColor: '#0b1221',
                borderColor: 'rgba(255,255,255,0.08)',
                borderWidth: 1,
            }},
            scales: {
                x: { ticks: { color: '#4b5563', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' }},
                y: { min: 0, max: 100, ticks: { color: '#4b5563', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' }}
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// AIRSPACE / WI-FI SCAN
// ═══════════════════════════════════════════════════════════════════════════════
function renderAirspace(networks) {
    const tbody = $('airspace-tbody');
    if (!tbody) return;

    renderChannelChart(networks);

    if (!networks.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="tbl-loading">No networks detected yet.</td></tr>';
        return;
    }

    tbody.innerHTML = networks.map(n => {
        const auth = n.authentication || 'Unknown';
        const risk = calcNetworkRisk(auth);
        const sig  = n.signal || 0;
        const barW = sig + '%';
        const barCls = sig < 40 ? 'weak' : sig < 70 ? 'medium' : '';
        return `
          <tr>
            <td style="font-weight:600;">${escHtml(n.ssid || '[Hidden]')}</td>
            <td class="mono" style="font-size:0.75rem;color:var(--text-muted);">${escHtml(n.bssid || '--')}</td>
            <td>${n.channel || '--'}</td>
            <td style="max-width:180px;">
              <span style="font-size:0.75rem;">${escHtml(auth)}</span>
              ${n.encryption ? `<br><span style="font-size:0.68rem;color:var(--text-muted);">${escHtml(n.encryption)}</span>` : ''}
            </td>
            <td>
              <div class="signal-bar">
                <div class="signal-bar-track">
                  <div class="signal-bar-fill ${barCls}" style="width:${barW}"></div>
                </div>
                <span>${sig}%</span>
              </div>
            </td>
            <td><span class="risk-badge ${risk.cls}">${risk.label}</span></td>
          </tr>`;
    }).join('');
}

function calcNetworkRisk(auth) {
    const a = (auth || '').toUpperCase();
    if (a.includes('OPEN') || a.includes('NONE') || a === '')
        return { cls: 'critical', label: 'OPEN' };
    if (a.includes('WEP')) return { cls: 'high', label: 'WEP' };
    if (a.includes('WPA') && !a.includes('WPA2') && !a.includes('WPA3'))
        return { cls: 'medium', label: 'WPA' };
    if (a.includes('WPA2')) return { cls: 'secure', label: 'WPA2' };
    if (a.includes('WPA3')) return { cls: 'secure', label: 'WPA3' };
    return { cls: 'medium', label: 'Unknown' };
}

function renderChannelChart(networks) {
    const canvas = $('wifi-channel-chart');
    if (!canvas) return;
    if (channelChart) { channelChart.destroy(); channelChart = null; }

    const chMap = {};
    networks.forEach(n => {
        const ch = parseInt(n.channel) || 0;
        if (!chMap[ch]) chMap[ch] = [];
        chMap[ch].push(n.signal || 0);
    });
    const channels = Object.keys(chMap).sort((a,b) => a-b);
    const avgSigs  = channels.map(ch => Math.round(chMap[ch].reduce((a,b)=>a+b,0)/chMap[ch].length));

    channelChart = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: channels.map(c => 'Ch ' + c),
            datasets: [{
                label: 'Avg Signal %',
                data: avgSigs,
                backgroundColor: channels.map((_, i) =>
                    [1,6,11].includes(parseInt(channels[i]))
                        ? 'rgba(34,211,238,0.6)' : 'rgba(59,130,246,0.4)'),
                borderColor: 'rgba(34,211,238,0.8)',
                borderWidth: 1,
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { backgroundColor: '#0b1221', borderColor: 'rgba(255,255,255,0.08)', borderWidth: 1 }
            },
            scales: {
                x: { ticks: { color: '#94a3b8', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.04)' }},
                y: { min: 0, max: 100, ticks: { color: '#4b5563' }, grid: { color: 'rgba(255,255,255,0.04)' }}
            }
        }
    });
}

// Scan airspace button
document.addEventListener('DOMContentLoaded', () => {
    const btn = $('scan-wifi-btn');
    if (btn) btn.addEventListener('click', () => {
        if (activeAgentId) { pollAgent(); showToast('Scanning', 'Airspace scan triggered.', 'info'); }
        else showToast('No Agent', 'Connect an agent first.', 'medium');
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DEVICES
// ═══════════════════════════════════════════════════════════════════════════════
function renderDevices(devices) {
    currentDevices = devices;
    const tbody = $('devices-tbody');
    if (!tbody) return;

    // Stats
    const total   = devices.length;
    const wl      = devices.filter(d => d.is_whitelisted).length;
    const bl      = devices.filter(d => d.is_blacklisted).length;
    const unauth  = devices.filter(d => !d.is_host && !d.is_whitelisted && !d.is_blacklisted).length;

    const set = (id, v) => { const el=$(id); if(el) el.textContent = v; };
    set('stat-total',  total);
    set('stat-wl',     wl);
    set('stat-unauth', unauth);
    set('stat-bl',     bl);

    // Update dropdown in inspector
    updateDeviceDropdown(devices);

    if (!devices.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="tbl-loading">No devices found.</td></tr>';
        return;
    }

    tbody.innerHTML = devices.map(d => {
        let statusCls, statusLabel;
        if (d.is_host)        { statusCls = 'host';    statusLabel = 'This Host'; }
        else if (d.is_blacklisted) { statusCls = 'blocked'; statusLabel = 'Blacklisted'; }
        else if (d.is_whitelisted) { statusCls = 'approved'; statusLabel = 'Approved'; }
        else                   { statusCls = 'unknown'; statusLabel = 'Unknown'; }

        const lat = d.latency_ms !== null && d.latency_ms !== undefined && d.latency_ms !== 'ERR'
            ? `${d.latency_ms}ms` : '--';

        return `
          <tr style="cursor:pointer;" onclick="selectDevice('${escHtml(d.mac)}')">
            <td><span class="status-dot ${statusCls}">${statusLabel}</span></td>
            <td class="mono" style="color:var(--cyan)">${escHtml(d.ip)}</td>
            <td style="color:var(--text-secondary);font-size:0.75rem;">${escHtml(d.hostname || '--')}</td>
            <td class="mono" style="font-size:0.78rem;">${escHtml(d.mac)}</td>
            <td style="font-size:0.8rem;">${escHtml(d.vendor || '--')}</td>
            <td style="color:${lat === '--' ? 'var(--text-muted)' : 'var(--green)'};">${lat}</td>
            <td>
              ${!d.is_host ? `
                <button class="tbl-btn approve" onclick="event.stopPropagation();whitelistDevice('${escHtml(d.mac)}')">✓</button>
                <button class="tbl-btn block"   onclick="event.stopPropagation();blacklistDevice('${escHtml(d.mac)}')">✕</button>
              ` : '<span style="color:var(--text-muted);font-size:0.75rem;">Host</span>'}
            </td>
          </tr>`;
    }).join('');
}

function updateDeviceDropdown(devices) {
    // Updates the inspector if a device is selected
    if (selectedDevice) {
        const found = devices.find(d => d.mac === selectedDevice.mac);
        if (found) populateInspector(found);
    }
}

window.selectDevice = function(mac) {
    const d = currentDevices.find(d => d.mac === mac);
    if (d) { selectedDevice = d; populateInspector(d); switchTab('devices'); }
};

function populateInspector(d) {
    const set = (id, v) => { const el=$(id); if(el) el.textContent = v || '--'; };
    set('insp-ip',       d.ip);
    set('insp-mac',      d.mac);
    set('insp-hostname', d.hostname || '--');
    set('insp-vendor',   d.vendor);
    const lat = d.latency_ms !== null && d.latency_ms !== 'ERR' ? d.latency_ms + 'ms' : '--';
    set('insp-latency',  lat);

    $('insp-approve-btn').disabled = d.is_host;
    $('insp-block-btn').disabled   = d.is_host;
    $('insp-ping-btn').disabled    = false;
    const promoteBtn = $('insp-promote-btn');
    if (promoteBtn) promoteBtn.disabled = false;

    // Router guide
    const routerLink = $('router-link');
    const routerMac  = $('router-block-mac');
    if (routerLink) {
        const gw = currentDevices.find(x => x.is_host);
        const gwBase = gw ? gw.ip.split('.').slice(0,3).join('.') + '.1' : '192.168.1.1';
        routerLink.href = 'http://' + gwBase;
        routerLink.textContent = gwBase;
    }
    if (routerMac) routerMac.textContent = d.mac;
}

function setupDeviceInspector() {
    $('insp-approve-btn')?.addEventListener('click', () => {
        if (selectedDevice) { whitelistDevice(selectedDevice.mac); }
    });
    $('insp-block-btn')?.addEventListener('click', () => {
        if (selectedDevice) { blacklistDevice(selectedDevice.mac); }
    });
    $('insp-ping-btn')?.addEventListener('click', async () => {
        if (!selectedDevice) return;
        const btn = $('insp-ping-btn');
        btn.disabled = true;
        btn.textContent = 'Pinging…';
        
        let data = null;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 1200);
            let res = null;
            try {
                res = await fetch(`http://127.0.0.1:8000/api/network/ping?ip=${selectedDevice.ip}`, { signal: controller.signal });
                clearTimeout(timeoutId);
            } catch(err) {
                // Fallback to current domain server (e.g. Render)
                res = await fetch(`${BASE_URL}/api/network/ping?ip=${selectedDevice.ip}`);
            }
            data = await res.json();
            
            const el = $('insp-latency');
            if (data.status === 'online') {
                if (el) el.textContent = data.latency_ms + 'ms';
                showToast('Ping Success', `${selectedDevice.ip} responded in ${data.latency_ms}ms`, 'success');
            } else {
                if (el) el.textContent = 'Offline';
                showToast('Ping Failed', `${selectedDevice.ip} is unreachable.`, 'medium');
            }
        } catch(e) {
            showToast('Ping Error', e.message, 'high');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i data-lucide="activity"></i> Ping';
            lucide.createIcons();
        }
    });

    $('insp-promote-btn')?.addEventListener('click', () => {
        if (selectedDevice) {
            $('asset-mac').value = selectedDevice.mac;
            $('asset-name').value = selectedDevice.hostname || selectedDevice.vendor || 'Discovered Subnet Node';
            $('asset-type').value = 'device';
            $('asset-vendor').value = selectedDevice.vendor || 'Unknown';
            switchTab('inventory');
        }
    });

    $('scan-devices-btn')?.addEventListener('click', () => {
        if (activeAgentId) { pollAgent(); showToast('Scanning', 'Subnet map triggered.', 'info'); }
        else showToast('No Agent', 'Connect an agent first.', 'medium');
    });
}

window.whitelistDevice = async function(mac) {
    whitelist = [...new Set([...whitelist, mac.toUpperCase()])];
    blacklist = blacklist.filter(m => m !== mac.toUpperCase());
    await saveWhitelistBlacklist();
    showToast('Approved', `Device ${mac} whitelisted.`, 'success');
    pollAgent();
};

window.blacklistDevice = async function(mac) {
    blacklist = [...new Set([...blacklist, mac.toUpperCase()])];
    whitelist = whitelist.filter(m => m !== mac.toUpperCase());
    await saveWhitelistBlacklist();
    showToast('Blocked', `Device ${mac} blacklisted.`, 'high');
    pollAgent();
};

async function loadWhitelistBlacklist() {
    try {
        const [wlRes, blRes] = await Promise.all([
            fetch(`${BASE_URL}/api/whitelist`),
            fetch(`${BASE_URL}/api/blacklist`)
        ]);
        whitelist = await wlRes.json();
        blacklist = await blRes.json();
    } catch(e) {}
}

async function saveWhitelistBlacklist() {
    try {
        await fetch(`${BASE_URL}/api/whitelist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ macs: whitelist })
        });
        await fetch(`${BASE_URL}/api/blacklist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ macs: blacklist })
        });
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY TIMELINE
// ═══════════════════════════════════════════════════════════════════════════════
async function loadAgentTimeline(agentId) {
    if (!agentId) return;
    const lbl = $('timeline-agent-label');
    if (lbl) lbl.textContent = agentId;
    try {
        const res  = await fetch(`${BASE_URL}/api/alerts/${agentId}?limit=100`);
        const data = await res.json();
        renderTimeline(data);
    } catch(e) {}
}

function renderTimeline(events) {
    const list = $('timeline-list');
    if (!list) return;
    if (!events.length) {
        list.innerHTML = `<div class="empty-state">
            <i data-lucide="clock" class="empty-icon"></i>
            <p>No historical events yet.</p></div>`;
        lucide.createIcons();
        return;
    }
    list.innerHTML = events.map((e, i) => `
      <div class="timeline-item">
        <div class="timeline-marker">
          <div class="timeline-dot ${e.severity || 'info'}"></div>
          ${i < events.length - 1 ? '<div class="timeline-line"></div>' : ''}
        </div>
        <div class="timeline-content">
          <div class="timeline-meta">
            <span class="alert-sev-tag ${e.severity}">${(e.severity||'info').toUpperCase()}</span>
            <span class="timeline-cat">${escHtml(e.category || '')}</span>
            <span class="timeline-time">${fmtTime(e.ts)}</span>
          </div>
          <div class="timeline-msg">${escHtml(e.message || '')}</div>
        </div>
      </div>`).join('');
    lucide.createIcons();
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUTTONS / GLOBAL ACTIONS
// ═══════════════════════════════════════════════════════════════════════════════
function setupButtons() {
    $('global-refresh-btn')?.addEventListener('click', async () => {
        const icon = $('refresh-icon');
        if (icon) { icon.style.animation = 'spin 1s linear infinite'; }
        try {
            if (activeAgentId) { await pollAgent(); }
            else {
                // local mode
                await Promise.all([
                    fetch(`${BASE_URL}/api/wifi/connection`).then(r=>r.json()).then(renderProfileCard),
                    fetch(`${BASE_URL}/api/network/devices`).then(r=>r.json()).then(d=>renderDevices(d.devices||[])),
                    fetch(`${BASE_URL}/api/security/audit`).then(r=>r.json()).then(data=>{
                        renderScoreRing(data.security_score || 0);
                        renderAlerts(data.alerts || []);
                    }),
                    fetch(`${BASE_URL}/api/wifi/scan`).then(r=>r.json()).then(d=>renderAirspace(d.networks||[]))
                ]);
            }
            showToast('Audit Complete', 'Security scan finished.', 'success');
        } catch(e) {
            showToast('Audit Error', e.message, 'high');
        } finally {
            if (icon) icon.style.animation = '';
        }
    });

    $('clear-console-btn')?.addEventListener('click', () => {
        const box = $('console-stream');
        if (box) box.innerHTML = '<div class="cline sys">[SYSTEM] Console cleared.</div>';
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC IP
// ═══════════════════════════════════════════════════════════════════════════════
async function fetchPublicIP() {
    try {
        const res  = await fetch('https://ipapi.co/json/', { signal: AbortSignal.timeout(5000) });
        const data = await res.json();
        const set = (id, v) => { const el=$(id); if(el) el.textContent = v||'--'; };
        set('pub-ip',  data.ip);
        set('pub-isp', data.org || data.asn);
    } catch(e) {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESET
// ═══════════════════════════════════════════════════════════════════════════════
function resetDashboard() {
    ['score-num','pr-ssid','pr-bssid','pr-auth','pr-cipher','pr-band',
     'pr-signal','pr-radio','pr-mac','pr-rate','pr-level',
     'pr-adapter','pr-password','pr-enc','pr-status',
     'kpi-score-val','kpi-threats-val','kpi-devices-val','kpi-networks-val',
     'stat-total','stat-wl','stat-unauth','stat-bl'].forEach(id => {
        const el = $(id); if (el) el.textContent = '--';
    });
    const ring = $('ring-fill');
    if (ring) ring.style.strokeDashoffset = '314.16';

    const ac = $('alerts-container');
    if (ac) ac.innerHTML = `<div class="empty-state"><i data-lucide="shield-check" class="empty-icon ok"></i><p>No active threats.</p></div>`;

    currentAlerts = []; currentDevices = []; selectedDevice = null;
    lucide.createIcons();
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOASTS
// ═══════════════════════════════════════════════════════════════════════════════
function showToast(title, msg, sev = 'info') {
    const area = $('toast-area');
    if (!area) return;
    const toast = document.createElement('div');
    toast.className = `toast ${sev}`;
    toast.innerHTML = `
      <div class="toast-body">
        <strong>${escHtml(title)}</strong>
        <span>${escHtml(msg)}</span>
      </div>
      <button class="toast-close" onclick="this.parentElement.remove()">✕</button>`;
    area.appendChild(toast);
    setTimeout(() => toast.remove(), 7000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSOLE LOG
// ═══════════════════════════════════════════════════════════════════════════════
function consoleLog(msg, cls = 'sys') {
    const box = $('console-stream');
    if (!box) return;
    const ts   = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = `cline ${cls}`;
    line.textContent = `[${ts}] ${msg}`;
    box.appendChild(line);
    box.scrollTop = box.scrollHeight;
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ═══════════════════════════════════════════════════════════════════════════════
function escHtml(str) {
    if (typeof str !== 'string') str = String(str || '');
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtTime(iso, short = false) {
    try {
        const d = new Date(iso);
        if (short) return d.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
        return d.toLocaleString([], { month:'short', day:'numeric',
            hour:'2-digit', minute:'2-digit', second:'2-digit' });
    } catch(e) { return iso || ''; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ASSETS & COMPLIANCE & REPORTS
// ═══════════════════════════════════════════════════════════════════════════════
window.saveAsset = async function() {
    const payload = {
        mac: $('asset-mac').value.trim().toUpperCase(),
        name: $('asset-name').value.trim(),
        type: $('asset-type').value,
        expected_vendor: $('asset-vendor').value.trim() || null,
        expected_channel: $('asset-channel').value.trim() || null,
        expected_encryption: $('asset-encryption').value.trim() || null,
        location: $('asset-location').value.trim() || null,
        owner: $('asset-owner').value.trim() || null,
        notes: ''
    };
    try {
        const res = await fetch(`${BASE_URL}/api/assets`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            showToast('Asset Saved', `Asset ${payload.name} registered.`, 'success');
            $('asset-form').reset();
            fetchAssets();
            if (activeAgentId) pollAgent();
        }
    } catch(e) {
        showToast('Error', 'Failed to save asset.', 'high');
    }
};

window.fetchAssets = async function() {
    const tbody = $('assets-tbody');
    if (!tbody) return;
    try {
        const res = await fetch(`${BASE_URL}/api/assets`);
        const list = await res.json();
        if (!list.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No assets registered yet.</td></tr>';
            return;
        }
        tbody.innerHTML = list.map(a => {
            const exp = [];
            if (a.expected_vendor) exp.push(`Vendor: ${a.expected_vendor}`);
            if (a.expected_channel) exp.push(`Ch: ${a.expected_channel}`);
            if (a.expected_encryption) exp.push(`Security: ${a.expected_encryption}`);
            return `
              <tr>
                <td><strong>${escHtml(a.name)}</strong></td>
                <td class="mono" style="font-size:0.75rem; color:var(--cyan);">${escHtml(a.mac)}</td>
                <td><span style="font-size:0.72rem; text-transform:uppercase; color:var(--text-secondary);">${escHtml(a.type)}</span></td>
                <td style="font-size:0.78rem; color:var(--text-secondary);">${escHtml(exp.join(' | ') || 'None')}</td>
                <td><button class="tbl-btn block" onclick="window.deleteAsset('${escHtml(a.mac)}')">Remove</button></td>
              </tr>`;
        }).join('');
    } catch(e) {}
};

window.deleteAsset = async function(mac) {
    if (!confirm(`Are you sure you want to remove asset ${mac}?`)) return;
    try {
        const res = await fetch(`${BASE_URL}/api/assets/${mac}`, { method: 'DELETE' });
        if (res.ok) {
            showToast('Removed', 'Asset removed successfully.', 'success');
            fetchAssets();
            if (activeAgentId) pollAgent();
        }
    } catch(e) {}
};

window.fetchCompliance = async function() {
    if (!activeAgentId) {
        $('comp-score-val').textContent = '--%';
        $('compliance-checklist-container').innerHTML = '<div class="empty-state"><i data-lucide="info" class="empty-icon"></i><p>Connect an agent to check compliance.</p></div>';
        lucide.createIcons();
        return;
    }
    try {
        const res = await fetch(`${BASE_URL}/api/compliance/${activeAgentId}`);
        const data = await res.json();
        
        const score = data.score || 0;
        $('comp-score-val').textContent = score + '%';
        
        const ring = $('comp-ring-fill');
        if (ring) {
            const circumference = 314.16;
            ring.style.strokeDashoffset = circumference - (score / 100) * circumference;
            ring.style.stroke = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : '#ef4444';
        }
        
        const checks = [
            { name: 'WPA3 Personal Protocol Preferred', status: data.wpa3_status, rec: 'Enable WPA3-Personal encryption key on your router.', details: 'WPA3 prevents modern brute-force offline handshake decryption.' },
            { name: 'WPS Secure (Disabled/Inactive)', status: data.wps_status, rec: 'Disable WPS in wireless admin configurations.', details: 'Wi-Fi Protected Setup PIN brute-forcing allows complete network intrusion.' },
            { name: 'Management Frame Protection (PMF) Active', status: data.pmf_status, rec: 'Set PMF to Required or Capable under security settings.', details: 'PMF prevents attackers from sending spoofed deauthentication packets.' },
            { name: 'Non-Default SSID Configuration', status: data.default_ssid_status, rec: 'Rename your SSID to a custom pattern that hides manufacturer.', details: 'Default names (e.g. NETGEAR, TP-LINK) invite target profile lookups.' },
            { name: 'Secure Encrypted Workspace Connection', status: data.open_network_status, rec: 'Ensure local network has WPA2/WPA3 passwords.', details: 'Connecting to Open/WEP hotspots exposes your traffic to local capture.' }
        ];
        
        const container = $('compliance-checklist-container');
        if (container) {
            container.innerHTML = checks.map(c => `
              <div class="threat-card ${c.status ? 'low' : 'critical'}">
                <div class="threat-hdr">
                  <div class="threat-hdr-left">
                    <span class="threat-sev-dot"></span>
                    <div class="threat-cat">${escHtml(c.name)}</div>
                  </div>
                  <span class="alert-sev-tag ${c.status ? 'low' : 'critical'}">${c.status ? 'COMPLIANT' : 'NON-COMPLIANT'}</span>
                </div>
                <div class="threat-msg">${escHtml(c.details)}</div>
                ${!c.status ? `<div class="remediation" style="margin-top:8px;"><strong>Fix Action:</strong> ${escHtml(c.rec)}</div>` : ''}
              </div>`).join('');
            lucide.createIcons();
        }
    } catch(e) {}
};

function setupReportExports() {
    $('export-html-btn')?.addEventListener('click', () => {
        if (!activeAgentId) { showToast('No Agent', 'Connect an agent to export reports.', 'medium'); return; }
        window.open(`${BASE_URL}/api/reports/export/${activeAgentId}?format=html`, '_blank');
    });
    $('export-csv-btn')?.addEventListener('click', () => {
        if (!activeAgentId) { showToast('No Agent', 'Connect an agent to export data.', 'medium'); return; }
        window.open(`${BASE_URL}/api/reports/export/${activeAgentId}?format=csv`, '_blank');
    });
}
