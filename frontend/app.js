// WiFi Monitor Application Controller - Vanilla Javascript Engine

document.addEventListener("DOMContentLoaded", () => {
    // State management
    function safeCreateIcons(options) {
        if (typeof lucide !== "undefined" && lucide && typeof lucide.createIcons === "function") {
            try {
                lucide.createIcons(options);
            } catch (e) {
                console.error("Lucide creation error:", e);
            }
        }
    }

    let state = {
        activeTab: "dashboard",
        wifiConnection: {},
        scanResults: [],
        devices: [],
        whitelist: [],
        blacklist: [],
        auditData: {},
        channelChart: null,
        wsConn: null,
        selectedThreatMac: ""
    };

    let apiHost = "";
    const localStatusBanner = document.getElementById("local-status-banner");

    async function detectLocalServer() {
        if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
            apiHost = "";
            if (localStatusBanner) localStatusBanner.classList.add("hidden");
            return true;
        }

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 1200);
            
            const res = await fetch("http://127.0.0.1:8000/api/wifi/connection", {
                signal: controller.signal,
                headers: { "Accept": "application/json" }
            });
            clearTimeout(timeoutId);
            
            if (res.ok) {
                const data = await res.json();
                if (data && !data.error) {
                    apiHost = "http://127.0.0.1:8000";
                    if (localStatusBanner) localStatusBanner.classList.add("hidden");
                    logToConsole("Local scan agent auto-detected at 127.0.0.1:8000! Connecting...", "system");
                    return true;
                }
            }
        } catch (e) {
            // Not running
        }

        apiHost = "";
        if (localStatusBanner) localStatusBanner.classList.remove("hidden");
        logToConsole("Local scan agent is offline. Visualizing cloud mock mode.", "system");
        return false;
    }

    // DOM Elements
    const navItems = document.querySelectorAll(".nav-item");
    const tabPanels = document.querySelectorAll(".tab-panel");
    const currentTabTitle = document.getElementById("current-tab-title");
    const currentTabSubtitle = document.getElementById("current-tab-subtitle");
    
    const wsStatusText = document.getElementById("ws-status-text");
    const wsStatusDot = document.querySelector(".status-indicator-dot");
    const headerConnectionBadge = document.getElementById("header-connection-badge");
    
    // Buttons
    const globalRefreshBtn = document.getElementById("global-refresh-btn");
    const refreshIcon = document.getElementById("refresh-icon");
    const scanWifiBtn = document.getElementById("scan-wifi-btn");
    const scanDevicesBtn = document.getElementById("scan-devices-btn");
    const clearConsoleBtn = document.getElementById("clear-console-btn");
    
    // Tab 1: Dashboard Elements
    const scoreNumber = document.getElementById("score-number");
    const scoreText = document.getElementById("score-text");
    const ringProgress = document.getElementById("security-ring-progress");
    const profileCipher = document.getElementById("profile-cipher");
    const profileGateway = document.getElementById("profile-gateway");
    const profileStatus = document.getElementById("profile-status");
    const profileAdapter = document.getElementById("profile-adapter");
    const profileMac = document.getElementById("profile-mac");
    const profileRadio = document.getElementById("profile-radio");
    const profileAuth = document.getElementById("profile-auth");
    const profilePassword = document.getElementById("profile-password");
    const profileLevel = document.getElementById("profile-level");
    const profileStrength = document.getElementById("profile-strength");
    const connSsid = document.getElementById("conn-ssid");
    const connBssid = document.getElementById("conn-bssid");
    const connSignal = document.getElementById("conn-signal");
    const connChannelBand = document.getElementById("conn-channel-band");
    const connRate = document.getElementById("conn-rate");
    const pubIp = document.getElementById("pub-ip");
    const pubIsp = document.getElementById("pub-isp");
    const alertsContainer = document.getElementById("alerts-container");
    const alertCountBadge = document.getElementById("alert-count-badge");
    
    // Agent ID Connection Elements
    const agentIdInput = document.getElementById("agent-id-input");
    const agentConnectBtn = document.getElementById("agent-connect-btn");
    const agentDisconnectBtn = document.getElementById("agent-disconnect-btn");
    const agentActiveBadge = document.getElementById("agent-active-badge");
    const agentActiveText = document.getElementById("agent-active-text");
    const agentInputGroup = document.getElementById("agent-input-group");
    let connectedAgentId = localStorage.getItem("wifi_monitor_agent_id") || "";
    
    // Tab 2: WiFi Inspector Elements
    const wifiScanTbody = document.getElementById("wifi-scan-tbody");
    
    // Tab 3: Subnet Devices Elements
    const devicesTbody = document.getElementById("devices-tbody");
    const statActiveHosts = document.getElementById("stat-active-hosts");
    const statWhitelisted = document.getElementById("stat-whitelisted");
    const statUnauthorized = document.getElementById("stat-unauthorized");

    // Tab: Threat Center Elements
    const threatDeviceSelect = document.getElementById("threat-device-select");
    const threatIp = document.getElementById("threat-ip");
    const threatMac = document.getElementById("threat-mac");
    const threatVendor = document.getElementById("threat-vendor");
    const threatStatusBadge = document.getElementById("threat-status-badge");
    const pingTestBtn = document.getElementById("ping-test-btn");
    const latencyValue = document.getElementById("latency-value");
    const latencyStatusText = document.getElementById("latency-status-text");
    const threatApproveBtn = document.getElementById("threat-approve-btn");
    const threatBlockBtn = document.getElementById("threat-block-btn");
    const routerGatewayLink = document.getElementById("router-gateway-link");
    const routerBlockMacVal = document.getElementById("router-block-mac-val");
    
    // Tab 4: Console
    const consoleStream = document.getElementById("console-stream");
    const toastArea = document.getElementById("toast-area");

    // Initialize Lucide Icons
    safeCreateIcons();

    // Tab Switching Logic
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const targetTab = item.getAttribute("data-tab");
            switchTab(targetTab);
        });
    });

    function switchTab(tabId) {
        state.activeTab = tabId;
        
        // Toggle Sidebar Active
        navItems.forEach(btn => {
            if (btn.getAttribute("data-tab") === tabId) {
                btn.classList.add("active");
            } else {
                btn.classList.remove("active");
            }
        });

        // Toggle Panels
        tabPanels.forEach(panel => {
            if (panel.id === `panel-${tabId}`) {
                panel.classList.add("active");
            } else {
                panel.classList.remove("active");
            }
        });

        // Update Titles
        const titles = {
            "dashboard": { title: "Security Dashboard", subtitle: "Real-time WiFi threats and configuration audit" },
            "wifi-scan": { title: "WiFi Inspector", subtitle: "Spectral scanning and overlapping channel analysis" },
            "devices": { title: "Subnet Devices", subtitle: "Active local network nodes mapping and whitelisting" },
            "threat-center": { title: "Threat Center", subtitle: "Active local network nodes risk profile and access control policy" },
            "logs": { title: "Console Log", subtitle: "Raw telemetry and intrusion alert events" }
        };

        currentTabTitle.textContent = titles[tabId].title;
        currentTabSubtitle.textContent = titles[tabId].subtitle;
        
        // Refresh specific tab assets
        if (tabId === "wifi-scan") {
            // Re-render chart since it requires canvas visibility to scale correctly
            renderChannelChart();
        } else if (tabId === "threat-center") {
            populateThreatSelector();
        }
    }

    // Console Logging Utility
    function logToConsole(message, type = "system") {
        const time = new Date().toLocaleTimeString();
        const line = document.createElement("div");
        line.className = `console-line ${type}-line`;
        
        let prefix = "[SYSTEM]";
        if (type === "event-update") prefix = "[UPDATE]";
        if (type === "event-alert") prefix = "[ALERT]";
        
        line.textContent = `${time} ${prefix} ${message}`;
        consoleStream.appendChild(line);
        consoleStream.scrollTop = consoleStream.scrollHeight;
    }

    // Toast Alert system
    function triggerToast(title, message, dev = null) {
        const toast = document.createElement("div");
        toast.className = "toast";
        
        // Sound alert
        try {
            const context = new (window.AudioContext || window.webkitAudioContext)();
            const osc = context.createOscillator();
            const gain = context.createGain();
            osc.connect(gain);
            gain.connect(context.destination);
            
            osc.type = "sine";
            osc.frequency.setValueAtTime(880, context.currentTime); // A5 note
            gain.gain.setValueAtTime(0.15, context.currentTime);
            
            osc.start();
            osc.stop(context.currentTime + 0.12);
        } catch (e) {
            // Audio context blocked or not supported
        }

        toast.innerHTML = `
            <i data-lucide="shield-alert"></i>
            <div class="toast-msg">
                <div class="toast-title">${title}</div>
                <div class="toast-text">${message}</div>
            </div>
            <button class="toast-close"><i data-lucide="x" style="width:14px;height:14px;"></i></button>
        `;
        
        toastArea.appendChild(toast);
        safeCreateIcons({attrs: {class: 'toast-close-btn'}});

        // Bind Close Click
        toast.querySelector(".toast-close").addEventListener("click", () => {
            toast.style.animation = "fadeOut 0.3s forwards";
            setTimeout(() => toast.remove(), 300);
        });

        // Auto remove after 6s
        setTimeout(() => {
            if (toast.parentNode) {
                toast.style.animation = "fadeOut 0.3s forwards";
                setTimeout(() => toast.remove(), 300);
            }
        }, 6000);
    }

    // Connect WebSocket
    function connectWS() {
        let wsUrl;
        if (apiHost) {
            const wsProtocol = apiHost.startsWith("https") ? "wss:" : "ws:";
            const wsDomain = apiHost.replace(/^https?:\/\//, "");
            wsUrl = `${wsProtocol}//${wsDomain}/ws/monitor`;
        } else {
            const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
            const host = window.location.host || "localhost:8000";
            wsUrl = `${protocol}//${host}/ws/monitor`;
        }

        logToConsole("Initializing WebSocket connection to " + wsUrl);
        state.wsConn = new WebSocket(wsUrl);

        state.wsConn.onopen = () => {
            logToConsole("WebSocket link established.", "system");
            wsStatusText.textContent = "Live Telemetry Feed Online";
            wsStatusDot.classList.add("online");
            wsStatusDot.classList.remove("offline");
        };

        state.wsConn.onclose = () => {
            logToConsole("WebSocket link disconnected. Reconnecting in 5s...", "system");
            wsStatusText.textContent = "Offline (Reconnecting)";
            wsStatusDot.classList.add("offline");
            wsStatusDot.classList.remove("online");
            setTimeout(connectWS, 5000);
        };

        state.wsConn.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                
                if (data.type === "alert") {
                    logToConsole(data.message, "event-alert");
                    triggerToast(data.title, data.message, data.device);
                    // Refresh devices list
                    fetchDevices();
                    fetchAudit();
                } else if (data.type === "update") {
                    logToConsole("Periodic background data payload received.", "event-update");
                    
                    // Update active WiFi stats
                    if (data.wifi && data.wifi.status === "connected") {
                        updateWifiUI(data.wifi);
                    }
                    
                    // Update Devices
                    if (data.devices) {
                        state.devices = data.devices;
                        renderDevicesTable();
                    }
                }
            } catch (err) {
                console.error("Error processing WS packet: ", err);
            }
        };
    }

    // Fetch active WiFi connection
    async function fetchWifiConnection() {
        try {
            const res = await fetch(apiHost + "/api/wifi/connection");
            const data = await res.json();
            if (!res.ok || data.detail || data.error) {
                throw new Error(data.detail || data.error || `Server error (${res.status})`);
            }
            state.wifiConnection = data;
            updateWifiUI(data);
        } catch (e) {
            logToConsole("Error fetching WiFi interface: " + e.message, "system");
            updateWifiUI({ status: "disconnected" });
        }
    }

    function updateWifiUI(data) {
        if (data.status === "connected") {
            headerConnectionBadge.className = "network-badge connected";
            headerConnectionBadge.innerHTML = `<i data-lucide="wifi"></i> <span>Connected: ${data.ssid}</span>`;
            
            connSsid.textContent = data.ssid;
            connBssid.textContent = data.bssid;
            connSignal.textContent = `${data.signal}%`;
            connChannelBand.textContent = `Ch ${data.channel} / ${data.band}`;
            connRate.textContent = `↓ ${data.receive_rate} Mbps / ↑ ${data.transmit_rate} Mbps`;
            
            if (profileStatus) {
                profileStatus.textContent = "CONNECTED";
                profileStatus.className = "val text-glow-green";
            }
            if (profileAdapter) profileAdapter.textContent = data.description || data.interface_name || "--";
            if (profileMac) profileMac.textContent = data.mac_address || "--";
            if (profileRadio) profileRadio.textContent = data.radio_type || "--";
            if (profileAuth) profileAuth.textContent = data.authentication || "--";
            if (profileCipher) profileCipher.textContent = data.cipher || "--";
            
            if (profilePassword) {
                profilePassword.textContent = data.password_protected ? "Yes (Secured)" : "No (Open / Vulnerable)";
                profilePassword.className = data.password_protected ? "val text-glow-green" : "val text-glow-red";
            }
            if (profileLevel) {
                profileLevel.textContent = data.security_level || "--";
                if (data.security_level && data.security_level.includes("Strong")) {
                    profileLevel.className = "val text-glow-green";
                } else if (data.security_level && data.security_level.includes("Standard")) {
                    profileLevel.className = "val text-glow-cyan";
                } else {
                    profileLevel.className = "val text-glow-yellow";
                }
            }
            if (profileStrength) {
                profileStrength.textContent = data.encryption_strength || "--";
                profileStrength.className = data.password_protected ? "val text-glow-green" : "val text-glow-red";
            }
        } else {
            headerConnectionBadge.className = "network-badge disconnected";
            headerConnectionBadge.innerHTML = `<i data-lucide="wifi-off"></i> <span>Wlan Disconnected</span>`;
            
            connSsid.textContent = "Disconnected";
            connBssid.textContent = "--";
            connSignal.textContent = "0%";
            connChannelBand.textContent = "--";
            connRate.textContent = "--";
            
            if (profileStatus) {
                profileStatus.textContent = "DISCONNECTED";
                profileStatus.className = "val text-glow-red";
            }
            if (profileAdapter) profileAdapter.textContent = "--";
            if (profileMac) profileMac.textContent = "--";
            if (profileRadio) profileRadio.textContent = "--";
            if (profileAuth) profileAuth.textContent = "--";
            if (profileCipher) profileCipher.textContent = "None";
            
            if (profilePassword) {
                profilePassword.textContent = "--";
                profilePassword.className = "val";
            }
            if (profileLevel) {
                profileLevel.textContent = "--";
                profileLevel.className = "val";
            }
            if (profileStrength) {
                profileStrength.textContent = "--";
                profileStrength.className = "val";
            }
        }
        safeCreateIcons();
    }
       // Fetch Whitelist
    async function fetchWhitelist() {
        try {
            const res = await fetch(apiHost + "/api/whitelist");
            state.whitelist = await res.json();
        } catch (e) {
            console.error("Error fetching whitelist", e);
        }
    }

    // Fetch Blacklist
    async function fetchBlacklist() {
        try {
            const res = await fetch(apiHost + "/api/blacklist");
            state.blacklist = await res.json();
        } catch (e) {
            console.error("Error fetching blacklist", e);
        }
    }

    // Set Device status policies
    async function setDeviceStatus(mac, status) {
        mac = mac.toUpperCase();
        try {
            if (status === "approved") {
                let updatedList = [...state.whitelist];
                if (!updatedList.includes(mac)) updatedList.push(mac);
                logToConsole(`Approving and Whitelisting MAC: ${mac}`);
                
                const res = await fetch(apiHost + "/api/whitelist", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ macs: updatedList })
                });
                const data = await res.json();
                state.whitelist = data.whitelist;
                // Update local blacklist state
                state.blacklist = state.blacklist.filter(m => m !== mac);
            } 
            else if (status === "blocked") {
                let updatedList = [...state.blacklist];
                if (!updatedList.includes(mac)) updatedList.push(mac);
                logToConsole(`Banning and Blacklisting MAC: ${mac}`, "event-alert");
                
                const res = await fetch(apiHost + "/api/blacklist", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ macs: updatedList })
                });
                const data = await res.json();
                state.blacklist = data.blacklist;
                // Update local whitelist state
                state.whitelist = state.whitelist.filter(m => m !== mac);
            }
            else { // reset to unknown
                logToConsole(`Resetting policy for MAC: ${mac}`);
                const updatedWhite = state.whitelist.filter(m => m !== mac);
                const updatedBlack = state.blacklist.filter(m => m !== mac);
                
                await fetch(apiHost + "/api/whitelist", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ macs: updatedWhite })
                });
                await fetch(apiHost + "/api/blacklist", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ macs: updatedBlack })
                });
                
                state.whitelist = updatedWhite;
                state.blacklist = updatedBlack;
            }
            
            // Re-fetch Devices and Audit to update UI and score
            await fetchDevices();
            await fetchAudit();
            
            // If in Threat Center, refresh the selected device card
            if (state.activeTab === "threat-center") {
                updateThreatDetailsCard(state.selectedThreatMac);
            }
        } catch (e) {
            logToConsole("Error updating device policy: " + e.message, "system");
          }
    }

    // Fetch Subnet Devices
    async function fetchDevices() {
        try {
            const res = await fetch(apiHost + "/api/network/devices");
            const data = await res.json();
            
            if (!res.ok || data.error || data.detail) {
                const errMsg = data.error || data.detail || `Server error (${res.status})`;
                devicesTbody.innerHTML = `<tr><td colspan="6" class="table-loading text-glow-red">${errMsg}</td></tr>`;
                return;
            }

            state.devices = data.devices || [];
            if (data.wifi_ip && typeof data.wifi_ip === "string") {
                profileGateway.textContent = data.wifi_ip.substring(0, data.wifi_ip.lastIndexOf('.')) + ".1";
            } else {
                profileGateway.textContent = "--";
            }
            renderDevicesTable();
        } catch (e) {
            devicesTbody.innerHTML = `<tr><td colspan="6" class="table-loading text-glow-red">Failed to map network: ${e.message}</td></tr>`;
        }
    }

    function renderDevicesTable() {
        if (!state.devices || state.devices.length === 0) {
            devicesTbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--text-muted);">No devices located on subnet.</td></tr>';
            return;
        }

        let html = "";
        let activeCount = 0;
        let whiteCount = 0;
        let threatCount = 0;

        state.devices.forEach(dev => {
            activeCount++;
            const isWhitelisted = state.whitelist.includes(dev.mac);
            const isBlacklisted = state.blacklist.includes(dev.mac);
            
            let statusBadge = "";
            if (dev.is_host) {
                statusBadge = '<span class="badge" style="background:rgba(6,182,212,0.15);color:var(--color-cyan);">HOST</span>';
                whiteCount++;
            } else if (isWhitelisted) {
                statusBadge = '<span class="badge" style="background:rgba(16,185,129,0.15);color:var(--color-green);">APPROVED</span>';
                whiteCount++;
            } else if (isBlacklisted) {
                statusBadge = '<span class="badge" style="background:rgba(239,68,68,0.15);color:var(--color-red);box-shadow:var(--glow-red);">BLOCKED</span>';
                threatCount++;
            } else {
                statusBadge = '<span class="badge" style="background:rgba(245,158,11,0.12);color:var(--color-yellow);">UNKNOWN</span>';
                threatCount++;
            }

            html += `
                <tr>
                    <td>${statusBadge}</td>
                    <td>${dev.ip}</td>
                    <td class="font-mono">${dev.mac}</td>
                    <td>${dev.vendor}</td>
                    <td>${dev.is_host ? "This Workstation" : "Remote Node"}</td>
                    <td>
                        ${dev.is_host ? "--" : `
                        <div class="controls-cell">
                            <button class="btn-ctrl btn-approve ${isWhitelisted ? 'approved' : ''}" data-mac="${dev.mac}">
                                <i data-lucide="${isWhitelisted ? 'check-circle' : 'circle'}"></i> Approve
                            </button>
                            <button class="btn-ctrl btn-block ${isBlacklisted ? 'blocked' : ''}" data-mac="${dev.mac}">
                                <i data-lucide="${isBlacklisted ? 'slash' : 'circle'}"></i> Block
                            </button>
                        </div>
                        `}
                    </td>
                </tr>
            `;
        });

        devicesTbody.innerHTML = html;
        safeCreateIcons();
        
        // Update stats widgets
        statActiveHosts.textContent = activeCount;
        statWhitelisted.textContent = whiteCount;
        statUnauthorized.textContent = threatCount;
        
        // Bind events to Approve buttons
        devicesTbody.querySelectorAll(".btn-approve").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const button = e.target.closest("button");
                const mac = button.getAttribute("data-mac");
                const isApproved = button.classList.contains("approved");
                setDeviceStatus(mac, isApproved ? "unknown" : "approved");
            });
        });

        // Bind events to Block buttons
        devicesTbody.querySelectorAll(".btn-block").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const button = e.target.closest("button");
                const mac = button.getAttribute("data-mac");
                const isBlocked = button.classList.contains("blocked");
                setDeviceStatus(mac, isBlocked ? "unknown" : "blocked");
            });
        });
    }

    // Fetch and compute WiFi scan
    async function fetchWifiScan() {
        wifiScanTbody.innerHTML = '<tr><td colspan="6" class="table-loading"><i data-lucide="loader" class="icon-spin"></i> Inspecting WiFi frequencies...</td></tr>';
        safeCreateIcons();

        try {
            const res = await fetch(apiHost + "/api/wifi/scan");
            const data = await res.json();
            if (!res.ok || data.detail || data.error) {
                throw new Error(data.detail || data.error || `Server error (${res.status})`);
            }
            state.scanResults = Array.isArray(data) ? data : [];
            renderScanTable();
            renderChannelChart();
        } catch (e) {
            wifiScanTbody.innerHTML = `<tr><td colspan="6" class="table-loading text-glow-red">Scan failed: ${e.message}</td></tr>`;
        }
    }

    function renderScanTable() {
        if (!state.scanResults || state.scanResults.length === 0) {
            wifiScanTbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--text-muted);">No wireless networks found.</td></tr>';
            return;
        }

        let html = "";
        state.scanResults.forEach(net => {
            const bssidDetails = net.bssids[0] || {};
            
            // Format security badges
            let secColor = "var(--color-green)";
            if (net.authentication.includes("Open") || net.authentication.includes("None")) {
                secColor = "var(--color-red)";
            } else if (net.authentication.includes("WPA2")) {
                secColor = "var(--color-yellow)";
            }

            html += `
                <tr>
                    <td><strong>${net.ssid}</strong></td>
                    <td class="font-mono">${bssidDetails.bssid || "--"}</td>
                    <td>Channel ${bssidDetails.channel || "--"}</td>
                    <td>${bssidDetails.band || "--"}</td>
                    <td><span class="badge" style="border: 1px solid ${secColor}; color: ${secColor};">${net.authentication}</span></td>
                    <td>
                        <div style="display:flex;align-items:center;gap:0.5rem;">
                            <span class="text-glow-cyan" style="font-weight:600;width:35px;">${bssidDetails.signal}%</span>
                            <div style="width:60px;height:4px;background:rgba(255,255,255,0.05);border-radius:2px;overflow:hidden;">
                                <div style="width:${bssidDetails.signal}%;height:100%;background:var(--color-cyan);box-shadow:var(--glow-cyan);"></div>
                            </div>
                        </div>
                    </td>
                </tr>
            `;
        });

        wifiScanTbody.innerHTML = html;
    }

    // Render Spectral Overlapping WiFi Chart (Chart.js)
    function renderChannelChart() {
        const canvas = document.getElementById("wifi-channel-chart");
        if (!canvas) return;
        
        // If chart exists, destroy it first
        if (state.channelChart) {
            state.channelChart.destroy();
        }

        // Separate networks into 2.4GHz vs 5GHz
        const nets24 = [];
        const nets5 = [];

        state.scanResults.forEach(net => {
            net.bssids.forEach(bssid => {
                const ch = parseInt(bssid.channel) || 0;
                const sig = bssid.signal || 0;
                
                if (bssid.band && bssid.band.includes("2.4")) {
                    nets24.push({ ssid: net.ssid, channel: ch, signal: sig });
                } else {
                    nets5.push({ ssid: net.ssid, channel: ch, signal: sig });
                }
            });
        });

        // Determine if we show 2.4GHz or 5GHz on the chart (default 2.4GHz since it overlaps more, or show both)
        // Let's create an elegant continuous spectrum on X-axis from 1 to 14 for 2.4GHz.
        // If 2.4GHz networks is empty but 5GHz is not, we can scan 36-165. Let's build a unified X-axis for 2.4GHz: Channels 1 to 14.
        const channelsRange = Array.from({ length: 14 }, (_, i) => i + 1);
        
        const datasets = nets24.map((net, idx) => {
            const centerCh = net.channel;
            const maxSignal = net.signal;
            
            // Build a curve (bell shape) centered at the network channel
            // WiFi channel width spans about 5 channels (+-2 channels)
            const data = channelsRange.map(ch => {
                const dist = Math.abs(ch - centerCh);
                if (dist === 0) return maxSignal;
                if (dist === 1) return maxSignal * 0.7;
                if (dist === 2) return maxSignal * 0.35;
                return 0; // Beyond channel width
            });

            // Cycle colors
            const colors = [
                "rgba(6, 182, 212, 0.45)",  // Cyan
                "rgba(16, 185, 129, 0.45)", // Green
                "rgba(245, 158, 11, 0.45)",  // Yellow
                "rgba(244, 63, 94, 0.45)",   // Red
                "rgba(139, 92, 246, 0.45)"   // Purple
            ];
            const borderColors = [
                "#06b6d4",
                "#10b981",
                "#f59e0b",
                "#f43f5e",
                "#8b5cf6"
            ];
            const cIdx = idx % colors.length;

            return {
                label: net.ssid,
                data: data,
                borderColor: borderColors[cIdx],
                backgroundColor: colors[cIdx],
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0
            };
        });

        if (state.activeTab !== "wifi-scan") return; // Avoid chart sizing errors on hidden elements!

        try {
            state.channelChart = new Chart(canvas, {
                type: 'line',
                data: {
                    labels: channelsRange.map(ch => `Ch ${ch}`),
                    datasets: datasets
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#94a3b8',
                                font: { family: 'Outfit', size: 11 }
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return `SSID: ${context.dataset.label} (Strength: ${context.raw}%)`;
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255, 255, 255, 0.03)' },
                            ticks: { color: '#94a3b8', font: { family: 'Outfit' } }
                        },
                        y: {
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(255, 255, 255, 0.03)' },
                            ticks: { 
                                color: '#94a3b8', 
                                font: { family: 'Outfit' },
                                callback: function(val) { return val + '%'; }
                            }
                        }
                    }
                }
            });
        } catch (e) {
            console.error("Failed to render Chart.js spectrum: ", e);
        }
    }

    // Render alerts UI block
    function renderAlerts(alerts) {
        let alertsHtml = "";
        let alertCount = alerts.length;
        
        if (alertCount === 0) {
            alertsHtml = `
                <div class="empty-state">
                    <i data-lucide="shield-check" class="text-success"></i>
                    <p>No active threats or vulnerabilities found on this network.</p>
                </div>
            `;
        } else {
            alerts.forEach(alert => {
                let severityClass = `severity-${alert.severity}`;
                let iconName = "info";
                
                if (alert.severity === "critical" || alert.severity === "high") {
                    iconName = "shield-alert";
                } else if (alert.severity === "medium" || alert.severity === "low") {
                    iconName = "alert-triangle";
                }

                alertsHtml += `
                    <div class="alert-item ${severityClass}">
                        <div class="alert-icon ${alert.severity === 'critical' || alert.severity === 'high' ? 'danger' : alert.severity === 'info' ? 'info' : 'warning'}">
                            <i data-lucide="${iconName}"></i>
                        </div>
                        <div class="alert-body">
                            <h4>${alert.category}</h4>
                            <p>${alert.message}</p>
                        </div>
                    </div>
                `;
            });
        }
        
        alertsContainer.innerHTML = alertsHtml;
        alertCountBadge.textContent = `${alertCount} Alert(s)`;
        alertCountBadge.className = alertCount > 0 ? "badge text-glow-red" : "badge badge-outline";
        if (alertCount > 0) {
            alertCountBadge.style.borderColor = "var(--color-red)";
        } else {
            alertCountBadge.style.borderColor = "";
        }
        
        safeCreateIcons();
    }

    // Run detailed Connection Audit
    async function fetchAudit() {
        try {
            const res = await fetch(apiHost + "/api/security/audit");
            const data = await res.json();
            if (!res.ok || data.detail || data.error) {
                throw new Error(data.detail || data.error || `Server error (${res.status})`);
            }
            state.auditData = data;
            
            // Render Score Ring
            updateSecurityScore(data.security_score || 0);
            
            // Render exposed ports & DNS
            const pubInfo = data.public_ip_info || {};
            pubIp.textContent = pubInfo.public_ip || "Unavailable (Sandboxed)";
            pubIsp.textContent = pubInfo.org || "Protected Gateway Network";
            
            // Render Alerts
            renderAlerts(data.alerts || []);
        } catch (e) {
            logToConsole("Audit fetch failed: " + e.message, "system");
        }
    }

    // Fetch unified cloud agent report
    async function fetchAgentReport() {
        if (!connectedAgentId) return;
        
        try {
            const res = await fetch(apiHost + `/api/agent/report/${connectedAgentId}`);
            if (!res.ok) {
                if (res.status === 404) {
                    logToConsole(`No scan data received from Agent: ${connectedAgentId}. Keep the script running on that PC!`, "system");
                    updateWifiUI({ status: "disconnected" });
                    return;
                }
                throw new Error(`Server error (${res.status})`);
            }
            
            const data = await res.json();
            
            // 1. Connection properties
            state.wifiConnection = data.wifi || {};
            updateWifiUI(state.wifiConnection);
            
            if (state.wifiConnection.status === "connected") {
                profileGateway.textContent = state.wifiConnection.gateway_ip || "--";
            }
            
            // 2. Devices table
            state.devices = data.devices || [];
            renderDevicesTable();
            
            // 3. WiFi inspector scans (restructure flat model to nested model)
            const rawScan = data.wifi_scan || [];
            state.scanResults = rawScan.map(net => {
                const chanNum = parseInt(net.channel) || 1;
                const bandStr = chanNum <= 14 ? "2.4 GHz" : "5 GHz";
                return {
                    ssid: net.ssid,
                    authentication: net.authentication,
                    encryption: net.encryption,
                    bssids: [
                        {
                            bssid: net.bssid,
                            signal: net.signal,
                            channel: net.channel,
                            band: bandStr
                        }
                    ]
                };
            });
            renderScanTable();
            renderChannelChart();
            
            // 4. Security Score Ring
            updateSecurityScore(data.security_score || 0);
            
            // 5. Alerts list
            renderAlerts(data.alerts || []);
            
            logToConsole(`Telemetry synchronized for Agent: ${connectedAgentId}.`, "system");
        } catch (e) {
            logToConsole(`Agent telemetry fetch failed: ${e.message}`, "system");
        }
    }

    function updateSecurityScore(score) {
        scoreNumber.textContent = score;
        
        // Animate stroke-dashoffset of SVG ring (circumference is 2 * pi * r = 2 * 3.1415 * 40 = 251.2)
        const circumference = 251.2;
        const offset = circumference - (score / 100) * circumference;
        ringProgress.style.strokeDashoffset = offset;
        
        // Color transition
        if (score >= 80) {
            ringProgress.style.stroke = "var(--color-green)";
            scoreText.textContent = "Secure Network";
            scoreText.className = "score-label text-glow-green";
        } else if (score >= 50) {
            ringProgress.style.stroke = "var(--color-yellow)";
            scoreText.textContent = "Moderate Risk";
            scoreText.className = "score-label text-glow-yellow";
        } else {
            ringProgress.style.stroke = "var(--color-red)";
            scoreText.textContent = "Critical Danger";
            scoreText.className = "score-label text-glow-red";
        }
    }

    // Global Manual Audit trigger
    async function triggerGlobalAudit() {
        const activeRefreshIcon = document.getElementById("refresh-icon");
        if (activeRefreshIcon) activeRefreshIcon.classList.add("icon-spin");
        globalRefreshBtn.disabled = true;
        
        if (connectedAgentId) {
            logToConsole(`Requesting remote scan refresh for agent ${connectedAgentId}...`, "system");
            try {
                await fetchAgentReport();
            } catch (err) {
                logToConsole("Agent sync failed: " + err.message, "event-alert");
            } finally {
                setTimeout(() => {
                    const activeRefreshIcon = document.getElementById("refresh-icon");
                    if (activeRefreshIcon) activeRefreshIcon.classList.remove("icon-spin");
                    globalRefreshBtn.disabled = false;
                    logToConsole("Agent scan refresh completed.", "system");
                }, 800);
            }
            return;
        }

        logToConsole("Executing full environment security audit...", "system");

        try {
            await fetchWhitelist();
            await fetchBlacklist();
            await fetchWifiConnection();
            await fetchWifiScan();
            await fetchDevices();
            await fetchAudit();
        } catch (err) {
            logToConsole("Audit failed: " + err.message, "event-alert");
            console.error("Audit error: ", err);
        } finally {
            setTimeout(() => {
                const activeRefreshIcon = document.getElementById("refresh-icon");
                if (activeRefreshIcon) activeRefreshIcon.classList.remove("icon-spin");
                globalRefreshBtn.disabled = false;
                logToConsole("Environment audit completed.", "system");
            }, 800);
        }
    }

    // Threat Center: Populate Selector Dropdown
    function populateThreatSelector() {
        if (!state.devices || state.devices.length === 0) {
            threatDeviceSelect.innerHTML = '<option value="">-- No Devices Located --</option>';
            updateThreatDetailsCard("");
            return;
        }

        let optionsHtml = '<option value="">-- Select a Subnet Node --</option>';
        state.devices.forEach(dev => {
            let label = `${dev.ip} - ${dev.vendor}`;
            if (dev.is_host) label += " (This Host)";
            optionsHtml += `<option value="${dev.mac}">${label}</option>`;
        });
        
        threatDeviceSelect.innerHTML = optionsHtml;
        
        // Preserve selection if possible
        if (state.selectedThreatMac) {
            threatDeviceSelect.value = state.selectedThreatMac;
        } else {
            updateThreatDetailsCard("");
        }
    }

    // Threat Center: Render Selected Device Profile
    function updateThreatDetailsCard(mac) {
        if (!mac) {
            state.selectedThreatMac = "";
            threatIp.textContent = "--";
            threatMac.textContent = "--";
            threatVendor.textContent = "--";
            threatStatusBadge.innerHTML = "--";
            
            latencyValue.textContent = "--";
            latencyStatusText.textContent = "Select a device to test latency";
            
            pingTestBtn.disabled = true;
            threatApproveBtn.disabled = true;
            threatBlockBtn.disabled = true;
            
            routerGatewayLink.textContent = "http://192.168.1.1";
            routerGatewayLink.href = "#";
            routerBlockMacVal.textContent = "--";
            return;
        }

        const dev = state.devices.find(d => d.mac === mac);
        if (!dev) return;

        state.selectedThreatMac = mac;
        threatIp.textContent = dev.ip;
        threatMac.textContent = dev.mac;
        threatVendor.textContent = dev.vendor;

        // Generate status badge
        const isWhitelisted = state.whitelist.includes(mac);
        const isBlacklisted = state.blacklist.includes(mac);
        
        let statusBadgeHtml = "";
        if (dev.is_host) {
            statusBadgeHtml = '<span class="badge" style="background:rgba(6,182,212,0.15);color:var(--color-cyan);">HOST MACHINE</span>';
        } else if (isWhitelisted) {
            statusBadgeHtml = '<span class="badge" style="background:rgba(16,185,129,0.15);color:var(--color-green);">APPROVED WORKSTATION</span>';
        } else if (isBlacklisted) {
            statusBadgeHtml = '<span class="badge" style="background:rgba(239,68,68,0.15);color:var(--color-red);box-shadow:var(--glow-red);">BLOCKED THREAT</span>';
        } else {
            statusBadgeHtml = '<span class="badge" style="background:rgba(245,158,11,0.12);color:var(--color-yellow);">UNKNOWN SUSPECT</span>';
        }
        threatStatusBadge.innerHTML = statusBadgeHtml;

        // Enable action buttons
        pingTestBtn.disabled = false;
        threatApproveBtn.disabled = dev.is_host;
        threatBlockBtn.disabled = dev.is_host;

        // Set action button active states
        if (isWhitelisted) {
            threatApproveBtn.className = "btn btn-primary"; // approved style
            threatApproveBtn.innerHTML = '<i data-lucide="check-circle"></i> Approved';
            
            threatBlockBtn.className = "btn btn-secondary";
            threatBlockBtn.innerHTML = '<i data-lucide="slash"></i> Block Blacklist';
        } else if (isBlacklisted) {
            threatApproveBtn.className = "btn btn-secondary";
            threatApproveBtn.innerHTML = '<i data-lucide="check-circle"></i> Approve Whitelist';
            
            threatBlockBtn.className = "btn btn-outline-danger"; // blocked style
            threatBlockBtn.style.background = "rgba(239,68,68,0.1)";
            threatBlockBtn.innerHTML = '<i data-lucide="slash"></i> Blocked';
        } else {
            threatApproveBtn.className = "btn btn-secondary";
            threatApproveBtn.innerHTML = '<i data-lucide="check-circle"></i> Approve Whitelist';
            
            threatBlockBtn.className = "btn btn-secondary";
            threatBlockBtn.innerHTML = '<i data-lucide="slash"></i> Block Blacklist';
            threatBlockBtn.style.background = "";
        }

        // Configure router gateway details
        const gw = dev.ip.substring(0, dev.ip.lastIndexOf('.')) + ".1";
        routerGatewayLink.textContent = `http://${gw}`;
        routerGatewayLink.href = `http://${gw}`;
        routerBlockMacVal.textContent = dev.mac;
        
        latencyValue.textContent = "--";
        latencyStatusText.textContent = "Press 'Test Ping' to check node latency";
        
        safeCreateIcons();
    }

    // Ping device test handler
    async function testPingLatency() {
        if (!state.selectedThreatMac) return;
        const dev = state.devices.find(d => d.mac === state.selectedThreatMac);
        if (!dev) return;

        pingTestBtn.disabled = true;

        if (connectedAgentId) {
            latencyValue.textContent = "??";
            latencyStatusText.textContent = `Reading remote latency check...`;
            
            setTimeout(() => {
                const latencyVal = dev.latency_ms;
                if (latencyVal !== undefined && latencyVal !== null && latencyVal !== "ERR") {
                    latencyValue.textContent = latencyVal + " ms";
                    latencyStatusText.textContent = `Remote host responded. Latency: ${latencyVal} ms.`;
                } else {
                    latencyValue.textContent = "ERR";
                    latencyStatusText.textContent = `Remote host is unreachable or blocking ICMP pings.`;
                }
                pingTestBtn.disabled = false;
            }, 600);
            return;
        }

        latencyValue.textContent = "??";
        latencyStatusText.textContent = `Pinging host at ${dev.ip}...`;
        
        try {
            const res = await fetch(apiHost + `/api/network/ping?ip=${dev.ip}`);
            const data = await res.json();
            
            if (data.status === "online") {
                latencyValue.textContent = data.latency_ms;
                latencyStatusText.textContent = `Device is online. Latency is stable.`;
            } else if (data.status === "offline") {
                latencyValue.textContent = "ERR";
                latencyStatusText.textContent = `Host is offline or blocking ICMP ping sweeps.`;
            } else {
                latencyValue.textContent = "ERR";
                latencyStatusText.textContent = `Ping check failed.`;
            }
        } catch (e) {
            latencyValue.textContent = "ERR";
            latencyStatusText.textContent = `API error: ${e.message}`;
        }
        
        pingTestBtn.disabled = false;
    }

    // Event listeners
    globalRefreshBtn.addEventListener("click", triggerGlobalAudit);
    scanWifiBtn.addEventListener("click", fetchWifiScan);
    scanDevicesBtn.addEventListener("click", fetchDevices);
    clearConsoleBtn.addEventListener("click", () => {
        consoleStream.innerHTML = '<div class="console-line system-line">[SYSTEM] Console monitor cleared.</div>';
    });

    threatDeviceSelect.addEventListener("change", (e) => {
        updateThreatDetailsCard(e.target.value);
    });

    pingTestBtn.addEventListener("click", testPingLatency);

    threatApproveBtn.addEventListener("click", () => {
        if (!state.selectedThreatMac) return;
        const isApproved = state.whitelist.includes(state.selectedThreatMac);
        setDeviceStatus(state.selectedThreatMac, isApproved ? "unknown" : "approved");
    });

    threatBlockBtn.addEventListener("click", () => {
        if (!state.selectedThreatMac) return;
        const isBlocked = state.blacklist.includes(state.selectedThreatMac);
        setDeviceStatus(state.selectedThreatMac, isBlocked ? "unknown" : "blocked");
    });

    // Bind agent click listeners
    if (agentConnectBtn) {
        agentConnectBtn.addEventListener("click", () => {
            const idVal = agentIdInput.value.trim().toUpperCase();
            if (!idVal) {
                alert("Please enter your computer name / Agent ID");
                return;
            }
            connectedAgentId = idVal;
            localStorage.setItem("wifi_monitor_agent_id", connectedAgentId);
            logToConsole(`Connecting to agent stream: ${connectedAgentId}...`, "system");
            updateAgentUI();
            
            // Fetch remote data immediately
            fetchAgentReport();
        });
    }

    if (agentDisconnectBtn) {
        agentDisconnectBtn.addEventListener("click", () => {
            logToConsole(`Disconnecting from agent: ${connectedAgentId}`, "system");
            connectedAgentId = "";
            localStorage.removeItem("wifi_monitor_agent_id");
            updateAgentUI();
            
            // Reload local workspace
            window.location.reload();
        });
    }

    function updateAgentUI() {
        if (!agentIdInput || !agentActiveBadge || !agentInputGroup) return;
        
        if (connectedAgentId) {
            agentInputGroup.classList.add("hidden");
            agentActiveBadge.classList.remove("hidden");
            agentActiveText.textContent = `Active: ${connectedAgentId}`;
            if (localStatusBanner) localStatusBanner.classList.add("hidden");
        } else {
            agentInputGroup.classList.remove("hidden");
            agentActiveBadge.classList.add("hidden");
            if (window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1" && !apiHost) {
                if (localStatusBanner) localStatusBanner.classList.remove("hidden");
            }
        }
    }

    // Initial triggers
    updateAgentUI();

    if (connectedAgentId) {
        // Fetch Agent report and set up 20s poll loop
        fetchAgentReport();
        setInterval(fetchAgentReport, 20000);
    } else {
        // Normal local dashboard sequence
        detectLocalServer().then(() => {
            Promise.all([fetchWhitelist(), fetchBlacklist()]).then(() => {
                fetchWifiConnection();
                fetchWifiScan();
                fetchDevices();
                fetchAudit();
                connectWS();
            });
        });
    }
});
