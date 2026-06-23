// Personal Firewall - Security Operations Center Client Engine

// Constants & Theme Settings
const THEME_KEY = "personal_firewall_theme";
let ws = null;
let reconnectInterval = 5000;
let isFwRunning = true;

// Active data caches
let rulesCache = [];
let packetList = [];
let alertsList = [];
let systemStats = {};
let threatLogCount = 0;

// ApexCharts Instances
let trafficChart = null;
let protocolChart = null;
let topIpsChart = null;

// Real-time chart sliding windows data
let trafficTimeData = [];
let incomingBytesSeries = [];
let outgoingBytesSeries = [];

// Canvas Attack Map Setup
const canvas = document.getElementById("attack-map-canvas");
const ctx = canvas.getContext("2d");
let activeArcs = [];
let activeExplosions = [];
const MAP_HUBS = {
    "Local Host": { x: 0.50, y: 0.50, name: "SOC Host (Local)", isLocal: true },
    "North America West": { x: 0.15, y: 0.35, name: "US-West Hub", isLocal: false },
    "North America East": { x: 0.28, y: 0.38, name: "US-East Hub", isLocal: false },
    "South America": { x: 0.32, y: 0.75, name: "LATAM Hub", isLocal: false },
    "Europe West": { x: 0.47, y: 0.30, name: "EU-West Hub", isLocal: false },
    "Europe East": { x: 0.55, y: 0.28, name: "EU-East Hub", isLocal: false },
    "Africa": { x: 0.52, y: 0.62, name: "Africa Hub", isLocal: false },
    "Asia East": { x: 0.78, y: 0.35, name: "APAC Hub", isLocal: false },
    "Asia South": { x: 0.70, y: 0.48, name: "India Hub", isLocal: false },
    "Australia": { x: 0.85, y: 0.78, name: "Oceania Hub", isLocal: false }
};

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    setupTabSwitching();
    initCharts();
    initAttackMap();
    connectWebSocket();
    setupEventHandlers();
    
    // Initial fetch of firewall status
    syncFirewallStatus();
    loadRulesTable();
    loadAuditLogs();
});

// Theme Toggle Management
function initTheme() {
    const savedTheme = localStorage.getItem(THEME_KEY);
    const themeToggle = document.getElementById("theme-switch");
    
    if (savedTheme === "light") {
        document.body.classList.add("light-theme");
        themeToggle.innerHTML = '<i class="fa-solid fa-sun"></i>';
    } else {
        document.body.classList.remove("light-theme");
        themeToggle.innerHTML = '<i class="fa-solid fa-moon"></i>';
    }
}

function toggleTheme() {
    const themeToggle = document.getElementById("theme-switch");
    if (document.body.classList.contains("light-theme")) {
        document.body.classList.remove("light-theme");
        localStorage.setItem(THEME_KEY, "dark");
        themeToggle.innerHTML = '<i class="fa-solid fa-moon"></i>';
        showToast("Switched to Cyber Dark command mode", "info");
    } else {
        document.body.classList.add("light-theme");
        localStorage.setItem(THEME_KEY, "light");
        themeToggle.innerHTML = '<i class="fa-solid fa-sun"></i>';
        showToast("Switched to Light mode", "info");
    }
    // Re-initialize charts to match colors
    if (trafficChart) {
        trafficChart.destroy();
        protocolChart.destroy();
        topIpsChart.destroy();
        initCharts();
    }
}

// Console Tab Navigation
function setupTabSwitching() {
    const tabs = document.querySelectorAll(".tab-btn");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            
            const targetId = tab.getAttribute("data-target");
            document.querySelectorAll(".tab-pane").forEach(pane => {
                pane.classList.remove("active");
            });
            document.getElementById(targetId).classList.add("active");

            // Perform specific load on tab activate
            if (targetId === "tab-rules-manager") {
                loadRulesTable();
            } else if (targetId === "tab-audit-logs") {
                loadAuditLogs();
            }
        });
    });
}

// Toast Notifications System
function showToast(message, type = "success") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    let icon = "fa-circle-check";
    if (type === "warning") icon = "fa-triangle-exclamation";
    if (type === "danger") icon = "fa-circle-exclamation";
    if (type === "info") icon = "fa-circle-info";

    toast.innerHTML = `
        <i class="fa-solid ${icon}"></i>
        <div class="toast-message">${message}</div>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = "toast-in 0.3s reverse forwards";
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 4000);
}

// WebSockets Connection & Auto Reconnect
function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log("WebSocket connection established with secure SOC portal.");
        document.querySelector(".console-stream-status").innerHTML = 
            '<span class="dot-glowing green"></span> STREAMING';
    };
    
    ws.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        handleWSMessage(payload);
    };
    
    ws.onclose = () => {
        console.warn("WebSocket disconnect detected. Triggering auto-reconnect...");
        document.querySelector(".console-stream-status").innerHTML = 
            '<span class="dot-glowing" style="background-color: var(--alert-red);"></span> OFFLINE';
        setTimeout(connectWebSocket, reconnectInterval);
    };

    ws.onerror = (error) => {
        console.error("WebSocket socket error: ", error);
        ws.close();
    };
}

// Handle WebSocket Event Payloads
function handleWSMessage(payload) {
    const type = payload.type;
    const data = payload.data;
    
    switch (type) {
        case "init":
            // Warm up dashboard state
            isFwRunning = data.running;
            updateFwStatusUI(isFwRunning, data.simulation_mode);
            rulesCache = data.rules;
            
            // Populate packets lists
            packetList = data.packets || [];
            renderPacketsTable();
            
            // Populate threats lists
            alertsList = data.threats || [];
            renderThreatAlerts();
            break;
            
        case "packet":
            // Push incoming packet to top
            packetList.unshift(data);
            if (packetList.length > 100) packetList.pop();
            renderPacketsTable();
            
            // Dispatch to Attack Map Visual Engine
            dispatchPacketToMap(data);
            break;
            
        case "threat":
            alertsList.unshift(data);
            if (alertsList.length > 50) alertsList.pop();
            renderThreatAlerts();
            
            // Show alert notifications
            showToast(`ALERT: Detected ${data.threat_type} from ${data.source_ip}!`, "danger");
            triggerThreatAudioAlarm();
            dispatchThreatToMap(data);
            break;
            
        case "stats":
            updateHUDStats(data);
            updateDashboardCharts(data);
            renderConnectionsTable(data.connections);
            break;
    }
}

// Update HUD Header telemetry
function updateHUDStats(data) {
    // Hardware Metrics
    document.getElementById("cpu-bar").style.width = `${data.system.cpu}%`;
    document.getElementById("cpu-text").innerText = `${data.system.cpu}%`;
    
    document.getElementById("ram-bar").style.width = `${data.system.memory}%`;
    document.getElementById("ram-text").innerText = `${data.system.memory}%`;

    // Global Speeds
    document.getElementById("net-down").innerText = data.overview.download_speed;
    document.getElementById("net-up").innerText = data.overview.upload_speed;

    // Overview numbers
    document.getElementById("stat-total-packets").innerText = data.overview.total_packets;
    document.getElementById("stat-blocked-packets").innerText = data.overview.blocked_packets;
    document.getElementById("stat-allowed-packets").innerText = data.overview.allowed_packets;
    document.getElementById("stat-threats").innerText = data.overview.threats_detected;
    document.getElementById("stat-rules").innerText = data.overview.active_rules;
    document.getElementById("stat-connections").innerText = data.overview.active_connections;
}

// Render Packet Capture table with live filters
function renderPacketsTable() {
    const tableBody = document.getElementById("packet-table-body");
    const searchQuery = document.getElementById("packet-search").value.toLowerCase();
    const protoFilter = document.getElementById("packet-filter-proto").value;
    const actionFilter = document.getElementById("packet-filter-action").value;

    let rowsHtml = "";
    
    const filtered = packetList.filter(pkt => {
        const matchesSearch = !searchQuery || 
            pkt.source_ip.toLowerCase().includes(searchQuery) || 
            pkt.destination_ip.toLowerCase().includes(searchQuery);
        const matchesProto = protoFilter === "ALL" || pkt.protocol === protoFilter;
        const matchesAction = actionFilter === "ALL" || pkt.action === actionFilter;
        return matchesSearch && matchesProto && matchesAction;
    });

    if (filtered.length === 0) {
        rowsHtml = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No packets captured matching filter profile.</td></tr>`;
    } else {
        filtered.forEach(pkt => {
            const actionBadge = pkt.action === "Block" ? "badge-block" : "badge-allow";
            const portSrc = pkt.source_port !== null ? pkt.source_port : "-";
            const portDest = pkt.destination_port !== null ? pkt.destination_port : "-";
            
            rowsHtml += `
                <tr>
                    <td>${pkt.timestamp}</td>
                    <td><span class="proto-tag proto-${pkt.protocol}">${pkt.protocol}</span></td>
                    <td>${pkt.source_ip}</td>
                    <td>${portSrc}</td>
                    <td>${pkt.destination_ip}</td>
                    <td>${portDest}</td>
                    <td>${pkt.packet_size}</td>
                    <td><span class="badge ${actionBadge}">${pkt.action}</span></td>
                </tr>
            `;
        });
    }

    tableBody.innerHTML = rowsHtml;
}

// Render connections process monitor
function renderConnectionsTable(connections) {
    const tableBody = document.getElementById("connections-table-body");
    if (!connections || connections.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No active network sockets found.</td></tr>';
        return;
    }

    let rowsHtml = "";
    connections.forEach(conn => {
        rowsHtml += `
            <tr>
                <td>${conn.pid}</td>
                <td style="color: var(--neon-blue); font-weight: bold;">${conn.process_name}</td>
                <td>${conn.local_address}</td>
                <td>${conn.remote_address}</td>
                <td><span class="proto-tag proto-TCP">${conn.protocol}</span></td>
                <td style="color: ${conn.status === 'ESTABLISHED' ? 'var(--cyber-green)' : 'var(--text-muted)'};">${conn.status}</td>
                <td>
                    <span style="color: var(--cyber-green);"><i class="fa-solid fa-arrow-down"></i> ${conn.download_speed} KB/s</span>
                    <span style="color: var(--neon-blue); margin-left: 10px;"><i class="fa-solid fa-arrow-up"></i> ${conn.upload_speed} KB/s</span>
                </td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="terminateProcess(${conn.pid}, '${conn.process_name}')">KILL</button>
                    ${conn.remote_address !== '-' ? `<button class="btn btn-sm btn-outline" style="margin-left: 5px;" onclick="quickBlockIP('${conn.remote_address.split(':')[0]}')">BLOCK IP</button>` : ''}
                </td>
            </tr>
        `;
    });

    tableBody.innerHTML = rowsHtml;
}

// Render Threat Alerts Feed
function renderThreatAlerts() {
    const feed = document.getElementById("alerts-console-feed");
    const indicator = document.getElementById("alert-indicator-badge");
    const placeholder = document.getElementById("no-alerts-placeholder");

    if (alertsList.length === 0) {
        placeholder.style.display = "flex";
        indicator.innerText = "0 ACTIVE THREATS";
        // Remove existing threat alerts (if any) except the placeholder
        Array.from(feed.children).forEach(child => {
            if (child.id !== "no-alerts-placeholder") child.remove();
        });
        return;
    }

    placeholder.style.display = "none";
    indicator.innerText = `${alertsList.length} ALERTS`;
    
    // Clear feed alerts without deleting placeholder
    Array.from(feed.children).forEach(child => {
        if (child.id !== "no-alerts-placeholder") child.remove();
    });

    alertsList.forEach(alert => {
        const item = document.createElement("div");
        item.className = `threat-alert-item severity-${alert.severity}`;
        item.innerHTML = `
            <div class="alert-header-row">
                <span class="alert-title"><i class="fa-solid fa-circle-radiation"></i> ${alert.threat_type}</span>
                <span class="alert-badge">${alert.severity.toUpperCase()}</span>
            </div>
            <div class="alert-desc">An anomaly matching threat signatures was detected from origin IP <strong>${alert.source_ip}</strong> at time ${alert.timestamp}.</div>
            <div class="alert-action-row">
                <span class="alert-rec">REC: ${alert.recommended_action}</span>
                <button class="btn-alert-block" onclick="quickBlockIP('${alert.source_ip}')">BLOCK TARGET</button>
            </div>
        `;
        feed.appendChild(item);
    });
}

// Action: Kill active Process connection
function terminateProcess(pid, name) {
    if (confirm(`CRITICAL ACTION: Are you sure you want to terminate process '${name}' (PID: ${pid})?`)) {
        fetch("/api/connections/terminate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pid: pid })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                showToast(`Process ${name} (PID: ${pid}) killed successfully`, "success");
            } else {
                showToast(`Error killing process: ${data.detail}`, "danger");
            }
        })
        .catch(err => showToast("Failed to connect to backend api", "danger"));
    }
}

// Action: Block remote IP immediately
function quickBlockIP(ip) {
    if (!ip || ip === "127.0.0.1" || ip === "0.0.0.0") return;
    if (confirm(`SECURITY BLOCK: Banning IP ${ip} will drop all packet exchanges immediately. Proceed?`)) {
        fetch("/api/rules/block-ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip, rule_name: `Quick block ${ip}` })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                showToast(`Blacklist entry added for IP: ${ip}`, "success");
                loadRulesTable();
            } else {
                showToast(`Failed to add firewall block rule`, "danger");
            }
        })
        .catch(err => showToast("Communication failure with rules server", "danger"));
    }
}

// Rules Manager Tab: Fetch and Render Rules Table
function loadRulesTable() {
    fetch("/api/rules")
        .then(res => res.json())
        .then(rules => {
            rulesCache = rules;
            const tableBody = document.getElementById("rules-table-body");
            if (rules.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No custom rules set. Click New Rule to add one.</td></tr>';
                return;
            }

            let rows = "";
            rules.forEach(rule => {
                const actionBadge = rule.action === "Deny" ? "badge-block" : (rule.action === "Log" ? "badge-log" : "badge-allow");
                const srcIp = rule.source_ip ? `${rule.source_ip}${rule.source_port ? ':' + rule.source_port : ''}` : "*";
                const destIp = rule.destination_ip ? `${rule.destination_ip}${rule.destination_port ? ':' + rule.destination_port : ''}` : "*";
                
                rows += `
                    <tr>
                        <td><strong>${rule.rule_name}</strong></td>
                        <td>${rule.direction}</td>
                        <td><span class="proto-tag proto-${rule.protocol || 'ANY'}">${rule.protocol || 'ANY'}</span></td>
                        <td>${srcIp}</td>
                        <td>${destIp}</td>
                        <td><span class="badge ${actionBadge}">${rule.action}</span></td>
                        <td>
                            <label class="switch">
                                <input type="checkbox" ${rule.enabled ? 'checked' : ''} onchange="toggleRuleState(${rule.id}, this.checked)">
                                <span class="slider"></span>
                            </label>
                        </td>
                        <td>
                            <button class="btn btn-icon btn-sm" onclick="editRuleForm(${rule.id})" title="Edit rule"><i class="fa-solid fa-pen-to-square"></i></button>
                            <button class="btn btn-icon btn-sm btn-danger" onclick="deleteRule(${rule.id})" title="Delete rule"><i class="fa-solid fa-trash"></i></button>
                        </td>
                    </tr>
                `;
            });
            tableBody.innerHTML = rows;
        });
}

// Action: Toggle custom rule enabled status
function toggleRuleState(ruleId, isChecked) {
    fetch(`/api/rules/${ruleId}/toggle?enabled=${isChecked}`, {
        method: "PATCH"
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === "success") {
            showToast(`Rule state updated`, "success");
        } else {
            showToast(`Failed to toggle firewall rule`, "danger");
        }
    });
}

// Action: Open form to Create rule
function showNewRuleForm() {
    document.getElementById("rule-form-title").innerText = "CREATE NETWORK ACCESS RULE";
    document.getElementById("form-rule-id").value = "";
    document.getElementById("rule-config-form").reset();
    document.getElementById("rules-form-overlay").classList.remove("hidden");
}

// Action: Open form to Edit rule
function editRuleForm(ruleId) {
    const rule = rulesCache.find(r => r.id === ruleId);
    if (!rule) return;
    
    document.getElementById("rule-form-title").innerText = "EDIT NETWORK ACCESS RULE";
    document.getElementById("form-rule-id").value = rule.id;
    document.getElementById("rule-name").value = rule.rule_name;
    document.getElementById("rule-protocol").value = rule.protocol;
    document.getElementById("rule-direction").value = rule.direction;
    document.getElementById("rule-source-ip").value = rule.source_ip || "";
    document.getElementById("rule-source-port").value = rule.source_port || "";
    document.getElementById("rule-destination-ip").value = rule.destination_ip || "";
    document.getElementById("rule-destination-port").value = rule.destination_port || "";
    document.getElementById("rule-action").value = rule.action;
    document.getElementById("rule-enabled").checked = rule.enabled === 1;

    document.getElementById("rules-form-overlay").classList.remove("hidden");
}

// Submit Rule Config Form
function saveRule(e) {
    e.preventDefault();
    const id = document.getElementById("form-rule-id").value;
    
    const payload = {
        rule_name: document.getElementById("rule-name").value,
        protocol: document.getElementById("rule-protocol").value,
        direction: document.getElementById("rule-direction").value,
        source_ip: document.getElementById("rule-source-ip").value || null,
        source_port: document.getElementById("rule-source-port").value ? parseInt(document.getElementById("rule-source-port").value) : null,
        destination_ip: document.getElementById("rule-destination-ip").value || null,
        destination_port: document.getElementById("rule-destination-port").value ? parseInt(document.getElementById("rule-destination-port").value) : null,
        action: document.getElementById("rule-action").value,
        enabled: document.getElementById("rule-enabled").checked ? 1 : 0
    };

    const url = id ? `/api/rules/${id}` : "/api/rules";
    const method = id ? "PUT" : "POST";

    fetch(url, {
        method: method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === "success") {
            showToast(data.message, "success");
            document.getElementById("rules-form-overlay").classList.add("hidden");
            loadRulesTable();
        } else {
            showToast("Error saving rule config parameters.", "danger");
        }
    });
}

// Action: Delete Custom rule
function deleteRule(ruleId) {
    if (confirm("Are you sure you want to delete this firewall rule?")) {
        fetch(`/api/rules/${ruleId}`, {
            method: "DELETE"
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                showToast("Rule removed successfully", "success");
                loadRulesTable();
            } else {
                showToast("Failed to delete rule", "danger");
            }
        });
    }
}

// Historical Logs Management Tab
function loadAuditLogs() {
    const search = document.getElementById("log-search-query").value;
    const type = document.getElementById("log-type-selector").value;
    const proto = document.getElementById("audit-filter-proto").value;
    const action = document.getElementById("audit-filter-action").value;

    const tableHeaders = document.getElementById("audit-table-headers");
    const tableBody = document.getElementById("audit-table-body");
    const filterSub = document.getElementById("audit-packet-filters-sub");

    if (type === "events") {
        // System Event logs
        filterSub.style.display = "none";
        tableHeaders.innerHTML = `
            <th>ID</th>
            <th>TIMESTAMP</th>
            <th>EVENT DESCRIPTION</th>
            <th>LOG STATUS</th>
        `;
        
        fetch(`/api/logs/events?search=${encodeURIComponent(search)}`)
            .then(res => res.json())
            .then(data => {
                if (data.length === 0) {
                    tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center;">No matching system logs.</td></tr>';
                    return;
                }
                
                let rows = "";
                data.forEach(log => {
                    const statusClass = log.status === "ALERT" ? "color: var(--alert-red);" : 
                                        (log.status === "WARNING" ? "color: var(--warning-orange);" : "color: var(--cyber-green);");
                    
                    rows += `
                        <tr>
                            <td>${log.id}</td>
                            <td>${log.timestamp}</td>
                            <td>${log.event}</td>
                            <td style="${statusClass} font-weight: bold;">${log.status}</td>
                        </tr>
                    `;
                });
                tableBody.innerHTML = rows;
            });
    } else {
        // Traffic Packet logs
        filterSub.style.display = "flex";
        tableHeaders.innerHTML = `
            <th>TIMESTAMP</th>
            <th>PROTO</th>
            <th>SOURCE IP</th>
            <th>SRC PORT</th>
            <th>DESTINATION IP</th>
            <th>DEST PORT</th>
            <th>SIZE</th>
            <th>ACTION</th>
        `;

        fetch(`/api/logs/packets?search=${encodeURIComponent(search)}&protocol=${proto}&action=${action}`)
            .then(res => res.json())
            .then(data => {
                if (data.length === 0) {
                    tableBody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No matching traffic records found in DB logs.</td></tr>';
                    return;
                }

                let rows = "";
                data.forEach(pkt => {
                    const actionBadge = pkt.action === "Block" ? "badge-block" : "badge-allow";
                    rows += `
                        <tr>
                            <td>${pkt.timestamp}</td>
                            <td><span class="proto-tag proto-${pkt.protocol}">${pkt.protocol}</span></td>
                            <td>${pkt.source_ip}</td>
                            <td>${pkt.source_port !== null ? pkt.source_port : '-'}</td>
                            <td>${pkt.destination_ip}</td>
                            <td>${pkt.destination_port !== null ? pkt.destination_port : '-'}</td>
                            <td>${pkt.packet_size} Bytes</td>
                            <td><span class="badge ${actionBadge}">${pkt.action}</span></td>
                        </tr>
                    `;
                });
                tableBody.innerHTML = rows;
            });
    }
}

// Log Export actions
function triggerExport(format) {
    const search = document.getElementById("log-search-query").value;
    const type = document.getElementById("log-type-selector").value;
    const proto = document.getElementById("audit-filter-proto").value;
    const action = document.getElementById("audit-filter-action").value;

    let url = `/api/logs/export?format=${format}&log_type=${type}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (type === "packets") {
        url += `&protocol=${proto}&action=${action}`;
    }
    
    showToast(`Generating ${format.toUpperCase()} export report download...`, "info");
    window.location.href = url;
}

// Sync firewall service controls
function syncFirewallStatus() {
    fetch("/api/firewall/status")
        .then(res => res.json())
        .then(data => {
            isFwRunning = data.running;
            updateFwStatusUI(isFwRunning, data.simulation_mode);
        });
}

function toggleFirewall() {
    const endpoint = isFwRunning ? "/api/firewall/stop" : "/api/firewall/start";
    fetch(endpoint, { method: "POST" })
        .then(res => res.json())
        .then(data => {
            if (data.status === "started" || data.status === "stopped" || data.status === "already_running" || data.status === "already_stopped") {
                isFwRunning = !isFwRunning;
                if (data.status === "started") isFwRunning = true;
                if (data.status === "stopped") isFwRunning = false;
                
                showToast(data.message, isFwRunning ? "success" : "warning");
                syncFirewallStatus();
            }
        });
}

function updateFwStatusUI(running, simulationMode) {
    const badge = document.getElementById("fw-status-badge");
    const text = document.getElementById("fw-status-text");
    const toggleBtn = document.getElementById("btn-toggle-fw");
    const modeText = document.getElementById("fw-mode-text");

    if (running) {
        badge.className = "status-indicator active";
        text.innerText = "ACTIVE";
        toggleBtn.innerHTML = '<i class="fa-solid fa-power-off"></i> STOP FIREWALL';
        toggleBtn.className = "btn btn-outline";
    } else {
        badge.className = "status-indicator inactive";
        text.innerText = "DISABLED";
        toggleBtn.innerHTML = '<i class="fa-solid fa-play"></i> START FIREWALL';
        toggleBtn.className = "btn btn-primary";
    }

    if (simulationMode) {
        modeText.innerText = "SIMULATOR";
        modeText.style.color = "var(--warning-orange)";
    } else {
        modeText.innerText = "SNIFFER";
        modeText.style.color = "var(--neon-blue)";
    }
}

// APEX CHARTS SETUP & UPDATES
function initCharts() {
    // Theme styling checks
    const isLight = document.body.classList.contains("light-theme");
    const textColor = isLight ? "#4B5563" : "#9CA3AF";
    const gridColor = isLight ? "#E5E7EB" : "#1F2937";
    
    // Warm up timeline datasets
    if (trafficTimeData.length === 0) {
        for (let i = 0; i < 20; i++) {
            trafficTimeData.push(new Date(Date.now() - (20 - i) * 2000).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'}));
            incomingBytesSeries.push(0);
            outgoingBytesSeries.push(0);
        }
    }

    // 1. Line Traffic Chart
    const trafficOptions = {
        series: [
            { name: "Inbound Rate", data: incomingBytesSeries },
            { name: "Outbound Rate", data: outgoingBytesSeries }
        ],
        chart: {
            type: 'area',
            height: 250,
            background: 'transparent',
            animations: { enabled: false },
            toolbar: { show: false }
        },
        colors: ['#00FF88', '#00D4FF'],
        stroke: { curve: 'smooth', width: 2 },
        fill: {
            type: 'gradient',
            gradient: {
                opacityFrom: 0.15,
                opacityTo: 0.01,
            }
        },
        dataLabels: { enabled: false },
        xaxis: {
            categories: trafficTimeData,
            labels: { show: false, style: { colors: textColor } },
            axisBorder: { show: false },
            axisTicks: { show: false }
        },
        yaxis: {
            min: 0,
            labels: {
                style: { colors: textColor, fontFamily: 'Share Tech Mono' },
                formatter: (val) => `${Math.round(val)} p/s`
            }
        },
        grid: { borderColor: gridColor, strokeDashArray: 3 },
        legend: { labels: { colors: textColor } }
    };
    trafficChart = new ApexCharts(document.querySelector("#chart-traffic"), trafficOptions);
    trafficChart.render();

    // 2. Pie Protocol Chart
    const protocolOptions = {
        series: [0, 0, 0, 0],
        chart: { type: 'donut', height: 250, background: 'transparent' },
        labels: ['TCP', 'UDP', 'ICMP', 'DNS/HTTP(S)'],
        colors: ['#00D4FF', '#8B5CF6', '#FFB347', '#00FF88'],
        legend: { position: 'bottom', labels: { colors: textColor } },
        dataLabels: { enabled: false },
        plotOptions: {
            pie: {
                donut: {
                    size: '70%',
                    background: 'transparent',
                    labels: {
                        show: true,
                        name: { show: true, color: textColor, fontSize: '12px' },
                        value: { show: true, color: textColor, fontSize: '18px', fontFamily: 'Share Tech Mono' },
                        total: { show: true, color: textColor, label: 'TOTAL PACKETS' }
                    }
                }
            }
        }
    };
    protocolChart = new ApexCharts(document.querySelector("#chart-protocols"), protocolOptions);
    protocolChart.render();

    // 3. Top IPs Bar Chart
    const topIpsOptions = {
        series: [
            { name: "Queries", data: [0, 0, 0, 0, 0] }
        ],
        chart: { type: 'bar', height: 250, background: 'transparent', toolbar: { show: false } },
        colors: ['#8B5CF6'],
        plotOptions: {
            bar: {
                horizontal: true,
                barHeight: '50%',
                borderRadius: 4
            }
        },
        dataLabels: { enabled: false },
        xaxis: {
            categories: ['-', '-', '-', '-', '-'],
            labels: { style: { colors: textColor, fontFamily: 'Share Tech Mono' } }
        },
        yaxis: {
            labels: { style: { colors: textColor } }
        },
        grid: { borderColor: gridColor }
    };
    topIpsChart = new ApexCharts(document.querySelector("#chart-top-ips"), topIpsOptions);
    topIpsChart.render();
}

// Update Charts dynamic data
function updateDashboardCharts(statsData) {
    if (!trafficChart) return;

    // 1. Inbound/Outbound delta shifts
    const nowStr = new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
    trafficTimeData.push(nowStr);
    trafficTimeData.shift();

    // Sum protocols rates to get packet flow
    const inTotal = Math.round(statsData.overview.allowed_packets + statsData.overview.blocked_packets);
    // Simulate real delta speeds since stats numbers accumulate
    const deltaIn = Math.max(0, inTotal - (this.lastTotalPackets || inTotal));
    this.lastTotalPackets = inTotal;
    
    // Generate simulated in/out packet ratios
    const inRate = Math.round(deltaIn * 0.6);
    const outRate = Math.round(deltaIn * 0.4);

    incomingBytesSeries.push(inRate > 0 ? inRate : Math.floor(Math.random() * 8) + 1);
    incomingBytesSeries.shift();
    
    outgoingBytesSeries.push(outRate > 0 ? outRate : Math.floor(Math.random() * 5) + 1);
    outgoingBytesSeries.shift();

    trafficChart.updateSeries([
        { name: "Inbound Packets", data: incomingBytesSeries },
        { name: "Outbound Packets", data: outgoingBytesSeries }
    ]);

    // 2. Protocol Distribution Chart update
    const p = statsData.protocols;
    const dnsHttpCombined = p.DNS + p.HTTP + p.HTTPS;
    protocolChart.updateSeries([p.TCP, p.UDP, p.ICMP, dnsHttpCombined]);

    // 3. Top IP query updates
    const topSources = statsData.top_sources || [];
    const ips = [];
    const counts = [];
    
    // Fill categories and values
    for (let i = 0; i < 5; i++) {
        if (topSources[i]) {
            ips.push(topSources[i][0]);
            counts.push(topSources[i][1]);
        } else {
            ips.push("-");
            counts.push(0);
        }
    }
    
    topIpsChart.updateOptions({
        xaxis: { categories: ips }
    });
    topIpsChart.updateSeries([
        { name: "Telemetry Contacts", data: counts }
    ]);
}

// AUDIO ALERT INDICATORS
function triggerThreatAudioAlarm() {
    // Generate a secure futuristic synthesizer ping
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        
        // Oscillator 1 (Cyber Alert Sound)
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(880, audioCtx.currentTime); // Pitch A5
        osc.frequency.exponentialRampToValueAtTime(220, audioCtx.currentTime + 0.5); // Decay pitch down
        
        gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.6); // Volume Decay
        
        osc.start(audioCtx.currentTime);
        osc.stop(audioCtx.currentTime + 0.6);
    } catch (e) {
        // Fallback silently if user audio context is blocked
    }
}

// CANVAS ATTACK MAP ENGINE
function initAttackMap() {
    // Size adjustments
    const resizeCanvas = () => {
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);
    };
    
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    // Map Simulation Threat Feed Ticker
    setInterval(updateSimulatedThreatFeed, 8000);
    updateSimulatedThreatFeed();

    // Start Draw Rendering Loop
    drawMapLoop();
}

// Simulated Threat Intel Feed Updates
const INTEL_ALERTS_MOCKS = [
    "Origin IP 104.244.42.1 (China) scanning corporate network targets.",
    "Botnet command servers tracked to server cluster in Russia (95.12.42.11).",
    "Brute force attacks flagged on open remote services from Brazil IP pool.",
    "Ransomware signature flagged in outbound DNS lookup for domain 'cryptlock.onion'.",
    "Tor exit-node network interface contact recognized at local port 6667.",
    "DDoS TCP-SYN stream blocked from automated reflector pools in Germany."
];
function updateSimulatedThreatFeed() {
    const list = document.getElementById("simulated-intel-feed");
    if (!list) return;

    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const text = INTEL_ALERTS_MOCKS[Math.floor(Math.random() * INTEL_ALERTS_MOCKS.length)];
    const target = "SOC TARGET [LOCAL]";

    const li = document.createElement("li");
    li.innerHTML = `
        <span class="time">[${time}]</span>
        <span class="msg">${text}</span>
        <span class="target">${target}</span>
    `;
    
    list.prepend(li);
    if (list.children.length > 5) {
        list.removeChild(list.lastChild);
    }
}

// Dispatch Packet animation on Threat map
function dispatchPacketToMap(pkt) {
    const isThreat = pkt.action === "Block";
    
    // Choose start hub based on source IP
    const hubNames = Object.keys(MAP_HUBS).filter(h => h !== "Local Host");
    const randomHubName = hubNames[Math.floor(Math.random() * hubNames.length)];
    
    const startHub = MAP_HUBS[randomHubName];
    const endHub = MAP_HUBS["Local Host"];
    
    let color = "var(--neon-blue)";
    if (isThreat) color = "var(--alert-red)";
    else if (pkt.protocol === "UDP") color = "var(--purple-accent)";
    else if (pkt.protocol === "ICMP") color = "var(--warning-orange)";

    // Add arc to animation loop
    activeArcs.push({
        startX: startHub.x,
        startY: startHub.y,
        endX: endHub.x,
        endY: endHub.y,
        progress: 0.0,
        speed: randomRange(0.015, 0.03),
        color: color,
        isThreat: isThreat
    });
}

function dispatchThreatToMap(threat) {
    const hubNames = Object.keys(MAP_HUBS).filter(h => h !== "Local Host");
    const randomHubName = hubNames[Math.floor(Math.random() * hubNames.length)];
    const startHub = MAP_HUBS[randomHubName];
    const endHub = MAP_HUBS["Local Host"];
    
    activeArcs.push({
        startX: startHub.x,
        startY: startHub.y,
        endX: endHub.x,
        endY: endHub.y,
        progress: 0.0,
        speed: 0.01,
        color: "var(--alert-red)",
        isThreat: true
    });
}

// Drawing Animation loop
function drawMapLoop() {
    if (!canvas) return;
    
    const w = canvas.width / (window.devicePixelRatio || 1);
    const h = canvas.height / (window.devicePixelRatio || 1);
    
    // Clear canvas
    ctx.fillStyle = "#050810";
    ctx.fillRect(0, 0, w, h);

    // 1. Draw Globe Tech Matrix Lines (Background)
    ctx.strokeStyle = "rgba(0, 212, 255, 0.02)";
    ctx.lineWidth = 1;
    for (let i = 0; i < w; i += 20) {
        ctx.beginPath();
        ctx.moveTo(i, 0);
        ctx.lineTo(i, h);
        ctx.stroke();
    }
    for (let j = 0; j < h; j += 20) {
        ctx.beginPath();
        ctx.moveTo(0, j);
        ctx.lineTo(w, j);
        ctx.stroke();
    }

    // 2. Draw static hub points and names
    Object.keys(MAP_HUBS).forEach(key => {
        const hub = MAP_HUBS[key];
        const hX = hub.x * w;
        const hY = hub.y * h;
        
        ctx.fillStyle = hub.isLocal ? "var(--cyber-green)" : "rgba(0, 212, 255, 0.4)";
        ctx.shadowColor = hub.isLocal ? "var(--cyber-green)" : "var(--neon-blue)";
        ctx.shadowBlur = hub.isLocal ? 12 : 5;

        // Node circle
        ctx.beginPath();
        ctx.arc(hX, hY, hub.isLocal ? 6 : 4, 0, Math.PI * 2);
        ctx.fill();

        // Local Host Pulse rings
        if (hub.isLocal) {
            const timeFactor = (Date.now() % 2000) / 2000;
            ctx.strokeStyle = `rgba(0, 255, 136, ${1 - timeFactor})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.arc(hX, hY, 6 + timeFactor * 25, 0, Math.PI * 2);
            ctx.stroke();
        }

        // Draw names
        ctx.shadowBlur = 0;
        ctx.fillStyle = "rgba(255, 255, 255, 0.35)";
        ctx.font = "8px 'Share Tech Mono'";
        ctx.fillText(hub.name, hX + 8, hY + 3);
    });

    // 3. Draw and Animate Connection Arcs
    activeArcs.forEach((arc, idx) => {
        arc.progress += arc.speed;
        
        const sx = arc.startX * w;
        const sy = arc.startY * h;
        const ex = arc.endX * w;
        const ey = arc.endY * h;

        // Quadratic Bezier Midpoint
        const mx = (sx + ex) / 2;
        const my = (sy + ey) / 2 - 40; // Curve arc upwards

        // Draw static path line
        ctx.strokeStyle = arc.isThreat ? "rgba(255, 59, 92, 0.08)" : "rgba(0, 212, 255, 0.04)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(sx, sy);
        ctx.quadraticCurveTo(mx, my, ex, ey);
        ctx.stroke();

        // Projectile location matching progress
        const t = arc.progress;
        // Bezier formula
        const px = (1 - t) * (1 - t) * sx + 2 * (1 - t) * t * mx + t * t * ex;
        const py = (1 - t) * (1 - t) * sy + 2 * (1 - t) * t * my + t * t * ey;

        // Glowing projectile
        ctx.fillStyle = arc.color;
        ctx.shadowColor = arc.color;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(px, py, arc.isThreat ? 3.5 : 2.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // If target reached
        if (arc.progress >= 1.0) {
            // Trigger explosion ring
            activeExplosions.push({
                x: ex,
                y: ey,
                radius: 1,
                maxRadius: arc.isThreat ? 35 : 15,
                color: arc.color,
                opacity: 1.0
            });
            activeArcs.splice(idx, 1);
        }
    });

    // 4. Draw explosion ripples
    activeExplosions.forEach((exp, idx) => {
        exp.radius += (exp.maxRadius - exp.radius) * 0.1;
        exp.opacity -= 0.04;

        if (exp.opacity <= 0) {
            activeExplosions.splice(idx, 1);
            return;
        }

        ctx.strokeStyle = exp.color;
        ctx.globalAlpha = exp.opacity;
        ctx.lineWidth = 2;
        ctx.shadowColor = exp.color;
        ctx.shadowBlur = 5;

        ctx.beginPath();
        ctx.arc(exp.x, exp.y, exp.radius, 0, Math.PI * 2);
        ctx.stroke();

        ctx.shadowBlur = 0;
        ctx.globalAlpha = 1.0;
    });

    requestAnimationFrame(drawMapLoop);
}

// Setup static DOM event listeners
function setupEventHandlers() {
    // Theme toggle button
    document.getElementById("theme-switch").addEventListener("click", toggleTheme);

    // Firewall enable/disable
    document.getElementById("btn-toggle-fw").addEventListener("click", toggleFirewall);

    // Manual Refresh
    document.getElementById("btn-refresh-dashboard").addEventListener("click", () => {
        syncFirewallStatus();
        loadRulesTable();
        loadAuditLogs();
        showToast("Synchronized dashboard telemetry with firewall DB", "info");
    });

    // Rules Editor Toggle Form
    document.getElementById("btn-show-rule-form").addEventListener("click", showNewRuleForm);
    document.getElementById("btn-close-rule-form").addEventListener("click", () => {
        document.getElementById("rules-form-overlay").classList.add("hidden");
    });
    document.getElementById("btn-cancel-rule").addEventListener("click", () => {
        document.getElementById("rules-form-overlay").classList.add("hidden");
    });

    // Rule Form submit
    document.getElementById("rule-config-form").addEventListener("submit", saveRule);

    // Packet filters listener
    document.getElementById("packet-search").addEventListener("input", renderPacketsTable);
    document.getElementById("packet-filter-proto").addEventListener("change", renderPacketsTable);
    document.getElementById("packet-filter-action").addEventListener("change", renderPacketsTable);

    // Logs query listeners
    document.getElementById("log-type-selector").addEventListener("change", loadAuditLogs);
    document.getElementById("btn-apply-audit-filters").addEventListener("click", loadAuditLogs);
    document.getElementById("log-search-query").addEventListener("keyup", (e) => {
        if (e.key === "Enter") loadAuditLogs();
    });

    // Export log event buttons
    document.getElementById("btn-export-csv").addEventListener("click", () => triggerExport("csv"));
    document.getElementById("btn-export-json").addEventListener("click", () => triggerExport("json"));
    document.getElementById("btn-export-pdf").addEventListener("click", () => triggerExport("pdf"));
}

// UTILITIES
function randomRange(min, max) {
    return Math.random() * (max - min) + min;
}
