/**
 * Aegis SOC Threat Intelligence Console — Client Core Controller
 */

// Application State
const state = {
    totalFlows: 0,
    activeIncidents: 0,
    bandwidthHistory: [],
    maxDataPoints: 35,
    incidents: [],
    nodes: [
        { id: "192.168.1.10", label: "Analyst Host", x: 100, y: 90, color: "#06b6d4" },
        { id: "10.0.0.1", label: "Gateway Router", x: 290, y: 45, color: "#10b981" },
        { id: "10.0.0.50", label: "Internal Server", x: 290, y: 135, color: "#ef4444" },
        { id: "198.51.100.44", label: "External C2 Node", x: 480, y: 90, color: "#f59e0b" }
    ],
    edges: [],
    filterCategory: "ALL",
    filterSeverity: "ALL"
};

// HTML5 Canvas Contexts
const bwCanvas = document.getElementById('bandwidthCanvas');
const bwCtx = bwCanvas ? bwCanvas.getContext('2d') : null;

const topoCanvas = document.getElementById('topologyCanvas');
const topoCtx = topoCanvas ? topoCanvas.getContext('2d') : null;

/* -------------------------------------------------------------------------- */
/* Bandwidth Throughput Chart                                                 */
/* -------------------------------------------------------------------------- */
function drawBandwidthChart() {
    if (!bwCtx) return;
    const width = bwCanvas.width;
    const height = bwCanvas.height;

    bwCtx.clearRect(0, 0, width, height);

    // Background Grid
    bwCtx.strokeStyle = "#1f2937";
    bwCtx.lineWidth = 1;
    for (let y = 0; y < height; y += 30) {
        bwCtx.beginPath();
        bwCtx.moveTo(0, y);
        bwCtx.lineTo(width, y);
        bwCtx.stroke();
    }

    if (state.bandwidthHistory.length < 2) return;

    const maxVal = Math.max(...state.bandwidthHistory, 1000);
    const stepX = width / (state.maxDataPoints - 1);

    // Plot Line
    bwCtx.beginPath();
    bwCtx.strokeStyle = "#06b6d4";
    bwCtx.lineWidth = 2;

    for (let i = 0; i < state.bandwidthHistory.length; i++) {
        const x = i * stepX;
        const val = state.bandwidthHistory[i];
        const y = height - ((val / maxVal) * (height - 30)) - 10;
        if (i === 0) bwCtx.moveTo(x, y);
        else bwCtx.lineTo(x, y);
    }
    bwCtx.stroke();

    // Area Gradient Fill
    bwCtx.lineTo((state.bandwidthHistory.length - 1) * stepX, height);
    bwCtx.lineTo(0, height);
    bwCtx.closePath();
    const grad = bwCtx.createLinearGradient(0, 0, 0, height);
    grad.addColorStop(0, 'rgba(6, 182, 212, 0.25)');
    grad.addColorStop(1, 'rgba(6, 182, 212, 0.0)');
    bwCtx.fillStyle = grad;
    bwCtx.fill();
}

/* -------------------------------------------------------------------------- */
/* Topology Graph Render                                                      */
/* -------------------------------------------------------------------------- */
function drawTopologyGraph() {
    if (!topoCtx) return;
    const width = topoCanvas.width;
    const height = topoCanvas.height;

    topoCtx.clearRect(0, 0, width, height);

    // Render Attack Edges
    state.edges.forEach(e => {
        const srcNode = state.nodes.find(n => n.id === e.source) || { x: 100, y: 90 };
        const dstNode = state.nodes.find(n => n.id === e.target) || { x: 450, y: 90 };

        topoCtx.beginPath();
        topoCtx.strokeStyle = "#ef4444";
        topoCtx.lineWidth = 2;
        topoCtx.setLineDash([4, 4]);
        topoCtx.moveTo(srcNode.x, srcNode.y);
        topoCtx.lineTo(dstNode.x, dstNode.y);
        topoCtx.stroke();
        topoCtx.setLineDash([]);
    });

    // Render Host Nodes
    state.nodes.forEach(n => {
        topoCtx.beginPath();
        topoCtx.arc(n.x, n.y, 12, 0, Math.PI * 2);
        topoCtx.fillStyle = n.color;
        topoCtx.fill();
        topoCtx.lineWidth = 2;
        topoCtx.strokeStyle = "#111827";
        topoCtx.stroke();

        topoCtx.fillStyle = "#9ca3af";
        topoCtx.font = "10px monospace";
        topoCtx.fillText(n.id, n.x - 24, n.y + 24);
    });
}

/* -------------------------------------------------------------------------- */
/* WebSocket Communications & Connection Status                               */
/* -------------------------------------------------------------------------- */
let socket;
let reconnectTimer;

function connectWebSocket() {
    updateConnectionStatus("reconnecting", "CONNECTING");
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/live`;
    
    try {
        socket = new WebSocket(wsUrl);

        socket.onopen = function() {
            updateConnectionStatus("connected", "ONLINE");
            if (reconnectTimer) clearTimeout(reconnectTimer);
        };

        socket.onmessage = function(event) {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'flow') {
                    handleFlowEvent(msg.data);
                } else if (msg.type === 'incident') {
                    handleIncidentEvent(msg.data);
                }
            } catch (err) {
                console.error("WebSocket message parse error:", err);
            }
        };

        socket.onclose = function() {
            updateConnectionStatus("disconnected", "DISCONNECTED");
            reconnectTimer = setTimeout(connectWebSocket, 3000);
        };

        socket.onerror = function() {
            updateConnectionStatus("disconnected", "ERROR");
        };
    } catch (e) {
        updateConnectionStatus("disconnected", "FAILED");
        reconnectTimer = setTimeout(connectWebSocket, 3000);
    }
}

function updateConnectionStatus(stateClass, text) {
    const badge = document.getElementById('ws-status-badge');
    const textSpan = document.getElementById('ws-status-text');
    if (badge && textSpan) {
        const dot = badge.querySelector('.status-dot');
        dot.className = `status-dot ${stateClass}`;
        textSpan.innerText = text;
    }
}

/* -------------------------------------------------------------------------- */
/* Event Processing Handlers                                                  */
/* -------------------------------------------------------------------------- */
function handleFlowEvent(flowData) {
    state.totalFlows++;
    document.getElementById('stat-total-flows').innerText = state.totalFlows;

    state.bandwidthHistory.push(flowData.bytes_per_sec || 0);
    if (state.bandwidthHistory.length > state.maxDataPoints) {
        state.bandwidthHistory.shift();
    }
    drawBandwidthChart();
}

function handleIncidentEvent(incidentData) {
    state.activeIncidents++;
    document.getElementById('stat-active-incidents').innerText = state.activeIncidents;

    state.incidents.unshift(incidentData);

    // Dynamic topology edge addition
    state.edges.push({ source: incidentData.src_ip, target: incidentData.dst_ip });
    if (!state.nodes.find(n => n.id === incidentData.src_ip)) {
        state.nodes.push({
            id: incidentData.src_ip,
            label: incidentData.src_ip,
            x: Math.random() * 400 + 80,
            y: Math.random() * 100 + 40,
            color: "#ef4444"
        });
    }
    drawTopologyGraph();

    renderIncidentFeed();
}

/* -------------------------------------------------------------------------- */
/* Incident Rendering & Filtering                                             */
/* -------------------------------------------------------------------------- */
function renderIncidentFeed() {
    const feed = document.getElementById('incidents-feed');
    if (!feed) return;

    // Filter incidents
    const filtered = state.incidents.filter(inc => {
        const matchCat = state.filterCategory === "ALL" || inc.threat_category === state.filterCategory;
        const matchSev = state.filterSeverity === "ALL" || inc.severity === state.filterSeverity;
        return matchCat && matchSev;
    });

    if (filtered.length === 0) {
        feed.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">
                    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <div class="empty-title">${state.incidents.length === 0 ? "Awaiting Traffic Signals" : "No Matching Incidents"}</div>
                <div class="empty-desc">${state.incidents.length === 0 ? "Inject an attack payload above to observe real-time detection & feature attributions." : "Try clearing category or severity filters to view past alerts."}</div>
            </div>
        `;
        return;
    }

    feed.innerHTML = '';
    filtered.forEach(inc => {
        const card = document.createElement('div');
        card.className = `incident-card ${inc.severity}`;
        card.onclick = () => openDetailModal(inc);

        let attrHtml = '';
        const attributions = inc.feature_attributions || inc.shap_attributions;
        if (attributions) {
            attrHtml = '<div class="attr-list">';
            for (const [feat, score] of Object.entries(attributions)) {
                const pct = Math.min(100, Math.round(score * 100));
                attrHtml += `
                    <div class="attr-row">
                        <span class="attr-name">${feat}</span>
                        <div class="attr-track"><div class="attr-fill" style="width: ${pct}%"></div></div>
                        <span class="attr-val">${pct}%</span>
                    </div>
                `;
            }
            attrHtml += '</div>';
        }

        card.innerHTML = `
            <div class="inc-header">
                <span class="inc-title">${inc.threat_category.toUpperCase()} (${(inc.confidence * 100).toFixed(0)}%)</span>
                <span class="inc-badge ${inc.severity}">${inc.severity}</span>
            </div>
            <div class="inc-meta">
                ${inc.src_ip}:${inc.src_port} ➔ ${inc.dst_ip}:${inc.dst_port} (${inc.protocol}) | ${inc.mitre_attack_id}
            </div>
            <div class="inc-summary">${inc.evidence_summary}</div>
            ${attrHtml}
        `;

        feed.appendChild(card);
    });
}

function filterIncidents() {
    state.filterCategory = document.getElementById('filter-category').value;
    state.filterSeverity = document.getElementById('filter-severity').value;
    renderIncidentFeed();
}

/* -------------------------------------------------------------------------- */
/* Incident Detail Modal Drawer                                               */
/* -------------------------------------------------------------------------- */
function openDetailModal(inc) {
    const modal = document.getElementById('detail-modal');
    const badge = document.getElementById('modal-severity-badge');
    const title = document.getElementById('modal-title');
    const body = document.getElementById('modal-body-content');

    badge.className = `modal-badge inc-badge ${inc.severity}`;
    badge.innerText = inc.severity;
    title.innerText = `${inc.threat_category.toUpperCase()} THREAT INCIDENT`;

    let evidenceItems = (inc.evidence_points || [inc.evidence_summary]).map(e => `
        <div class="evidence-item">
            <span style="color: var(--color-cyan)">✦</span>
            <div>${e}</div>
        </div>
    `).join('');

    body.innerHTML = `
        <div class="detail-section">
            <h4>Incident Identifiers</h4>
            <div class="detail-grid">
                <div><strong>Incident ID:</strong> ${inc.incident_id}</div>
                <div><strong>MITRE Technique:</strong> ${inc.mitre_attack_id}</div>
                <div><strong>Source IP:Port:</strong> ${inc.src_ip}:${inc.src_port}</div>
                <div><strong>Destination IP:Port:</strong> ${inc.dst_ip}:${inc.dst_port}</div>
                <div><strong>Protocol:</strong> ${inc.protocol}</div>
                <div><strong>Confidence Score:</strong> ${(inc.confidence * 100).toFixed(1)}%</div>
                <div><strong>Detection Version:</strong> ${inc.model_version || 'v1.2.0-HeuristicEngine'}</div>
                <div><strong>Suppressed:</strong> ${inc.suppressed ? 'Yes (' + inc.suppression_reason + ')' : 'No'}</div>
            </div>
        </div>

        <div class="detail-section">
            <h4>Extracted Rule-Based Evidence</h4>
            <div class="evidence-bullets">
                ${evidenceItems}
            </div>
        </div>
    `;

    modal.classList.remove('hidden');
}

function closeDetailModal(event) {
    const modal = document.getElementById('detail-modal');
    if (modal) modal.classList.add('hidden');
}

/* -------------------------------------------------------------------------- */
/* Toast Notification System                                                  */
/* -------------------------------------------------------------------------- */
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span>${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

/* -------------------------------------------------------------------------- */
/* Attack Injection Trigger API Call                                          */
/* -------------------------------------------------------------------------- */
function injectAttack(category) {
    showToast(`Injecting synthetic ${category.toUpperCase()} vector...`, 'info');
    fetch(`/api/v1/inject-attack?category=${category}`, { method: 'POST' })
        .then(res => {
            if (!res.ok) throw new Error(`HTTP error ${res.status}`);
            return res.json();
        })
        .then(data => {
            showToast(`Successfully injected ${category.toUpperCase()}: ${data.packets_generated} pkts ➔ ${data.incidents_detected} threats scored.`, 'success');
        })
        .catch(err => {
            showToast(`Injection failed: ${err.message}`, 'error');
            console.error(err);
        });
}

// Initial Load Handler
window.onload = function() {
    drawBandwidthChart();
    drawTopologyGraph();
    connectWebSocket();
};

