let totalFlows = 0;
let activeIncidents = 0;
let bandwidthHistory = [];
const maxDataPoints = 30;

// Setup HTML5 Canvas Bandwidth Chart
const bwCanvas = document.getElementById('bandwidthCanvas');
const bwCtx = bwCanvas ? bwCanvas.getContext('2d') : null;

// Setup HTML5 Canvas Topology Graph
const topoCanvas = document.getElementById('topologyCanvas');
const topoCtx = topoCanvas ? topoCanvas.getContext('2d') : null;

let nodes = [
    { id: "192.168.1.10", x: 100, y: 100, color: "#38bdf8" },
    { id: "10.0.0.1", x: 300, y: 50, color: "#4ade80" },
    { id: "10.0.0.50", x: 300, y: 150, color: "#f87171" },
    { id: "198.51.100.44", x: 500, y: 100, color: "#fbbf24" }
];
let edges = [];

function drawBandwidthChart() {
    if (!bwCtx) return;
    const width = bwCanvas.width;
    const height = bwCanvas.height;

    bwCtx.clearRect(0, 0, width, height);

    // Background Grid
    bwCtx.strokeStyle = "#1e293b";
    bwCtx.lineWidth = 1;
    for (let y = 0; y < height; y += 40) {
        bwCtx.beginPath();
        bwCtx.moveTo(0, y);
        bwCtx.lineTo(width, y);
        bwCtx.stroke();
    }

    if (bandwidthHistory.length < 2) return;

    const maxVal = Math.max(...bandwidthHistory, 1000);
    const stepX = width / (maxDataPoints - 1);

    bwCtx.beginPath();
    bwCtx.strokeStyle = "#38bdf8";
    bwCtx.lineWidth = 2;

    for (let i = 0; i < bandwidthHistory.length; i++) {
        const x = i * stepX;
        const val = bandwidthHistory[i];
        const y = height - ((val / maxVal) * (height - 30)) - 10;
        if (i === 0) bwCtx.moveTo(x, y);
        else bwCtx.lineTo(x, y);
    }
    bwCtx.stroke();

    // Fill Gradient
    bwCtx.lineTo((bandwidthHistory.length - 1) * stepX, height);
    bwCtx.lineTo(0, height);
    bwCtx.closePath();
    const grad = bwCtx.createLinearGradient(0, 0, 0, height);
    grad.addColorStop(0, 'rgba(56, 189, 248, 0.25)');
    grad.addColorStop(1, 'rgba(56, 189, 248, 0.0)');
    bwCtx.fillStyle = grad;
    bwCtx.fill();
}

function drawTopologyGraph() {
    if (!topoCtx) return;
    const width = topoCanvas.width;
    const height = topoCanvas.height;

    topoCtx.clearRect(0, 0, width, height);

    // Draw Edges
    edges.forEach(e => {
        const srcNode = nodes.find(n => n.id === e.source) || { x: 100, y: 100 };
        const dstNode = nodes.find(n => n.id === e.target) || { x: 450, y: 100 };

        topoCtx.beginPath();
        topoCtx.strokeStyle = "#ef4444";
        topoCtx.lineWidth = 2;
        topoCtx.setLineDash([4, 4]);
        topoCtx.moveTo(srcNode.x, srcNode.y);
        topoCtx.lineTo(dstNode.x, dstNode.y);
        topoCtx.stroke();
        topoCtx.setLineDash([]);
    });

    // Draw Nodes
    nodes.forEach(n => {
        topoCtx.beginPath();
        topoCtx.arc(n.x, n.y, 14, 0, Math.PI * 2);
        topoCtx.fillStyle = n.color;
        topoCtx.fill();
        topoCtx.lineWidth = 2;
        topoCtx.strokeStyle = "#ffffff";
        topoCtx.stroke();

        topoCtx.fillStyle = "#cbd5e1";
        topoCtx.font = "11px sans-serif";
        topoCtx.fillText(n.id, n.x - 30, n.y + 28);
    });
}

// WebSocket Connection Setup
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${wsProtocol}//${window.location.host}/ws/live`;
let socket;

function connectWebSocket() {
    socket = new WebSocket(wsUrl);

    socket.onmessage = function(event) {
        const msg = JSON.parse(event.data);
        if (msg.type === 'flow') {
            totalFlows++;
            document.getElementById('val-total-flows').innerText = totalFlows;
            bandwidthHistory.push(msg.data.bytes_per_sec || 0);
            if (bandwidthHistory.length > maxDataPoints) {
                bandwidthHistory.shift();
            }
            drawBandwidthChart();
        } else if (msg.type === 'incident') {
            activeIncidents++;
            document.getElementById('val-active-incidents').innerText = activeIncidents;
            renderIncidentCard(msg.data);
            
            // Add to topology graph
            edges.push({ source: msg.data.src_ip, target: msg.data.dst_ip });
            if (!nodes.find(n => n.id === msg.data.src_ip)) {
                nodes.push({ id: msg.data.src_ip, x: Math.random() * 450 + 50, y: Math.random() * 120 + 40, color: "#f87171" });
            }
            drawTopologyGraph();
        }
    };

    socket.onclose = function() {
        setTimeout(connectWebSocket, 3000);
    };
}

function renderIncidentCard(inc) {
    const feed = document.getElementById('incidents-feed');
    const emptyState = feed.querySelector('.empty-state');
    if (emptyState) {
        emptyState.remove();
    }

    const card = document.createElement('div');
    card.className = `incident-card ${inc.severity}`;

    let shapHtml = '';
    const attributions = inc.feature_attributions || inc.shap_attributions;
    if (attributions) {
        shapHtml = '<div class="shap-bars">';
        for (const [feat, score] of Object.entries(attributions)) {
            const pct = Math.min(100, Math.round(score * 100));
            shapHtml += `
                <div class="shap-row">
                    <span class="shap-name">${feat}</span>
                    <div class="shap-track"><div class="shap-fill" style="width: ${pct}%"></div></div>
                    <span>${pct}%</span>
                </div>
            `;
        }
        shapHtml += '</div>';
    }

    card.innerHTML = `
        <div class="inc-top">
            <span class="inc-title">🚨 ${inc.threat_category.toUpperCase()} (${(inc.confidence * 100).toFixed(0)}%)</span>
            <span class="inc-tag">${inc.mitre_attack_id}</span>
        </div>
        <div class="inc-detail">
            <strong>Src:</strong> ${inc.src_ip}:${inc.src_port} ➜ <strong>Dst:</strong> ${inc.dst_ip}:${inc.dst_port} (${inc.protocol})
        </div>
        <div class="inc-summary">💡 ${inc.evidence_summary}</div>
        ${shapHtml}
    `;

    feed.prepend(card);
}

function injectAttack(category) {
    fetch(`/api/v1/inject-attack?category=${category}`, { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            showToast(`Injected ${category.toUpperCase()}: ${data.packets_generated} pkts -> ${data.incidents_detected} threats scored.`);
        })
        .catch(err => console.error(err));
}

function showToast(msg) {
    const toast = document.getElementById('toast-msg');
    toast.innerText = msg;
    toast.className = 'toast-visible';
    setTimeout(() => { toast.className = 'toast-hidden'; }, 4000);
}

window.onload = function() {
    drawBandwidthChart();
    drawTopologyGraph();
    connectWebSocket();
};
