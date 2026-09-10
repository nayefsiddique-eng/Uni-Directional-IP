let flowCount = 0;
let incidentCount = 0;

// Initialize Chart.js
const ctx = document.getElementById('bandwidthChart').getContext('2d');
const bandwidthChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Network Throughput (bytes/sec)',
            data: [],
            borderColor: '#38bdf8',
            backgroundColor: 'rgba(56, 189, 248, 0.1)',
            fill: true,
            tension: 0.3
        }]
    },
    options: {
        responsive: true,
        scales: {
            x: { grid: { color: '#334155' } },
            y: { grid: { color: '#334155' } }
        }
    }
});

// Setup WebSocket connection
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${wsProtocol}//${window.location.host}/ws/live`;
let socket = new WebSocket(wsUrl);

socket.onmessage = function(event) {
    const data = JSON.parse(event.data);
    if (data.type === 'flow') {
        flowCount++;
        document.getElementById('stat-total-flows').innerText = flowCount;
        
        // Update Chart
        const now = new Date().toLocaleTimeString();
        bandwidthChart.data.labels.push(now);
        bandwidthChart.data.datasets[0].data.push(data.data.bytes_per_sec);
        if (bandwidthChart.data.labels.length > 20) {
            bandwidthChart.data.labels.shift();
            bandwidthChart.data.datasets[0].data.shift();
        }
        bandwidthChart.update();
    } else if (data.type === 'incident') {
        incidentCount++;
        document.getElementById('stat-active-incidents').innerText = incidentCount;
        renderIncident(data.data);
    }
};

function renderIncident(inc) {
    const container = document.getElementById('incidents-container');
    if (container.querySelector('.empty-msg')) {
        container.innerHTML = '';
    }
    
    const card = document.createElement('div');
    card.className = `incident-card ${inc.severity}`;
    card.innerHTML = `
        <div class="incident-header">
            <span>🚨 ${inc.threat_category.toUpperCase()} (${(inc.confidence * 100).toFixed(0)}%)</span>
            <span class="mitre-tag">${inc.mitre_attack_id}</span>
        </div>
        <div class="evidence-text">
            <strong>Src:</strong> ${inc.src_ip} ➜ <strong>Dst:</strong> ${inc.dst_ip}:${inc.dst_port}
        </div>
        <div class="evidence-text">
            💡 <em>${inc.evidence_summary}</em>
        </div>
    `;
    container.prepend(card);
}

function triggerAttack(category) {
    fetch(`/api/v1/inject-attack?category=${category}`, { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            console.log("Attack injected:", data);
        })
        .catch(err => console.error("Error triggering attack:", err));
}
