// Incident Detail Drawer Component
export function initIncidentDetail() {
    const modal = document.getElementById('detail-modal');
    const closeBtn = document.getElementById('modal-close-btn');

    if (closeBtn) {
        closeBtn.addEventListener('click', closeModal);
    }

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
    }
}

export function openIncidentModal(inc) {
    const modal = document.getElementById('detail-modal');
    const badge = document.getElementById('modal-severity-badge');
    const title = document.getElementById('modal-title');
    const body = document.getElementById('modal-body-content');

    if (!modal || !body) return;

    badge.className = `modal-badge inc-badge ${inc.severity || 'CRITICAL'}`;
    badge.textContent = inc.severity || 'CRITICAL';
    title.textContent = `${(inc.threat_category || 'UNKNOWN').toUpperCase()} INCIDENT ANALYSIS`;

    body.innerHTML = `
        <div class="detail-section">
            <h4>Incident Identifiers</h4>
            <div class="detail-grid">
                <div><strong>Incident ID:</strong> ${inc.incident_id || 'INC-' + Math.random().toString(36).substr(2, 8)}</div>
                <div><strong>MITRE Technique:</strong> ${inc.mitre_attack_id || 'T1059'}</div>
                <div><strong>Source Endpoint:</strong> ${inc.src_ip}:${inc.src_port}</div>
                <div><strong>Destination Endpoint:</strong> ${inc.dst_ip}:${inc.dst_port}</div>
                <div><strong>L4 Protocol:</strong> ${inc.protocol || 'TCP'}</div>
                <div><strong>Confidence Score:</strong> ${((inc.confidence || 0) * 100).toFixed(1)}%</div>
                <div><strong>Detection Subsystem:</strong> ${inc.model_version || 'v1.2.0-HeuristicEngine'}</div>
                <div><strong>Flow ID:</strong> ${inc.flow_id || 'N/A'}</div>
            </div>
        </div>

        <div class="detail-section">
            <h4>Rule-Based Feature Evidence Points</h4>
            <div class="evidence-bullets">
                ${(inc.evidence_points || [inc.evidence_summary || 'No detailed evidence text provided.']).map(e => `
                    <div class="evidence-item">
                        <i data-lucide="shield-check" style="color: var(--color-cyan); width: 16px;"></i>
                        <div>${escapeHtml(e)}</div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;

    modal.classList.remove('hidden');
    if (window.lucide) window.lucide.createIcons();
}

export function closeModal() {
    const modal = document.getElementById('detail-modal');
    if (modal) modal.classList.add('hidden');
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
