// Filterable Incident Feed Component with Safe DOM Construction
import { state, updateState } from '../state.js';
import { openIncidentModal } from './incident-detail.js';

export function initIncidentFeed() {
    const catSelect = document.getElementById('filter-category');
    const sevSelect = document.getElementById('filter-severity');

    if (catSelect) {
        catSelect.addEventListener('change', (e) => {
            updateState({ filterCategory: e.target.value });
            renderFeed();
        });
    }

    if (sevSelect) {
        sevSelect.addEventListener('change', (e) => {
            updateState({ filterSeverity: e.target.value });
            renderFeed();
        });
    }

    renderFeed();
}

export function renderFeed() {
    const container = document.getElementById('incidents-feed-container');
    if (!container) return;

    const filtered = state.incidents.filter(inc => {
        const matchCat = state.filterCategory === 'ALL' || inc.threat_category === state.filterCategory;
        const matchSev = state.filterSeverity === 'ALL' || inc.severity === state.filterSeverity;
        return matchCat && matchSev;
    });

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon"><i data-lucide="radar"></i></div>
                <div class="empty-title">${state.incidents.length === 0 ? 'Awaiting Passive Signals' : 'No Matching Incidents'}</div>
                <div class="empty-desc">${state.incidents.length === 0 ? 'Trigger an attack payload above to observe real-time detection & attributions.' : 'Try adjusting filter parameters to inspect historical alerts.'}</div>
            </div>
        `;
        if (window.lucide) window.lucide.createIcons();
        return;
    }

    container.innerHTML = '';
    filtered.forEach(inc => {
        const card = createIncidentCard(inc);
        container.appendChild(card);
    });

    if (window.lucide) window.lucide.createIcons();
}

function createIncidentCard(inc) {
    const card = document.createElement('div');
    card.className = `incident-card ${inc.severity || 'MEDIUM'}`;
    card.addEventListener('click', () => openIncidentModal(inc));

    const header = document.createElement('div');
    header.className = 'inc-header';

    const title = document.createElement('span');
    title.className = 'inc-title';
    title.textContent = `${(inc.threat_category || 'UNKNOWN').toUpperCase()} (${((inc.confidence || 0) * 100).toFixed(0)}%)`;

    const badge = document.createElement('span');
    badge.className = `inc-badge ${inc.severity || 'MEDIUM'}`;
    badge.textContent = inc.severity || 'MEDIUM';

    header.appendChild(title);
    header.appendChild(badge);

    const meta = document.createElement('div');
    meta.className = 'inc-meta';
    meta.textContent = `${inc.src_ip}:${inc.src_port} ➔ ${inc.dst_ip}:${inc.dst_port} (${inc.protocol}) | ${inc.mitre_attack_id || 'T1048'}`;

    const summary = document.createElement('div');
    summary.className = 'inc-summary';
    summary.textContent = inc.evidence_summary || 'Multi-signal heuristic anomaly detected.';

    card.appendChild(header);
    card.appendChild(meta);
    card.appendChild(summary);

    const attributions = inc.feature_attributions || inc.shap_attributions;
    if (attributions) {
        const attrList = document.createElement('div');
        attrList.className = 'attr-list';

        Object.entries(attributions).forEach(([feat, score]) => {
            const pct = Math.min(100, Math.round(score * 100));
            const row = document.createElement('div');
            row.className = 'attr-row';

            const name = document.createElement('span');
            name.className = 'attr-name';
            name.textContent = feat;

            const track = document.createElement('div');
            track.className = 'attr-track';
            const fill = document.createElement('div');
            fill.className = 'attr-fill';
            fill.style.width = `${pct}%`;
            track.appendChild(fill);

            const val = document.createElement('span');
            val.className = 'attr-val';
            val.textContent = `${pct}%`;

            row.appendChild(name);
            row.appendChild(track);
            row.appendChild(val);
            attrList.appendChild(row);
        });

        card.appendChild(attrList);
    }

    return card;
}
