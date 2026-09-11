import { state, subscribe } from '../state.js';

export function initMetricsBar() {
    subscribe((newState) => {
        const flowsEl = document.getElementById('stat-total-flows');
        const incsEl = document.getElementById('stat-active-incidents');
        const latEl = document.getElementById('stat-latency');
        
        if (flowsEl) flowsEl.innerText = newState.totalFlows.toLocaleString();
        if (incsEl) incsEl.innerText = newState.activeIncidents.toLocaleString();
        if (latEl) latEl.innerText = `${newState.meanLatency.toFixed(2)} ms`;
    });
}
