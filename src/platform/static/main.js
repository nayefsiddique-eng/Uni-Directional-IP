// Aegis Platform ES Module Composition Root
import { state, updateState } from './state.js';
import { injectAttack, fetchIncidents, fetchStats } from './api.js';
import { initWebSocket } from './ws.js';
import { initMetricsBar } from './components/metrics-bar.js';
import { initThroughputChart, updateThroughputChart } from './components/throughput-chart.js';
import { initTopologyGraph, updateTopologyGraph } from './components/topology-graph.js';
import { initIncidentFeed, renderFeed } from './components/incident-feed.js';
import { initIncidentDetail } from './components/incident-detail.js';
import { showToast } from './components/toast.js';

document.addEventListener('DOMContentLoaded', async () => {
    // 1. Initialize Lucide Icons
    if (window.lucide) window.lucide.createIcons();

    // 2. Initialize UI Components
    initMetricsBar();
    initThroughputChart();
    initTopologyGraph();
    initIncidentFeed();
    initIncidentDetail();

    // 3. Attach Attack Injector Button Event Listeners
    const injectorGrid = document.getElementById('attack-injector-controls');
    if (injectorGrid) {
        injectorGrid.addEventListener('click', async (e) => {
            const btn = e.target.closest('button[data-category]');
            if (!btn) return;

            const category = btn.getAttribute('data-category');
            btn.disabled = true;
            showToast(`Injecting synthetic ${category.toUpperCase()} vector...`, 'info');

            try {
                const res = await injectAttack(category);
                showToast(`Injected ${category.toUpperCase()}: ${res.packets_generated} pkts ➔ ${res.incidents_detected} threats scored.`, 'success');
            } catch (err) {
                showToast(`Injection failed: ${err.message}`, 'error');
            } finally {
                btn.disabled = false;
            }
        });
    }

    // 4. Initial REST Data Fetch
    try {
        const initialIncidents = await fetchIncidents(50);
        const stats = await fetchStats();

        updateState(s => {
            s.incidents = initialIncidents;
            s.activeIncidents = stats.incidents_detected || initialIncidents.length;
            s.totalFlows = stats.flows_processed || 0;
        });

        renderFeed();
        initialIncidents.forEach(inc => {
            updateTopologyGraph(inc.src_ip, inc.dst_ip, inc.severity);
        });
    } catch (e) {
        console.warn('Initial REST data load warning:', e);
    }

    // 5. Connect WebSocket Live Broadcaster
    initWebSocket(
        // Flow Handler
        (flow) => {
            updateState(s => {
                s.totalFlows++;
                s.bandwidthHistory.push(flow.bytes_per_sec || 0);
                if (s.bandwidthHistory.length > s.maxDataPoints) {
                    s.bandwidthHistory.shift();
                }
            });
            updateThroughputChart(state.bandwidthHistory);
        },
        // Incident Handler
        (incident) => {
            updateState(s => {
                s.activeIncidents++;
                s.incidents.unshift(incident);
            });
            renderFeed();
            updateTopologyGraph(incident.src_ip, incident.dst_ip, incident.severity);
            showToast(`HIGH THREAT ALERT: ${incident.threat_category.toUpperCase()} Detected`, 'error');
        }
    );
});
