// WebSocket Connection & Reconnection Manager with Exponential Backoff
import { updateState } from './state.js';
import { showToast } from './components/toast.js';

let socket = null;
let reconnectAttempts = 0;
const maxBackoff = 10000;

export function initWebSocket(onFlow, onIncident) {
    connect(onFlow, onIncident);
}

function connect(onFlow, onIncident) {
    updateState({ connectionState: 'connecting' });
    updateStatusUI('connecting', 'CONNECTING...');

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;

    try {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            reconnectAttempts = 0;
            updateState({ connectionState: 'connected' });
            updateStatusUI('connected', 'ONLINE');
            showToast('WebSocket connected to live diode stream', 'success');
        };

        socket.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'flow' && onFlow) {
                    onFlow(msg.data);
                } else if (msg.type === 'incident' && onIncident) {
                    onIncident(msg.data);
                }
            } catch (e) {
                console.error('Failed to parse WebSocket message:', e);
            }
        };

        socket.onclose = () => {
            updateState({ connectionState: 'disconnected' });
            updateStatusUI('disconnected', 'DISCONNECTED');
            scheduleReconnect(onFlow, onIncident);
        };

        socket.onerror = (err) => {
            console.error('WebSocket error:', err);
            updateState({ connectionState: 'disconnected' });
            updateStatusUI('disconnected', 'ERROR');
        };
    } catch (e) {
        updateState({ connectionState: 'disconnected' });
        updateStatusUI('disconnected', 'FAILED');
        scheduleReconnect(onFlow, onIncident);
    }
}

function scheduleReconnect(onFlow, onIncident) {
    reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), maxBackoff);
    updateStatusUI('disconnected', `RECONNECTING (${Math.round(delay/1000)}s)`);
    setTimeout(() => connect(onFlow, onIncident), delay);
}

function updateStatusUI(stateClass, text) {
    const badge = document.getElementById('ws-status-badge');
    const textSpan = document.getElementById('ws-status-text');
    if (badge && textSpan) {
        const dot = badge.querySelector('.status-dot');
        if (dot) dot.className = `status-dot ${stateClass}`;
        textSpan.innerText = text;
    }
}
