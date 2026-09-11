// Centralized Reactive Client Store
export const state = {
    connectionState: 'connecting', // 'connected' | 'connecting' | 'disconnected'
    totalFlows: 0,
    activeIncidents: 0,
    meanLatency: 0.42,
    bandwidthHistory: Array(35).fill(0),
    maxDataPoints: 35,
    incidents: [],
    topology: { nodes: [], edges: [] },
    filterCategory: 'ALL',
    filterSeverity: 'ALL',
    selectedIncident: null
};

const listeners = new Set();

export function subscribe(fn) {
    listeners.add(fn);
    fn(state);
    return () => listeners.delete(fn);
}

export function updateState(updater) {
    if (typeof updater === 'function') {
        updater(state);
    } else {
        Object.assign(state, updater);
    }
    listeners.forEach(fn => fn(state));
}
