// REST API Abstraction Module for Aegis Platform
export async function fetchHealth() {
    const res = await fetch('/api/v1/health');
    if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
    return await res.json();
}

export async function fetchStats() {
    const res = await fetch('/api/v1/stats');
    if (!res.ok) throw new Error(`Stats fetch failed: ${res.statusText}`);
    return await res.json();
}

export async function fetchIncidents(limit = 50) {
    const res = await fetch(`/api/v1/incidents?limit=${limit}`);
    if (!res.ok) throw new Error(`Incidents fetch failed: ${res.statusText}`);
    return await res.json();
}

export async function fetchTopology() {
    const res = await fetch('/api/v1/topology');
    if (!res.ok) throw new Error(`Topology fetch failed: ${res.statusText}`);
    return await res.json();
}

export async function injectAttack(category) {
    const res = await fetch(`/api/v1/inject-attack?category=${category}`, { method: 'POST' });
    if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error || `Attack injection failed (${res.status})`);
    }
    return await res.json();
}
