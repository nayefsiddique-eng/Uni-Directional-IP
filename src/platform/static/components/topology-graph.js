// D3 Force-Directed Topology Graph Component
let simulation = null;
let svg = null;
let gNodes = null;
let gLinks = null;

let nodesData = [
    { id: "192.168.1.10", label: "Analyst Host", role: "host" },
    { id: "10.0.0.1", label: "Gateway Router", role: "gateway" },
    { id: "10.0.0.50", label: "Internal Target", role: "server" },
    { id: "198.51.100.44", label: "C2 Server", role: "external" }
];
let linksData = [];

export function initTopologyGraph() {
    const container = document.getElementById('topology-graph-container');
    if (!container || !window.d3) return;

    container.innerHTML = '';
    const width = container.clientWidth || 550;
    const height = container.clientHeight || 180;

    svg = window.d3.select('#topology-graph-container')
        .append('svg')
        .attr('width', '100%')
        .attr('height', '100%')
        .attr('viewBox', `0 0 ${width} ${height}`);

    gLinks = svg.append('g').attr('class', 'links');
    gNodes = svg.append('g').attr('class', 'nodes');

    simulation = window.d3.forceSimulation(nodesData)
        .force('link', window.d3.forceLink(linksData).id(d => d.id).distance(90))
        .force('charge', window.d3.forceManyBody().strength(-180))
        .force('center', window.d3.forceCenter(width / 2, height / 2))
        .on('tick', ticked);

    render();
}

export function updateTopologyGraph(srcIp, dstIp, severity) {
    if (!srcIp || !dstIp) return;

    if (!nodesData.find(n => n.id === srcIp)) {
        nodesData.push({ id: srcIp, role: 'attacker' });
    }
    if (!nodesData.find(n => n.id === dstIp)) {
        nodesData.push({ id: dstIp, role: 'victim' });
    }

    if (!linksData.find(l => (l.source.id === srcIp || l.source === srcIp) && (l.target.id === dstIp || l.target === dstIp))) {
        linksData.push({ source: srcIp, target: dstIp, severity: severity || 'CRITICAL' });
    }

    if (simulation) {
        simulation.nodes(nodesData);
        simulation.force('link').links(linksData);
        simulation.alpha(0.3).restart();
        render();
    }
}

function render() {
    if (!svg) return;

    const link = gLinks.selectAll('line').data(linksData);
    link.exit().remove();
    const linkEnter = link.enter().append('line')
        .attr('stroke', d => d.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b')
        .attr('stroke-width', 2)
        .attr('stroke-dasharray', '4,4');

    const node = gNodes.selectAll('g').data(nodesData, d => d.id);
    node.exit().remove();
    const nodeEnter = node.enter().append('g');

    nodeEnter.append('circle')
        .attr('r', 8)
        .attr('fill', d => {
            if (d.role === 'attacker') return '#ef4444';
            if (d.role === 'gateway') return '#10b981';
            if (d.role === 'host') return '#06b6d4';
            return '#3b82f6';
        })
        .attr('stroke', '#111827')
        .attr('stroke-width', 2);

    nodeEnter.append('text')
        .text(d => d.id)
        .attr('x', 12)
        .attr('y', 4)
        .attr('fill', '#9ca3af')
        .attr('font-size', '10px')
        .attr('font-family', 'JetBrains Mono');
}

function ticked() {
    if (!svg) return;
    gLinks.selectAll('line')
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

    gNodes.selectAll('g')
        .attr('transform', d => `translate(${d.x},${d.y})`);
}
