// Real Chart.js Throughput Stream Component
let chartInstance = null;

export function initThroughputChart() {
    const canvas = document.getElementById('throughputCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    chartInstance = new window.Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(35).fill(''),
            datasets: [{
                label: 'Throughput (Bytes/Sec)',
                data: Array(35).fill(0),
                borderColor: '#06b6d4',
                borderWidth: 2,
                backgroundColor: (context) => {
                    const chart = context.chart;
                    const {ctx, chartArea} = chart;
                    if (!chartArea) return null;
                    const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                    gradient.addColorStop(0, 'rgba(6, 182, 212, 0.3)');
                    gradient.addColorStop(1, 'rgba(6, 182, 212, 0.0)');
                    return gradient;
                },
                fill: true,
                tension: 0.3,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 250 },
            plugins: {
                legend: { display: false },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: '#1f2937',
                    titleColor: '#9ca3af',
                    bodyColor: '#06b6d4',
                    borderColor: '#374151',
                    borderWidth: 1,
                    padding: 10,
                    callbacks: {
                        label: (ctx) => ` Throughput: ${ctx.parsed.y.toLocaleString()} B/s`
                    }
                }
            },
            scales: {
                x: { display: false },
                y: {
                    grid: { color: 'rgba(55, 65, 81, 0.4)' },
                    ticks: {
                        color: '#6b7280',
                        font: { family: 'JetBrains Mono', size: 10 },
                        callback: (val) => val >= 1000 ? `${(val/1000).toFixed(0)}k` : val
                    },
                    min: 0
                }
            }
        }
    });
}

export function updateThroughputChart(history) {
    if (!chartInstance) return;
    chartInstance.data.datasets[0].data = [...history];
    chartInstance.update('none');
}
