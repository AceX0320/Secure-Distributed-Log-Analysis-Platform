/**
 * SecureLog Dashboard — Real-Time Client Logic
 * Socket.IO + Plotly.js interactive charts with live data
 */

// ============================================================
// State
// ============================================================
const state = {
    socket: null,
    startTime: Date.now(),
    totalEvents: 0,
    eventsThisMinute: 0,
    threatCount: 0,
    lastMinuteReset: Date.now(),
    maxFeedItems: 80,
};

// ============================================================
// Plotly Theme
// ============================================================
const plotlyLayout = {
    paper_bgcolor: 'rgba(0,0,0,0)',
    plot_bgcolor: 'rgba(0,0,0,0)',
    font: { family: 'Inter, sans-serif', color: '#8892b0', size: 11 },
    margin: { t: 10, r: 20, b: 40, l: 50 },
    xaxis: { gridcolor: 'rgba(255,255,255,0.04)', zerolinecolor: 'rgba(255,255,255,0.06)' },
    yaxis: { gridcolor: 'rgba(255,255,255,0.04)', zerolinecolor: 'rgba(255,255,255,0.06)' },
    showlegend: true,
    legend: { font: { size: 10, color: '#8892b0' }, bgcolor: 'rgba(0,0,0,0)' },
};

const plotlyConfig = {
    displayModeBar: false,
    responsive: true,
};

// ============================================================
// Initialize
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    initSocket();
    initCharts();
    startUptime();
    initFeeds();
    startPeriodicRefresh();
});

// ============================================================
// Socket.IO
// ============================================================
function initSocket() {
    state.socket = io();

    state.socket.on('connect', () => {
        const el = document.getElementById('connection-status');
        el.classList.add('connected');
        el.querySelector('.status-text').textContent = 'Connected';
    });

    state.socket.on('disconnect', () => {
        const el = document.getElementById('connection-status');
        el.classList.remove('connected');
        el.querySelector('.status-text').textContent = 'Disconnected';
    });

    state.socket.on('processed_log', (data) => {
        state.totalEvents++;
        state.eventsThisMinute++;
        addToFeed('log-feed', data);
        updateLogCount();
    });

    state.socket.on('anomaly_detected', (data) => {
        state.threatCount++;
        addToFeed('threat-feed', data, true);
        updateThreatCount();
        flashStatCard('stat-anomalies');
    });

    state.socket.on('stats_update', (data) => {
        updateStats(data);
    });
}

// ============================================================
// Stats
// ============================================================
function updateStats(data) {
    animateNumber('total-logs', data.total_logs || 0);
    animateNumber('total-anomalies', data.total_anomalies || 0);
    animateNumber('critical-events', data.critical_events || 0);
    animateNumber('unique-ips', data.unique_source_ips || 0);
    document.getElementById('anomaly-rate').textContent = (data.anomaly_rate || 0) + '%';
}

function animateNumber(id, target) {
    const el = document.getElementById(id);
    const current = parseInt(el.textContent.replace(/,/g, '')) || 0;
    if (current === target) return;
    const diff = target - current;
    const steps = 20;
    const increment = diff / steps;
    let step = 0;
    const timer = setInterval(() => {
        step++;
        const val = Math.round(current + increment * step);
        el.textContent = val.toLocaleString();
        if (step >= steps) {
            el.textContent = target.toLocaleString();
            clearInterval(timer);
        }
    }, 30);
}

function flashStatCard(id) {
    const el = document.getElementById(id);
    el.style.boxShadow = '0 0 30px rgba(255, 56, 96, 0.3)';
    setTimeout(() => { el.style.boxShadow = ''; }, 600);
}

// ============================================================
// Feed
// ============================================================
function addToFeed(feedId, data, isThreat = false) {
    const feed = document.getElementById(feedId);
    const item = document.createElement('div');
    const sev = (data.severity || 'INFO').toLowerCase();

    item.className = `feed-item severity-${sev}`;
    const time = data.timestamp ? new Date(data.timestamp).toLocaleTimeString() : '--:--:--';
    const sevClass = `sev-${sev}`;

    item.innerHTML = `
        <span class="feed-time">${time}</span>
        <span class="feed-severity ${sevClass}">${(data.severity || 'INFO')}</span>
        <span class="feed-type">${data.event_type || 'UNKNOWN'}</span>
        <span class="feed-ip">${data.source_ip || '—'}</span>
        <span class="feed-msg">${escapeHtml(data.message || '')}</span>
    `;

    feed.insertBefore(item, feed.firstChild);

    // Limit feed size
    while (feed.children.length > state.maxFeedItems) {
        feed.removeChild(feed.lastChild);
    }
}

function updateThreatCount() {
    document.getElementById('threat-count').textContent = state.threatCount + ' threats';
}

function updateLogCount() {
    document.getElementById('log-count').textContent = state.totalEvents + ' events';
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ============================================================
// Initial Feed Population
// ============================================================
function initFeeds() {
    // Recent Anomalies
    fetch('/api/recent-anomalies')
        .then(r => r.json())
        .then(data => {
            if (!data || !data.length) return;
            // Clear existing and add from oldest to newest (so newest is top)
            const feed = document.getElementById('threat-feed');
            feed.innerHTML = '';
            data.reverse().forEach(item => addToFeed('threat-feed', item, true));
            state.threatCount = data.length;
            updateThreatCount();
        })
        .catch(err => console.error('Error fetching recent anomalies:', err));

    // Recent Logs
    fetch('/api/recent-logs')
        .then(r => r.json())
        .then(data => {
            if (!data || !data.length) return;
            const feed = document.getElementById('log-feed');
            feed.innerHTML = '';
            data.reverse().forEach(item => addToFeed('log-feed', item));
            state.totalEvents = data.length; // Approximate from recent
            updateLogCount();
        })
        .catch(err => console.error('Error fetching recent logs:', err));
}

// ============================================================
// Charts
// ============================================================
function initCharts() {
    // Timeline chart placeholder
    Plotly.newPlot('timeline-chart', [
        { x: [], y: [], type: 'scatter', mode: 'lines', name: 'Total Logs',
          line: { color: '#3a86ff', width: 2 }, fill: 'tozeroy',
          fillcolor: 'rgba(58,134,255,0.08)' },
        { x: [], y: [], type: 'scatter', mode: 'lines', name: 'Anomalies',
          line: { color: '#ff3860', width: 2 }, fill: 'tozeroy',
          fillcolor: 'rgba(255,56,96,0.08)' },
    ], { ...plotlyLayout, xaxis: { ...plotlyLayout.xaxis, title: 'Time' },
         yaxis: { ...plotlyLayout.yaxis, title: 'Count' } }, plotlyConfig);

    // Attack distribution
    Plotly.newPlot('attack-chart', [{
        labels: [], values: [], type: 'pie', hole: 0.55,
        marker: { colors: ['#ff3860','#fb5607','#ffd166','#06d6a0','#3a86ff',
                           '#7b2ff7','#ff006e','#00f5d4','#8338ec','#ff9f1c'] },
        textinfo: 'label+percent', textposition: 'outside',
        textfont: { size: 10, color: '#8892b0' },
    }], { ...plotlyLayout, margin: { t: 10, r: 10, b: 10, l: 10 },
          showlegend: false }, plotlyConfig);

    // Severity distribution
    Plotly.newPlot('severity-chart', [{
        x: [], y: [], type: 'bar',
        marker: { color: ['#3a86ff','#06d6a0','#ffd166','#fb5607','#ff3860'],
                  borderRadius: 4 },
    }], { ...plotlyLayout, xaxis: { ...plotlyLayout.xaxis },
          yaxis: { ...plotlyLayout.yaxis, title: 'Count' } }, plotlyConfig);

    // Top IPs
    Plotly.newPlot('top-ips-chart', [{
        x: [], y: [], type: 'bar', orientation: 'h', name: 'Total',
        marker: { color: 'rgba(58,134,255,0.7)' },
    }, {
        x: [], y: [], type: 'bar', orientation: 'h', name: 'Anomalies',
        marker: { color: 'rgba(255,56,96,0.7)' },
    }], { ...plotlyLayout, barmode: 'overlay',
          yaxis: { ...plotlyLayout.yaxis, automargin: true },
          xaxis: { ...plotlyLayout.xaxis, title: 'Count' },
          margin: { ...plotlyLayout.margin, l: 120 } }, plotlyConfig);
}

function refreshCharts() {
    // Timeline
    fetch('/api/timeline').then(r => r.json()).then(data => {
        if (!data.length) return;
        Plotly.react('timeline-chart', [
            { x: data.map(d => d.time), y: data.map(d => d.total),
              type: 'scatter', mode: 'lines+markers', name: 'Total Logs',
              line: { color: '#3a86ff', width: 2, shape: 'spline' },
              marker: { size: 4 },
              fill: 'tozeroy', fillcolor: 'rgba(58,134,255,0.06)' },
            { x: data.map(d => d.time), y: data.map(d => d.anomalies),
              type: 'scatter', mode: 'lines+markers', name: 'Anomalies',
              line: { color: '#ff3860', width: 2, shape: 'spline' },
              marker: { size: 4 },
              fill: 'tozeroy', fillcolor: 'rgba(255,56,96,0.06)' },
        ], { ...plotlyLayout, xaxis: { ...plotlyLayout.xaxis, title: 'Time' },
             yaxis: { ...plotlyLayout.yaxis, title: 'Count' } }, plotlyConfig);
    }).catch(() => {});

    // Attack types
    fetch('/api/event-types').then(r => r.json()).then(data => {
        if (!data.length) return;
        Plotly.react('attack-chart', [{
            labels: data.map(d => d.event_type), values: data.map(d => d.count),
            type: 'pie', hole: 0.55,
            marker: { colors: ['#ff3860','#fb5607','#ffd166','#06d6a0','#3a86ff',
                               '#7b2ff7','#ff006e','#00f5d4','#8338ec','#ff9f1c'] },
            textinfo: 'label+percent', textposition: 'outside',
            textfont: { size: 9, color: '#8892b0' },
        }], { ...plotlyLayout, margin: { t: 10, r: 10, b: 10, l: 10 },
              showlegend: false }, plotlyConfig);
    }).catch(() => {});

    // Severity
    fetch('/api/severity').then(r => r.json()).then(data => {
        if (!data.length) return;
        const colorMap = { INFO: '#3a86ff', LOW: '#06d6a0', MEDIUM: '#ffd166',
                           HIGH: '#fb5607', CRITICAL: '#ff3860' };
        Plotly.react('severity-chart', [{
            x: data.map(d => d.severity), y: data.map(d => d.count), type: 'bar',
            marker: { color: data.map(d => colorMap[d.severity] || '#8892b0') },
        }], { ...plotlyLayout, yaxis: { ...plotlyLayout.yaxis, title: 'Count' } }, plotlyConfig);
    }).catch(() => {});

    // Top IPs
    fetch('/api/top-ips').then(r => r.json()).then(data => {
        if (!data.length) return;
        data.reverse();
        Plotly.react('top-ips-chart', [{
            x: data.map(d => d.count), y: data.map(d => d.source_ip),
            type: 'bar', orientation: 'h', name: 'Total',
            marker: { color: 'rgba(58,134,255,0.6)' },
        }, {
            x: data.map(d => d.anomaly_count), y: data.map(d => d.source_ip),
            type: 'bar', orientation: 'h', name: 'Anomalies',
            marker: { color: 'rgba(255,56,96,0.7)' },
        }], { ...plotlyLayout, barmode: 'overlay',
              yaxis: { ...plotlyLayout.yaxis, automargin: true },
              xaxis: { ...plotlyLayout.xaxis, title: 'Count' },
              margin: { ...plotlyLayout.margin, l: 120 } }, plotlyConfig);
    }).catch(() => {});

    // Stats
    fetch('/api/stats').then(r => r.json()).then(data => {
        updateStats(data);
    }).catch(() => {});
}

// ============================================================
// Utilities
// ============================================================
function startUptime() {
    setInterval(() => {
        const diff = Math.floor((Date.now() - state.startTime) / 1000);
        const h = String(Math.floor(diff / 3600)).padStart(2, '0');
        const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
        const s = String(diff % 60).padStart(2, '0');
        document.getElementById('uptime').textContent = `${h}:${m}:${s}`;
    }, 1000);

    // Events per minute counter
    setInterval(() => {
        document.getElementById('events-per-min').textContent = state.eventsThisMinute;
        state.eventsThisMinute = 0;
    }, 60000);
}

function startPeriodicRefresh() {
    // Initial load
    setTimeout(refreshCharts, 1000);
    // Refresh every 5 seconds
    setInterval(refreshCharts, 5000);
}
