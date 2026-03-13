// --- CONFIGURATION ---
const MAX_TABLE_ROWS = 50; 
const MAX_CHART_POINTS = 30;

// --- STATE ---
let dataBuffer = [];
let fullSessionLog = []; 
let chartEnabled = false; // Safety Flag

// --- DOM ELEMENTS ---
const elStatus = document.getElementById('ws-status');
const elThreat = document.getElementById('threat-val');
const elFlows = document.getElementById('flow-val');
const elTarget = document.getElementById('target-val');
const elTableBody = document.getElementById('log-body');
const elSysLog = document.getElementById('system-log-console');

// --- CHART SETUP (Safe Mode) ---
let mainChart = null;
try {
    if (typeof Chart === 'undefined') throw new Error("Chart.js not loaded (Offline?)");
    
    const ctx = document.getElementById('mainChart').getContext('2d');
    mainChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(MAX_CHART_POINTS).fill(''),
            datasets: [{
                label: 'Malice Probability',
                data: Array(MAX_CHART_POINTS).fill(0),
                borderColor: '#007acc',
                backgroundColor: 'rgba(0, 122, 204, 0.1)',
                borderWidth: 2,
                tension: 0.3,
                pointRadius: 0,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: { mode: 'nearest', intersect: false },
            scales: {
                y: { min: 0, max: 1, grid: { color: '#333' } },
                x: { display: false }
            },
            plugins: { legend: { display: false } }
        }
    });
    chartEnabled = true;
} catch (e) {
    console.warn("Graph Disabled:", e.message);
    document.querySelector('.chart-container').innerHTML = 
        `<div style="color:#666; text-align:center; padding-top:100px;">
            GRAPH UNAVAILABLE (OFFLINE MODE)<br>
            <small>Check internet connection or download Chart.js locally</small>
        </div>`;
}

// --- WEBSOCKET ---
const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${protocol}//${window.location.host}/ws`;
let socket;

function connect() {
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        elStatus.textContent = "CONNECTED";
        elStatus.className = "status-val text-safe";
        logToSystem("System Connected to WebSocket Stream", "sys");
    };

    socket.onclose = () => {
        elStatus.textContent = "DISCONNECTED";
        elStatus.className = "status-val text-danger";
        logToSystem("Connection Lost. Retrying...", "high-sev");
        setTimeout(connect, 3000);
    };

    socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        dataBuffer.push(data);
        fullSessionLog.push(data); 
    };
}

// LOOP
function renderLoop() {
    if (dataBuffer.length > 0) {
        while (dataBuffer.length > 0) {
            const data = dataBuffer.shift();
            updateDashboard(data);
        }
        // Only update chart if it exists
        if (chartEnabled && mainChart) {
            mainChart.update('none');
        }
    }
    requestAnimationFrame(renderLoop);
}

function updateDashboard(data) {
    // 1. Stats
    elThreat.innerText = (data.probability * 100).toFixed(2) + "%";
    elTarget.innerText = data.flow_key.split(':')[0];
    
    let color = '#007acc';
    if (data.severity === 'HIGH') color = '#dc3545';
    else if (data.severity === 'MEDIUM') color = '#ffc107';

    elThreat.style.color = color;
    
    if (chartEnabled) {
        mainChart.data.datasets[0].borderColor = color;
        mainChart.data.datasets[0].backgroundColor = color + '33';
        mainChart.data.datasets[0].data.push(data.probability);
        mainChart.data.datasets[0].data.shift();
    }

    // 2. Table Update
    const row = document.createElement('tr');
    let sevClass = data.severity === 'HIGH' ? 'text-danger' : (data.severity === 'MEDIUM' ? 'text-warn' : 'text-safe');
    
    row.innerHTML = `
        <td>${new Date().toLocaleTimeString()}</td>
        <td>${data.flow_key}</td>
        <td>${data.stats.mean_iat.toFixed(4)}</td>
        <td>${data.stats.skewness_iat.toFixed(2)}</td>
        <td>${(data.probability * 100).toFixed(1)}%</td>
        <td class="${sevClass}">${data.severity}</td>
    `;
    
    elTableBody.prepend(row);
    if (elTableBody.children.length > MAX_TABLE_ROWS) elTableBody.removeChild(elTableBody.lastChild);
    elFlows.innerText = elTableBody.children.length;

    if (data.severity === 'HIGH') {
        logToSystem(`CRITICAL ALERT: ${data.flow_key} detected with ${(data.probability*100).toFixed(1)}% confidence.`, "high-sev");
    }
}

// --- UTILITIES ---
window.switchView = function(viewName, btnElement) {
    document.querySelectorAll('.view-section').forEach(el => el.style.display = 'none');
    document.getElementById('view-' + viewName).style.display = 'block';
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    btnElement.classList.add('active');
}

function logToSystem(msg, type="") {
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.innerText = `[${new Date().toLocaleTimeString()}] ${msg}`;
    elSysLog.prepend(entry);
}

window.downloadCSV = function() {
    if (fullSessionLog.length === 0) {
        alert("No data to export yet!");
        return;
    }
    let csvContent = "data:text/csv;charset=utf-8,Timestamp,FlowKey,MeanIAT,Skewness,Probability,Severity\n";
    fullSessionLog.forEach(row => {
        const t = new Date().toISOString();
        csvContent += `${t},${row.flow_key},${row.stats.mean_iat},${row.stats.skewness_iat},${row.probability},${row.severity}\n`;
    });
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "eta_doh_report.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Start
connect();
requestAnimationFrame(renderLoop);
