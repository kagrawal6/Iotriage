// IoTriage Prototype - Frontend Logic

document.addEventListener("DOMContentLoaded", checkStatus);

// ==================== STATUS CHECK ====================
async function checkStatus() {
    try {
        const res = await fetch("/api/status");
        const data = await res.json();
        const badge = document.getElementById("status-badge");

        if (data.is_cloud) {
            badge.textContent = "Demo Mode";
            badge.className = "badge badge-demo";
        } else if (data.nmap_ready) {
            badge.textContent = "Live Mode";
            badge.className = "badge badge-live";
        } else {
            badge.textContent = "Demo Mode";
            badge.className = "badge badge-demo";
        }
    } catch (e) {
        console.error("Status check failed:", e);
    }
}

// ==================== SCANNING OVERLAY ====================
const SCAN_PHASES = [
    { pct: 0, phase: "Initializing Nmap scan engine...", delay: 800 },
    { pct: 3, phase: "Resolving target network range...", delay: 1200 },
    { pct: 5, phase: "ARP ping sweep -- discovering live hosts...", delay: 2500 },
    { pct: 12, phase: "Host discovery: sending ICMP echo requests...", delay: 2000 },
    { pct: 18, phase: "Host discovery complete. Starting port scan...", delay: 1500 },
    { pct: 22, phase: "SYN scanning common ports (1-1024)...", delay: 2500 },
    { pct: 32, phase: "Scanning IoT-specific ports (1883, 5353, 8080, 8443)...", delay: 2000 },
    { pct: 40, phase: "Scanning high ports (49152-65535)...", delay: 2500 },
    { pct: 48, phase: "Port scan complete. Running service detection...", delay: 1500 },
    { pct: 52, phase: "Service version detection (-sV) in progress...", delay: 3000 },
    { pct: 62, phase: "Running NSE vulnerability scripts...", delay: 3000 },
    { pct: 72, phase: "Checking CVE databases for known vulnerabilities...", delay: 2500 },
    { pct: 80, phase: "Analyzing firmware versions against NVD...", delay: 2000 },
    { pct: 86, phase: "Running IoT-specific checks (default creds, botnets)...", delay: 2000 },
    { pct: 92, phase: "Calculating risk scores...", delay: 1500 },
    { pct: 96, phase: "Generating report...", delay: 1000 },
    { pct: 100, phase: "Scan complete!", delay: 500 },
];

const TERMINAL_LINES = [
    { text: "Starting Nmap 7.94SVN ( https://nmap.org )", cls: "dim", delay: 500 },
    { text: "Initiating ARP Ping Scan at {time}", cls: "info", delay: 1200 },
    { text: "Scanning {target} [256 hosts]", cls: "", delay: 1800 },
    { text: "Discovered open port 80/tcp on 192.168.1.1", cls: "success", delay: 2800 },
    { text: "Discovered open port 443/tcp on 192.168.1.1", cls: "success", delay: 3200 },
    { text: "Discovered open port 22/tcp on 192.168.1.1", cls: "success", delay: 3500 },
    { text: "Discovered open port 23/tcp on 192.168.1.15", cls: "error", delay: 4500 },
    { text: "Discovered open port 554/tcp on 192.168.1.15", cls: "warn", delay: 5000 },
    { text: "Discovered open port 80/tcp on 192.168.1.15", cls: "success", delay: 5300 },
    { text: "Discovered open port 8001/tcp on 192.168.1.42", cls: "success", delay: 6000 },
    { text: "Discovered open port 9197/tcp on 192.168.1.42", cls: "warn", delay: 6500 },
    { text: "Discovered open port 23/tcp on 192.168.1.200", cls: "error", delay: 7500 },
    { text: "Discovered open port 37777/tcp on 192.168.1.200", cls: "warn", delay: 8000 },
    { text: "Discovered open port 554/tcp on 192.168.1.78", cls: "success", delay: 8500 },
    { text: "Discovered open port 445/tcp on 192.168.1.50", cls: "warn", delay: 9200 },
    { text: "Discovered open port 5000/tcp on 192.168.1.50", cls: "success", delay: 9800 },
    { text: "Discovered open port 23/tcp on 192.168.1.175", cls: "error", delay: 10500 },
    { text: "Discovered open port 554/tcp on 192.168.1.175", cls: "error", delay: 11000 },
    { text: "Discovered open port 1883/tcp on 192.168.1.88", cls: "warn", delay: 11500 },
    { text: "Completed ARP Ping Scan -- 12 hosts up", cls: "info", delay: 12500 },
    { text: "Initiating Service scan at {time}", cls: "info", delay: 13500 },
    { text: "Scanning 12 hosts [47 ports/host]", cls: "dim", delay: 14000 },
    { text: "NSE: Loaded 156 scripts for scanning.", cls: "dim", delay: 16000 },
    { text: "Service: 192.168.1.15:23 -- BusyBox telnetd (CRITICAL)", cls: "error", delay: 17500 },
    { text: "Service: 192.168.1.15:80 -- Hikvision DS-2CD2142FWD-I", cls: "warn", delay: 18500 },
    { text: "VULN: CVE-2021-36260 -- Hikvision Command Injection (CVSS 9.8)", cls: "error", delay: 19500 },
    { text: "VULN: CVE-2017-7921 -- Hikvision Auth Bypass (CVSS 10.0)", cls: "error", delay: 20000 },
    { text: "Service: 192.168.1.200:23 -- BusyBox telnetd 1.19.2", cls: "error", delay: 21000 },
    { text: "VULN: CVE-2021-33044 -- Dahua Auth Bypass (CVSS 9.8)", cls: "error", delay: 22000 },
    { text: "WARNING: Suspected botnet activity on 192.168.1.200", cls: "error", delay: 22500 },
    { text: "Service: 192.168.1.175:80 -- GoAhead WebServer 2.5 (OUTDATED)", cls: "error", delay: 23500 },
    { text: "VULN: CVE-2018-10088 -- GoAhead Buffer Overflow (CVSS 9.8)", cls: "error", delay: 24000 },
    { text: "WARNING: Unauthenticated RTSP stream on 192.168.1.175", cls: "error", delay: 24500 },
    { text: "Service: 192.168.1.50:445 -- Samba 4.15.13 (outdated)", cls: "warn", delay: 25500 },
    { text: "VULN: CVE-2024-10443 -- Synology Zero-Click RCE (CVSS 9.8)", cls: "error", delay: 26000 },
    { text: "Service: 192.168.1.150:443 -- Google Nest API 5.0 (up to date)", cls: "success", delay: 27000 },
    { text: "Service: 192.168.1.160:443 -- August Connect API 2.0 (secure)", cls: "success", delay: 27500 },
    { text: "NSE: Script scanning completed.", cls: "dim", delay: 28000 },
    { text: "Nmap done: 12 hosts up, 47 open ports, 28 vulnerabilities found", cls: "info", delay: 29000 },
];

let scanAnimationRunning = false;

function showScanOverlay(target) {
    const overlay = document.getElementById("scan-overlay");
    overlay.style.display = "flex";
    document.getElementById("scan-target-display").textContent = target;
    document.getElementById("terminal-target").textContent = target;
    document.getElementById("scan-progress-fill").style.width = "0%";
    document.getElementById("scan-progress-percent").textContent = "0%";
    document.getElementById("scan-phase").textContent = "Initializing scan engine...";
    document.getElementById("stat-hosts").textContent = "0";
    document.getElementById("stat-ports").textContent = "0";
    document.getElementById("stat-vulns").textContent = "0";

    // Reset terminal
    const terminal = document.getElementById("scan-terminal");
    terminal.innerHTML = `<div class="terminal-line dim">$ nmap -sV -sC --script vuln ${target}</div>`;

    scanAnimationRunning = true;
    animateProgress();
    animateTerminal(target);
    animateStats();
}

function hideScanOverlay() {
    scanAnimationRunning = false;
    document.getElementById("scan-overlay").style.display = "none";
}

function animateProgress() {
    let phaseIndex = 0;
    function nextPhase() {
        if (!scanAnimationRunning || phaseIndex >= SCAN_PHASES.length) return;
        const phase = SCAN_PHASES[phaseIndex];
        document.getElementById("scan-progress-fill").style.width = phase.pct + "%";
        document.getElementById("scan-progress-percent").textContent = phase.pct + "%";
        document.getElementById("scan-phase").textContent = phase.phase;
        phaseIndex++;
        if (phaseIndex < SCAN_PHASES.length) {
            setTimeout(nextPhase, phase.delay);
        }
    }
    nextPhase();
}

function animateTerminal(target) {
    const terminal = document.getElementById("scan-terminal");
    const now = new Date().toTimeString().split(" ")[0];

    TERMINAL_LINES.forEach((line) => {
        setTimeout(() => {
            if (!scanAnimationRunning) return;
            const div = document.createElement("div");
            div.className = `terminal-line ${line.cls}`;
            div.textContent = line.text.replace("{target}", target).replace("{time}", now);
            terminal.appendChild(div);
            terminal.scrollTop = terminal.scrollHeight;
        }, line.delay);
    });
}

function animateStats() {
    const hostsTarget = 12;
    const portsTarget = 47;
    const vulnsTarget = 28;

    // Animate hosts found (over ~12s)
    let hosts = 0;
    const hostTimes = [2800, 4500, 6000, 7500, 8000, 8500, 9200, 9800, 10500, 11000, 11500, 12500];
    hostTimes.forEach((t, i) => {
        setTimeout(() => {
            if (!scanAnimationRunning) return;
            document.getElementById("stat-hosts").textContent = i + 1;
        }, t);
    });

    // Animate ports (over ~15s)
    let portCount = 0;
    const portInterval = setInterval(() => {
        if (!scanAnimationRunning || portCount >= portsTarget) {
            clearInterval(portInterval);
            return;
        }
        portCount += Math.floor(Math.random() * 3) + 1;
        if (portCount > portsTarget) portCount = portsTarget;
        document.getElementById("stat-ports").textContent = portCount;
    }, 600);

    // Animate vulns (start at ~17s)
    let vulnCount = 0;
    setTimeout(() => {
        const vulnInterval = setInterval(() => {
            if (!scanAnimationRunning || vulnCount >= vulnsTarget) {
                clearInterval(vulnInterval);
                return;
            }
            vulnCount += Math.floor(Math.random() * 3) + 1;
            if (vulnCount > vulnsTarget) vulnCount = vulnsTarget;
            document.getElementById("stat-vulns").textContent = vulnCount;
        }, 700);
    }, 17000);
}

// ==================== SCAN TRIGGER ====================
async function startScan() {
    const btn = document.getElementById("scan-btn");
    const btnText = btn.querySelector(".btn-text");
    const btnLoading = btn.querySelector(".btn-loading");
    const target = document.getElementById("target").value.trim();

    if (!target) return;

    // Show loading overlay
    btn.disabled = true;
    btnText.style.display = "none";
    btnLoading.style.display = "inline";
    showScanOverlay(target);

    try {
        // Start the actual API call
        const fetchPromise = fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target }),
        }).then(r => r.json());

        // Wait for BOTH the animation (30s) AND the API response
        const [data] = await Promise.all([
            fetchPromise,
            new Promise(resolve => setTimeout(resolve, 30000))
        ]);

        hideScanOverlay();

        if (data.error) {
            alert("Scan error: " + data.error);
            return;
        }

        renderResults(data);
    } catch (e) {
        hideScanOverlay();
        alert("Failed to connect to server: " + e.message);
    } finally {
        btn.disabled = false;
        btnText.style.display = "inline";
        btnLoading.style.display = "none";
    }
}

// ==================== RENDER RESULTS ====================
function renderResults(data) {
    document.getElementById("empty-state").style.display = "none";

    const summary = document.getElementById("summary");
    summary.style.display = "grid";

    const devices = data.devices || [];
    const critical = devices.filter((d) => d.risk === "critical").length;
    const high = devices.filter((d) => d.risk === "high").length;
    const medium = devices.filter((d) => d.risk === "medium").length;
    const low = devices.filter((d) => d.risk === "low" || d.risk === "info").length;

    document.getElementById("total-devices").textContent = devices.length;
    document.getElementById("critical-risk").textContent = critical;
    document.getElementById("high-risk").textContent = high;
    document.getElementById("medium-risk").textContent = medium;
    document.getElementById("low-risk").textContent = low;

    const devicesSection = document.getElementById("devices");
    let html = "";

    // Sort: critical > high > medium > low
    const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...devices].sort((a, b) => {
        return (riskOrder[a.risk] ?? 5) - (riskOrder[b.risk] ?? 5);
    });

    sorted.forEach((device, i) => {
        const icon = getDeviceIcon(device);
        const riskLabel = device.risk === "critical" ? "CRITICAL" : device.risk.toUpperCase() + " RISK";
        const vulnCount = (device.vulnerabilities || []).length;

        // Services table
        const servicesHtml = (device.services || [])
            .map(s => `
            <tr>
                <td><span class="port-badge">${s.port}</span></td>
                <td>${s.protocol}</td>
                <td>${s.service}</td>
                <td>${s.product || ""} ${s.version || ""}</td>
            </tr>`).join("");

        // Vulnerabilities
        const vulnsHtml = (device.vulnerabilities || [])
            .map(v => {
                const sevClass = v.severity === "critical" ? "critical" :
                                 v.severity === "high" ? "high" :
                                 v.severity === "medium" ? "medium" :
                                 v.severity === "info" ? "info" : "low";
                const cvssClass = v.cvss >= 9.0 ? "critical" :
                                  v.cvss >= 7.0 ? "high" :
                                  v.cvss >= 4.0 ? "medium" :
                                  v.cvss > 0 ? "low" : "info";
                return `
                <div class="vuln-card">
                    <div class="vuln-header">
                        <span class="vuln-id" onclick="askChatAbout('${v.id}')" title="Click to ask AI about this">${v.id}</span>
                        <span class="cvss-badge cvss-${cvssClass}">CVSS ${v.cvss.toFixed(1)}</span>
                        <span class="vuln-severity" style="color: var(--${sevClass})">${v.severity.toUpperCase()}</span>
                    </div>
                    <div class="vuln-title">${v.title}</div>
                    <div class="vuln-description">${v.description}</div>
                    <div class="vuln-fix"><strong>Fix:</strong> ${v.fix}</div>
                </div>`;
            }).join("");

        // Firmware info
        const fwVersion = device.firmware_version || "Unknown";
        const fwLatest = device.firmware_latest || "Unknown";
        const fwOutdated = fwVersion !== fwLatest && fwLatest !== "Unknown";

        html += `
        <div class="device-card risk-${device.risk}">
            <div class="device-header" onclick="toggleDevice(${i})">
                <div class="device-info">
                    <div class="device-icon ${device.risk}">${icon}</div>
                    <div>
                        <div class="device-name">${device.hostname || device.ip}</div>
                        <div class="device-meta">${device.ip}${device.vendor ? " &mdash; " + device.vendor : ""}${vulnCount > 0 ? " &mdash; " + vulnCount + " vuln" + (vulnCount > 1 ? "s" : "") : ""}</div>
                    </div>
                </div>
                <span class="risk-badge risk-${device.risk}">${riskLabel}</span>
            </div>
            <div class="device-details" id="device-${i}">
                <div class="detail-grid">
                    <div class="detail-item">
                        <label>IP Address</label>
                        <span>${device.ip}</span>
                    </div>
                    <div class="detail-item">
                        <label>MAC Address</label>
                        <span>${device.mac || "Unknown"}</span>
                    </div>
                    <div class="detail-item">
                        <label>Manufacturer</label>
                        <span>${device.vendor || "Unknown"}</span>
                    </div>
                    <div class="detail-item">
                        <label>Operating System</label>
                        <span>${device.os || "Unknown"}</span>
                    </div>
                    <div class="detail-item">
                        <label>Firmware</label>
                        <span class="${fwOutdated ? 'outdated' : 'current'}">${fwVersion}</span>
                    </div>
                    <div class="detail-item">
                        <label>Latest Available</label>
                        <span class="${fwOutdated ? 'outdated' : 'current'}">${fwLatest}${fwOutdated ? ' (UPDATE NEEDED)' : ''}</span>
                    </div>
                </div>

                <div class="section-title">Open Services (${(device.services || []).length})</div>
                <table class="services-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                            <th>Product / Version</th>
                        </tr>
                    </thead>
                    <tbody>${servicesHtml}</tbody>
                </table>

                ${vulnsHtml ? `<div class="section-title">Vulnerabilities (${vulnCount})</div>${vulnsHtml}` : ''}
            </div>
        </div>`;
    });

    devicesSection.innerHTML = html;
}

function toggleDevice(index) {
    const el = document.getElementById(`device-${index}`);
    el.classList.toggle("open");
}

function getDeviceIcon(device) {
    const name = ((device.hostname || "") + " " + (device.vendor || "") + " " + (device.os || "")).toLowerCase();

    if (name.includes("router") || name.includes("gateway") || name.includes("tp-link") || name.includes("netgear") || name.includes("archer"))
        return "&#128225;";
    if (name.includes("tv") || name.includes("samsung") && name.includes("tizen") || name.includes("chromecast") || name.includes("roku"))
        return "&#128250;";
    if (name.includes("cam") || name.includes("hikvision") || name.includes("dahua") || name.includes("ring") || name.includes("doorbell"))
        return "&#128247;";
    if (name.includes("echo") || name.includes("alexa") || name.includes("home") || name.includes("speaker"))
        return "&#128266;";
    if (name.includes("hue") || name.includes("light") || name.includes("bulb"))
        return "&#128161;";
    if (name.includes("thermostat") || name.includes("nest"))
        return "&#127777;";
    if (name.includes("printer"))
        return "&#128424;";
    if (name.includes("nas") || name.includes("synology") || name.includes("qnap"))
        return "&#128451;";
    if (name.includes("baby") || name.includes("vtech") || name.includes("monitor"))
        return "&#128118;";
    if (name.includes("lock") || name.includes("august") || name.includes("schlage"))
        return "&#128274;";
    if (name.includes("plug") || name.includes("kasa") || name.includes("smart plug"))
        return "&#128268;";
    if (name.includes("macbook") || name.includes("laptop") || name.includes("dell") || name.includes("lenovo"))
        return "&#128187;";
    if (name.includes("phone") || name.includes("iphone") || name.includes("android"))
        return "&#128241;";

    return "&#128430;";
}

// ==================== CHATBOT ====================
let chatbotOpen = false;

function toggleChatbot() {
    chatbotOpen = !chatbotOpen;
    document.getElementById("chatbot-panel").style.display = chatbotOpen ? "flex" : "none";
    if (chatbotOpen) {
        document.getElementById("chat-input").focus();
    }
}

function askChatAbout(cveId) {
    // Open chatbot and ask about a specific CVE
    if (!chatbotOpen) toggleChatbot();
    document.getElementById("chat-input").value = `What is ${cveId}?`;
    sendChat();
}

async function sendChat() {
    const input = document.getElementById("chat-input");
    const message = input.value.trim();
    if (!message) return;

    const messages = document.getElementById("chatbot-messages");

    // Add user message
    const userDiv = document.createElement("div");
    userDiv.className = "chat-msg user";
    userDiv.innerHTML = `
        <div class="chat-avatar">You</div>
        <div class="chat-bubble">${escapeHtml(message)}</div>
    `;
    messages.appendChild(userDiv);
    input.value = "";
    messages.scrollTop = messages.scrollHeight;

    // Show typing indicator
    const typingDiv = document.createElement("div");
    typingDiv.className = "chat-msg bot";
    typingDiv.id = "typing-indicator";
    typingDiv.innerHTML = `
        <div class="chat-avatar">AI</div>
        <div class="chat-bubble">
            <div class="typing-dots"><span></span><span></span><span></span></div>
        </div>
    `;
    messages.appendChild(typingDiv);
    messages.scrollTop = messages.scrollHeight;

    try {
        const res = await fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message }),
        });
        const data = await res.json();

        // Remove typing indicator
        document.getElementById("typing-indicator")?.remove();

        // Add bot response with typing effect
        const botDiv = document.createElement("div");
        botDiv.className = "chat-msg bot";
        const formattedResponse = formatMarkdown(data.response);
        botDiv.innerHTML = `
            <div class="chat-avatar">AI</div>
            <div class="chat-bubble">${formattedResponse}</div>
        `;
        messages.appendChild(botDiv);
        messages.scrollTop = messages.scrollHeight;
    } catch (e) {
        document.getElementById("typing-indicator")?.remove();
        const errDiv = document.createElement("div");
        errDiv.className = "chat-msg bot";
        errDiv.innerHTML = `
            <div class="chat-avatar">AI</div>
            <div class="chat-bubble">Sorry, I couldn't process that request. Please try again.</div>
        `;
        messages.appendChild(errDiv);
    }
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

function formatMarkdown(text) {
    // Simple markdown-like formatting
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n- /g, '<br>&#8226; ')
        .replace(/\n(\d+)\. /g, '<br>$1. ')
        .replace(/\n\n/g, '<br><br>')
        .replace(/\n/g, '<br>');
}

// ==================== KEYBOARD SHORTCUTS ====================
document.getElementById("target").addEventListener("keydown", function (e) {
    if (e.key === "Enter") startScan();
});

document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && chatbotOpen) toggleChatbot();
});
