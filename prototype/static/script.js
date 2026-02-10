// IoTriage Prototype - Frontend Logic

document.addEventListener("DOMContentLoaded", checkStatus);

async function checkStatus() {
    try {
        const res = await fetch("/api/status");
        const data = await res.json();
        const badge = document.getElementById("status-badge");

        if (data.is_cloud) {
            badge.textContent = "Demo Mode";
            badge.className = "badge badge-demo";
            document.getElementById("scan-hint").textContent =
                "Running in the cloud with sample data. Download and run locally for live network scanning.";
        } else if (data.nmap_ready) {
            badge.textContent = "Live Mode";
            badge.className = "badge badge-live";
            document.getElementById("scan-hint").textContent =
                "Nmap detected. Scans will run against your real network.";
        } else {
            badge.textContent = "Demo Mode";
            badge.className = "badge badge-demo";
            document.getElementById("scan-hint").textContent =
                "Nmap not found. Showing demo data. Install nmap for live scanning.";
        }
    } catch (e) {
        console.error("Status check failed:", e);
    }
}

async function startScan() {
    const btn = document.getElementById("scan-btn");
    const btnText = btn.querySelector(".btn-text");
    const btnLoading = btn.querySelector(".btn-loading");
    const target = document.getElementById("target").value.trim();

    if (!target) return;

    // Loading state
    btn.disabled = true;
    btnText.style.display = "none";
    btnLoading.style.display = "inline";

    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target }),
        });

        const data = await res.json();

        if (data.error) {
            alert("Scan error: " + data.error);
            return;
        }

        renderResults(data);
    } catch (e) {
        alert("Failed to connect to server: " + e.message);
    } finally {
        btn.disabled = false;
        btnText.style.display = "inline";
        btnLoading.style.display = "none";
    }
}

function renderResults(data) {
    // Hide empty state
    document.getElementById("empty-state").style.display = "none";

    // Show summary
    const summary = document.getElementById("summary");
    summary.style.display = "grid";

    const devices = data.devices || [];
    const high = devices.filter((d) => d.risk === "high").length;
    const medium = devices.filter((d) => d.risk === "medium").length;
    const low = devices.filter((d) => d.risk === "low").length;

    document.getElementById("total-devices").textContent = devices.length;
    document.getElementById("high-risk").textContent = high;
    document.getElementById("medium-risk").textContent = medium;
    document.getElementById("low-risk").textContent = low;

    // Banners
    const devicesSection = document.getElementById("devices");
    let html = "";

    if (data.mode === "cloud_demo") {
        html += `<div class="demo-banner">
            Cloud Demo -- Showing realistic sample data to preview the experience.<br>
            Run locally with nmap installed to scan your actual network.
        </div>`;
    } else if (data.mode === "demo") {
        html += `<div class="demo-banner">
            Demo Mode -- Showing sample data. Install nmap for live network scanning.
        </div>`;
    } else if (data.mode === "demo_fallback" && data.warning) {
        html += `<div class="demo-banner">
            ${data.warning}<br>
            <strong>Tip:</strong> Run the app as Administrator for live results.
        </div>`;
    }

    // Sort: high risk first
    const sorted = [...devices].sort((a, b) => {
        const order = { high: 0, medium: 1, low: 2 };
        return (order[a.risk] ?? 3) - (order[b.risk] ?? 3);
    });

    // Render each device
    sorted.forEach((device, i) => {
        const icon = getDeviceIcon(device);
        const servicesHtml = device.services
            .map(
                (s) => `
            <tr>
                <td><span class="port-badge">${s.port}</span></td>
                <td>${s.protocol}</td>
                <td>${s.service}</td>
                <td>${s.product} ${s.version}</td>
            </tr>`
            )
            .join("");

        html += `
        <div class="device-card">
            <div class="device-header" onclick="toggleDevice(${i})">
                <div class="device-info">
                    <div class="device-icon ${device.risk}">${icon}</div>
                    <div>
                        <div class="device-name">${device.hostname || device.ip}</div>
                        <div class="device-meta">${device.ip}${device.vendor ? " - " + device.vendor : ""}</div>
                    </div>
                </div>
                <span class="risk-badge risk-${device.risk}">${device.risk} risk</span>
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
                </div>
                <div class="services-title">Open Services (${device.services.length})</div>
                <table class="services-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                            <th>Product</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${servicesHtml}
                    </tbody>
                </table>
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
    const name = (device.hostname + " " + device.vendor + " " + device.os).toLowerCase();

    if (name.includes("router") || name.includes("tp-link") || name.includes("netgear"))
        return "&#128225;";
    if (name.includes("tv") || name.includes("samsung") || name.includes("chromecast") || name.includes("roku"))
        return "&#128250;";
    if (name.includes("camera") || name.includes("ring") || name.includes("doorbell"))
        return "&#128247;";
    if (name.includes("echo") || name.includes("alexa") || name.includes("home") || name.includes("speaker"))
        return "&#128266;";
    if (name.includes("hue") || name.includes("light") || name.includes("bulb"))
        return "&#128161;";
    if (name.includes("thermostat") || name.includes("nest"))
        return "&#127777;";
    if (name.includes("printer"))
        return "&#128424;";
    if (name.includes("macbook") || name.includes("laptop") || name.includes("dell") || name.includes("lenovo"))
        return "&#128187;";
    if (name.includes("phone") || name.includes("iphone") || name.includes("android"))
        return "&#128241;";

    return "&#128430;";
}

// Allow Enter key to trigger scan
document.getElementById("target").addEventListener("keydown", function (e) {
    if (e.key === "Enter") startScan();
});
