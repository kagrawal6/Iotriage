"""
IoTriage Prototype - Flask Backend
A simple web app that scans your network and shows discovered devices.
"""

import os
from flask import Flask, render_template, jsonify, request
from scanner import scan_network, is_nmap_ready, get_chat_response

app = Flask(__name__)

# Detect cloud deployment (Railway sets RAILWAY_ENVIRONMENT, PORT, etc.)
IS_CLOUD = bool(os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("RENDER") or os.environ.get("DYNO"))

# Store last scan results in memory
last_scan = None


@app.route("/")
def index():
    """Serve the main page."""
    return render_template("index.html")


@app.route("/api/status")
def status():
    """Check if nmap is available."""
    return jsonify({
        "nmap_ready": is_nmap_ready(),
        "is_cloud": IS_CLOUD,
        "message": "Cloud demo mode" if IS_CLOUD else (
            "Nmap is ready" if is_nmap_ready() else "Nmap not found -- using demo data"
        ),
    })


@app.route("/api/scan", methods=["POST"])
def run_scan():
    """Run a network scan."""
    global last_scan

    data = request.get_json() or {}
    target = data.get("target", "192.168.1.0/24")

    try:
        # In cloud mode, always use demo data (can't scan user's local network)
        if IS_CLOUD:
            from scanner import _mock_scan
            results = _mock_scan(target)
            results["mode"] = "cloud_demo"
        else:
            results = scan_network(target)

            # If live scan got blocked by permissions, fall back to demo with warning
            if results.get("needs_admin"):
                from scanner import _mock_scan
                warning = results["warning"]
                results = _mock_scan(target)
                results["mode"] = "demo_fallback"
                results["warning"] = warning

        last_scan = results
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/results")
def get_results():
    """Get the last scan results."""
    if last_scan:
        return jsonify(last_scan)
    return jsonify({"error": "No scan results yet. Run a scan first."}), 404


@app.route("/api/chat", methods=["POST"])
def chat():
    """Chatbot endpoint for vulnerability explanations."""
    data = request.get_json() or {}
    message = data.get("message", "")

    if not message.strip():
        return jsonify({"response": "Please ask me a question about the vulnerabilities found in your scan."})

    response = get_chat_response(message)
    return jsonify({"response": response})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n  IoTriage Prototype")
    print("  ==================")
    if IS_CLOUD:
        print("  Mode: CLOUD DEMO")
    elif is_nmap_ready():
        print("  Nmap: READY (live scanning enabled)")
    else:
        print("  Nmap: NOT FOUND (using demo data)")
    print()
    print(f"  Open http://127.0.0.1:{port} in your browser")
    print()
    app.run(debug=not IS_CLOUD, host="0.0.0.0", port=port)
