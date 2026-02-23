# Research: Local Deployment and Packaging for IoTriage

## Overview

IoTriage needs to run as a local application on users' home computers. Network scanning (Nmap) requires direct access to the local network and elevated privileges, which means a cloud-hosted solution cannot perform real scans. This document evaluates packaging options to distribute IoTriage as a simple, installable desktop application for non-technical users.

## Current Architecture

Before evaluating options, here is what we are packaging:

- **Backend:** Python / Flask serving a REST API
- **Frontend:** HTML / CSS / JavaScript (served by Flask, no separate build step)
- **Core dependency:** Nmap (external binary, requires admin/root for full functionality)
- **Other Python deps:** python-nmap, potentially future AI libraries (Google Gemini SDK)
- **Target platforms:** Windows 10/11, macOS (Intel + Apple Silicon)

---

## Option 1: Electron + Python Backend

### How it works
Electron wraps the frontend in a Chromium browser window. The Python/Flask backend runs as a child process spawned by Electron. The frontend communicates with the backend over localhost HTTP (e.g. http://127.0.0.1:5000).

### Architecture
```
Electron App
  |-- Chromium (renders frontend HTML/CSS/JS)
  |-- Node.js main process
        |-- Spawns Python backend (bundled via PyInstaller)
        |-- Manages app lifecycle (start, stop, tray icon)
```

### Cross-platform support
- **Windows:** Full support. Electron builds .exe installers via electron-builder. Python backend bundled as a standalone .exe via PyInstaller.
- **macOS:** Full support. Builds .dmg or .app bundles. Python backend bundled as a macOS binary. Code signing required for distribution outside the App Store ($99/year Apple Developer account).
- **Linux:** Supported but not a priority for our target users.

### Nmap bundling
- Nmap binaries can be included in the Electron app's resources folder.
- On Windows, Npcap (required by Nmap) cannot be silently bundled due to licensing. The app would need to check for Npcap on startup and prompt the user to install it if missing.
- On macOS, Nmap can be bundled directly. No equivalent Npcap dependency.
- Alternative: The app detects if Nmap is already installed on the system PATH and uses it, with a fallback prompt to install.

### Pros
- Professional desktop app experience (system tray, native menus, notifications)
- Mature ecosystem with well-documented packaging (electron-builder, electron-forge)
- Auto-update support built in (electron-updater)
- Frontend stays as plain HTML/CSS/JS (no rewrite needed)
- Large community, lots of examples of Electron + Python setups

### Cons
- Large app size (~150-200 MB) because Chromium is bundled
- Memory usage is high (~100-200 MB RAM at idle) due to Chromium
- Two runtimes (Node.js + Python) adds complexity
- Npcap on Windows is a pain point for non-technical users

### Ease of install for non-technical users
- **Windows:** User downloads .exe installer, runs it, app installs like any normal program. If Npcap is missing, app shows a dialog with a download link. **Rating: 7/10**
- **macOS:** User downloads .dmg, drags to Applications. May need to right-click > Open to bypass Gatekeeper if unsigned. **Rating: 6/10** (8/10 if code-signed)

### Estimated development effort
- 2-3 weeks to set up Electron shell, Python process management, and packaging pipeline
- Ongoing maintenance for platform-specific build issues

---

## Option 2: PyInstaller + pywebview

### How it works
PyInstaller bundles the entire Python application (Flask + all dependencies) into a single standalone executable. pywebview creates a native OS window that renders the frontend HTML, eliminating the need for Electron/Chromium.

### Architecture
```
Single Executable (.exe / .app)
  |-- Python runtime (bundled by PyInstaller)
  |-- Flask backend (starts on localhost)
  |-- pywebview window (native OS webview renders frontend)
        |-- Windows: uses Edge WebView2 (pre-installed on Win 10/11)
        |-- macOS: uses WebKit (built into macOS)
```

### Cross-platform support
- **Windows:** Full support. PyInstaller generates a single .exe or a folder. pywebview uses Edge WebView2, which is pre-installed on Windows 10/11.
- **macOS:** Full support. PyInstaller generates a .app bundle. pywebview uses the native WebKit engine.
- **Linux:** Supported via GTK WebKit.

### Nmap bundling
- Same challenges as Electron. Nmap binary can be placed alongside the PyInstaller output.
- On Windows, Npcap remains a separate install requirement.
- On macOS, Nmap binary can be bundled in the .app bundle's Resources folder.
- The app should detect Nmap availability on startup and guide the user.

### Pros
- Much smaller app size (~30-60 MB) since no Chromium is bundled
- Lower memory usage (~50-80 MB) using native OS webview
- Single runtime (Python only), simpler architecture
- Everything is Python, so the whole team can maintain it
- pywebview supports window customization (title, size, frameless, etc.)

### Cons
- pywebview is less mature than Electron (smaller community, fewer examples)
- Native webview rendering can have slight differences between Windows (Edge) and macOS (WebKit), though for our simple frontend this is unlikely to matter
- No built-in auto-update mechanism (would need to build or use a third-party solution)
- PyInstaller can have issues with certain Python packages (e.g. ones with C extensions)
- Code signing still needed for macOS distribution

### Ease of install for non-technical users
- **Windows:** User downloads a single .exe, double-clicks to run. No install step needed if using one-file mode. **Rating: 8/10**
- **macOS:** User downloads .app bundle, moves to Applications. Same Gatekeeper considerations. **Rating: 6/10** (8/10 if code-signed)

### Estimated development effort
- 1-2 weeks to set up PyInstaller bundling and pywebview integration
- Less ongoing maintenance than Electron

---

## Option 3: Tauri (Rust-based alternative to Electron)

### How it works
Tauri is a lightweight framework for building desktop apps. Like Electron, it renders a web frontend in a window, but uses the OS native webview instead of bundling Chromium. The backend logic is written in Rust, but it can also spawn external processes (like our Python backend).

### Architecture
```
Tauri App
  |-- Native OS webview (Edge WebView2 on Windows, WebKit on macOS)
  |-- Rust core process
        |-- Spawns Python/Flask backend as a sidecar process
        |-- OR: Rewrite backend logic in Rust (long-term)
```

### Cross-platform support
- **Windows:** Full support. Builds .msi or .exe installers. Uses Edge WebView2.
- **macOS:** Full support. Builds .dmg bundles. Uses WebKit.
- **Linux:** Full support via GTK WebKit.

### Nmap bundling
- Same as other options. Nmap binary included as a sidecar/resource.
- Tauri has a built-in "sidecar" concept for bundling external binaries, which maps well to including Nmap.

### Pros
- Very small app size (~5-15 MB) since it uses native webview and Rust is compiled
- Very low memory usage (~20-40 MB)
- Built-in auto-update support
- Built-in sidecar support makes bundling Nmap straightforward
- Modern, actively developed, growing community
- Best security model of all three options

### Cons
- Requires Rust knowledge for the core process (learning curve for the team)
- Running Python as a sidecar adds complexity similar to Electron
- Newer framework, fewer Stack Overflow answers and tutorials
- If we want to go full Tauri, we would eventually need to rewrite the Flask backend in Rust, which is significant effort
- Team has no Rust experience (assumption)

### Ease of install for non-technical users
- **Windows:** User downloads .msi installer, runs it. Clean install/uninstall. **Rating: 8/10**
- **macOS:** User downloads .dmg, drags to Applications. **Rating: 6/10** (8/10 if code-signed)

### Estimated development effort
- 3-4 weeks due to Rust learning curve and sidecar configuration
- Lower maintenance long-term if fully adopted

---

## Option 4: Docker Desktop

### How it works
The entire application (Python, Flask, Nmap) runs inside a Docker container. The user installs Docker Desktop, then runs a single command or uses Docker Compose to start IoTriage. The frontend is accessed through a browser at localhost.

### Architecture
```
Docker Container
  |-- Python runtime
  |-- Flask backend
  |-- Nmap (installed via apt-get in container)
  |-- Frontend served at http://localhost:8000
User opens browser to http://localhost:8000
```

### Cross-platform support
- **Windows:** Requires Docker Desktop (free for personal use). Needs WSL2 or Hyper-V enabled.
- **macOS:** Requires Docker Desktop. Works on both Intel and Apple Silicon.
- **Linux:** Native Docker support, easiest platform.

### Nmap bundling
- This is where Docker excels. Nmap is installed directly in the container via `apt-get install nmap`. No Npcap issues, no PATH issues, no version conflicts.
- However, network scanning from inside a container is complicated. The container needs `--net=host` mode to access the host's network, which works on Linux but not on Windows/macOS Docker Desktop (Docker runs in a VM on these platforms).

### Pros
- Easiest development and bundling (we already have a working Dockerfile)
- Nmap works perfectly inside the container with no install hassle
- Consistent environment across all platforms
- No need to deal with PyInstaller, Electron, or native packaging

### Cons
- **Critical:** Network scanning from Docker on Windows/macOS does not work properly. Docker Desktop runs containers in a Linux VM, so the container sees the VM's network, not the user's home network. `--net=host` only works on Linux.
- Docker Desktop is a ~500 MB install and runs a background VM
- Non-technical users are unlikely to have Docker installed or know how to use it
- No native desktop app experience (no system tray, no notifications, just a browser tab)
- Docker Desktop licensing: free for personal use but the requirement to install it is a high barrier

### Ease of install for non-technical users
- **Windows:** User must install Docker Desktop, enable WSL2, pull image, run container. **Rating: 2/10**
- **macOS:** User must install Docker Desktop, pull image, run container. **Rating: 2/10**

### Estimated development effort
- Already mostly done (we have a Dockerfile)
- But solving the network scanning limitation on Windows/macOS may be unsolvable within Docker

---

## Nmap Bundling: Deep Dive

Since Nmap is our core dependency, here is a focused breakdown of how to handle it across platforms.

### Windows
- **Nmap installer:** Official .exe installer from nmap.org includes Npcap. ~25 MB.
- **Npcap requirement:** Nmap on Windows requires Npcap for raw packet capture. Npcap has its own installer and license (free for personal use).
- **Bundling strategy:**
  1. Check if Nmap is on PATH at app startup
  2. If not found, check common install locations (C:\Program Files (x86)\Nmap)
  3. If still not found, show a user-friendly dialog: "IoTriage needs Nmap to scan your network. Click here to download and install it (2 minutes)."
  4. Alternatively, bundle the Nmap zip (portable version) inside our installer and extract it to the app directory. This avoids needing a separate Nmap install but still requires Npcap.
- **Admin privileges:** Full Nmap scanning (SYN scan, OS detection) requires admin. The app can request elevation via UAC prompt. Without admin, we fall back to TCP connect scans (-sT) which still find open ports but are slower and less stealthy.

### macOS
- **Nmap install:** Available via Homebrew (`brew install nmap`) or official .dmg from nmap.org.
- **No Npcap equivalent:** macOS includes libpcap natively, so raw packet capture works out of the box.
- **Bundling strategy:**
  1. Bundle the Nmap binary directly inside the .app bundle
  2. Or detect Homebrew installation at startup
  3. If not found, prompt user: "Install Nmap via Homebrew: `brew install nmap`" or provide a one-click install script
- **Admin privileges:** Sudo required for SYN scan and OS detection. The app can use `osascript` to request admin privileges via a native macOS dialog.

### Recommendation for Nmap
- **Short-term:** Detect Nmap on the system, guide user to install if missing. This is simplest and avoids licensing/bundling complications.
- **Long-term:** Bundle Nmap portable binaries inside our installer. Create a custom installer (via NSIS on Windows, or pkgbuild on macOS) that handles Nmap + Npcap setup as part of the IoTriage install process.

---

## Comparison Summary

| Criteria                    | Electron + Python | PyInstaller + pywebview | Tauri              | Docker Desktop     |
|-----------------------------|-------------------|-------------------------|--------------------|-------------------|
| App size                    | 150-200 MB        | 30-60 MB                | 5-15 MB            | 500 MB (Docker)   |
| Memory usage                | 100-200 MB        | 50-80 MB                | 20-40 MB           | 200+ MB (VM)      |
| Install ease (non-tech)     | 7/10              | 8/10                    | 8/10               | 2/10              |
| Network scanning works      | Yes               | Yes                     | Yes                | No (Win/Mac)      |
| Dev effort                  | 2-3 weeks         | 1-2 weeks               | 3-4 weeks          | Already done       |
| Team skill match (Python)   | Partial           | Full                    | Low (Rust)         | Full              |
| Auto-update                 | Built-in          | Manual                  | Built-in           | Image pull        |
| Native app feel             | Yes               | Yes                     | Yes                | No (browser tab)  |
| Community/maturity          | Very large        | Medium                  | Growing            | Very large        |

---

## Recommendation

### Primary: PyInstaller + pywebview

**Why:** It is the lightest option that our team can fully own. Everything stays in Python, which is our primary language. The app size is small, memory footprint is low, and the install experience is clean (single .exe on Windows). Since our frontend is simple HTML/CSS/JS, we do not need the full power of Electron or Tauri.

### Fallback: Electron + Python

**Why:** If we hit limitations with pywebview (e.g. rendering issues, need for native notifications, need for auto-update), Electron is the proven fallback. It has the largest ecosystem and the most documentation. The tradeoff is a larger app and more complexity.

### Not recommended: Docker Desktop

**Why:** The network scanning limitation on Windows and macOS is a dealbreaker. Our core feature (scanning the user's home network) simply does not work from inside a Docker container on these platforms. Docker is great for our cloud demo and development, but not for end-user distribution.

### Not recommended for now: Tauri

**Why:** While Tauri produces the smallest and most efficient app, the Rust learning curve is too steep for our team and timeline. If the project continues beyond this semester, Tauri would be worth revisiting.

---

## Next Steps

1. Prototype the PyInstaller + pywebview approach with our existing Flask app
2. Test bundling on both Windows and macOS
3. Design the Nmap detection and install flow for first-time users
4. Investigate code signing requirements for macOS distribution
5. Build a simple installer using NSIS (Windows) or pkgbuild (macOS)
