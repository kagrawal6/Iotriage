# IoTriage Technology Stack Guide

## Table of Contents
1. [Network Scanning Technologies](#network-scanning-technologies)
2. [Backend Framework Options](#backend-framework-options)
3. [Database Solutions](#database-solutions)
4. [Frontend Technologies](#frontend-technologies)
5. [Vulnerability Data Sources](#vulnerability-data-sources)
6. [AI/LLM Integration](#aillm-integration)
7. [Architecture Patterns](#architecture-patterns)
8. [Caching Strategies](#caching-strategies)
9. [Additional Tools & Libraries](#additional-tools--libraries)

---

## Network Scanning Technologies

### Nmap (Network Mapper)
**What it is:** Industry-standard network scanning tool that discovers hosts and services on a network.

**Capabilities:**
- **Host Discovery:** Identify live devices on network (`-sn` ping sweep)
- **Port Scanning:** Find open ports and running services (`-p`)
- **Service Detection:** Identify service versions (`-sV`)
- **OS Fingerprinting:** Detect operating systems (`-O`)
- **NSE Scripts:** 600+ scripts for specific tasks (`--script`)
- **Output Formats:** XML, JSON, grepable formats for parsing

**Pros:**
- Extremely powerful and feature-rich
- Well-documented with huge community
- Can detect device types, manufacturers, firmware versions
- Scriptable and extensible (NSE Lua scripts)
- Works on Windows, Linux, macOS
- Free and open source
- Python wrappers available (`python-nmap`, `nmap3`)
- Reliable service version detection

**Cons:**
- Can be slow on large networks (aggressive scans take time)
- Requires elevated privileges for some features (OS detection, SYN scan)
- May trigger IDS/IPS systems (looks like attack traffic)
- Learning curve for advanced features
- XML parsing can be tedious without libraries
- Not ideal for continuous real-time monitoring

**Best for:** Comprehensive device discovery, service enumeration, IoT device identification

**Integration Options:**
```python
# Option 1: python-nmap library
import nmap
nm = nmap.PortScanner()
nm.scan('192.168.1.0/24', arguments='-sV')

# Option 2: Subprocess with XML parsing
subprocess.run(['nmap', '-sV', '-oX', 'scan.xml', '192.168.1.0/24'])
# Then parse XML with xml.etree.ElementTree

# Option 3: nmap3 (modern Python 3 wrapper)
import nmap3
nmap = nmap3.Nmap()
results = nmap.scan_top_ports("192.168.1.1")
```

**Recommended nmap flags for IoT scanning:**
- `-sV` - Service/version detection (critical for CVE matching)
- `-O` - OS detection
- `-A` - Aggressive scan (OS, version, script, traceroute)
- `--script=banner` - Grab service banners
- `--script=upnp-info` - UPnP device info (common in IoT)
- `-T4` - Faster timing (T0-T5, where T5 is insane speed)
- `-oX` - XML output for parsing

---

### Masscan
**What it is:** Ultra-fast port scanner, can scan entire internet in minutes.

**Capabilities:**
- Asynchronous TCP/UDP scanning
- Custom packet crafting
- Banner grabbing

**Pros:**
- Incredibly fast (1000x faster than nmap)
- Great for initial discovery on large networks
- Can scan thousands of hosts simultaneously
- Low resource usage

**Cons:**
- Less detailed than nmap (no service version detection)
- No OS fingerprinting
- No NSE script equivalent
- Can overwhelm network infrastructure
- Less accurate than nmap

**Best for:** Initial fast discovery, then hand off to nmap for detailed scanning

**When to use:**
- Large enterprise networks (100+ devices)
- Quick "what's out there" sweeps
- When speed > accuracy

**When NOT to use:**
- Small home networks (overkill)
- When you need detailed service info
- Vulnerability assessment (needs nmap's depth)

---

### Scapy
**What it is:** Python library for packet manipulation and custom protocol implementation.

**Capabilities:**
- Craft custom packets at any layer
- Sniff network traffic
- Implement custom network protocols
- ARP scanning, traceroute, network discovery

**Pros:**
- Ultimate flexibility (build any packet you want)
- Great for custom IoT protocol analysis
- Python-native (no subprocess calls)
- Real-time packet capture
- Can implement passive scanning

**Cons:**
- Requires deep networking knowledge
- More code to write vs using nmap
- Performance not as good as C-based tools
- Requires root/admin privileges
- Steeper learning curve

**Best for:** Custom scanning logic, packet analysis, when nmap can't do what you need

**Example use case:**
```python
from scapy.all import ARP, Ether, srp

# Quick ARP scan (faster than nmap for local network)
def arp_scan(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices
```

---

### Arp-scan
**What it is:** Specialized tool for discovering IPv4 hosts using ARP requests.

**Pros:**
- Very fast for local network discovery
- Reliable on local LANs
- Minimal false negatives
- Lightweight

**Cons:**
- Only works on local network (Layer 2)
- No port scanning or service detection
- IPv4 only

**Best for:** Quick initial device discovery on local networks before deep nmap scan

---

### Zeroconf/Bonjour/mDNS
**What it is:** Service discovery protocols where devices advertise themselves.

**Pros:**
- Passive (doesn't actively scan)
- Devices self-identify with names/services
- Common in IoT devices (smart speakers, printers, etc.)
- Non-intrusive

**Cons:**
- Only finds devices that advertise
- Many IoT devices don't use mDNS
- No vulnerability information

**Best for:** Supplementing active scans, discovering smart home devices

**Python library:** `zeroconf`

---

### **Recommendation for IoTriage:**
**Primary:** Nmap (comprehensive, IoT-focused)
**Secondary:** Arp-scan or Scapy for quick initial discovery
**Optional:** Zeroconf for passive device discovery

**Workflow:**
1. Quick arp-scan to find all devices
2. Deep nmap scan on discovered devices for services/versions
3. Zeroconf listening for devices that advertise

---

## Backend Framework Options

### Flask (Python)
**What it is:** Micro web framework for Python, minimalist and unopinionated.

**Pros:**
- Simple to learn and get started
- Lightweight, minimal boilerplate
- Huge ecosystem of extensions
- Great documentation and community
- Flexible - structure your app however you want
- Perfect for APIs (Flask-RESTful, Flask-RESTX)
- Easy integration with nmap (both Python)
- Built-in development server

**Cons:**
- Not async by default (blocking I/O)
- Slower than FastAPI for concurrent requests
- Need to add everything yourself (auth, validation, etc.)
- Can become messy without structure in large apps
- Less type safety (no automatic validation)

**Best for:** 
- Quick MVP development
- When you want control over architecture
- Teams familiar with Python
- Smaller to medium projects

**Example structure:**
```python
from flask import Flask, jsonify
import nmap

app = Flask(__name__)
nm = nmap.PortScanner()

@app.route('/scan', methods=['POST'])
def scan_network():
    nm.scan('192.168.1.0/24', arguments='-sV')
    return jsonify(nm.all_hosts())
```

**Key Extensions:**
- `Flask-CORS` - Handle cross-origin requests
- `Flask-SQLAlchemy` - Database ORM
- `Flask-Migrate` - Database migrations
- `Flask-Login` - User authentication
- `Celery` - Background tasks (for long-running scans)

---

### FastAPI (Python)
**What it is:** Modern, fast async web framework with automatic API documentation.

**Pros:**
- Very fast performance (async/await)
- Automatic API documentation (Swagger UI, ReDoc)
- Type hints and automatic validation (Pydantic)
- Modern Python features (3.7+)
- Great for concurrent operations (multiple scans)
- Built-in WebSocket support
- Fewer bugs due to type checking
- Easy to test

**Cons:**
- Async can be complex for beginners
- Younger ecosystem than Flask
- Need to think about async/await for everything
- Some libraries aren't async-compatible
- Slightly steeper learning curve

**Best for:**
- High-performance APIs
- Real-time features (WebSocket scan updates)
- When handling many concurrent requests
- Modern codebases with type safety

**Example:**
```python
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

app = FastAPI()

class ScanRequest(BaseModel):
    network: str
    scan_type: str = "quick"

@app.post("/scan")
async def scan_network(request: ScanRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_nmap_scan, request.network)
    return {"status": "scan started"}
```

**Why it's great for IoTriage:**
- Multiple scans can run concurrently
- Real-time progress updates via WebSockets
- Automatic input validation (IP addresses, etc.)
- API docs generated automatically

---

### Django (Python)
**What it is:** Full-featured "batteries included" web framework.

**Pros:**
- Everything included (ORM, admin panel, auth, forms)
- Excellent security defaults
- Powerful ORM with migrations
- Admin interface out of the box
- Well-established patterns
- Great for user management

**Cons:**
- Heavy for API-only backend
- More opinionated (Django way or highway)
- Slower than Flask/FastAPI
- Overkill for this project
- Steeper learning curve
- More boilerplate code

**Best for:**
- Full web applications with traditional views
- When you need admin panel
- Large teams with established Django experience

**Verdict for IoTriage:** Probably overkill unless you want the admin panel

---

### Express.js (Node.js)
**What it is:** Minimal web framework for Node.js.

**Pros:**
- JavaScript everywhere (frontend + backend)
- Huge NPM ecosystem
- Non-blocking I/O (async by nature)
- Fast for I/O-bound operations
- Many nmap libraries (`node-nmap`, `libnmap`)
- Easy WebSocket integration
- JSON handling is native

**Cons:**
- Callback hell / async complexity
- Less structure than Python frameworks
- JavaScript type issues (use TypeScript)
- Python better for security/networking tools
- Weaker typing (even with TypeScript)

**Best for:**
- JavaScript-first teams
- Real-time applications
- When frontend and backend share code

---

### NestJS (Node.js)
**What it is:** Structured Node.js framework inspired by Angular.

**Pros:**
- TypeScript-first
- Excellent structure and organization
- Dependency injection
- Great for large teams
- Built-in support for WebSockets, GraphQL, microservices

**Cons:**
- Steep learning curve
- More boilerplate than Express
- Opinionated architecture
- Overkill for smaller projects

**Best for:** Enterprise-level applications with large teams

---

### Go (Golang)
**What it is:** Compiled language designed for concurrent systems.

**Pros:**
- Extremely fast (compiled to native code)
- Excellent concurrency (goroutines)
- Single binary deployment (no dependencies)
- Great for high-performance scanning
- Strong typing
- Low memory footprint

**Cons:**
- Steeper learning curve if team doesn't know Go
- Less ecosystem for web/AI compared to Python
- More verbose code
- Fewer vulnerability database libraries
- Gemini API better supported in Python

**Best for:** Performance-critical scanning engine (could build scan service in Go, API in Python)

---

### **Recommendation for IoTriage:**

**Best Choice: FastAPI**
- Async scanning operations
- Real-time updates via WebSocket
- Automatic API docs (helpful for development)
- Great Python integration with nmap
- Type safety reduces bugs

**Alternative: Flask**
- Simpler if team is new to async
- Add Celery for background tasks
- More tutorials/resources available

**Verdict:** FastAPI for modern features, Flask for simplicity

---

## Database Solutions

### PostgreSQL
**What it is:** Advanced open-source relational database.

**Pros:**
- Feature-rich (JSON support, full-text search, arrays)
- ACID compliant (reliable transactions)
- Great for complex queries
- Excellent performance with proper indexing
- JSONb type (store scan results as JSON)
- Supports full-text search (CVE descriptions)
- Robust backup/restore
- Concurrent connections
- Great Python support (psycopg2, SQLAlchemy)

**Cons:**
- Requires separate server process
- More complex setup than SQLite
- Overkill for single-user deployments
- More memory usage

**Best for:** Production deployments, multi-user scenarios, complex reporting

**Schema example:**
```sql
CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    mac_address MACADDR,
    hostname VARCHAR(255),
    manufacturer VARCHAR(255),
    device_type VARCHAR(100),
    scan_data JSONB,  -- Store full nmap results
    first_seen TIMESTAMP,
    last_seen TIMESTAMP
);

CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE,
    description TEXT,
    cvss_score FLOAT,
    published_date DATE,
    cve_data JSONB  -- Full CVE JSON from NVD
);

CREATE TABLE device_vulnerabilities (
    device_id INT REFERENCES devices(id),
    vulnerability_id INT REFERENCES vulnerabilities(id),
    detected_at TIMESTAMP,
    PRIMARY KEY (device_id, vulnerability_id)
);
```

---

### SQLite
**What it is:** Serverless, file-based SQL database.

**Pros:**
- Zero configuration (no server)
- Single file database
- Perfect for development/prototyping
- Fast for small to medium datasets
- Built into Python standard library
- Great for single-user deployments
- Easy backups (copy file)
- Cross-platform

**Cons:**
- No concurrent writes (locks database)
- Limited scalability
- No user management/authentication
- Not ideal for web apps with multiple users
- Less powerful than PostgreSQL

**Best for:** MVP, development, single-user home network tool, proof-of-concept

---

### MongoDB
**What it is:** NoSQL document database (stores JSON-like documents).

**Pros:**
- Schema-less (flexible data models)
- Great for storing varied scan results
- Native JSON storage (nmap XML → JSON → MongoDB)
- Horizontal scaling
- Easy to evolve schema
- Good for rapid development

**Cons:**
- No ACID transactions (in older versions)
- Takes more disk space
- Relational queries are harder
- Easy to create messy data models
- Requires separate server

**Best for:** 
- When scan data structure varies widely
- Rapid prototyping
- When you don't want to define schema upfront

**Data example:**
```json
{
  "_id": "device_192.168.1.100",
  "ip": "192.168.1.100",
  "mac": "AA:BB:CC:DD:EE:FF",
  "scans": [
    {
      "timestamp": "2026-02-09T10:00:00Z",
      "open_ports": [80, 443, 8080],
      "services": {...},
      "vulnerabilities": [
        {"cve": "CVE-2024-1234", "score": 9.8}
      ]
    }
  ]
}
```

---

### Redis
**What it is:** In-memory key-value store.

**Pros:**
- Extremely fast (in-memory)
- Perfect for caching
- Built-in data expiration (TTL)
- Pub/sub for real-time updates
- Session storage
- Rate limiting implementation
- Job queue (with Celery)

**Cons:**
- Not a primary database (volatile by default)
- Limited query capabilities
- Memory-bound (can't store more than RAM)
- Requires separate server

**Best for:** 
- Caching CVE API responses
- Rate limiting API calls
- Task queue (background scans)
- Session management

**Not for:** Primary data storage

---

### **Recommendation for IoTriage:**

**Development/MVP:**
- **SQLite** for primary data
- **No Redis** (keep it simple)

**Production:**
- **PostgreSQL** for primary data (devices, scans, CVEs)
- **Redis** for caching (CVE lookups, rate limiting)

**Why PostgreSQL + Redis:**
- PostgreSQL: Structured device/vulnerability data
- Redis: Cache NVD API responses (they rate-limit heavily)
- Best of both worlds

**Alternative (simpler):**
- **SQLite only** for home user tool
- File-based caching for CVE data

---

## Frontend Technologies

### React
**What it is:** Component-based JavaScript library for building UIs.

**Pros:**
- Huge ecosystem and community
- Component reusability
- Virtual DOM (good performance)
- Tons of UI libraries (Material-UI, Ant Design, Chakra)
- React Hooks for state management
- Great developer tools
- Easy to find help/tutorials
- Job market demand (good for portfolio)

**Cons:**
- Learning curve (JSX, hooks, state)
- Boilerplate code
- Build tooling complexity
- Decision fatigue (many ways to do things)
- Not a full framework (need router, state management separately)

**Best for:** 
- Complex dashboards
- Teams with React experience
- When you need rich UI components

**Stack example:**
- **React** + **React Router** + **React Query** (API calls) + **Tailwind CSS**

---

### Next.js
**What it is:** React framework with server-side rendering and routing.

**Pros:**
- All React benefits plus more
- File-based routing (easy)
- Server-side rendering (SSR)
- Static site generation (SSG)
- API routes built-in (could skip separate backend)
- Image optimization
- Great performance

**Cons:**
- More complex than plain React
- Server required for SSR features
- Opinionated structure
- Overkill for simple dashboards

**Best for:** 
- Production web apps
- SEO-important sites (not really needed here)
- When you want frontend + backend in one

---

### Vue.js
**What it is:** Progressive JavaScript framework.

**Pros:**
- Easier learning curve than React
- Great documentation
- Two-way data binding
- Single-file components
- Good performance
- Less boilerplate than React

**Cons:**
- Smaller ecosystem than React
- Fewer job opportunities
- Less corporate backing

**Best for:**
- Teams new to frontend frameworks
- Rapid development
- When you want simplicity

---

### Svelte
**What it is:** Compiler-based framework (no virtual DOM).

**Pros:**
- Minimal boilerplate
- Excellent performance (compiles to vanilla JS)
- Reactive by default
- Smaller bundle sizes
- Easy to learn

**Cons:**
- Smaller ecosystem
- Fewer component libraries
- Less corporate adoption
- Newer (less mature)

**Best for:**
- Performance-critical apps
- Smaller projects
- When bundle size matters

---

### Vanilla JavaScript (No Framework)
**Pros:**
- No build step
- Fast load times
- No dependencies
- Simple deployment

**Cons:**
- More code to write
- Harder to maintain
- No component reusability
- Manual DOM manipulation

**Best for:** Very simple UIs, quick prototypes

---

### CSS Frameworks

#### Tailwind CSS
**Pros:**
- Utility-first (fast development)
- No naming classes
- Highly customizable
- Small production bundle (purges unused)
- Consistent design system

**Cons:**
- HTML can look cluttered
- Learning curve for utilities
- Need build step

#### Material-UI / MUI
**Pros:**
- Pre-built components
- Google Material Design
- Accessible components
- Fast prototyping

**Cons:**
- Larger bundle size
- Generic look (everyone uses it)
- Customization can be tricky

#### shadcn/ui
**Pros:**
- Copy components into your project (full control)
- Built on Radix UI (accessible)
- Tailwind-based
- Modern, clean design

**Cons:**
- Requires setup
- More recent (less mature)

---

### Visualization Libraries

#### D3.js
**What it is:** Data visualization library for custom charts.

**Pros:**
- Ultimate flexibility
- Network topology visualization
- Custom interactive charts

**Cons:**
- Steep learning curve
- Lots of code for simple charts

**Best for:** Network topology maps, custom vulnerability dashboards

#### Chart.js
**What it is:** Simple charting library.

**Pros:**
- Easy to use
- Good-looking default charts
- Responsive

**Cons:**
- Limited customization
- Not great for network graphs

**Best for:** Risk score charts, vulnerability trends over time

#### Cytoscape.js
**What it is:** Graph theory / network visualization library.

**Pros:**
- Perfect for network topology
- Device relationship visualization
- Interactive graphs

**Cons:**
- Specialized use case
- Learning curve

**Best for:** Showing how devices connect, network maps

---

### **Recommendation for IoTriage:**

**Best Choice: React + Vite + Tailwind CSS**
- React: Industry standard, great for dashboards
- Vite: Super fast dev server
- Tailwind: Quick styling

**Add-ons:**
- **React Query** - API state management
- **React Router** - Navigation
- **Recharts** or **Chart.js** - Simple charts
- **Cytoscape.js** - Network visualization (optional)

**Alternative (Simpler):**
- **Vue.js + Tailwind** - Easier learning curve

---

## Vulnerability Data Sources

### National Vulnerability Database (NVD/NIST)
**What it is:** US government repository of vulnerability data.

**API:** https://services.nvd.nist.gov/rest/json/cves/2.0

**Pros:**
- Official, authoritative source
- Comprehensive CVE coverage
- Free API
- Includes CVSS scores, CPEs, descriptions
- Well-structured JSON
- Updated regularly

**Cons:**
- Strict rate limits (5 requests per 30 seconds without API key)
- 50 requests per 30 seconds WITH API key
- Slow to update sometimes
- Can be down during high traffic
- Complex data structure
- Large response sizes

**Rate Limiting Strategy:**
- Get free API key (higher limits)
- Cache responses aggressively (24+ hours)
- Use local CVE database mirror
- Batch requests when possible

**Example query:**
```python
import requests

def search_cve_by_keyword(product_name):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": product_name,
        "resultsPerPage": 20
    }
    headers = {
        "apiKey": "YOUR_API_KEY"  # Get from nvd.nist.gov
    }
    response = requests.get(url, params=params, headers=headers)
    return response.json()
```

**Best for:** Primary CVE source, authoritative data

---

### CVE Details (cvedetails.com)
**What it is:** Web interface and API for CVE data.

**Pros:**
- User-friendly interface
- Good search capabilities
- Vendor-specific CVE lists
- Statistics and trends

**Cons:**
- No official public API (scraping discouraged)
- Rate limiting
- Better as research tool than API

**Best for:** Manual research, not programmatic access

---

### Vulners API
**What it is:** Vulnerability database aggregator.

**API:** https://vulners.com/api

**Pros:**
- Aggregates multiple sources (NVD, exploit-db, etc.)
- Better search than NVD
- Exploit information included
- Fast response times
- Good documentation
- Free tier available

**Cons:**
- Requires API key
- Rate limits on free tier
- Less "official" than NVD

**Example:**
```python
import requests

def search_vulners(software, version):
    url = "https://vulners.com/api/v3/search/lucene/"
    data = {
        "query": f"{software} AND affectedSoftware.version:{version}",
        "apiKey": "YOUR_API_KEY"
    }
    response = requests.post(url, json=data)
    return response.json()
```

**Best for:** Supplementing NVD, finding exploits

---

### Shodan API
**What it is:** Search engine for internet-connected devices.

**API:** https://developer.shodan.io/api

**Pros:**
- Device-specific vulnerability data
- Real-world exploit information
- Can search by device type, manufacturer
- Shows what's actually exposed on internet
- Great for IoT research

**Cons:**
- Paid API (free tier very limited)
- Not all devices are indexed
- Privacy/ethical concerns

**Best for:** 
- Cross-referencing discovered devices
- Finding known vulnerable device models
- Research phase

---

### Exploit-DB
**What it is:** Archive of exploits and vulnerable software.

**API:** https://www.exploit-db.com/

**Pros:**
- Shows actively exploited vulnerabilities
- Exploit code available
- CSV download of entire database
- Free

**Cons:**
- No official REST API
- Need to download CSV and parse locally
- Not as comprehensive as NVD

**Best for:** 
- Prioritizing vulnerabilities (exploit available = higher risk)
- Severity scoring

---

### OSV (Open Source Vulnerabilities)
**What it is:** Google's open-source vulnerability database.

**API:** https://osv.dev

**Pros:**
- Fast, modern API
- Great for open-source software
- No rate limits
- Free
- Well-documented

**Cons:**
- Focused on open-source (not commercial IoT devices)
- Less comprehensive for firmware

**Best for:** Software vulnerabilities, libraries, dependencies

---

### CPE (Common Platform Enumeration) Lookup
**What it is:** Standardized naming scheme for IT products.

**Pros:**
- Standard format for matching products to CVEs
- Nmap can detect CPEs
- NVD uses CPEs for indexing

**Format:** `cpe:2.3:h:vendor:product:version:*:*:*:*:*:*:*`

**Example:**
```
cpe:2.3:o:dlink:dir-615_firmware:4.11:*:*:*:*:*:*:*
```

**Workflow:**
1. Nmap detects device → gets CPE string
2. Search NVD using CPE
3. Get matching CVEs

---

### Local CVE Database Mirror
**What it is:** Download entire CVE database and search locally.

**Options:**
- **cve-search** - Open-source local CVE database
- **NVD Data Feeds** - JSON feeds of all CVEs

**Pros:**
- No rate limits
- Fast searches
- Offline capability
- No API key needed

**Cons:**
- Setup complexity
- Storage space (GBs)
- Need to update regularly
- Maintenance overhead

**Best for:** 
- High-volume scanning
- Enterprise deployments
- When NVD rate limits are problem

---

### **Recommendation for IoTriage:**

**Primary:** NVD API with aggressive caching
- Get API key (50 req/30sec)
- Cache all responses 24-48 hours
- Use CPE matching when possible

**Secondary:** Vulners API
- For better search results
- When NVD doesn't return good matches

**Optional:** Local database
- Only if doing hundreds of scans
- Probably overkill for class project

**Caching strategy:**
```python
# Redis cache example
import redis
import json
from datetime import timedelta

cache = redis.Redis(host='localhost')

def get_cve_data(cve_id):
    # Check cache first
    cached = cache.get(f"cve:{cve_id}")
    if cached:
        return json.loads(cached)
    
    # Fetch from NVD
    data = fetch_from_nvd(cve_id)
    
    # Cache for 48 hours
    cache.setex(
        f"cve:{cve_id}",
        timedelta(hours=48),
        json.dumps(data)
    )
    return data
```

---

## AI/LLM Integration

### Google Gemini API
**What it is:** Google's multimodal AI model API.

**Why it's required:** Project spec requires using Gemini for explanations.

**Capabilities:**
- Text generation (explanations)
- Reasoning and analysis
- Structured output
- Multimodal (can process images if needed)

**Pros:**
- Free tier available
- Good at explanations
- Fast response times
- Structured output support
- Python SDK (`google-generativeai`)
- Can handle technical content

**Cons:**
- Requires API key
- Rate limits on free tier
- Costs money at scale
- Responses not deterministic
- Can hallucinate

**Setup:**
```python
import google.generativeai as genai

genai.configure(api_key="YOUR_API_KEY")
model = genai.GenerativeModel('gemini-pro')
```

---

### Prompt Engineering for IoTriage

**Goal:** Translate technical CVE data into non-technical explanations.

#### Template 1: Vulnerability Explanation
```python
def explain_vulnerability(device_name, cve_data):
    prompt = f"""
You are a home security advisor explaining to a non-technical homeowner.

Device: {device_name}
Vulnerability: {cve_data['id']}
CVSS Score: {cve_data['cvss']}/10
Description: {cve_data['description']}

Explain in simple terms:
1. What is this vulnerability? (use 5th grade language)
2. What could a hacker do if they exploited it?
3. How likely is this to affect them?
4. Should they be worried? (rate urgency 1-10)

Keep it under 150 words, don't use technical jargon.
"""
    
    response = model.generate_content(prompt)
    return response.text
```

#### Template 2: Mitigation Steps
```python
def generate_fix_instructions(device_name, cve_data):
    prompt = f"""
You are helping a non-technical person fix a security issue.

Device: {device_name}
Problem: {cve_data['description']}

Provide step-by-step fix instructions:
- Use simple language (no technical terms)
- Number each step
- Be specific about button names, menu locations
- If it requires technical skills, suggest calling support
- Include what to do if fix doesn't work

Format as a numbered list.
"""
    
    response = model.generate_content(prompt)
    return response.text
```

#### Template 3: Risk Prioritization
```python
def prioritize_risk(device_type, cvss_score, exploit_available):
    prompt = f"""
Risk assessment for home network:

Device Type: {device_type}
Vulnerability Severity: {cvss_score}/10
Known Exploit: {'Yes' if exploit_available else 'No'}

Rate the urgency to fix this (1-10) and explain why in one sentence.
Consider: device type, severity, exploit availability, typical home network exposure.

Return JSON: {{"urgency": 8, "reason": "..."}}
"""
    
    response = model.generate_content(prompt)
    return response.text  # Parse JSON
```

---

### Prompt Best Practices

**1. Be Specific:**
Bad: "Explain this CVE"
Good: "Explain this CVE to a non-technical homeowner in simple terms"

**2. Provide Context:**
- Include device name (people understand "my Ring doorbell" better than "IP camera")
- Include severity (helps frame importance)
- Include real-world impact examples

**3. Set Constraints:**
- Word limits (prevents rambling)
- Reading level (5th grade, no jargon)
- Format (bullet points, numbered lists)

**4. Few-Shot Examples:**
```python
prompt = f"""
Example 1:
Input: CVE-2024-1234, SQL Injection in router admin panel, CVSS 9.8
Output: "Your router's admin page has a serious flaw that lets hackers take full control. They could see all your internet traffic, change settings, or lock you out. Fix this immediately."

Example 2:
Input: CVE-2023-5678, XSS in smart speaker, CVSS 4.3
Output: "Your smart speaker has a minor bug in its web interface. Low risk since most people don't access it. Update when convenient."

Now explain:
{cve_data}
"""
```

**5. Request Structured Output:**
```python
# Instead of free text, request JSON
prompt = """
Return JSON with these fields:
{
  "simple_explanation": "...",
  "risk_level": "low|medium|high|critical",
  "action_required": "...",
  "urgency_days": 1-30
}
"""
```

---

### Rate Limiting & Cost Management

**Gemini Free Tier:**
- 60 requests per minute
- 1500 requests per day

**Strategies:**
1. **Batch requests:** Explain multiple CVEs in one prompt
2. **Cache responses:** Same CVE = same explanation
3. **Generate on-demand:** Only when user clicks "Explain"
4. **Template responses:** For common CVEs, use pre-written explanations

**Cost-saving pattern:**
```python
def get_explanation(cve_id, cve_data):
    # Check cache first
    cached = cache.get(f"explanation:{cve_id}")
    if cached:
        return cached
    
    # Check if we have template for this CVE
    template = get_template_explanation(cve_id)
    if template:
        return template
    
    # Only then call Gemini
    explanation = call_gemini(cve_data)
    cache.set(f"explanation:{cve_id}", explanation, ttl=30*24*60*60)  # 30 days
    return explanation
```

---

### LangChain (Optional Enhancement)
**What it is:** Framework for LLM application development.

**Pros:**
- Prompt templates management
- Output parsers (JSON, structured data)
- Chaining multiple LLM calls
- Memory/conversation history
- Agent capabilities

**Cons:**
- Additional dependency
- Learning curve
- Might be overkill for simple prompts

**When to use:**
- Complex multi-step reasoning
- Conversation-based interface
- Need for output validation

**Example:**
```python
from langchain.prompts import PromptTemplate
from langchain.llms import GoogleGenerativeAI
from langchain.output_parsers import PydanticOutputParser

parser = PydanticOutputParser(pydantic_object=VulnerabilityExplanation)

template = PromptTemplate(
    template="Explain {cve_id} for device {device}\n{format_instructions}",
    input_variables=["cve_id", "device"],
    partial_variables={"format_instructions": parser.get_format_instructions()}
)
```

---

### **Recommendation for IoTriage:**

**Approach:**
1. **Simple prompts first** - Don't use LangChain initially
2. **Cache aggressively** - Store Gemini responses
3. **Template common CVEs** - Pre-write explanations for top 100 CVEs
4. **Batch when possible** - Explain multiple CVEs in one request
5. **On-demand generation** - Only call API when user requests

**API Structure:**
```
GET /api/device/{id}/vulnerabilities
# Returns CVE IDs and basic info

GET /api/vulnerability/{cve_id}/explain
# Calls Gemini, returns plain-language explanation
# Cached after first request
```

---

## Architecture Patterns

### 1. Monolithic Architecture
**What it is:** Everything in one application (API, scanning, database, AI).

```
┌─────────────────────────────────┐
│      Single Application         │
│                                 │
│  ┌──────────┐  ┌─────────────┐ │
│  │   API    │  │   Scanner   │ │
│  └──────────┘  └─────────────┘ │
│  ┌──────────┐  ┌─────────────┐ │
│  │ Database │  │ Gemini LLM  │ │
│  └──────────┘  └─────────────┘ │
└─────────────────────────────────┘
```

**Pros:**
- Simple to develop and deploy
- Easy to debug (everything in one place)
- No network latency between components
- Single codebase
- Easier for small teams
- Good for MVP

**Cons:**
- Scaling is all-or-nothing
- Long-running scans block web requests (without async)
- Single point of failure
- Harder to split work among team

**Best for:** Class projects, MVPs, single-user tools

---

### 2. API-First Architecture
**What it is:** Separate frontend and backend completely.

```
┌──────────────┐         ┌─────────────────┐
│   Frontend   │  HTTP   │   API Backend   │
│  (React SPA) │ ◄─────► │   (FastAPI)     │
└──────────────┘         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │    Database     │
                         └─────────────────┘
```

**Pros:**
- Frontend/backend can be developed independently
- Multiple frontends possible (web, mobile, CLI)
- Can deploy separately
- Clear separation of concerns
- Easy to version API
- Team can split work (frontend vs backend)

**Cons:**
- More complex deployment
- CORS configuration needed
- Network overhead

**Best for:** Most modern web apps, team collaboration

---

### 3. Microservices Architecture
**What it is:** Multiple small services, each with one responsibility.

```
┌──────────┐
│ Frontend │
└────┬─────┘
     │
┌────▼────────────────────────┐
│      API Gateway            │
└─┬─────────┬─────────┬───────┘
  │         │         │
┌─▼──────┐ ┌▼───────┐ ┌▼──────────┐
│Scanner │ │ CVE    │ │ Explainer │
│Service │ │Service │ │  Service  │
└────────┘ └────────┘ └───────────┘
```

**Pros:**
- Services can scale independently
- Different languages per service
- Failure isolation
- Team autonomy

**Cons:**
- Complex deployment
- Network latency between services
- Distributed system challenges
- Overkill for small projects
- Harder debugging

**Best for:** Large enterprises, not suitable for class project

---

### 4. Task Queue Architecture
**What it is:** Separate long-running tasks from web requests.

```
┌──────────┐         ┌─────────────┐
│ Frontend │ ◄─────► │  API Server │
└──────────┘         └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │  Task Queue │
                     │   (Celery)  │
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │   Workers   │
                     │ (Run scans) │
                     └─────────────┘
```

**Pros:**
- Web API stays responsive
- Scan progress can be tracked
- Can retry failed scans
- Multiple workers for parallel scanning
- Can schedule recurring scans

**Cons:**
- Additional complexity (Redis/RabbitMQ)
- More moving parts
- Deployment complexity

**Best for:** When scans take >30 seconds, production deployments

**Implementation:**
```python
# API endpoint
@app.post("/scan")
def start_scan(network: str):
    task = scan_network.delay(network)  # Queue task
    return {"task_id": task.id, "status": "started"}

# Background worker
@celery_app.task
def scan_network(network):
    # Run nmap scan
    results = nmap_scan(network)
    # Store in database
    save_results(results)
    return results
```

---

### 5. Serverless Architecture
**What it is:** Functions run on-demand in cloud (AWS Lambda, Google Cloud Functions).

**Pros:**
- Auto-scaling
- Pay per use
- No server management

**Cons:**
- Cold start latency
- Execution time limits (15 min max)
- Nmap requires system access
- Complex for network scanning

**Best for:** Not suitable for network scanning tools

---

### **Recommendation for IoTriage:**

**MVP/Class Project:**
```
Architecture: Monolithic with async tasks
- FastAPI (handles API + background tasks)
- SQLite database
- React frontend (separate repo)
- No task queue initially
```

**If scans are slow (>30 sec):**
```
Architecture: API + Task Queue
- FastAPI (API only)
- Celery + Redis (background scans)
- PostgreSQL database
- React frontend
```

**Deployment options:**
1. **Simple:** Single VPS (DigitalOcean droplet)
2. **Modern:** Frontend on Vercel, Backend on Railway/Render
3. **Local:** Docker Compose with all services

---

## Caching Strategies

### Why Caching Matters for IoTriage

**Problem:** NVD API rate limits (50 req/30 sec)
**Solution:** Cache CVE data aggressively

**Problem:** Gemini API costs money
**Solution:** Cache AI-generated explanations

**Problem:** Repeated scans of same network
**Solution:** Cache device data with TTL

---

### Caching Layers

#### 1. Application-Level Cache (In-Memory)
**What:** Store data in application memory (Python dict, LRU cache).

**Pros:**
- Fastest (no network/disk)
- No external dependencies
- Simple to implement

**Cons:**
- Lost on restart
- Not shared between workers
- Memory-bound

**Implementation:**
```python
from functools import lru_cache
from datetime import datetime, timedelta

# Simple in-memory cache with expiration
cache = {}

def get_cached(key, ttl_seconds):
    if key in cache:
        value, timestamp = cache[key]
        if datetime.now() - timestamp < timedelta(seconds=ttl_seconds):
            return value
    return None

def set_cached(key, value):
    cache[key] = (value, datetime.now())

# Or use Python's built-in LRU cache (no expiration)
@lru_cache(maxsize=1000)
def get_cve_data(cve_id):
    return fetch_from_nvd(cve_id)
```

**Best for:** Single-server deployments, development

---

#### 2. Redis Cache
**What:** In-memory key-value store, shared across application instances.

**Pros:**
- Persistent (can save to disk)
- Shared between workers
- Built-in expiration (TTL)
- Fast (in-memory)
- Supports complex data types

**Cons:**
- Additional service to run
- Memory-bound
- Network latency (minimal)

**Implementation:**
```python
import redis
import json
from datetime import timedelta

r = redis.Redis(host='localhost', port=6379)

def get_cve_cached(cve_id):
    # Check cache
    cached = r.get(f"cve:{cve_id}")
    if cached:
        return json.loads(cached)
    
    # Fetch from API
    data = fetch_from_nvd(cve_id)
    
    # Cache for 48 hours
    r.setex(
        f"cve:{cve_id}",
        timedelta(hours=48),
        json.dumps(data)
    )
    return data
```

**Best for:** Production, multiple workers, task queues

---

#### 3. Database Cache
**What:** Store cached data in database with timestamps.

**Pros:**
- Persistent
- Can query cached data
- No additional service

**Cons:**
- Slower than Redis
- Database bloat

**Schema:**
```sql
CREATE TABLE cve_cache (
    cve_id VARCHAR(20) PRIMARY KEY,
    data JSONB,
    cached_at TIMESTAMP DEFAULT NOW()
);

-- Query with freshness check
SELECT data FROM cve_cache
WHERE cve_id = 'CVE-2024-1234'
  AND cached_at > NOW() - INTERVAL '48 hours';
```

**Best for:** When you already use database, don't want Redis

---

#### 4. HTTP Cache (Client-Side)
**What:** Browser caches API responses.

**Pros:**
- Reduces server load
- Faster for users
- No server-side cache needed

**Cons:**
- Each user has own cache
- Less control

**Implementation:**
```python
from fastapi import Response

@app.get("/api/cve/{cve_id}")
def get_cve(cve_id: str, response: Response):
    data = get_cve_data(cve_id)
    
    # Cache for 24 hours in browser
    response.headers["Cache-Control"] = "public, max-age=86400"
    
    return data
```

---

### Caching Strategy for Each Component

#### CVE Data from NVD
```python
# Cache for 48 hours (CVEs don't change often)
TTL = 48 * 60 * 60  # 48 hours

def get_cve(cve_id):
    key = f"nvd:cve:{cve_id}"
    cached = redis.get(key)
    
    if cached:
        return json.loads(cached)
    
    # Fetch from NVD with rate limiting
    data = fetch_nvd_with_backoff(cve_id)
    
    redis.setex(key, TTL, json.dumps(data))
    return data
```

#### Gemini Explanations
```python
# Cache indefinitely (explanation for CVE won't change)
def get_explanation(cve_id, device_type):
    key = f"gemini:explain:{cve_id}:{device_type}"
    cached = redis.get(key)
    
    if cached:
        return cached
    
    # Generate with Gemini
    explanation = generate_explanation(cve_id, device_type)
    
    redis.set(key, explanation)  # No expiration
    return explanation
```

#### Device Scan Results
```python
# Cache for 1 hour (devices/services might change)
TTL = 60 * 60  # 1 hour

def get_device_info(ip_address):
    key = f"device:{ip_address}"
    cached = redis.get(key)
    
    if cached:
        return json.loads(cached)
    
    # Scan with nmap
    data = nmap_scan(ip_address)
    
    redis.setex(key, TTL, json.dumps(data))
    return data
```

#### Manufacturer (MAC OUI) Lookup
```python
# Cache forever (OUI database is static)
def get_manufacturer(mac_address):
    oui = mac_address[:8]  # First 3 bytes
    key = f"oui:{oui}"
    
    cached = redis.get(key)
    if cached:
        return cached
    
    manufacturer = lookup_oui(oui)
    redis.set(key, manufacturer)  # No expiration
    return manufacturer
```

---

### Cache Invalidation Strategies

**1. Time-Based (TTL):**
- Most common
- Set expiration time
- Data automatically removed

**2. Event-Based:**
```python
# Invalidate when user requests new scan
def force_rescan(ip_address):
    redis.delete(f"device:{ip_address}")
    return scan_device(ip_address)
```

**3. Version-Based:**
```python
# Change cache key when data structure changes
CACHE_VERSION = "v2"
key = f"{CACHE_VERSION}:cve:{cve_id}"
```

**4. LRU (Least Recently Used):**
```python
# Redis with maxmemory policy
# redis.conf:
# maxmemory 256mb
# maxmemory-policy allkeys-lru
```

---

### **Recommendation for IoTriage:**

**Development:**
- Simple in-memory cache (Python dict with expiration)
- Or use `@lru_cache` decorator

**Production:**
- Redis for CVE and Gemini response caching
- Short TTL for device scans (1 hour)
- Long TTL for CVE data (48 hours)
- No expiration for Gemini explanations

**Cache hierarchy:**
```python
def get_vulnerability_info(cve_id):
    # 1. Check in-memory cache (fastest)
    if cve_id in memory_cache:
        return memory_cache[cve_id]
    
    # 2. Check Redis (fast)
    redis_data = redis.get(f"cve:{cve_id}")
    if redis_data:
        memory_cache[cve_id] = redis_data  # Promote to memory
        return redis_data
    
    # 3. Check database (slower)
    db_data = db.query("SELECT * FROM cve_cache WHERE cve_id = ?", cve_id)
    if db_data and is_fresh(db_data):
        redis.setex(f"cve:{cve_id}", TTL, db_data)  # Promote to Redis
        memory_cache[cve_id] = db_data  # Promote to memory
        return db_data
    
    # 4. Fetch from API (slowest)
    api_data = fetch_from_nvd(cve_id)
    
    # Populate all caches
    db.insert("cve_cache", api_data)
    redis.setex(f"cve:{cve_id}", TTL, api_data)
    memory_cache[cve_id] = api_data
    
    return api_data
```

---

## Additional Tools & Libraries

### Python Libraries

#### Network & Scanning
- **python-nmap** - Nmap wrapper
- **scapy** - Packet manipulation
- **netaddr** - IP address manipulation
- **mac-vendor-lookup** - MAC OUI database
- **python-whois** - Domain/IP info

#### Web Framework
- **FastAPI** - Modern async framework
- **Flask** - Minimal framework
- **uvicorn** - ASGI server (for FastAPI)
- **gunicorn** - WSGI server (for Flask)

#### Database
- **SQLAlchemy** - ORM (works with PostgreSQL, SQLite)
- **psycopg2** - PostgreSQL driver
- **alembic** - Database migrations
- **redis-py** - Redis client

#### API & HTTP
- **requests** - HTTP client
- **httpx** - Async HTTP client
- **aiohttp** - Async HTTP client/server

#### Background Tasks
- **Celery** - Distributed task queue
- **RQ (Redis Queue)** - Simpler alternative to Celery
- **APScheduler** - In-process scheduler

#### AI/LLM
- **google-generativeai** - Gemini API
- **langchain** - LLM framework
- **tiktoken** - Token counting (optimize prompts)

#### Data Processing
- **pandas** - Data analysis (scan results)
- **pydantic** - Data validation
- **python-dotenv** - Environment variables

---

### JavaScript/Node.js Libraries

#### Scanning
- **node-nmap** - Nmap wrapper for Node
- **evilscan** - Pure JS port scanner

#### Backend
- **express** - Web framework
- **fastify** - Fast alternative to Express
- **socket.io** - WebSocket for real-time updates

#### Frontend
- **react** - UI library
- **react-router-dom** - Routing
- **axios** - HTTP client
- **react-query** / **@tanstack/query** - API state management
- **zustand** or **redux** - Global state
- **tailwindcss** - CSS framework

#### Visualization
- **recharts** - Simple charts for React
- **cytoscape** - Network graphs
- **d3** - Custom visualizations

---

### DevOps & Deployment

#### Containerization
- **Docker** - Containerization
- **Docker Compose** - Multi-container orchestration

**Example docker-compose.yml:**
```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/iotriage
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
  
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
  
  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7-alpine
  
  worker:
    build: ./backend
    command: celery -A app.celery worker
    depends_on:
      - redis
      - db

volumes:
  postgres_data:
```

#### Deployment Platforms
- **Vercel** - Frontend hosting (free for students)
- **Railway** - Backend + database (easy setup)
- **Render** - Full-stack hosting
- **DigitalOcean** - VPS (more control)
- **AWS/GCP** - Enterprise (overkill)

---

### Development Tools

#### API Testing
- **Postman** - API testing
- **httpie** - CLI HTTP client
- **curl** - Classic CLI tool

#### Code Quality
- **black** - Python formatter
- **ruff** - Fast Python linter
- **mypy** - Python type checker
- **pytest** - Python testing
- **eslint** - JavaScript linter
- **prettier** - JavaScript formatter

#### Version Control
- **Git** - Version control
- **GitHub Actions** - CI/CD

---

### Security Tools (Research/Testing)

**WARNING: Use ethically and with permission only!**

- **OpenVAS** - Vulnerability scanner
- **Nikto** - Web server scanner
- **Metasploit** - Penetration testing framework
- **Wireshark** - Packet analyzer
- **Burp Suite** - Web security testing

**Note:** These are for understanding vulnerabilities, not for attacking networks!

---

### Useful Databases & Resources

#### OUI (Manufacturer) Database
- **Wireshark OUI database** - MAC to manufacturer
- **macvendors.com API** - Free lookup API

#### CPE Database
- **NVD CPE dictionary** - Product names to CPE strings

#### IP Geolocation
- **ipapi.co** - Free IP location API
- **geoip2** - Offline IP database

---

### Monitoring & Logging

#### Logging
```python
import logging

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Log scan events
logger.info(f"Starting scan of {network}")
logger.warning(f"High severity CVE found: {cve_id}")
logger.error(f"Nmap scan failed: {error}")
```

#### Metrics (Optional)
- **Prometheus** - Metrics collection
- **Grafana** - Visualization
- **Sentry** - Error tracking

---

## Technology Stack Decision Matrix

### Recommended Stack for IoTriage

| Component | Technology | Reasoning |
|-----------|-----------|-----------|
| **Scanning** | Nmap | Industry standard, comprehensive |
| **Backend** | FastAPI | Async, modern, auto docs |
| **Database** | PostgreSQL | Robust, JSON support, production-ready |
| **Cache** | Redis | Fast, shared between workers, TTL support |
| **Frontend** | React + Vite | Popular, great ecosystem, fast dev |
| **Styling** | Tailwind CSS | Quick development, modern look |
| **Charts** | Recharts | Easy integration with React |
| **Network Graph** | Cytoscape.js | Best for network topology |
| **AI** | Google Gemini | Required by project spec |
| **Task Queue** | Celery (if needed) | Mature, reliable for background scans |
| **Deployment** | Docker Compose | Easy local development + deployment |

---

### Alternative Simpler Stack (MVP)

| Component | Technology | Reasoning |
|-----------|-----------|-----------|
| **Scanning** | Nmap | Same |
| **Backend** | Flask | Simpler to learn |
| **Database** | SQLite | No server setup |
| **Cache** | In-memory dict | No dependencies |
| **Frontend** | React + Vite | Same |
| **AI** | Google Gemini | Required |
| **Deployment** | Single server | One process, easier |

---

## Next Steps

1. **Prototype Phase:**
   - Set up basic nmap scanning script
   - Test NVD API integration
   - Experiment with Gemini prompts
   - Build simple React dashboard

2. **Core Development:**
   - Implement device discovery
   - CVE matching logic
   - AI explanation generation
   - Database schema

3. **Polish:**
   - Error handling
   - Rate limiting
   - Caching
   - UI/UX improvements

4. **Deployment:**
   - Docker containerization
   - Cloud deployment
   - Documentation

---

## Questions to Answer Before Starting

1. **Scope:** Home networks only, or support enterprise?
2. **Users:** Single user tool, or multi-user web service?
3. **Deployment:** Cloud-hosted or user runs locally?
4. **Team:** Who's doing frontend vs backend?
5. **Timeline:** How many weeks to build?
6. **Priorities:** Feature-complete or polished MVP?

---

## Resources

### Documentation
- [Nmap Documentation](https://nmap.org/book/)
- [NVD API Docs](https://nvd.nist.gov/developers)
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [React Docs](https://react.dev/)
- [Gemini API Docs](https://ai.google.dev/docs)

### Tutorials
- Network scanning with Python
- Building REST APIs with FastAPI
- React dashboard development
- Docker for Python apps

### Similar Projects (Inspiration)
- **Nessus** - Commercial vulnerability scanner
- **OpenVAS** - Open-source scanner
- **Netdisco** - Network management
- **Pi-hole** - Network monitoring

---

*Last updated: February 9, 2026*
