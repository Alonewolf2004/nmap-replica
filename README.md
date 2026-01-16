# Argus – The All-Seeing Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="Platform">
</p>

**Argus** is a high-performance, asynchronous port scanner built in Python. It combines speed with intelligence—featuring SSL/TLS support, smart banner grabbing, and built-in honeypot detection.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| ⚡ **Async Scanning** | Concurrent scanning with configurable workers (up to 5000) |
| 🔒 **SSL/TLS Support** | Proper HTTPS detection with SNI for CDNs like Akamai |
| 🕵️ **Honeypot Detection** | Multi-layer scoring: port density, banner consistency, timing analysis |
| 🎯 **Smart Banner Grabbing** | Optional `-sV` mode with multi-stage probing |
| 📊 **JSON Output** | Machine-readable results with detailed honeypot breakdown |
| 🗃️ **Community Databases** | Extensible JSON databases for service patterns and fingerprints |

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/yourusername/argus.git
cd argus
pip install -r requirements.txt
```

### Basic Usage

```bash
# Simple scan
python argus.py -t example.com -p 1-1000

# Fast scan with output file
python argus.py -t example.com -p 80,443,8080 -o results.json

# Deep service detection (-sV)
python argus.py -t example.com -p 1-1000 -sV
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target IP or hostname |
| `-p, --ports` | Ports to scan (e.g., `80,443` or `1-1000`) |
| `-c, --concurrency` | Concurrent connections (default: 500) |
| `-o, --output` | Save results to JSON file |
| `-sV, --service-version` | Deep service detection with multi-stage probing |

---

## 🏗️ Architecture

```
argus/
├── scanner.py          # Core async scanning engine
├── analyzer.py         # Banner analysis with Trie-based protocol detection
├── honeypot_detector.py # Multi-layer honeypot scoring
├── smart_banner.py     # Multi-stage probing (-sV mode)
├── database.py         # Community database loader
├── ui.py               # Rich terminal UI
├── utils.py            # Bloom filter, rate limiter, caching
├── config.py           # Pydantic configuration validation
├── analyzers/          # Protocol-specific analyzers
│   ├── http.py
│   ├── ssh.py
│   ├── database.py
│   └── generic.py
└── data/               # Community-contributed databases
    ├── honeypot_ips.json
    ├── service_patterns.json
    └── os_fingerprints.json
```

---

## 🕵️ Honeypot Detection

Argus detects potential honeypots using multiple signals:

| Check | Weight | Description |
|-------|--------|-------------|
| **Port Density** | 40 pts | Too many open ports (100+ = max score) |
| **Banner Consistency** | 30 pts | OS mismatches (SSH says Linux, HTTP says Windows) |
| **Response Timing** | 30 pts | Too-fast responses (<5ms) or zero jitter |
| **Database Checks** | Bonus | Known honeypot IPs, suspicious service combos |

**Confidence Levels:**
- `LOW` (0-39): Likely legitimate
- `MEDIUM` (40-59): Suspicious, investigate further  
- `HIGH` (60+): Likely honeypot

---

## 🔬 Smart Banner Grabbing (`-sV`)

When enabled, Argus performs multi-stage probing:

1. **Passive** – Wait for server greeting (2s timeout)
2. **Null Probe** – Send `\r\n` to trigger response
3. **Protocol Probe** – Port-specific request (USER for FTP, OPTIONS for RTSP)
4. **Malformed Probe** – Invalid request to analyze error fingerprint

This takes longer (~3x) but provides deeper service identification.

---

## 📦 Community Databases

Argus uses JSON databases that anyone can contribute to:

### `data/honeypot_ips.json`
Known honeypot IP ranges with scoring.

### `data/service_patterns.json`
Suspicious service combinations:
```json
{
  "name": "Linux SSH + Windows IIS",
  "requires": ["SSH", "IIS"],
  "score": 35
}
```

### `data/os_fingerprints.json`
OS detection patterns from banners.

**To contribute:** Submit a Pull Request with your additions!

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 📋 Example Output

```
╭───────────────────────────────── Honeypot Detection ─────────────────────────────────╮
│ ✓ Honeypot Score: 5/100 (LOW)                                                        │
│   • Port Density: 0/40 - 4 open ports is normal                                      │
│   • Banner Consistency: 0/30 - OS indicators consistent                              │
│   • Timing: 5/30 - Timing patterns appear normal                                     │
╰──────────────────────────────────────────────────────────────────────────────────────╯

                    Scan Results for 23.55.244.114 (OS: Unknown)
┏━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Port ┃ State ┃ Service                       ┃ Version/Banner                ┃ OS Guess ┃
┡━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│   80 │ OPEN  │ [HTTP] Server: AkamaiGHost    │ HTTP/1.0 400 Bad Request      │ Unknown  │
│  443 │ OPEN  │ [HTTP] Server: AkamaiGHost    │ HTTP/1.0 400 Bad Request      │ Unknown  │
└──────┴───────┴───────────────────────────────┴───────────────────────────────┴──────────┘

Scan completed in 1.08 seconds.
```

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- Inspired by [Nmap](https://nmap.org)
- Built with [Rich](https://github.com/Textualize/rich) for beautiful terminal UI
- Uses [Pydantic](https://pydantic-docs.helpmanual.io/) for configuration validation
