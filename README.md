# Argus – Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="Platform">
</p>

**Argus** is a high-performance, asynchronous port scanner built in Python. It combines speed with intelligence—featuring SSL/TLS support, smart banner grabbing, and built-in honeypot detection.

## ⚠️ Legal Disclaimer

> **This tool is for educational and authorized testing only.**  
> Unauthorized scanning of networks you do not own or have permission to test may be illegal in your jurisdiction. Always obtain proper authorization before scanning.

---

## Features

| Feature | Description |
|---------|-------------|
| ⚡ **Async Scanning** | Concurrent scanning with configurable workers (up to 5000) |
| 🔒 **SSL/TLS Support** | HTTPS detection with SNI for CDNs like Akamai |
| 🕵️ **Honeypot Detection** | Multi-layer scoring: port density, banner consistency, timing |
| 🎯 **Smart Banner Grabbing** | Optional `-sV` mode with multi-stage probing |
| 📊 **JSON Output** | Machine-readable results with honeypot breakdown |

---

## Installation

### From PyPI (Recommended)

```bash
pip install argus-scanner
```

### From Source

```bash
git clone https://github.com/yourusername/argus-port-scanner.git
cd argus-port-scanner
pip install -e .
```

---

## Usage

```bash
# Simple scan
argus -t example.com -p 1-1000

# Fast scan with JSON output
argus -t example.com -p 80,443,8080 -o results.json

# Deep service detection
argus -t example.com -p 1-1000 -sV
```

### Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target IP or hostname |
| `-p, --ports` | Ports to scan (e.g., `80,443` or `1-1000`) |
| `-c, --concurrency` | Concurrent connections (default: 500) |
| `-o, --output` | Save results to JSON file |
| `-sV` | Deep service detection with multi-stage probing |

---

## Honeypot Detection

Argus detects potential honeypots using multiple signals:

| Check | Weight | What It Detects |
|-------|--------|-----------------|
| Port Density | 40 pts | Too many open ports (100+ = max) |
| Banner Consistency | 30 pts | OS mismatches across services |
| Response Timing | 30 pts | Too-fast or zero-jitter responses |

**Confidence Levels:** `LOW` (0-39), `MEDIUM` (40-59), `HIGH` (60+)

See [docs/honeypot_detection.md](docs/honeypot_detection.md) for detailed scoring logic.

---

## Example Output

```
╭────────────────────── Honeypot Detection ──────────────────────╮
│ ✓ Honeypot Score: 5/100 (LOW)                                  │
│   • Port Density: 0/40 - 4 open ports is normal                │
│   • Banner Consistency: 0/30 - OS indicators consistent        │
│   • Timing: 5/30 - Timing patterns appear normal               │
╰────────────────────────────────────────────────────────────────╯

              Scan Results for 23.55.244.114
┏━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port ┃ State ┃ Service             ┃ Version/Banner           ┃
┡━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│   80 │ OPEN  │ [HTTP] AkamaiGHost  │ HTTP/1.0 400 Bad Request │
│  443 │ OPEN  │ [HTTP] AkamaiGHost  │ HTTP/1.0 400 Bad Request │
└──────┴───────┴─────────────────────┴──────────────────────────┘
```

---

## Roadmap

| Feature | Status |
|---------|--------|
| UDP scanning | Planned |
| IPv6 support | Planned |
| Plugin-based analyzers | Planned |
| PCAP-based timing analysis | Research |
| Nmap NSE script compatibility | Research |

See [docs/validation.md](docs/validation.md) for real-world test results.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with [Rich](https://github.com/Textualize/rich) for terminal UI
- Uses [Pydantic](https://pydantic-docs.helpmanual.io/) for configuration
