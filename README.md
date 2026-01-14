# ARGUS (The All-Seeing Scanner)

A high-performance, asynchronous port scanner written in Python, designed to replicate core Nmap functionality with a modern codebase.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Asyncio](https://img.shields.io/badge/Asyncio-Core-green)
![License](https://img.shields.io/badge/License-MIT-purple)

## 🚀 Features

*   **Fast & Asynchronous**: Built on `asyncio` for non-blocking I/O. Scans thousands of ports in seconds.
*   **Modular Architecture**: Clean separation of concerns (`scanner`, `analyzer`, `ui`).
*   **Rich CLI Dashboard**: Professional terminal UI using the `rich` library with real-time progress bars.
*   **Robust TCP State Logic**: Explicitly distinguishes between **OPEN**, **CLOSED** (Refused), and **FILTERED** (Timeout) ports.
*   **Intelligent Banner Grabbing**:
    *   **HTTP**: Parses `Server`, `X-Powered-By`, and `Title` without dumping raw HTML.
    *   **MySQL**: Decodes binary V10 Handshakes to extract precise version strings.
    *   **Protocols**: RTSP (`OPTIONS`), PPTP, Redis, FTP, SMTP, and more.
*   **Service Tagging**: Standardized `[Tag] Vendor Product` output format (e.g., `[HTTP] nginx/1.18`).
*   **Safety Guardrails**: Strict input clamping (1-65535) preventing integer overflow bugs.
*   **OS Aggregation**: Heuristic OS fingerprinting based on banner analysis from open ports.
*   **Export**: JSON reporting for automated post-processing.

## 📦 Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/argus.git
    cd argus
    ```

2.  **Install dependencies**:
    ```bash
    pip install rich
    ```

## 🛠️ Usage

Run the scanner wrapper:

```bash
python argus.py
```

### Interactive Mode
The tool will prompt for:
1.  **Target**: IP address or Hostname (e.g., `scanme.nmap.org`).
2.  **Ports**: Integers, ranges, or lists (e.g., `22 80 1000-2000`).
3.  **Speed Level**:
    *   **1 (Stealthy)**: 50 concurrent tasks
    *   **3 (Normal)**: 500 concurrent tasks (Default)
    *   **5 (Insane)**: 2000 concurrent tasks

### Output Example

```text
Scan Results for scanme.nmap.org (OS: Ubuntu Linux)
┌──────┬───────┬──────────────────────────┬─────────────────────────────────┬──────────────┐
│ Port │ State │ Service                  │ Version/Banner                  │ OS Guess     │
├──────┼───────┼──────────────────────────┼─────────────────────────────────┼──────────────┤
│   22 │ OPEN  │ [SSH] OpenSSH 7.6p1      │ SSH-2.0-OpenSSH_7.6p1 Ubuntu-4u │ Ubuntu Linux │
│   80 │ OPEN  │ [HTTP] Apache 2.4.29     │ Server: Apache/2.4.29 (Ubuntu)  │ Ubuntu Linux │
└──────┴───────┴──────────────────────────┴─────────────────────────────────┴──────────────┘
```

## 📂 Project Structure

```text
nmap_replica/
├── __init__.py
├── main.py       # Entry point
├── scanner.py    # Core Async Scanner Logic & TCP State Machine
├── analyzer.py   # Regex & Protocol Probing Logic
├── ui.py         # Rich Console & Table Rendering
└── utils.py      # Input Verification & Guardrails
```

## 🧠 Design Decisions

*   **Asyncio vs Threading**: pure `asyncio` was chosen over `threading` to avoid GIL locking overhead and handle thousands of concurrent connections efficiently.
*   **Strict Bounds**: Port inputs are strictly clamped to 1-65535 to avoid OS-level integer wrapping on invalid ports.
*   **Analysis Separation**: Banner analysis is decoupled from the socket loop to allow for easy extensibility of new protocols without touching the core scanner.

## 📝 Future Roadmap

*   [ ] **OS Logic**: Correlate service versions (e.g. OpenSSH 8.0) to Linux kernel versions with confidence scoring.
*   [ ] **NSE-like Scripts**: Add a plugin system for deeper service enumeration.
*   [ ] **SYN Scan**: Implement raw socket `SYN` scanning (requires root) for stealth.

---
*Built for educational purposes and authorized security testing only.*
