# Vortex: Nmap Automation & Network Security Platform

```text
__      __        _
\ \    / /__ _ __| |_ _____  __
 \ \  / / _ \ '_ \  _/ -_) \/ /
  \_\/_/\___/_| \_\__\___|\_,_/
```

## Overview
This script is designed to automate Nmap scans with a variety of customizable options to suit different use cases. It simplifies the process of running Nmap commands by providing a user-friendly interface and predefined arguments for common scanning scenarios.

## Features
- Supports multiple scan types, including TCP, UDP, and aggressive scans.
- Allows specification of custom port ranges and target IPs.
- Includes advanced Nmap arguments for vulnerability detection, service version detection, and more.
- Saves scan results in multiple formats (normal, XML, grepable).
- Provides timing control for stealth or speed optimization.
- Supports custom NSE scripts for specialized tasks.
- **Integrated Wireshark Suite**: Seamlessly transition from Nmap discovery to targeted packet capture and analysis.

## Requirements
- Python 3.x
- Nmap installed on the system
- Required Python libraries (install via `pip install -r nmap-requirements.txt`)
- **Docker** (Recommended for full platform deployment)

## 📚 Documentation

*   **[User Guide](USER_GUIDE.md)**: Complete manual for all features.
*   **[Workflow Integration](directives/workflow_integration.md)**: Details on the Nmap-to-Wireshark bridge.
*   **[Wireshark Automation](directives/wireshark_automation.md)**: Technical directive for trap & trace features.

## 🛠️ Quick Start

### Prerequisites
*   Docker & Docker Compose

### Installation & Run

```bash
git clone https://github.com/fxinfo24/Vortex.git
cd Vortex

# Start the full platform
docker-compose up -d --build
```

Access the dashboard at: **http://localhost:8000**

### CLI Usage (Standalone Script)
The underlying `NmapScanner.py` can still be used directly from the command line:

```bash
python execution/NmapScanner.py -t 192.168.1.1 -p 1-1000 -s syn
```

## 🏗️ Architecture

*   **Backend**: FastAPI (Python 3.13)
*   **Frontend**: React + TypeScript + Vite
*   **Engine**: Nmap, PyShark, Scapy

## ⚠️ Legal Disclaimer
**Vortex is for authorized security testing only.** Unauthorized use against systems you do not own or have explicit permission to test is illegal. The developers assume no liability for misuse.