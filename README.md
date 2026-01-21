# Vortex: Advanced Network Reconnaissance Platform

Vortex is a powerful, integrated network security platform combining the discovery capabilities of **Nmap** with the deep analysis features of **Wireshark**. Designed for security professionals, it offers a unified interface for reconnaissance, traffic analysis, and authorized red team operations.

## 🚀 Features

*   **Integrated Workflow**: Seamlessly transition from Nmap discovery to targeted Wireshark packet capture.
*   **Nmap Scanner**:
    *   Full suite of scan profiles (SYN, UDP, Vulnerability, Comprehensive).
    *   Visual results with service detection.
    *   CLI automation script support.
*   **Wireshark Suite**:
    *   **Packet Capture**: Live traffic sniffing with auto-generated filters.
    *   **Secret Hunter**: Automated detection of credentials, cookies, and tokens.
    *   **Network Map**: Real-time ARP discovery of local devices.
*   **Red Team Operations** (Authorized Use Only):
    *   **MITM**: ARP Spoofing for traffic interception.
    *   **DoS**: Controlled stress testing.
    *   **SSL Decryption**: Analyze encrypted traffic with key logs.

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