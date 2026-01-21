# Vortex User Guide

> **Network Reconnaissance and Vulnerability Assessment Platform**

---

## ⚠️ DISCLAIMER

**IMPORTANT: READ BEFORE USE**

Vortex is a powerful network reconnaissance and security testing tool designed for **authorized use only**. By using this software, you acknowledge and agree to the following:

1. **Authorization Required**: You must have explicit, written authorization from the network owner before performing any scans, captures, or attacks on any network or system.

2. **Legal Compliance**: Unauthorized network scanning, packet sniffing, traffic interception, and denial-of-service attacks are **illegal** in most jurisdictions. Violations may result in criminal prosecution, civil liability, and significant penalties.

3. **Ethical Use**: This tool is intended for:
   - Security professionals conducting authorized penetration tests
   - Network administrators analyzing their own networks
   - Educational purposes in controlled lab environments
   - Red team exercises with proper authorization

4. **No Liability**: The developers and contributors of Vortex assume no responsibility for misuse of this software. You are solely responsible for ensuring your use complies with all applicable laws and regulations.

5. **Sensitive Data**: This tool can capture and display sensitive network data (credentials, tokens, cookies). Handle all captured data responsibly and in accordance with privacy regulations (GDPR, CCPA, etc.).

**By proceeding, you confirm that you have read, understood, and agree to these terms.**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Nmap Scanner Module](#nmap-scanner-module)
4. [Wireshark Suite](#wireshark-suite)
5. [Red Team Operations](#red-team-operations)
6. [API Reference](#api-reference)
7. [Troubleshooting](#troubleshooting)

---

## Introduction

Vortex is an integrated network security platform that combines:

- **Nmap Integration**: Port scanning, service detection, and vulnerability assessment
- **Packet Analysis**: Live traffic capture and analysis (Wireshark-like capabilities)
- **Network Discovery**: ARP-based device mapping
- **Sensitive Data Detection**: Automated hunting for credentials and tokens
- **Red Team Tools**: Advanced operations including MITM and DoS capabilities

### Key Features

| Feature | Description |
|---------|-------------|
| Port Scanning | SYN, UDP, Comprehensive, and Vulnerability scans |
| Packet Capture | Real-time traffic sniffing with filtering |
| Network Mapping | ARP-based device discovery |
| Secret Hunter | Pattern matching for credentials, cookies, tokens |
| MITM Attack | ARP spoofing for traffic interception |
| DoS Testing | Controlled SYN flood for stress testing |
| SSL Decryption | Decrypt captured HTTPS traffic with keys |

---

## Getting Started

### Prerequisites

- Docker Desktop installed and running
- Port 8000 available on your host machine
- Network access to target systems (for scanning)

### Installation & Deployment

```bash
# Clone the repository
git clone <repository-url>
cd Vortex

# Build and deploy with Docker
docker-compose up -d --build

# Access the application
open http://localhost:8000
```

### First Launch

1. Navigate to `http://localhost:8000` in your browser
2. You'll see the **Vortex** dashboard with two modes:
   - **Nmap Scanner**: Traditional port scanning
   - **Wireshark Suite**: Packet capture and analysis

---

## Nmap Scanner Module

The Nmap Scanner provides a user-friendly interface for network reconnaissance.

### Scan Types

| Type | Description | Use Case |
|------|-------------|----------|
| **SYN** | Stealth TCP SYN scan | Fast, less detectable scanning |
| **UDP** | UDP port scan | Discovering UDP services |
| **Full** | Comprehensive scan with service detection | Deep enumeration |
| **Vulnerability** | Scan with vulnerability scripts | Security assessment |

### How to Use

1. **Enter Target**: IP address (e.g., `192.168.1.1`) or CIDR range (e.g., `192.168.1.0/24`)
2. **Set Port Range**: Default `1-1000`, or specify custom (e.g., `80,443,8080`)
3. **Select Scan Profile**: Choose from SYN, UDP, Full, or Vulnerability
4. **Click "Start Scan"**: Wait for results

### Understanding Results

Results are displayed in a structured format showing:
- **Host**: IP address of discovered devices
- **Status**: Online/Offline
- **Protocol**: TCP or UDP
- **Port**: Port number
- **State**: open, closed, filtered
- **Service**: Detected service name
- **Version**: Service version (if detected)

---

## Wireshark Suite

The Wireshark Suite provides network traffic analysis capabilities.

### Tabs Overview

#### 1. Packet Capture
Capture live network traffic from the container's interface.

**Controls:**
- **Start Capture**: Begin capturing packets (default 5 seconds, 50 packets)
- **Inject Test Packets**: Send test traffic to verify capture is working

**Output:**
- Timestamp
- Protocol (TCP, UDP, ICMP, etc.)
- Source IP
- Destination IP
- Packet info/summary

#### 2. Network Map
Discover devices on the network using ARP scanning.

**Controls:**
- **Subnet**: Enter CIDR notation (e.g., `172.18.0.0/16` for Docker networks)
- **Start Mapper**: Begin ARP discovery

**Output:**
- IP Address
- MAC Address

#### 3. Secret Hunter
Analyze traffic for sensitive data patterns.

**What it detects:**
- Username/password patterns
- Session cookies
- API tokens and keys
- Authentication headers

**Controls:**
- **Start Analysis**: Begin 5-second capture with pattern matching

**Output:**
- Credentials found (highlighted in red)
- Cookies detected (highlighted in orange)

---

## Red Team Operations

⚠️ **WARNING**: These features are for authorized testing only. Misuse is illegal.

### Accessing Red Team Mode

1. Switch to **Wireshark Suite**
2. Click the **Red Team** tab (skull icon)

### Available Operations

#### MITM Attack (ARP Spoofing)
Intercept traffic between a target and the gateway.

**Inputs:**
- **Target IP**: The victim's IP address
- **Gateway IP**: The network gateway
- **Duration**: Attack duration in seconds

**How it works:**
1. Sends spoofed ARP packets to target claiming to be gateway
2. Sends spoofed ARP packets to gateway claiming to be target
3. Traffic flows through your machine

#### DoS Attack (SYN Flood)
Stress test a target with a flood of TCP SYN packets.

**Inputs:**
- **Target IP**: The target system
- **Port**: Target port (default 80)
- **Duration**: Attack duration in seconds

**How it works:**
1. Launches multiple threads sending SYN packets
2. Target receives flood of half-open connections
3. Automatically stops after specified duration

#### SSL Decryption
Decrypt HTTPS traffic using pre-shared key logs.

**Inputs:**
- **PCAP Path**: Path to captured traffic file
- **Key Path**: Path to SSL key log file

**Requirements:**
- Target application must be configured to export SSL keys
- Key log file format: NSS Key Log Format

---

## Best Practice Workflow: Integrated Reconnaissance

Vortex implements the professional workflow of using Nmap for discovery and Wireshark for targeted analysis.

### Step-by-Step Guide

1. **Phase 1: Discovery (Nmap)**
   - Go to **Nmap Scanner**.
   - Run a scan against your target (e.g., `192.168.1.100`, Full Profile).
   - Vortex will discover open ports and services.

2. **Phase 2: Transition**
   - In the scan results, locate the **"Analyze in Wireshark"** button.
   - Clicking this automatically:
     - Generates a precise Wireshark display filter based on discovered ports (e.g., `tcp.port == 80 or tcp.port == 443`).
     - Swithes the interface to **Wireshark Suite**.
     - Pre-fills the "Display Filter" input.

3. **Phase 3: Targeted Analysis (Wireshark)**
   - In the **Packet Capture** tab, the filter is now ready.
   - Click **Start Capture**.
   - You will now capture *only* traffic relevant to the services discovered by Nmap, eliminating noise and focusing your analysis.

---

## API Reference

Vortex exposes a REST API for programmatic access.

### Base URL
```
http://localhost:8000
```

### Endpoints

#### Nmap Scanning
```http
POST /scan
Content-Type: application/json

{
  "target": "192.168.1.1",
  "ports": "1-1000",
  "scan_type": "syn",
  "timing": 4
}
```

#### Network Mapping
```http
POST /api/net/scan
Content-Type: application/json

{
  "subnet": "172.18.0.0/16"
}
```

#### Packet Capture
```http
POST /api/net/capture
Content-Type: application/json

{
  "duration": 5,
  "count": 50,
  "filter": "tcp.port == 80"
}
```

#### Sensitive Data Analysis
```http
POST /api/net/analyze
```

#### Packet Injection
```http
POST /api/net/inject
Content-Type: application/json

{
  "target": "172.18.0.1",
  "port": 80,
  "count": 5
}
```

#### MITM Attack
```http
POST /api/net/mitm
Content-Type: application/json

{
  "target": "192.168.1.100",
  "gateway": "192.168.1.1",
  "duration": 10
}
```

#### DoS Attack
```http
POST /api/net/dos
Content-Type: application/json

{
  "target": "192.168.1.100",
  "port": 80,
  "duration": 10
}
```

#### SSL Decryption
```http
POST /api/net/decrypt
Content-Type: application/json

{
  "pcap_path": "/app/capture.pcap",
  "key_path": "/app/ssl.keys"
}

#### Filter Generation
```http
POST /api/utils/nmap-to-filter
Content-Type: application/json
Input: Full Nmap Results JSON
Output: { "filter": "tcp.port == 80 or ..." }
```
```

---

## Troubleshooting

### Common Issues

#### "Network analyzer not initialized"
**Cause**: The container couldn't access the network interface.
**Solution**: Ensure Docker has network privileges. You may need to run with `--privileged` flag or add network capabilities.

#### Empty packet capture results
**Cause**: No traffic on the interface during capture window.
**Solution**: 
1. Use "Inject Test Packets" to generate traffic
2. Ensure the container is on the correct network
3. Try a longer capture duration

#### Network map shows no devices
**Cause**: ARP scan requires being on the same subnet as targets.
**Solution**:
1. Verify the subnet CIDR is correct
2. Check Docker network configuration
3. Some networks may block ARP requests

#### Nmap scans fail
**Cause**: Target may be blocking scans or unreachable.
**Solution**:
1. Verify target is reachable with ping
2. Check firewall rules
3. Try a different scan type

### Docker Network Tips

- Default Docker bridge network: `172.17.0.0/16`
- Docker Compose networks: Usually `172.18.0.0/16`
- To find your Docker network: `docker network inspect bridge`

### Viewing Container Logs

```bash
docker-compose logs -f vortex
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-22 | Initial release with Nmap, Wireshark Suite, and Red Team features |

---

## License & Credits

Vortex is provided for educational and authorized security testing purposes.

**Built with:**
- FastAPI (Backend)
- React + TypeScript (Frontend)
- Nmap, PyShark, Scapy (Network Tools)
- Docker (Deployment)

---

*For questions, issues, or contributions, please refer to the project repository.*
