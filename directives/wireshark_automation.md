# Wireshark Automation Directive

## Objective
Integrate the `WireShark_Automation` capabilities into the Vortex application, exposing them via the API and Frontend.

## Scope
1. **Network Mapping**: Scan subnets for active devices.
2. **Packet Capture**: Capture live traffic on demand.
3. **Traffic Analysis**: Analyze captured traffic for sensitive data (credentials, cookies).
4. **Packet Injection**: Inject custom packets for testing.
5. **Red Team Operations**:
   - **MITM Attack**: Perform ARP Spoofing.
   - **DoS Attack**: Execute SYN Floods.
   - **SSL Decryption**: Decrypt encapsulated traffic using keys.
   - **Promiscuous Mode**: Enable interface promiscuous mode.

## Inputs
- **Network Map**: Subnet CIDR (e.g., `172.18.0.0/16`)
- **Capture**: Duration (s), Packet Count
- **Injection**: Target IP, Port, Count
- **MITM**: Target IP, Gateway IP, Duration
- **DoS**: Target IP, Port, Duration
- **Decrypt**: PCAP path, Key path

## Execution Tools
- `execution/NetworkAnalyzer.py`:
  - `AdvancedNetworkAnalyzer` class.
  - Dependencies: `pyshark`, `scapy`, `cryptography`, `tshark` (system).

## Edge Cases
- **Permissions**: Requires root/privileged Docker container (handled via `privileged: true` or caps).
- **Interface**: Default `eth0`, might vary.
- **Concurrency**: Capture/Attacks should be threaded/async to not block API.

## Outputs
- JSON responses with scan results, captured packet summaries, analysis reports, or operation status.
