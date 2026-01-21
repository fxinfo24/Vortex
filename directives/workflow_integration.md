# Nmap-Wireshark Integration Directive

## Objective
Implement a cohesive "Best Workflow" integrating Nmap scanning and Wireshark packet capture as a unified process.

## Features
1. **Filter Generation**: Auto-generate Wireshark display filters from Nmap scan results.
2. **Context Switching**: Seamlessly transition from Nmap results to Wireshark capture with pre-filled filters.
3. **Enhanced Capture**: Support display filters in the packet capture API.

## Implementation Details

### Backend
1. **NetworkAnalyzer.py**:
   - Update `packet_capture` to accept `display_filter` string.
   - Pass this filter to `pyshark.LiveCapture`.

2. **main.py**:
   - Update `CaptureRequest` model.
   - Add new endpoint: `POST /api/utils/nmap-to-filter`.
     - Input: Nmap Scan Result (JSON).
     - Output: `{"filter": "..."}` string (e.g., `tcp.port == 80 or tcp.port == 443`).
     - Logic: Iterate through hosts and ports in the JSON, construct a Wireshark display filter string.

### Frontend
1. **WiresharkPanel.tsx**:
   - Accept optional `initialFilter` prop.
   - Add text input for "Display Filter" in the "Packet Capture" tab.
   - Include filter value in API calls to `/api/net/capture`.

2. **App.tsx**:
   - In Nmap results view (Results Output section), add an "Analyze in Wireshark" button.
   - On click: 
     - Call `/api/utils/nmap-to-filter` with current results.
     - Switch mode to `wireshark`.
     - Pass the generated filter to `WiresharkPanel`.
