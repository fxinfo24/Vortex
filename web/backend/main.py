from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import sys
import os
import logging
import asyncio
import threading
import nmap
from typing import Optional, Dict, Any, List

# Add execution directory to path to import NmapScanner modules
sys.path.append(os.path.join(os.path.dirname(__file__), "../../execution"))

app = FastAPI(title="Vortex API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (Frontend build)
frontend_dist = os.path.join(os.path.dirname(__file__), "../frontend/dist")
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")
    
    @app.get("/")
    async def serve_frontend():
        return FileResponse(os.path.join(frontend_dist, "index.html"))

    @app.get("/logo.png")
    async def serve_logo():
        return FileResponse(os.path.join(frontend_dist, "logo.png"))

    @app.get("/favicon.png")
    async def serve_favicon():
        return FileResponse(os.path.join(frontend_dist, "favicon.png"))

# --- Scan Manager for Cancellable Scans ---

class ScanManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.active_events = []
    
    def register_event(self, event: threading.Event):
        with self._lock:
            self.active_events.append(event)
            
    def unregister_event(self, event: threading.Event):
        with self._lock:
            if event in self.active_events:
                self.active_events.remove(event)

    def stop_current_scan(self):
        """ Aggressively kill nmap processes to stop the scan and signal threads. """
        import subprocess
        
        # Stop Python Tasks
        with self._lock:
            count = len(self.active_events)
            for event in self.active_events:
                event.set()
            # We don't clear list immediately as threads remove themselves, 
            # but for safety we can clear to avoid holding stale refs if threads die weirdly?
            # Actually threads call unregister in finally block, so let's just set events.
        
        try:
             # This is a rough way to stop, but `python-nmap` leaves us little choice 
             # without rewriting `NmapScanner.py` to use `subprocess.Popen` directly.
             # We kill "nmap" processes.
             subprocess.run(["pkill", "nmap"], check=False)
             return True
        except Exception as e:
             logging.error(f"Failed to kill nmap: {e}")
             return False

scan_manager = ScanManager()

class ScanRequest(BaseModel):
    target: str
    ports: str
    scan_type: str
    timing: Optional[int] = 4

@app.get("/api/status")
async def api_status():
    return {"status": "online", "service": "Nmap Automation API"}

@app.post("/scan")
async def run_scan(request: ScanRequest):
    # Run in thread to allow non-blocking API so we can call /scan/stop
    try:
        from NmapScanner import perform_scan, validate_target, validate_port_range
        
        # Pre-validation
        validate_target(request.target)
        validate_port_range(request.ports)
        
        # We use asyncio.to_thread to run the blocking scan function
        # This frees the event loop to accept the /scan/stop request
        results = await asyncio.to_thread(
            perform_scan, 
            request.target, 
            request.ports, 
            request.scan_type, 
            retries=1, 
            timing=request.timing
        )
        return results
        
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/stop")
async def stop_scan():
    """Stop any currently running nmap scans."""
    success = scan_manager.stop_current_scan()
    if success:
        return {"status": "success", "message": "Scan stopped (nmap processes killed)"}
    else:
         raise HTTPException(status_code=500, detail="Failed to stop scan")

# --- Network Analyzer Integration ---
try:
    from NetworkAnalyzer import AdvancedNetworkAnalyzer
except ImportError:
    # Fallback if specific file is not found or path issues
    from execution.NetworkAnalyzer import AdvancedNetworkAnalyzer

# Try to initialize analyzer. 
# In Docker, eth0 is common. If it fails, we might just log it.
try:
    net_analyzer = AdvancedNetworkAnalyzer(interface="eth0")
except Exception as e:
    logging.error(f"Failed to init network analyzer: {e}")
    net_analyzer = None

class NetworkScanRequest(BaseModel):
    subnet: str

class CaptureRequest(BaseModel):
    duration: int = 5
    count: int = 20
    filter: Optional[str] = ""

class InjectRequest(BaseModel):
    target: str
    port: int = 80
    count: int = 1

class MitmRequest(BaseModel):
    target: str
    gateway: str
    duration: int = 10

class DosRequest(BaseModel):
    target: str
    port: int = 80
    duration: int = 10

class DecryptRequest(BaseModel):
    pcap_path: str
    key_path: str

@app.post("/api/net/scan")
async def network_scan(req: NetworkScanRequest):
    if not net_analyzer:
        raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    return await asyncio.to_thread(net_analyzer.network_mapper, req.subnet)

@app.post("/api/net/capture")
async def packet_capture(req: CaptureRequest):
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    
    stop_event = threading.Event()
    scan_manager.register_event(stop_event)
    try:
        return await net_analyzer.packet_capture(duration=req.duration, packet_count=req.count, display_filter=req.filter, stop_event=stop_event)
    finally:
        scan_manager.unregister_event(stop_event)

@app.post("/api/net/analyze")
async def sensitive_analysis():
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    # Fixed short duration for demo analysis
    return net_analyzer.extract_sensitive_data(duration=5)

@app.post("/api/net/inject")
async def inject_packets(req: InjectRequest):
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    return net_analyzer.inject_packet(req.target, req.port, req.count)

@app.post("/api/net/mitm")
async def mitm_attack(req: MitmRequest):
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    
    stop_event = threading.Event()
    scan_manager.register_event(stop_event)
    try:
        return await asyncio.to_thread(net_analyzer.mitm_attack, req.target, req.gateway, req.duration, stop_event)
    finally:
        scan_manager.unregister_event(stop_event)

@app.post("/api/net/dos")
async def dos_attack(req: DosRequest):
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    
    stop_event = threading.Event()
    scan_manager.register_event(stop_event)
    try:
        return await asyncio.to_thread(net_analyzer.dos_attack, req.target, req.port, req.duration, stop_event)
    finally:
        scan_manager.unregister_event(stop_event)

@app.post("/api/net/decrypt")
async def decrypt_traffic(req: DecryptRequest):
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    return net_analyzer.decrypt_ssl_traffic(req.pcap_path, req.key_path)

@app.post("/api/net/promisc")
async def enable_promisc():
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    success = net_analyzer.enable_promiscuous_mode()
    if success:
        return {"status": "success", "message": "Promiscuous mode enabled on interface"}
    else:
        raise HTTPException(status_code=500, detail="Failed to enable promiscuous mode")

@app.post("/api/utils/nmap-to-filter")
async def generate_filter(results: Dict[str, Any]):
    filters = []
    # Results structure: {"ip": {"tcp": {"80": ...}, "udp": ...}}
    for ip, data in results.items():
        if ip == "runtime": continue # skip metadata
        
        for proto in ["tcp", "udp"]:
            if proto in data:
                for port in data[proto]:
                    # Filters like: tcp.port == 80
                    filters.append(f"{proto}.port == {port}")
    
    if not filters:
        return {"filter": ""}
        
    return {"filter": " or ".join(filters)}
