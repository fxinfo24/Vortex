from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys
import os
import logging
from typing import Optional, Dict

# Add execution directory to path to import NmapScanner modules
sys.path.append(os.path.join(os.path.dirname(__file__), '../../execution'))

try:
    from NmapScanner import perform_scan, validate_ip, validate_port_range, validate_target
except ImportError as e:
    logging.error(f"Failed to import NmapScanner: {e}")
    # Create mock functions if import fails (dev mode fallback or error)
    def perform_scan(*args, **kwargs): raise NotImplementedError("Scanner module not found")

app = FastAPI(title="Vortex API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Mount static files (Frontend build)
# Check if dist exists (production/docker mode)
frontend_dist = os.path.join(os.path.dirname(__file__), '../frontend/dist')
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
    try:
        # Validate inputs using the script's validators
        try:
            # The script validators raise argument errors tailored for CLI (argparse)
            # We might want to catch them or just let the scanner handle it
            validate_target(request.target)
            validate_port_range(request.ports)
        except Exception as e:
             raise HTTPException(status_code=400, detail=str(e))

        # Perform Scan
        # perform_scan(target, ports, scan_type, retries=3, timing=None)
        # It is synchronous, so we might want to run it in a threadpool if it blocks too long,
        # but NmapScanner already uses async internally for multiple targets.
        # However, perform_scan itself is blocking wrapper around the async loop if multiple targets,
        # or direct call if single.
        # For a web request, we should probably run this in a thread to not block the event loop.
        # But wait, NmapScanner imports asyncio. 
        # Let's just call it directly for now. Ideally we refactor NmapScanner to be purely async.
        
        results = perform_scan(
            target=request.target,
            ports=request.ports,
            scan_type=request.scan_type,
            timing=request.timing
        )
        
        return results

    except Exception as e:
        logging.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

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
    return net_analyzer.network_mapper(req.subnet)

@app.post("/api/net/capture")
async def packet_capture(req: CaptureRequest):
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    return await net_analyzer.packet_capture(duration=req.duration, packet_count=req.count, display_filter=req.filter)

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
    return net_analyzer.mitm_attack(req.target, req.gateway, req.duration)

@app.post("/api/net/dos")
async def dos_attack(req: DosRequest):
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    return net_analyzer.dos_attack(req.target, req.port, req.duration)

@app.post("/api/net/decrypt")
async def decrypt_traffic(req: DecryptRequest):
    if not net_analyzer:
         raise HTTPException(status_code=503, detail="Network analyzer not initialized")
    return net_analyzer.decrypt_ssl_traffic(req.pcap_path, req.key_path)

@app.post("/api/utils/nmap-to-filter")
async def generate_filter(results: Dict[str, Any]):
    filters = []
    # Results structure: {"ip": {"tcp": {"80": ...}, "udp": ...}}
    for ip, data in results.items():
        if ip == "runtime": continue # skip metadata
        
        # Add host filter? Usually mapped per port, but let's follow user script logic:
        # User script: protocol.port == portid.
        # It doesn't restrict by IP in the filter logic provided, but practically we should OR them.
        
        for proto in ['tcp', 'udp']:
            if proto in data:
                for port in data[proto]:
                    # Filters like: tcp.port == 80
                    filters.append(f"{proto}.port == {port}")
    
    if not filters:
        return {"filter": ""}
        
    return {"filter": " or ".join(filters)}

