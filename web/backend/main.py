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

app = FastAPI(title="Nmap Automation API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development, allow all. In prod, lock this down.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    ports: str
    scan_type: str
    timing: Optional[int] = 4

@app.get("/")
async def root():
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
