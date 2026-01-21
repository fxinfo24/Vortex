#!/bin/bash
echo "Starting Nmap Automation Web Interface..."

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run setup first."
    exit 1
fi

# Activate venv
source venv/bin/activate

# Start Backend
echo "Starting Backend on http://localhost:8000..."
uvicorn web.backend.main:app --reload --port 8000 > backend.log 2>&1 &
BACKEND_PID=$!

# Start Frontend
echo "Starting Frontend..."
cd web/frontend

# Trap SIGINT and SIGTERM to kill backend
trap "kill $BACKEND_PID" EXIT

npm run dev
