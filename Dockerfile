# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Install system dependencies (Nmap & Node.js)
RUN apt-get update && apt-get install -y \
    nmap \
    tshark \
    libpcap-dev \
    iproute2 \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# Set working directory
WORKDIR /app

# Copy backend requirements and install
COPY web/backend/requirements.txt ./web/backend/requirements.txt
COPY nmap-requirements.txt ./
RUN pip install --no-cache-dir -r web/backend/requirements.txt
RUN pip install --no-cache-dir -r nmap-requirements.txt

# Copy the entire project
COPY . .

# Build the Frontend
WORKDIR /app/web/frontend
RUN npm install && npm run build

# Go back to root
WORKDIR /app

# Expose ports (Backend & Frontend serving)
EXPOSE 8000

# Start script
CMD ["uvicorn", "web.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
