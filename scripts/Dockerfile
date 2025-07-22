# Web-Toolkit Pro Docker Image
FROM ubuntu:22.04

LABEL maintainer="byfranke.com"
LABEL description="Web-Toolkit Pro - Professional Security Assessment Suite"
LABEL version="2.0"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/modules:$PYTHONPATH

# Update system and install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    sqlmap \
    wget \
    curl \
    gobuster \
    whatweb \
    git \
    unzip \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install seclists wordlists
RUN git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# Install modern security tools from GitHub releases
WORKDIR /tmp

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.4_linux_amd64.zip -O nuclei.zip \
    && unzip nuclei.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei.zip

# Install Subfinder
RUN wget https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.3_linux_amd64.zip -O subfinder.zip \
    && unzip subfinder.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder.zip

# Create app directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY modules/ ./modules/
COPY tests/ ./tests/
COPY web-toolkit-pro.py ./
COPY config.ini ./
COPY DOCUMENTATION.md ./

# Update Nuclei templates
RUN nuclei -update-templates || true

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash scanner \
    && chown -R scanner:scanner /app

# Create directories for output
RUN mkdir -p /app/reports /app/logs \
    && chown -R scanner:scanner /app/reports /app/logs

# Switch to non-root user
USER scanner

# Set up environment
ENV HOME=/home/scanner
ENV PATH=/usr/local/bin:$PATH

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 web-toolkit-pro.py --version || exit 1

# Volume for reports
VOLUME ["/app/reports"]

# Entry point
ENTRYPOINT ["python3", "web-toolkit-pro.py"]
CMD ["--help"]
