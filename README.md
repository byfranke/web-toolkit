# WEB-TOOLKIT PROFESSIONAL

Professional penetration testing toolkit with automated vulnerability detection and comprehensive security assessment capabilities.

## Overview

Web-Toolkit is an enterprise-grade security assessment platform designed for penetration testers and security professionals. It provides automated vulnerability detection, CVE correlation, and comprehensive reporting capabilities while maintaining strict security standards.

## Features

### Core Capabilities
- **Automated Security Scanning**: Integration with industry-standard tools (Nmap, Nuclei, Gobuster, WhatWeb)
- **CVE Detection**: Real-time vulnerability identification with CVSS scoring
- **Project Management**: Encrypted multi-client project isolation and organization
- **Professional Reporting**: Executive and technical report generation
- **Audit Logging**: Complete activity tracking and forensic capabilities

### Security Features
- **Input Sanitization**: Protection against command injection attacks
- **Secure Authentication**: bcrypt password hashing with salt
- **Data Encryption**: Fernet symmetric encryption for sensitive data
- **Access Control**: Role-based project access management
- **Compliance**: Adherence to industry security standards

### Supported Tools
- **Network Scanning**: Nmap, Masscan
- **Vulnerability Assessment**: Nuclei, OpenVAS integration
- **Web Application Testing**: Gobuster, Dirb, WhatWeb
- **Information Gathering**: Subfinder, Amass
- **Exploitation Framework**: SQLMap integration

## System Requirements

- **Operating System**: Linux (Ubuntu 18.04+, Debian 10+, Kali Linux), macOS (10.14+)
- **Python Version**: 3.8 or higher
- **Memory**: 2GB RAM minimum
- **Storage**: 1GB available disk space
- **Network**: Internet connection for CVE database updates

## Installation

### Quick Installation
```bash
git clone https://github.com/byfranke/web-toolkit
cd web-toolkit
chmod +x setup.sh
./setup.sh
```

### Manual Installation
```bash
# Clone repository
git clone https://github.com/byfranke/web-toolkit
cd web-toolkit

# Install Python dependencies
pip3 install -r requirements.txt

# Install system tools
sudo apt-get update
sudo apt-get install nmap nuclei gobuster whatweb curl wget

# Configure permissions
chmod +x web-toolkit.py setup.sh
```

## Usage

### Interactive Mode
```bash
python3 web-toolkit.py
```

### Command Line Interface
```bash
# Full target assessment
python3 web-toolkit.py --scan-full target.example.com

# Web application scan
python3 web-toolkit.py --web https://target.example.com

# Vulnerability scan with Nuclei
python3 web-toolkit.py --nuclei-scan target.example.com

# SSH enumeration
python3 web-toolkit.py --ssh-enum 192.168.1.100

# Display help
python3 web-toolkit.py --help
```

### Project Management
1. Launch the toolkit: `python3 web-toolkit.py`
2. Select "Project Management" from the main menu
3. Create a new project with a secure password
4. Execute scans and organize results within the project structure
5. Generate professional reports for stakeholders

## Project Structure

```
web-toolkit/
├── web-toolkit.py              # Main executable
├── setup.sh                    # Installation script
├── README.md                   # Project documentation
├── requirements.txt            # Python dependencies
├── modules/                    # Core application modules
│   ├── cve_intelligence.py     # CVE detection and analysis
│   ├── project_manager.py      # Project management system
│   ├── validators.py           # Input validation
│   ├── reporting.py            # Report generation
│   └── tools.py                # Tool integration
├── tests/                      # Unit tests
├── scripts/                    # Utility scripts and tools
│   ├── Dockerfile              # Container configuration
│   ├── Makefile                # Build automation
│   ├── security_patches.py     # Security patches
│   └── tools/                  # External tool scripts
├── config/                     # Configuration files
│   └── config.ini              # Application configuration
├── database/                   # Database files
├── logs/                       # Application logs
├── docs/                       # Documentation
```

## Configuration

### Application Settings
Configuration is managed through `config/config.ini`:

```ini
[Security]
password_min_length = 12
session_timeout = 1800
audit_logging = true

[Database]
connection_timeout = 30
backup_interval = 3600

[Reporting]
default_format = pdf
include_screenshots = true
```

### Tool Configuration
External security tools are automatically detected and configured. Custom tool paths can be specified in the configuration file.

## Security Considerations

### Best Practices
- Use strong passwords for project creation (minimum 12 characters)
- Execute in isolated environments when possible
- Regularly update CVE database and tool signatures
- Implement proper access controls for multi-user environments
- Maintain secure backup procedures for project data

### Compliance
- **Authorization Required**: Only use against systems you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Data Protection**: Implement appropriate data handling procedures
- **Documentation**: Maintain detailed records of all testing activities

## Reporting

### Executive Reports
- Risk assessment summary
- Business impact analysis
- Remediation priority matrix
- Compliance status overview

### Technical Reports
- Detailed vulnerability descriptions
- Proof-of-concept demonstrations
- Step-by-step remediation procedures
- CVSS scoring and risk metrics

### Export Formats
- PDF (executive and technical reports)
- HTML (interactive reports)
- JSON (machine-readable data)
- CSV (metrics and statistics)

## API Integration

Web-Toolkit provides REST API endpoints for integration with SIEM systems and security orchestration platforms:

```bash
# Health check
curl -X GET http://localhost:8080/api/health

# Project status
curl -X GET http://localhost:8080/api/projects/{project_id}/status

# Vulnerability data
curl -X GET http://localhost:8080/api/vulnerabilities?format=json
```

## Development

### Building from Source
```bash
make install-deps
make test
make security-check
make build
```

### Testing
```bash
# Run unit tests
python3 -m pytest tests/

# Security testing
bandit -r modules/
safety check

# Code quality
flake8 modules/ --max-line-length=88
black modules/ --check
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Run security checks
5. Submit pull request

## Support

### Community
- **Issues**: [GitHub Issues](https://github.com/byfranke/web-toolkit/issues)
- **Security Reports**: contact@byfranke.com

## Donation Support

This tool is maintained through community support. Help keep it active:

[![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://donate.stripe.com/28o8zQ2wY3Dr57G001)

## Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring compliance with applicable laws and regulations. The developers assume no liability for misuse of this software.

## Acknowledgments

- OWASP Foundation for security testing methodologies
- NIST for CVE database and vulnerability standards
- Security research community for vulnerability intelligence
- Open source contributors and maintainers

---

**For authorized security testing only. Use responsibly.**
