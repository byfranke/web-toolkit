# Web-Toolkit

Web-Toolkit is a versatile command-line tool designed to streamline and automate various penetration testing tasks. It simplifies managing encrypted projects, running multiple scan tools, and collecting scan results—all from a unified interface.

---

## Key Features

### Project Management
- **Secure Storage**: Create password-protected projects to securely store notes and scan results in an encrypted SQLite database.
- **Comprehensive Note Handling**: Read, edit, and export your stored notes with ease.
- **Based on [EncryptNotes](https://github.com/byfranke/EncryptNotes)**: This project management system is built upon the foundation of EncryptNotes, ensuring robust encryption and efficient note handling.

### Scan Tools
- **Full Web Scan**: Combine multiple tools (e.g., nmap, webrecon) for a complete target overview.
- **Web Recon**: Use `wget` to mirror websites and search for sensitive keywords.
- **SQL Injection Testing**: Perform quick SQL injection tests with `sqlmap`.
- **Service Enumeration**: Enumerate SMTP (using VRFY) and test SSH logins with provided credentials.
- **Nuclei Hunter**: Discover subdomains with `subfinder` and scan for vulnerabilities using `nuclei` templates.
- **Silent Scan**: Execute stealthy nmap scans for minimal detection.
- **WHOIS Lookup**: Retrieve detailed domain registration information.
- **Gobuster Scan**: Brute-force directories using gobuster with an automatic fallback to a default wordlist.

### Auto-Update and Dependency Management
- **Self-Update**: Automatically check for and update to the latest version from GitHub, archiving previous files.
- **Automatic Dependency Installation**: Installs and verifies required tools (Python3, pip3, nmap, sqlmap, wget, curl, gobuster, and seclists) on Debian-based (apt-get) and Arch-based (pacman) Linux systems.

---

## Installation

Follow these steps to install Web-Toolkit:

    # 1. Clone the repository
    git clone https://github.com/byfranke/web-toolkit

    # 2. Navigate to the project directory
    cd web-toolkit

    # 3. Run the setup script
    chmod +x setup.sh
    ./setup.sh

    # 4. Select "Install/Configure Local Version" when prompted.
    # This installs the required dependencies and copies web-toolkit.py to /usr/bin/web-toolkit,
    # allowing you to run the tool by simply typing:
    web-toolkit

**Note:** The setup script supports Debian-based and Arch-based Linux distributions. Windows users must install the dependencies manually.

---

## Usage

### Interactive Mode

After installation, run:

    web-toolkit

Or, if not installed system-wide:

    python3 web-toolkit.py

In interactive mode, you can:
- **Manage Projects**: Create new projects or open existing ones to securely store scan results.
- **Scan Tools**: Access a variety of scans (Full Web Scan, Web Recon, SQLi Test, SMTP Enum, SSH Enum, Nuclei Hunter, Silent Scan, WHOIS, Gobuster Scan).
- **Help**: Detailed usage instructions.
- **Update Toolkit**: Update to the latest version from GitHub.

### Command-Line Interface (CLI)

Web-Toolkit also supports CLI arguments for quick operations:

    # Run a full web scan on a target
    web-toolkit --scan-full https://example.com

    # Perform a web recon scan
    web-toolkit --web https://example.com

    # Execute an SQL injection test
    web-toolkit --sql https://example.com

    # Enumerate SMTP services
    web-toolkit --smtp 192.168.1.10

    # Test SSH login (interactive input required)
    web-toolkit --ssh 192.168.1.10

    # Run a Nuclei Hunter scan
    web-toolkit --nuclei-scan example.com vulnerabilities

    # Perform a silent scan
    web-toolkit --scan-silence https://example.com

    # Retrieve WHOIS information for a domain
    web-toolkit --whois example.com

    # Perform a Gobuster Scan (if supported/implemented)
    web-toolkit --gobuster-scan https://example.com

---

## Donations

If you find Web-Toolkit useful and wish to support its development and maintenance, consider making a donation. Your contribution helps keep the project updated for the cybersecurity community.

**Bitcoin Address**: `bc1qkdh3eqpj87q5hlhc7pvm025hmsd9zp2kadxf76`

Web-Toolkit is continuously evolving. Contributions, bug reports, and feature requests are always welcome!
