# Web-Toolkit

Web-Toolkit is a command-line utility that helps automate and organize common penetration testing tasks, including:

- Creating and managing encrypted projects to store notes and scan results.
- Running a variety of scanning tools (nmap, sqlmap, whatweb, dirsearch, etc.)
- Enumerating services (SMTP, SSH, etc.).
- Performing WHOIS lookups.
- Installing dependencies automatically on Linux systems.
- Updating itself from GitHub.

---
## Features

1. **Project Management**
   - Create password-protected projects.
   - Store notes and scan results in an encrypted SQLite database.
   - Read, edit, and export notes.

2. **Scan Tools**
   - **Full Web Scan**: Combines multiple tools (e.g., nmap, webrecon) for a comprehensive overview.
   - **Web Recon**: Crawls a website with `wget` and searches for specific keywords.
   - **SQLi Test**: Quick test for SQL injection using `sqlmap`.
   - **SMTP Enum**: Attempts to find valid users with VRFY.
   - **SSH Enum**: Tries SSH login with user-provided credentials.
   - **Nuclei Hunter**: Subdomain discovery with `subfinder` followed by template-based scanning with `nuclei`.
   - **Silent Scan**: Minimal, stealthy nmap scanning.
   - **WHOIS**: Looks up domain registration details.

3. **Auto-Update**
   - Pulls the latest version from GitHub, moves old files to a backup folder.

4. **Automatic Dependencies Installation**
   - Checks for Python3, pip3, nmap, sqlmap, wget, and curl on apt-get or pacman-based Linux.

---
## Installation

```bash
# 1) Clone this repository
$ git clone https://github.com/byfranke/web-toolkit

# 2) Enter the directory
$ cd web-toolkit

# 3) Run setup.sh
$ chmod +x setup.sh
$ ./setup.sh

# 4) Choose 'Install/Configure Local Version'
# This will install the required dependencies and copy web-toolkit.py into /usr/bin/web-toolkit
# so you can run it simply by typing:
$ web-toolkit
```

This setup script supports Debian-based (apt-get) and Arch-based (pacman) Linux systems. On Windows, manual installation of dependencies is required.

---
## Usage

After installation, run:

```bash
web-toolkit
```

or from the local folder if you haven't installed it system-wide:

```bash
python3 web-toolkit.py
```

You will see a menu:

- **Manage Projects**: Create a new encrypted project or open an existing one.
- **Scan Tools**: Access sub-menus for Full Web Scan, Web Recon, etc.
- **Install Dependencies**: Installs or checks required tools.
- **Help**: Explains usage.
- **Update Toolkit**: Updates from GitHub.

### CLI Usage

You can also use CLI arguments:

```bash
web-toolkit --install
web-toolkit --scan-full https://example.com
web-toolkit --web https://example.com
web-toolkit --sql https://example.com
web-toolkit --smtp 192.168.1.10
web-toolkit --ssh 192.168.1.10
web-toolkit --nuclei-scan example.com vulnerabilities
web-toolkit --scan-silence https://example.com
web-toolkit --whois example.com
```

---

# Donations

If you find these tools useful and would like to support ongoing development and maintenance, please consider making a donation. Your contribution helps ensure that these tools are regularly updated and improved, benefiting the cybersecurity community. Any amount is greatly appreciated and will make a significant difference in supporting this project. Thank you for considering supporting this work!

Address Bitcoin: bc1qkdh3eqpj87q5hlhc7pvm025hmsd9zp2kadxf76
