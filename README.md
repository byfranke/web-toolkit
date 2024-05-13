# web-toolkit

This toolkit provides versatile scripts for security analysis and network reconnaissance. It includes functionalities for SMTP and SSH user enumeration, URL encoding, vulnerability detection using Nuclei, and comprehensive web analyses integrating tools like Nmap, WhatWeb, and Sqlmap. Ideal for security professionals needing robust and efficient automation in penetration testing and security assessments of digital infrastructures.


**dns-info**
The dns-info script is a Python script for querying WHOIS servers to obtain domain registration information. It uses the socket library to connect to a specified WHOIS server and sends a query for a domain provided via command line. It first tries the IANA server, then a specific server based on IANA's response. The query result is printed to the console, and errors are handled and displayed if they occur during the query process.

**smtp-enum**
The smtp-enum script is used for SMTP user enumeration by attempting to validate usernames on a specified SMTP server. It tries to connect to the server using the provided IP address and sends VRFY commands to check for the existence of users from either a standard list or a specified custom list. If a user is validated by the server, the script prints the username found. Connection errors and interruptions are managed and displayed.

**ssh-enum**
The ssh-enum script uses the paramiko library to attempt SSH connections to a specified server. It aims to identify valid usernames by trying to authenticate with an invalid password. The script operates with either a standard list of usernames or a custom list provided via a file. If the SSH server responds with an authentication exception, this indicates a valid username. Various types of errors such as SSH errors, connection errors, and user interruptions are managed.

**urlchar**
The urlchar script is a Bash script that manages a simple web service (using Apache and PHP) to encode URL characters. It allows starting or stopping the Apache service, opening a PHP page in a browser with specific text for encoding, and replacing the PHP file if necessary. The PHP page created encodes and displays the text sent as a URL parameter, including examples with special characters like # and &.

**nuclei-hunter**
The nuclei-hunter script is a Bash script that automates the use of subfinder and nuclei tools to discover subdomains and scan these subdomains based on specified vulnerability templates. The script requires two parameters: a domain and a type of vulnerability template. Results are saved in a text file in the user's Documents/Nuclei directory with timestamp records.

**scan-web**
The scan-web script is a Bash script for performing a comprehensive scan of a specified web host. It integrates various network and web scanning tools including WhatWeb, webrecon, nmap, dirsearch, and curl. Each tool is used for different purposes such as software identification, directory enumeration, HTTP configuration testing, and vulnerability scanning. Results from some tools are recorded in specific text files for later review.

**scan-websilence**
The scan-websilence script is a simpler, more direct version for host scanning, using exclusively nmap. The script is configured to perform a stealthy scan of major TCP ports. This procedure is useful for determining open ports without attracting much attention.

**sql-short**
The sql-short script is a Bash script that automates the use of sqlmap to test SQL injections on a specified URL or IP. It performs two phases of tests: one to discover available databases and another to list columns within those databases. The script uses the tampering technique space2comment to bypass simple space filters and sets sqlmap to act as a random user agent, also handling forms found during the scan.

**webrecon**
The webrecon script is designed to perform a simple reconnaissance on a specified URL, using wget to download the complete content of the site while ignoring the robots.txt file. After downloading, it searches for keywords related to credentials and authentication tokens in the downloaded content, recording any occurrences in a result file. This process is useful for a preliminary analysis of potential exposures of sensitive data on web pages.

**update-web-toolkit**
The update-web-toolkit script is a very simple Bash script that updates tools in the /usr/bin directory by copying all files from the current directory there. Then, it removes itself from the /usr/bin directory. This script can be used to facilitate the updating of command-line tools in a Unix-like system.

# How to Use

Step : 1 Download

```
git clone https://github.com/byfranke/web-toolkit
```
Step : 2 Move to directory
```
cd web-toolkit
```
Step : 3 Permission to execute
```
chmod +x update-web-toolkit
```
Step : 4 Run
```
sudo ./update-web-toolkit
```

# Donations

If you find these tools useful and would like to support ongoing development and maintenance, please consider making a donation. Your contribution helps ensure that these tools are regularly updated and improved, benefiting the cybersecurity community. Any amount is greatly appreciated and will make a significant difference in supporting this project. Thank you for considering supporting this work!

**BTC DONATE:**
Addres Bitcoin: bc1qkdh3eqpj87q5hlhc7pvm025hmsd9zp2kadxf76
