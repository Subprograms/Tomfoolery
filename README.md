# Tomfoolery: Tomcat Reconnaissance and Brute Forcer

Tomfoolery is a high-efficiency automation tool designed for security professionals to identify, fingerprint, and audit Apache Tomcat management interfaces. It combines rapid port discovery, protocol-level vulnerability checking (AJP/Ghostcat), and multi-threaded credential auditing in a single automated workflow.

## Features

* **Multi-Port Discovery**: Automatically sweeps common web ports to locate hidden Tomcat instances.
* **Aggressive Fingerprinting**: Scrapes version data through forced 404 error pages and validates management paths via HTTP headers, bypassing hardened configurations where server headers are suppressed.
* **Protocol Audit**: Identifies open AJP (Port 8009) connectors to flag potential CVE-2020-1938 (Ghostcat) vulnerabilities.
* **Lethal Brute Force**: Uses a multi-threaded producer-consumer model with connection pooling for high-speed credential auditing.
* **Metasploit-Style Logic**: Supports separate username and password wordlists, falling back to industry-standard Tomcat default accounts if no username list is provided.
* **Visual Progress**: Real-time feedback via TQDM progress bars without interrupting successful hit reporting.

## Installation

### Prerequisites

* Python 3.x
* Pip (Python package manager)

### Dependencies

Install the required Python libraries:

```bash
pip install requests tqdm urllib3
```

## Usage

Run the script from your terminal:

```bash
python3 tomfoolery.py
```

### Configuration Prompts

1. **Target IP**: The IPv4 address of the target server.
2. **Username Wordlist**: Path to a text file containing usernames. If left blank, the tool uses a built-in list of common Tomcat users (tomcat, admin, manager, root, both, role1).
3. **Password Wordlist**: Path to your password wordlist (e.g., rockyou.txt or a custom list). This field is required.

### Input Formats

The tool handles two types of wordlist entries:
* **Single Entries**: Standard password lists. The tool will attempt every username against every password.
* **Colon Separated**: If a line contains a colon (user:pass), the tool treats it as a specific credential pair.

## Technical Details

### Vulnerability Mapping

The tool assists in identifying the following weaknesses:

| Identification | Vulnerability |
| --- | --- |
| Port 8009 Open | CVE-2020-1938 (Ghostcat) |
| Version Scraping | CWE-200 (Information Exposure) |
| Successful Login | CWE-1393 (Use of Default Password) |
| Rapid Brute Force | CWE-307 (Improper Restriction of Authentication Attempts) |

### Optimization

To prevent high CPU usage and system freezing, the tool utilizes a fixed thread pool (default 15 threads) and a synchronized queue. This ensures a steady request rate that mimics professional tools like Hydra while remaining stable on low-resource machines.

## Disclaimer

This tool is for educational purposes and authorized security auditing only. Unauthorized access to computer systems is illegal. The user is responsible for compliance with all local, state, and federal laws.
