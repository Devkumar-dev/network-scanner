# Multi-Threaded Python Network Scanner

A high-performance, concurrent TCP/UDP network scanner and service enumerator built entirely with Python's standard library. Developed as an educational cybersecurity laboratory project, this tool demonstrates transport-layer mechanics, socket programming, multithreaded concurrency, banner grabbing, and structured reporting without external third-party dependencies.

---

## ⚠️ Legal & Ethical Disclaimer

> **IMPORTANT**: This software is intended strictly for authorized educational, research, and laboratory use on locally owned or explicitly permitted systems (such as `127.0.0.1` / `localhost` and isolated cyber range networks). Unauthorized scanning of networks without explicit, written permission from the system owner is illegal and unethical under computer fraud and abuse regulations worldwide. The author assumes no liability for misuse.

---

## 🎯 Project Purpose

This project serves as a hands-on educational network scanner designed to demonstrate core networking, systems programming, and cybersecurity reconnaissance principles from first principles using Python's standard library. The primary learning objectives include:

- **TCP/IP Socket Communication**: Understanding socket creation, connection lifecycles, and low-level transport-layer communication.
- **TCP and UDP Port Scanning**: Contrasting connection-oriented TCP 3-way handshakes with connectionless UDP datagram probing, including interpreting `OPEN`, `CLOSED`, and `OPEN|FILTERED` states.
- **Concurrency and Timeouts**: Managing high-throughput multi-port scanning using `ThreadPoolExecutor` while balancing network latency, socket timeouts, and system resource limits.
- **Service Identification**: Performing standard IANA service resolution (`socket.getservbyport`) and opportunistic TCP banner grabbing to fingerprint listening network applications.
- **Security and Network Reconnaissance Concepts**: Gaining practical, foundational insight into how security analysts and penetration testers discover active services and map attack surfaces.
- **Generating and Interpreting Scan Results**: Producing clear, human-readable terminal summaries and persistent, structured exports (`scan_report.txt` and `scan_results.csv`) for post-scan auditing and reporting.

---

## 🚀 Key Features

- **Multi-Protocol Scanning**:
  - **TCP Scanning**: Full 3-way handshake verification using `socket.SOCK_STREAM`.
  - **UDP Scanning**: Connectionless probing using `socket.SOCK_DGRAM` with ICMP Port Unreachable error detection.
  - **TCP + UDP Scanning**: Combined interleaved scan across identical port boundaries.
- **Four Scan Profiles**:
  - **Quick Scan**: Curated list of 24 high-value common ports.
  - **Standard Scan**: Well-known privileged ports 1–1024.
  - **Full Scan**: Complete 1–65535 port spectrum.
  - **Custom Scan**: Single port or custom hyphenated range (e.g. `8080` or `20-100`).
- **Flexible TCP Scan Modes**:
  - **Fast TCP Connect Scan**: Rapid connectivity check and service mapping without banner acquisition.
  - **Detailed TCP Scan**: Connect scan with active TCP banner grabbing.
- **High Concurrency**:
  - Configurable worker pool (1–200 threads, default: 50) using `ThreadPoolExecutor`.
- **Configurable Timeouts**:
  - Independent connection timeout settings for TCP (default: 0.5s) and UDP (default: 1.0s).
- **Service & Banner Identification**:
  - Standard IANA service name lookup via `socket.getservbyport` for both TCP and UDP.
  - Opportunistic banner extraction (capturing up to 1024 bytes, UTF-8 decoded).
- **Target Resolution & Robust Validation**:
  - Automatic input validation supporting IPv4 addresses and DNS hostnames (e.g. `localhost`, `scanme.nmap.org`).
  - Strict rejection of invalid targets, non-routable syntax, and IPv6 inputs with helpful error prompts.
- **Real-Time Terminal Feedback**:
  - In-place terminal progress indicator (`[*] Progress: X/Y checks (Z%)`).
  - Intelligent output suppression during large UDP scans to avoid terminal flooding while preserving confirmed open ports.
- **Dual Report Generation**:
  - Text summary report (`scan_report.txt`).
  - Excel-compatible CSV data export (`scan_results.csv`).

---

## 📋 System Requirements

- **Python Version**: Python 3.8 or higher.
- **Dependencies**: **None**. Uses standard library modules exclusively:
  - `socket`
  - `concurrent.futures`
  - `ipaddress`
  - `csv`
  - `time`
  - `typing`

---

## 📥 Installation & Setup

1. Clone or download the repository to your local machine:
   ```bash
   git clone https://github.com/your-username/network-scanner.git
   cd network-scanner
   ```

2. Confirm your Python installation:
   ```bash
   python --version
   ```

No external package installation (`pip install`) is required.

---

## 💻 How to Run the Scanner

Run the script from your terminal:

```bash
python scanner.py
```

Follow the interactive prompts to select your target, profile, protocol, mode, worker count, and timeouts:

```text
Network Scanner - Concurrent Multi-Port Scan
============================================

[1] Quick Scan - common TCP/UDP ports
[2] Standard Scan - ports 1-1024
[3] Full Scan - ports 1-65535
[4] Custom Scan - user enters a port or range
Enter scan profile [1]: 1

Enter target IP or hostname [127.0.0.1]: localhost

[1] TCP Scan
[2] UDP Scan
[3] TCP + UDP Scan
Enter protocol [1]: 1

[1] Fast TCP Connect Scan
[2] Detailed TCP Scan
Enter scan mode [1]: 2

Enter worker threads (1-200) [50]: 50
Enter TCP connection timeout in seconds [0.5]: 0.5
```

---

## 🔍 Scan Profiles Explained

| Profile | Port Scope | Checks (per protocol) | Typical Use Case |
| :--- | :--- | :--- | :--- |
| **[1] Quick Scan** | 24 common ports | 24 | Rapid triage of common services (`21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443`). |
| **[2] Standard Scan**| Ports 1–1024 | 1,024 | Comprehensive assessment of well-known system and privileged services. |
| **[3] Full Scan** | Ports 1–65535 | 65,535 | Exhaustive audit of the complete TCP/UDP port spectrum to locate high-numbered dynamic ports. |
| **[4] Custom Scan** | User-defined | Variable | Targeted testing of individual ports (e.g. `8080`) or specific ranges (e.g. `8000-8100`). |

---

## ⚙️ Core Technical Concepts

### 1. TCP vs. UDP Scanning

- **TCP Connect Scan (`SOCK_STREAM`)**:
  - Establishes a full TCP three-way handshake (`SYN` $\rightarrow$ `SYN/ACK` $\rightarrow$ `ACK`) via `s.connect_ex()`.
  - A return code of `0` confirms the port is **`OPEN`**.
  - Connection refused or timeout flags the port as closed or inaccessible.

- **UDP Probing (`SOCK_DGRAM`)**:
  - UDP is connectionless; it does not perform a handshake. The scanner transmits a minimal probe (a valid DNS payload for port 53, or `b"\x00"` for generic ports).
  - **`OPEN`**: The target service returns a valid UDP response datagram.
  - **`CLOSED`**: The target OS or gateway returns an ICMP Port Unreachable packet (detected via `ConnectionResetError` / `WSAECONNRESET` 10054 on Windows or `ECONNREFUSED` 111 on Linux).
  - **`OPEN|FILTERED`**: No response is received before timeout expiration. The packet was either dropped by a firewall or accepted silently without an initial reply.

### 2. Fast vs. Detailed TCP Scan Modes

- **Fast TCP Connect Scan**:
  - Executes connectivity check and resolves standard service names from the IANA database.
  - Skips banner grabbing, allowing high-throughput auditing.
- **Detailed TCP Scan**:
  - Executes connectivity check and service name lookup.
  - Opens a secondary socket connection to open ports to capture initial service greeting banners (capturing up to 1024 bytes with a 1.0s timeout), aiding in service fingerprinting.

---

## 📊 Reports & Output Files

Every completed scan produces two persistent output artifacts in the current working directory:

### 1. Text Summary (`scan_report.txt`)
A formatted ASCII report recording:
- Target hostname and resolved IP address.
- Configured scan profile, protocol, workers, and timeout values.
- Protocol state counters (`TCP Open`, `UDP Open`, `UDP Closed`, `UDP Open|Filtered`).
- Elapsed scan duration.
- Aligned table of all scanned ports with protocol, state, service, and banner columns.

### 2. CSV Export (`scan_results.csv`)
An Excel-compatible, RFC 4180 CSV file designed for automated ingestion:
- Header metadata lines prefixed with `#`.
- Comma-delimited rows with columns:
  ```csv
  Protocol,Port,State,Service,Banner
  TCP,135,OPEN,epmap,N/A
  TCP,445,OPEN,microsoft-ds,N/A
  ```

---

## 🖥️ Example Terminal Output

### Detailed TCP Scan on Localhost
```text
[*] Target IP       : 127.0.0.1
[*] Scan Profile   : Quick Scan
[*] Protocol(s)    : TCP
[*] Port Range     : Common Ports (24 ports)
[*] Total Checks   : 24
[*] TCP Scan Mode  : Detailed TCP Scan
[*] TCP Timeout    : 0.5 seconds
[*] Banner Timeout : 1.0 seconds
[*] Workers        : 50
[*] Scanning started...

[*] Progress: 24/24 checks (100.0%)

PROTO  PORT     STATE           SERVICE        BANNER
TCP    135      OPEN            epmap          No banner
TCP    445      OPEN            microsoft-ds   No banner

=============================================
                SCAN SUMMARY                 
=============================================
 Target Host     : 127.0.0.1
 Scan Profile    : Quick Scan
 Protocol(s)     : TCP
 Scanned Ports   : Common Ports (24 ports)
 Total Checks    : 24
 TCP Open        : 2
 Open Port List  : TCP:135 (epmap), TCP:445 (microsoft-ds)
 Time Elapsed    : 0.58 seconds
=============================================

[+] Report saved to scan_report.txt
[+] CSV report saved to scan_results.csv
```

---

## 🧪 Testing & Validation

All core features and scan profiles were systematically validated in a local Windows environment:

- **Quick Scan (`127.0.0.1`)**: Validated against common administrative ports; completed in under 1 second.
- **Standard Scan (Ports 1–1024)**: Verified multithreaded scanning of 1,024 ports across 50 workers; detected local Windows RPC/SMB services (`135`, `445`, `902`, `912`).
- **Full Scan (Ports 1–65535)**: Verified comprehensive scan of all 65,535 TCP ports; located high-numbered dynamic service endpoints (`49664`–`60684`).
- **Custom Scan**: Tested single-port checks (`53`, `8080`) and narrow custom ranges (`1-20`).
- **UDP Scans**: Verified connectionless response handling, ICMP unreachable error handling (`CLOSED`), and silent port categorization (`OPEN|FILTERED`).
- **Terminal Flood Suppression**: Confirmed that large UDP scans (such as Full 1–65535) cleanly summarize filtered ports without overwhelming the terminal buffer.

---

## ⚠️ Known Technical Limitations

1. **UDP Ambiguity (`OPEN|FILTERED`)**: Due to the connectionless nature of UDP, services that do not return an unsolicited greeting upon probe arrival cannot be distinguished from firewall packet drops without protocol-specific handshakes.
2. **Full-Scan Duration**: Scanning all 65,535 ports requires waiting for network round-trips and socket timeouts. While 50 concurrent worker threads accelerate the process, full scans naturally take longer (several minutes depending on network conditions).
3. **Opportunistic Banner Grabbing**: Many modern services (such as HTTP/HTTPS servers) wait for a valid client request header before returning data. The generic banner grabber will report `No banner` for services that require specific application-layer negotiation.

---

## 📁 Project Structure

```text
network-scanner/
├── scanner.py          # Core multithreaded port scanner CLI application
├── README.md           # Project documentation and technical reference
├── scan_report.txt     # Formatted text report generated after scan completion
└── scan_results.csv    # Structured CSV data export generated after scan completion
```
