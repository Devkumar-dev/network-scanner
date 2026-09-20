import csv
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple


# List of common TCP/UDP ports for Quick Scan profile
COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 3306,
    3389, 5432, 5900, 6379, 8080, 8443
]


def is_port_open(target_ip: str, port: int, timeout: float = 0.5) -> bool:
    """
    Checks if a single TCP port is open using a TCP 3-way handshake.
    Returns True if the connection succeeds, False otherwise.
    Guarantees socket closure in all circumstances.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        # connect_ex returns 0 if the TCP handshake succeeds
        return s.connect_ex((target_ip, port)) == 0
    except (socket.timeout, socket.error):
        return False
    except Exception:
        return False
    finally:
        s.close()


def scan_udp_port(
    target_ip: str, port: int, timeout: float = 1.0
) -> Tuple[str, int, str, str, str]:
    """
    Dedicated UDP scanning function.
    Handles UDP's connectionless behavior:
    - If a valid response is received: classifies the port as 'OPEN'.
    - If an ICMP 'port unreachable' error is detected: classifies as 'CLOSED'.
    - If no response is received before timeout: classifies as 'OPEN|FILTERED'
      (the packet was either dropped by a firewall or accepted silently).
    Returns tuple: ('UDP', port, state, service, 'N/A')
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    state = "OPEN|FILTERED"
    try:
        # Send minimal probe: valid DNS header query for port 53, single byte for others
        if port == 53:
            probe = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        else:
            probe = b"\x00"

        s.sendto(probe, (target_ip, port))
        data, _ = s.recvfrom(1024)
        # A valid UDP response was received from the remote service
        state = "OPEN"
    except socket.timeout:
        # No response before timeout: packet dropped by firewall or accepted silently
        state = "OPEN|FILTERED"
    except (ConnectionResetError, ConnectionRefusedError):
        # Detectable ICMP Port Unreachable error received from remote system
        state = "CLOSED"
    except socket.error as err:
        # On Windows, WSAECONNRESET (10054) or WSAECONNREFUSED (10061) indicates ICMP Port Unreachable
        # On Linux, ECONNREFUSED (111) indicates ICMP Port Unreachable
        if getattr(err, "winerror", None) in (10054, 10061) or getattr(err, "errno", None) in (10054, 111):
            state = "CLOSED"
        else:
            # Other socket errors (e.g. host unreachable or permission drops) are not confirmed closed
            state = "OPEN|FILTERED"
    except Exception:
        # Catch unexpected exceptions to ensure worker thread does not crash
        state = "OPEN|FILTERED"
    finally:
        s.close()

    service = get_service_name(port, "udp")
    return ("UDP", port, state, service, "N/A")


def get_service_name(port: int, proto: str = "tcp") -> str:
    """
    Looks up the standard IANA service name for a given port and protocol ('tcp' or 'udp')
    using socket.getservbyport. Returns 'unknown' if no mapping exists or on error.
    """
    try:
        return socket.getservbyport(port, proto.lower())
    except (OSError, socket.error):
        return "unknown"
    except Exception:
        return "unknown"


def grab_banner(target_ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Connects to an open TCP port and attempts to capture an initial service greeting/banner.
    Returns the decoded banner string, or 'No banner' if none received or on error.
    Guarantees socket closure in all execution paths.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target_ip, port))
        data = s.recv(1024)
        if data:
            banner = data.decode("utf-8", errors="ignore").strip()
            return banner if banner else "No banner"
        return "No banner"
    except (socket.timeout, socket.error):
        return "No banner"
    except Exception:
        return "No banner"
    finally:
        s.close()


def scan_tcp_port(
    target_ip: str,
    port: int,
    port_timeout: float = 0.5,
    banner_timeout: float = 1.0,
    grab_banners: bool = True,
) -> Optional[Tuple[str, int, str, str, str]]:
    """
    Worker function to test a TCP port.
    Returns ('TCP', port, 'OPEN', service, banner) if open, or None if closed.
    Safeguarded against unhandled exceptions to prevent terminating the scan.
    """
    try:
        if is_port_open(target_ip, port, timeout=port_timeout):
            service = get_service_name(port, "tcp")
            if grab_banners:
                banner = grab_banner(target_ip, port, timeout=banner_timeout)
            else:
                banner = "N/A"
            return ("TCP", port, "OPEN", service, banner)
        return None
    except Exception:
        return None


def parse_port_range(range_str: str) -> Optional[Tuple[int, int]]:
    """
    Parses a string like '1-1024' or '80' into (start_port, end_port).
    Returns (start_port, end_port) tuple or None if invalid.
    """
    range_str = range_str.strip()
    if not range_str:
        return (1, 1024)

    if "-" in range_str:
        parts = range_str.split("-", 1)
        try:
            start = int(parts[0].strip())
            end = int(parts[1].strip())
        except ValueError:
            return None
    else:
        try:
            start = end = int(range_str)
        except ValueError:
            return None

    if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
        return (start, end)
    return None


def validate_and_resolve_target(
    target_input: str,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """
    Validates the target as an IPv4 address or resolvable hostname.
    Returns tuple: (is_valid, resolved_ip, hostname_or_none, error_message)
    """
    target_str = target_input.strip()
    if not target_str:
        target_str = "127.0.0.1"

    # 1. Check if input is a valid IPv4 address
    try:
        ip_obj = ipaddress.IPv4Address(target_str)
        return (True, str(ip_obj), None, None)
    except ipaddress.AddressValueError:
        pass

    # 2. Check if input is an IPv6 address (only IPv4 supported)
    try:
        ipaddress.IPv6Address(target_str)
        return (
            False,
            None,
            None,
            "[-] Error: Invalid target. Please enter a valid IPv4 address or resolvable hostname.",
        )
    except ipaddress.AddressValueError:
        pass

    # 3. Attempt DNS resolution for hostname
    try:
        resolved_ip = socket.gethostbyname(target_str)
        return (True, resolved_ip, target_str, None)
    except socket.gaierror:
        return (
            False,
            None,
            target_str,
            "[-] Error: Could not resolve target hostname.",
        )
    except Exception:
        return (
            False,
            None,
            target_str,
            "[-] Error: Invalid target. Please enter a valid IPv4 address or resolvable hostname.",
        )


def save_report(
    target_ip: str,
    target_hostname: Optional[str],
    profile_name: str,
    proto_label: str,
    port_range_desc: str,
    total_checks: int,
    scan_mode: str,
    workers: int,
    tcp_timeout_display: str,
    udp_timeout_display: str,
    banner_timeout_display: str,
    scan_results: List[Tuple[str, int, str, str, str]],
    udp_counts: Dict[str, int],
    elapsed_time: float,
) -> None:
    """
    Saves the completed scan results, settings, and summary to scan_report.txt.
    """
    try:
        with open("scan_report.txt", "w", encoding="utf-8") as f:
            f.write("=" * 68 + "\n")
            f.write("                     NETWORK SCAN REPORT\n")
            f.write("=" * 68 + "\n\n")
            if target_hostname:
                f.write(f"Target Hostname     : {target_hostname}\n")
                f.write(f"Resolved IP         : {target_ip}\n")
            else:
                f.write(f"Target IP           : {target_ip}\n")
            f.write(f"Scan Profile        : {profile_name}\n")
            f.write(f"Protocol(s)         : {proto_label}\n")
            f.write(f"Scanned Port Range  : {port_range_desc}\n")
            f.write(f"Total Port Checks   : {total_checks}\n")
            f.write(f"TCP Scan Mode       : {scan_mode}\n")
            f.write(f"Worker Threads      : {workers}\n")
            f.write(f"TCP Port Timeout    : {tcp_timeout_display}\n")
            f.write(f"UDP Port Timeout    : {udp_timeout_display}\n")
            f.write(f"Banner Timeout      : {banner_timeout_display}\n")
            if "TCP" in proto_label:
                tcp_open_count = sum(1 for r in scan_results if r[0] == "TCP" and r[2] == "OPEN")
                f.write(f"TCP Open Ports Found: {tcp_open_count}\n")
            if "UDP" in proto_label:
                f.write("UDP State Summary   :\n")
                f.write(f"  - Open            : {udp_counts['open']}\n")
                f.write(f"  - Closed          : {udp_counts['closed']}\n")
                f.write(f"  - Open|Filtered   : {udp_counts['filtered']}\n")
            f.write(f"Total Elapsed Time  : {elapsed_time:.2f} seconds\n\n")
            f.write("-" * 68 + "\n")
            f.write(f"{'PROTO':<6} {'PORT':<8} {'STATE':<15} {'SERVICE':<14} {'BANNER'}\n")
            f.write("-" * 68 + "\n")
            if scan_results:
                for proto, port, state, service, banner in scan_results:
                    f.write(f"{proto:<6} {port:<8} {state:<15} {service:<14} {banner}\n")
            else:
                f.write("No open ports found.\n")
            f.write("=" * 68 + "\n")
        print("[+] Report saved to scan_report.txt")
    except Exception as err:
        print(f"[-] Error: Could not save report to scan_report.txt ({err})")


def save_csv_report(
    target_ip: str,
    target_hostname: Optional[str],
    profile_name: str,
    proto_label: str,
    port_range_desc: str,
    scan_mode: str,
    workers: int,
    tcp_timeout_display: str,
    udp_timeout_display: str,
    banner_timeout_display: str,
    scan_results: List[Tuple[str, int, str, str, str]],
    udp_counts: Dict[str, int],
    filename: str = "scan_results.csv",
) -> None:
    """
    Saves scan results to a clean, Excel-compatible CSV file with columns:
    Protocol, Port, State, Service, Banner. Includes metadata header comments at the top.
    """
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            if target_hostname:
                f.write(f"# Target Hostname: {target_hostname}\n")
                f.write(f"# Resolved IP: {target_ip}\n")
            else:
                f.write(f"# Target: {target_ip}\n")
            f.write(f"# Scan Profile: {profile_name}\n")
            f.write(f"# Protocol(s): {proto_label}\n")
            f.write(f"# Port Range: {port_range_desc}\n")
            f.write(f"# TCP Scan Mode: {scan_mode}\n")
            f.write(f"# Workers: {workers}\n")
            f.write(f"# TCP Timeout: {tcp_timeout_display}\n")
            f.write(f"# UDP Timeout: {udp_timeout_display}\n")
            f.write(f"# Banner Timeout: {banner_timeout_display}\n")
            if "TCP" in proto_label:
                tcp_open_count = sum(1 for r in scan_results if r[0] == "TCP" and r[2] == "OPEN")
                f.write(f"# TCP Open Ports: {tcp_open_count}\n")
            if "UDP" in proto_label:
                f.write(
                    f"# UDP States: Open={udp_counts['open']}, Closed={udp_counts['closed']}, Open|Filtered={udp_counts['filtered']}\n"
                )

            writer = csv.writer(f)
            writer.writerow(["Protocol", "Port", "State", "Service", "Banner"])

            for proto, port, state, service, banner in scan_results:
                writer.writerow([proto, port, state, service, banner])

        print(f"[+] CSV report saved to {filename}")
    except Exception as err:
        print(f"[-] Error: Could not save CSV report to {filename} ({err})")


def main() -> None:
    print("Network Scanner - Concurrent Multi-Port Scan")
    print("============================================")

    while True:
        # 1. Scan profile menu selection (before target/port configuration)
        print("\n[1] Quick Scan - common TCP/UDP ports")
        print("[2] Standard Scan - ports 1-1024")
        print("[3] Full Scan - ports 1-65535")
        print("[4] Custom Scan - user enters a port or range")
        profile_input = input("Enter scan profile [1]: ").strip()

        if not profile_input or profile_input == "1":
            profile_name = "Quick Scan"
            ports_to_scan = list(COMMON_PORTS)
            port_range_desc = "Common Ports"
        elif profile_input == "2":
            profile_name = "Standard Scan"
            ports_to_scan = list(range(1, 1025))
            port_range_desc = "1 - 1024"
        elif profile_input == "3":
            profile_name = "Full Scan"
            ports_to_scan = list(range(1, 65536))
            port_range_desc = "1 - 65535"
        elif profile_input == "4":
            profile_name = "Custom Scan"
            ports_to_scan = None
            port_range_desc = ""
        else:
            print("[-] Invalid scan profile. Defaulting to [1] Quick Scan.")
            profile_name = "Quick Scan"
            ports_to_scan = list(COMMON_PORTS)
            port_range_desc = "Common Ports"

        # 2. Target IP or hostname configuration with validation
        target_input = input("\nEnter target IP or hostname [127.0.0.1]: ").strip()
        is_valid, target_ip, target_hostname, error_msg = validate_and_resolve_target(
            target_input
        )

        if not is_valid:
            print(error_msg)
            print("[*] Returning to menu...\n")
            continue

        # If Custom Scan was selected, prompt for port or range using parse_port_range
        if profile_name == "Custom Scan":
            port_range_input = input(
                "Enter port range (e.g. 1-1024) [1-1024]: "
            ).strip()
            parsed_range = parse_port_range(port_range_input)
            if not parsed_range:
                print(
                    "[-] Error: Invalid port range. Ports must be between 1 and 65535 with start <= end."
                )
                print("[*] Returning to menu...\n")
                continue
            start_port, end_port = parsed_range
            ports_to_scan = list(range(start_port, end_port + 1))
            port_range_desc = f"{start_port} - {end_port}"

        # 3. Protocol selection menu
        print("\n[1] TCP Scan")
        print("[2] UDP Scan")
        print("[3] TCP + UDP Scan")
        proto_choice = input("Enter protocol [1]: ").strip()

        if not proto_choice or proto_choice == "1":
            proto_label = "TCP"
            scan_tcp = True
            scan_udp = False
        elif proto_choice == "2":
            proto_label = "UDP"
            scan_tcp = False
            scan_udp = True
        elif proto_choice == "3":
            proto_label = "TCP + UDP"
            scan_tcp = True
            scan_udp = True
        else:
            print("[-] Invalid protocol choice. Defaulting to [1] TCP Scan.")
            proto_label = "TCP"
            scan_tcp = True
            scan_udp = False

        # 4. Scan mode menu selection (Fast vs Detailed for TCP)
        if scan_tcp:
            print("\n[1] Fast TCP Connect Scan")
            print("[2] Detailed TCP Scan")
            mode_input = input("Enter scan mode [1]: ").strip()
            if not mode_input or mode_input == "1":
                scan_mode_name = "Fast TCP Connect Scan"
                grab_banners = False
            elif mode_input == "2":
                scan_mode_name = "Detailed TCP Scan"
                grab_banners = True
            else:
                print("[-] Invalid scan mode. Defaulting to mode 1 (Fast TCP Connect Scan).")
                scan_mode_name = "Fast TCP Connect Scan"
                grab_banners = False
        else:
            scan_mode_name = "N/A (UDP Scan)"
            grab_banners = False

        # 5. Worker threads input (default: 50, range: 1-200)
        workers_input = input("\nEnter worker threads (1-200) [50]: ").strip()
        if not workers_input:
            workers = 50
        else:
            try:
                workers = int(workers_input)
                if not (1 <= workers <= 200):
                    print("[-] Invalid worker count (must be 1-200). Defaulting to 50.")
                    workers = 50
            except ValueError:
                print("[-] Invalid input for worker threads. Defaulting to 50.")
                workers = 50

        # 6. Timeout inputs
        # TCP connection timeout
        if scan_tcp:
            timeout_input = input("Enter TCP connection timeout in seconds [0.5]: ").strip()
            if not timeout_input:
                port_timeout = 0.5
            else:
                try:
                    port_timeout = float(timeout_input)
                    if port_timeout <= 0:
                        print("[-] Timeout must be a positive numeric value. Defaulting to 0.5s.")
                        port_timeout = 0.5
                except ValueError:
                    print("[-] Invalid input for TCP timeout. Defaulting to 0.5s.")
                    port_timeout = 0.5
            tcp_timeout_display = f"{port_timeout} seconds"
        else:
            port_timeout = 0.5
            tcp_timeout_display = "N/A"

        # UDP timeout (default: 1.0 second)
        if scan_udp:
            udp_input = input("Enter UDP timeout in seconds [1.0]: ").strip()
            if not udp_input:
                udp_timeout = 1.0
            else:
                try:
                    udp_timeout = float(udp_input)
                    if udp_timeout <= 0:
                        print("[-] Timeout must be a positive numeric value. Defaulting to 1.0s.")
                        udp_timeout = 1.0
                except ValueError:
                    print("[-] Invalid input for UDP timeout. Defaulting to 1.0s.")
                    udp_timeout = 1.0
            udp_timeout_display = f"{udp_timeout} seconds"
        else:
            udp_timeout = 1.0
            udp_timeout_display = "N/A"

        banner_timeout = 1.0
        banner_timeout_display = (
            f"{banner_timeout} seconds" if (scan_tcp and grab_banners) else "N/A"
        )

        # Build execution tasks list
        tasks: List[Tuple[str, int]] = []
        if scan_tcp:
            for p in ports_to_scan:
                tasks.append(("TCP", p))
        if scan_udp:
            for p in ports_to_scan:
                tasks.append(("UDP", p))

        total_checks = len(tasks)

        # Display selected scan configuration
        if target_hostname:
            print(f"\n[*] Target Hostname : {target_hostname}")
            print(f"[*] Resolved IP     : {target_ip}")
        else:
            print(f"\n[*] Target IP       : {target_ip}")
        print(f"[*] Scan Profile   : {profile_name}")
        print(f"[*] Protocol(s)    : {proto_label}")
        print(f"[*] Port Range     : {port_range_desc} ({len(ports_to_scan)} ports)")
        print(f"[*] Total Checks   : {total_checks}")
        if scan_tcp:
            print(f"[*] TCP Scan Mode  : {scan_mode_name}")
            print(f"[*] TCP Timeout    : {tcp_timeout_display}")
            print(f"[*] Banner Timeout : {banner_timeout_display}")
        if scan_udp:
            print(f"[*] UDP Timeout    : {udp_timeout_display}")
        print(f"[*] Workers        : {workers}")
        print(f"[*] Scanning started...\n")

        start_time = time.time()
        scan_results: List[Tuple[str, int, str, str, str]] = []
        completed = 0

        # 7. Concurrent port scanning using ThreadPoolExecutor with real-time progress
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for proto, port in tasks:
                if proto == "TCP":
                    f = executor.submit(
                        scan_tcp_port,
                        target_ip,
                        port,
                        port_timeout,
                        banner_timeout,
                        grab_banners,
                    )
                else:
                    f = executor.submit(
                        scan_udp_port,
                        target_ip,
                        port,
                        udp_timeout,
                    )
                futures.append(f)

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        scan_results.append(result)
                except Exception:
                    # Defensive guard: one failing task does not terminate scan
                    pass
                completed += 1
                percent = (completed / total_checks) * 100 if total_checks else 100.0
                print(
                    f"\r[*] Progress: {completed}/{total_checks} checks ({percent:.1f}%)",
                    end="",
                    flush=True,
                )

        # Print newline after progress indicator so the results table begins cleanly
        print("\n")

        # Sort results numerically by port, then by protocol (TCP first)
        scan_results.sort(key=lambda x: (x[1], x[0]))

        # Calculate UDP state counts
        udp_counts = {
            "open": sum(1 for r in scan_results if r[0] == "UDP" and r[2] == "OPEN"),
            "closed": sum(1 for r in scan_results if r[0] == "UDP" and r[2] == "CLOSED"),
            "filtered": sum(1 for r in scan_results if r[0] == "UDP" and r[2] == "OPEN|FILTERED"),
        }
        tcp_open_count = sum(1 for r in scan_results if r[0] == "TCP" and r[2] == "OPEN")

        # Determine if this is a small scan (<= 50 ports) or a large scan
        is_small_scan = len(ports_to_scan) <= 50

        # Filter results for terminal display:
        # - Always display TCP OPEN results
        # - Always display UDP OPEN results
        # - Display UDP CLOSED results only for small/custom scans
        # - Display UDP OPEN|FILTERED results only for small/custom scans (suppressed during large scans)
        terminal_results = []
        for proto, port, state, service, banner in scan_results:
            if proto == "TCP":
                if state == "OPEN":
                    terminal_results.append((proto, port, state, service, banner))
            elif proto == "UDP":
                if state == "OPEN":
                    terminal_results.append((proto, port, state, service, banner))
                elif state == "CLOSED":
                    if is_small_scan:
                        terminal_results.append((proto, port, state, service, banner))
                elif state == "OPEN|FILTERED":
                    if is_small_scan:
                        terminal_results.append((proto, port, state, service, banner))

        # Display filtered results in tabular format with PROTO, PORT, STATE, SERVICE, BANNER
        if terminal_results:
            print(f"{'PROTO':<6} {'PORT':<8} {'STATE':<15} {'SERVICE':<14} {'BANNER'}")
            for proto, port, state, service, banner in terminal_results:
                print(f"{proto:<6} {port:<8} {state:<15} {service:<14} {banner}")
        else:
            print("No open ports found.")

        # For large scans, show a concise message for suppressed UDP ports
        if scan_udp and not is_small_scan:
            if udp_counts["filtered"] > 0:
                print(f"\n[*] UDP OPEN|FILTERED results suppressed from terminal: {udp_counts['filtered']:,} ports")
            if udp_counts["closed"] > 0:
                print(f"[*] UDP CLOSED results suppressed from terminal: {udp_counts['closed']:,} ports")
            print("[*] Full details for all scanned ports are saved in scan_report.txt and scan_results.csv")

        elapsed_time = time.time() - start_time

        # 8. Final summary
        print("\n" + "=" * 45)
        print("                SCAN SUMMARY                 ")
        print("=" * 45)
        if target_hostname:
            print(f" Target Hostname : {target_hostname}")
            print(f" Resolved IP     : {target_ip}")
        else:
            print(f" Target Host     : {target_ip}")
        print(f" Scan Profile    : {profile_name}")
        print(f" Protocol(s)     : {proto_label}")
        print(f" Scanned Ports   : {port_range_desc} ({len(ports_to_scan)} ports)")
        print(f" Total Checks    : {total_checks}")

        if scan_tcp:
            print(f" TCP Open        : {tcp_open_count}")
        if scan_udp:
            print(f" UDP Open        : {udp_counts['open']}")
            print(f" UDP Closed      : {udp_counts['closed']}")
            print(f" UDP Open|Filtered: {udp_counts['filtered']}")

        # Open Port List formatting
        if is_small_scan:
            # Small / custom scan: show all open and open|filtered ports
            open_or_responsive = [
                r for r in scan_results if r[2] in ("OPEN", "OPEN|FILTERED")
            ]
            if open_or_responsive:
                port_list_str = ", ".join(
                    f"{proto}:{port} ({service})"
                    if state == "OPEN"
                    else f"{proto}:{port} [{state}] ({service})"
                    for proto, port, state, service, banner in open_or_responsive
                )
                print(f" Open Port List  : {port_list_str}")
            else:
                print(" Open Port List  : None")
        else:
            # Large scan: display confirmed OPEN ports to avoid flooding terminal
            confirmed_open = [r for r in scan_results if r[2] == "OPEN"]
            if confirmed_open:
                port_list_str = ", ".join(
                    f"{proto}:{port} ({service})"
                    for proto, port, state, service, banner in confirmed_open
                )
                print(f" Open Port List  : {port_list_str}")
            else:
                if scan_udp and udp_counts["filtered"] > 0:
                    print(f" Open Port List  : None confirmed open ({udp_counts['filtered']:,} ports in OPEN|FILTERED state)")
                else:
                    print(" Open Port List  : None")

        print(f" Time Elapsed    : {elapsed_time:.2f} seconds")
        print("=" * 45 + "\n")

        # 9. Save results to scan_report.txt
        save_report(
            target_ip,
            target_hostname,
            profile_name,
            proto_label,
            port_range_desc,
            total_checks,
            scan_mode_name,
            workers,
            tcp_timeout_display,
            udp_timeout_display,
            banner_timeout_display,
            scan_results,
            udp_counts,
            elapsed_time,
        )

        # 10. Save results to scan_results.csv
        save_csv_report(
            target_ip,
            target_hostname,
            profile_name,
            proto_label,
            port_range_desc,
            scan_mode_name,
            workers,
            tcp_timeout_display,
            udp_timeout_display,
            banner_timeout_display,
            scan_results,
            udp_counts,
        )

        break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Scan cancelled by user. Exiting...\n")
