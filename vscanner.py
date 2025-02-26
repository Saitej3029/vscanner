#!/usr/bin/env python3
import subprocess
import time
import xml.etree.ElementTree as ET
import sys

def run_scan(scan_name, command):
    """
    Execute an Nmap command with a 30-second timeout.
    The XML output is captured and returned (without saving to a file).
    """
    print(f"\n--- Running: {scan_name} ---", flush=True)
    print("Command: " + " ".join(command), flush=True)
    try:
        start_time = time.time()
        result = subprocess.run(
            command, capture_output=True, text=True, check=True, timeout=30
        )
        elapsed = time.time() - start_time
        print(f"Scan completed in {elapsed:.2f} seconds.", flush=True)
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"Scan '{scan_name}' exceeded 30 seconds. Skipping to next scan.", flush=True)
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error running '{scan_name}': {e.stderr}", file=sys.stderr, flush=True)
        return None

def parse_and_print(xml_output):
    """
    Parse Nmap XML output and print a summary in plain language.
    """
    if not xml_output:
        print("No output received from this scan.", flush=True)
        return

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        print("Error parsing XML output:", e, flush=True)
        return

    hosts = root.findall('host')
    if not hosts:
        print("No hosts detected in the scan results.", flush=True)
    for host in hosts:
        # Get the target's IP address
        addr_elem = host.find('address')
        ip = addr_elem.attrib.get('addr', "Unknown") if addr_elem is not None else "Unknown"
        # Get the host status (e.g., up or down)
        status_elem = host.find('status')
        status = status_elem.attrib.get('state', "unknown") if status_elem is not None else "unknown"
        print(f"Target {ip} is {status}.", flush=True)
        # Print port information, if available
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_id = port.attrib.get('portid', "unknown")
                protocol = port.attrib.get('protocol', "unknown")
                state_elem = port.find('state')
                port_state = state_elem.attrib.get('state', "unknown") if state_elem is not None else "unknown"
                service_elem = port.find('service')
                service = service_elem.attrib.get('name', "unknown") if service_elem is not None else "unknown"
                print(f" - Port {port_id}/{protocol} is {port_state} and running {service}.", flush=True)
        else:
            print(" - No open ports found.", flush=True)

def main():
    target = input("Enter the target IP address or hostname: ").strip()
    if not target:
        print("Target cannot be empty. Exiting.", flush=True)
        sys.exit(1)

    # List of scans to run (each using XML output to stdout)
    scans = [
        ("Ping Scan (Host Discovery)", ["nmap", "-sn", "-oX", "-", target]),
        ("TCP SYN Scan (Port Scanning)", ["nmap", "-sS", "-oX", "-", target]),
        ("Service Version Detection", ["nmap", "-sV", "-oX", "-", target]),
        ("OS Detection", ["nmap", "-O", "-oX", "-", target]),
        ("Vulnerability Scan (Vuln Scripts)", ["nmap", "--script", "vuln", "-oX", "-", target]),
        ("Comprehensive Scan (Aggressive Mode)", ["nmap", "-A", "-oX", "-", target])
    ]

    print(f"\nStarting scans on target: {target}", flush=True)

    for scan_name, command in scans:
        xml_output = run_scan(scan_name, command)
        print("\nResults:", flush=True)
        parse_and_print(xml_output)
        print("-" * 50, flush=True)
    
    print("\nAll scans completed. Exiting.", flush=True)

if __name__ == "__main__":
    main()
