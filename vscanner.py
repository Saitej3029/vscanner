#!/usr/bin/env python3
import subprocess
import time
import xml.etree.ElementTree as ET
import sys

def run_scan(scan_name, command):
    """
    Execute an Nmap command with a 30-second timeout.
    If the scan doesn't finish within 30 seconds, abort and return None.
    """
    print(f"\n=== {scan_name} ===", flush=True)
    print("Command: " + " ".join(command), flush=True)
    try:
        start_time = time.time()
        result = subprocess.run(
            command, capture_output=True, text=True, check=True, timeout=30
        )
        elapsed = time.time() - start_time
        print(f"Scan finished in {elapsed:.2f} seconds.", flush=True)
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"Scan '{scan_name}' took longer than 30 seconds. Aborting and moving to next scan.", flush=True)
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error running '{scan_name}': {e.stderr}", file=sys.stderr, flush=True)
        return None

def parse_and_print(xml_output):
    """
    Parse the XML output from Nmap and print a summary of hosts and ports.
    """
    if xml_output is None:
        return

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        print("Error parsing XML:", e, file=sys.stderr, flush=True)
        return

    for host in root.findall('host'):
        addr_elem = host.find('address')
        ip = addr_elem.attrib.get('addr') if addr_elem is not None else "Unknown"
        status_elem = host.find('status')
        state = status_elem.attrib.get('state') if status_elem is not None else "unknown"
        print(f"Host: {ip} (Status: {state})", flush=True)
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_id = port.attrib.get('portid')
                protocol = port.attrib.get('protocol')
                state_elem = port.find('state')
                port_state = state_elem.attrib.get('state') if state_elem is not None else "unknown"
                service_elem = port.find('service')
                service = service_elem.attrib.get('name') if service_elem is not None else "unknown"
                print(f"  Port {port_id}/{protocol}: {port_state} (Service: {service})", flush=True)
        else:
            print("  No ports found.", flush=True)

def main():
    target = input("Enter the target IP address or hostname: ").strip()
    if not target:
        print("Target cannot be empty. Exiting.", flush=True)
        sys.exit(1)

    # Define the scans to run once.
    scans = [
        ("Ping Scan (Host Discovery)", ["nmap", "-sn", "-oX", "-", target]),
        ("TCP SYN Scan (Port Scanning)", ["nmap", "-sS", "-oX", "-", target]),
        ("Service Version Detection", ["nmap", "-sV", "-oX", "-", target]),
        ("OS Detection", ["nmap", "-O", "-oX", "-", target]),
        ("Vulnerability Scan (Vuln Scripts)", ["nmap", "--script", "vuln", "-oX", "-", target]),
        ("Comprehensive Scan (Aggressive Mode)", ["nmap", "-A", "-oX", "-", target])
    ]

    print("\nStarting scans on target:", target, flush=True)

    # Run each scan one time.
    for scan_name, command in scans:
        xml_output = run_scan(scan_name, command)
        parse_and_print(xml_output)
        print("\n", flush=True)

    print("All scans completed. Exiting.", flush=True)

if __name__ == "__main__":
    main()
