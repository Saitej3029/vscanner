#!/usr/bin/env python3
import subprocess
import time
import xml.etree.ElementTree as ET
import sys

def run_scan(scan_name, command):
    """
    Execute an Nmap command, measure its execution time,
    and return the XML output.
    """
    print(f"\n=== {scan_name} ===")
    print("Command: " + " ".join(command))
    start_time = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        xml_output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running {scan_name}: {e.stderr}", file=sys.stderr)
        xml_output = None
    end_time = time.time()
    elapsed = end_time - start_time

    # If the scan finishes before 30 seconds, proceed immediately.
    if elapsed < 30:
        print(f"Scan finished in {elapsed:.2f} seconds. Proceeding to next scan immediately.")
    else:
        print(f"Scan took {elapsed:.2f} seconds.")
    return xml_output

def parse_and_print(xml_output):
    """
    Parse the XML output from Nmap and print a summary of hosts and ports.
    """
    if xml_output is None:
        return

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        print("Error parsing XML:", e, file=sys.stderr)
        return

    for host in root.findall('host'):
        addr_elem = host.find('address')
        ip = addr_elem.attrib.get('addr') if addr_elem is not None else "Unknown"
        status_elem = host.find('status')
        state = status_elem.attrib.get('state') if status_elem is not None else "unknown"
        print(f"Host: {ip} (Status: {state})")

        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_id = port.attrib.get('portid')
                protocol = port.attrib.get('protocol')
                state_elem = port.find('state')
                port_state = state_elem.attrib.get('state') if state_elem is not None else "unknown"
                service_elem = port.find('service')
                service = service_elem.attrib.get('name') if service_elem is not None else "unknown"
                print(f"  Port {port_id}/{protocol}: {port_state} (Service: {service})")
        else:
            print("  No ports found.")

def main():
    target = input("Enter the target IP address or hostname: ").strip()
    if not target:
        print("Target cannot be empty. Exiting.")
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

    print("\nStarting scans on target:", target)

    # Run each scan one time.
    for scan_name, command in scans:
        xml_output = run_scan(scan_name, command)
        parse_and_print(xml_output)

    print("\nAll scans completed. Exiting.")

if __name__ == "__main__":
    main()
