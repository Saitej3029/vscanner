#!/usr/bin/env python3
import subprocess
import time
import xml.etree.ElementTree as ET
import sys
import re
import shutil

def validate_target(target):
    """Validate if target is a valid IP or hostname."""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    
    if re.match(ip_pattern, target):
        return all(0 <= int(octet) <= 255 for octet in target.split('.')) and target
    elif re.match(hostname_pattern, target):
        return target
    return None

def check_nmap_installed():
    """Check if Nmap is installed."""
    return shutil.which("nmap") is not None

def run_scan(scan_name, command):
    """Execute an Nmap command and return XML output."""
    timeout = 30
    print(f"\n--- Running: {scan_name} ---")
    print("Command: " + " ".join(command))
    try:
        start_time = time.time()
        result = subprocess.run(
            command, capture_output=True, text=True, check=True, timeout=timeout
        )
        elapsed = time.time() - start_time
        print(f"Scan completed in {elapsed:.2f} seconds.")
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"Scan '{scan_name}' exceeded {timeout} seconds. Skipping.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error running '{scan_name}': {e.stderr}", file=sys.stderr)
        return None

def parse_and_print(xml_output):
    """Parse Nmap XML output and print results instantly."""
    if not xml_output:
        print("No output received from this scan.")
        return

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        print("Error parsing XML output:", e)
        return

    hosts = root.findall('host')
    if not hosts:
        print("No hosts detected in the scan results.")
        return

    for host in hosts:
        addr_elem = host.find('address')
        ip = addr_elem.attrib.get('addr', "Unknown") if addr_elem is not None else "Unknown"
        status_elem = host.find('status')
        status = status_elem.attrib.get('state', "unknown") if status_elem is not None else "unknown"
        print(f"Target {ip} is {status}.")
        
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_id = port.attrib.get('portid', "unknown")
                protocol = port.attrib.get('protocol', "unknown")
                state_elem = port.find('state')
                port_state = state_elem.attrib.get('state', "unknown") if state_elem is not None else "unknown"
                service_elem = port.find('service')
                service = service_elem.attrib.get('name', "unknown") if service_elem is not None else "unknown"
                print(f" - Port {port_id}/{protocol} is {port_state} and running {service}.")
        else:
            print(" - No open ports found.")

def main():
    if not check_nmap_installed():
        print("Error: Nmap is not installed. Please install Nmap first.")
        sys.exit(1)

    print("WARNING: Ensure you have permission to scan the target network.")
    target = input("Enter the target IP address or hostname: ").strip()
    validated_target = validate_target(target)
    if not validated_target:
        print("Invalid target format. Use IP (x.x.x.x) or hostname (example.com).")
        sys.exit(1)

    scans = [
        ("Ping Scan (Host Discovery)", ["nmap", "-sn", "-oX", "-", validated_target]),
        ("TCP SYN Scan (Port Scanning)", ["nmap", "-sS", "-oX", "-", validated_target]),
        ("Service Version Detection", ["nmap", "-sV", "-oX", "-", validated_target]),
        ("OS Detection", ["nmap", "-O", "-oX", "-", validated_target]),
        ("Vulnerability Scan (Vuln Scripts)", ["nmap", "--script", "vuln", "-oX", "-", validated_target]),
        ("Comprehensive Scan (Aggressive Mode)", ["nmap", "-A", "-oX", "-", validated_target])
    ]

    print(f"\nStarting scans on target: {validated_target}")
    
    for scan_name, command in scans:
        xml_output = run_scan(scan_name, command)
        print("\nResults:")
        parse_and_print(xml_output)
        print("-" * 50)
    
    print("\nAll scans completed.")

if __name__ == "__main__":
    main()
