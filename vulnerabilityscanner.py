#!/usr/bin/env python3
import subprocess
import argparse
import time
import xml.etree.ElementTree as ET
import sys

def run_nmap(target, options):
    """
    Run an Nmap scan with the given options and return the XML output.
    The '-oX -' flag tells Nmap to output XML to stdout.
    """
    command = ["nmap"] + options + ["-oX", "-"] + [target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing Nmap: {e.stderr}", file=sys.stderr)
        return None

def parse_nmap_xml(xml_output):
    """
    Parse Nmap XML output and return a list of hosts with their port information.
    """
    hosts_info = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        print("Error parsing XML:", e, file=sys.stderr)
        return hosts_info

    for host in root.findall('host'):
        # Get host address
        addr_elem = host.find('address')
        ip_address = addr_elem.attrib.get('addr') if addr_elem is not None else "Unknown"
        # Get host status
        status_elem = host.find('status')
        status = status_elem.attrib.get('state') if status_elem is not None else "unknown"
        host_info = {"ip": ip_address, "status": status, "ports": []}

        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_info = {
                    "protocol": port.attrib.get('protocol'),
                    "portid": port.attrib.get('portid')
                }
                # Get port state
                state_elem = port.find('state')
                port_info["state"] = state_elem.attrib.get('state') if state_elem is not None else "unknown"
                # Get service name
                service_elem = port.find('service')
                port_info["service"] = service_elem.attrib.get('name') if service_elem is not None else "unknown"
                # Collect vulnerability script outputs (if any)
                vuln_scripts = []
                for script in port.findall('script'):
                    script_id = script.attrib.get('id')
                    script_output = script.attrib.get('output')
                    vuln_scripts.append({"id": script_id, "output": script_output})
                port_info["vuln_scripts"] = vuln_scripts
                host_info["ports"].append(port_info)
        hosts_info.append(host_info)
    return hosts_info

def print_scan_results(hosts_info):
    """
    Nicely print the scan results.
    """
    if not hosts_info:
        print("No hosts found or error parsing results.")
        return

    for host in hosts_info:
        print(f"\nHost: {host['ip']} (Status: {host['status']})")
        if host["ports"]:
            for port in host["ports"]:
                print(f"  Port {port['portid']}/{port['protocol']}: {port['state']} (Service: {port['service']})")
                if port["vuln_scripts"]:
                    print("    Vulnerability script outputs:")
                    for script in port["vuln_scripts"]:
                        print(f"      {script['id']}: {script['output']}")
        else:
            print("  No open ports found.")

def perform_scan(target, scan_type):
    """
    Determine the Nmap options based on the chosen scan type, run the scan,
    and print the results.
    """
    if scan_type == "basic":
        options = ["-sS", "-sV"]
    elif scan_type == "vuln":
        options = ["-sV", "--script", "vuln"]
    elif scan_type == "comprehensive":
        options = ["-A"]
    else:
        options = ["-sS", "-sV"]

    xml_output = run_nmap(target, options)
    if xml_output:
        hosts_info = parse_nmap_xml(xml_output)
        print_scan_results(hosts_info)
    else:
        print("Failed to retrieve scan results.")

def main():
    parser = argparse.ArgumentParser(
        description="Full-Fledged Vulnerability Scanner using Nmap (Educational Use Only)"
    )
    parser.add_argument("target", help="Target IP address, hostname, or network range")
    parser.add_argument("--scan", choices=["basic", "vuln", "comprehensive"],
                        default="basic", help="Type of scan to perform: basic, vuln, or comprehensive")
    parser.add_argument("--continuous", action="store_true", help="Run scans continuously")
    parser.add_argument("--interval", type=int, default=300,
                        help="Interval between scans in continuous mode (default: 300 seconds)")
    args = parser.parse_args()

    print("=== DISCLAIMER ===")
    print("This tool is for educational purposes only.")
    print("Only scan systems/networks that you have explicit permission to test!")
    print("==================\n")

    try:
        if args.continuous:
            print("Running in continuous mode. Press Ctrl+C to stop.")
            while True:
                print(f"\nPerforming '{args.scan}' scan on {args.target}...")
                perform_scan(args.target, args.scan)
                print(f"\nWaiting for {args.interval} seconds before the next scan...\n")
                time.sleep(args.interval)
        else:
            print(f"Performing '{args.scan}' scan on {args.target}...")
            perform_scan(args.target, args.scan)
    except KeyboardInterrupt:
        print("\n[INFO] Scanning interrupted by user. Exiting.")

if __name__ == "__main__":
    main()
