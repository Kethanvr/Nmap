import nmap
from colorama import Fore, Style, init
import os
import sys
import re
import argparse
import datetime
import ipaddress
import json

# Initialize colorama
init(autoreset=True)

DEFAULT_FILENAME = "scan_results.txt"

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results_history = []

    def scan(self, target, extra_args):
        try:
            print(f"{Fore.BLUE}[*] Starting scan on {target} with arguments: {extra_args}{Style.RESET_ALL}")
            start_time = datetime.datetime.now()
            
            self.nm.scan(hosts=target, arguments=extra_args)
            
            end_time = datetime.datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            if self.nm.all_hosts():
                scan_result = {
                    "target": target,
                    "arguments": extra_args,
                    "timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "duration": f"{duration:.2f} seconds",
                    "data": self.nm.csv()
                }
                self.results_history.append(scan_result)
                return scan_result
            return {"target": target, "arguments": extra_args, "error": "No results found!"}
        except nmap.PortScannerError as e:
            return {"target": target, "arguments": extra_args, "error": f"Scan error: {str(e)}"}
        except Exception as e:
            return {"target": target, "arguments": extra_args, "error": f"Unexpected error: {str(e)}"}

def is_valid_ip(ip):
    try:
        # Handle CIDR notation
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False

def save_results(results, filename=DEFAULT_FILENAME, format="txt"):
    try:
        if format.lower() == "json":
            with open(f"{filename}.json", "w") as file:
                json.dump(results, file, indent=2)
            print(f"{Fore.GREEN}[✔] Scan results saved as {filename}.json{Style.RESET_ALL}")
        else:
            with open(filename, "w") as file:
                if isinstance(results, dict):
                    file.write(f"Target: {results['target']}\n")
                    file.write(f"Arguments: {results['arguments']}\n")
                    file.write(f"Timestamp: {results.get('timestamp', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n")
                    file.write(f"Duration: {results.get('duration', 'N/A')}\n\n")
                    file.write(results.get('data', results.get('error', 'No data available')))
                else:
                    file.write(str(results))
            print(f"{Fore.GREEN}[✔] Scan results saved as {filename}{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}[✘] Error saving results: {str(e)}{Style.RESET_ALL}")
        return False

def build_scan_arguments(options):
    args = []
    
    # Add scan type
    if options.get('scan_type'):
        args.append(options['scan_type'])
    
    # Add OS detection
    if options.get('os_detect'):
        args.append("-O")
    
    # Add port options
    if options.get('port_option') == 'all':
        args.append("-p-")
    elif options.get('port_option') == 'common':
        args.append("--top-ports 1000")
    elif options.get('custom_ports'):
        args.append(f"-p {options['custom_ports']}")
    
    # Add dummy bot option
    if options.get('dummy_bot'):
        args.append("-D RND:10")
    
    # Add verbosity
    if options.get('verbose'):
        args.append("-v")
    
    # Add service detection
    if options.get('service_detection'):
        args.append("-sV")
    
    # Add script scanning
    if options.get('script_scan'):
        args.append("--script=default")
    
    # Add timing template
    if options.get('timing'):
        args.append(f"-T{options['timing']}")
        
    return " ".join(args)

def scan_menu(scan_type, scanner):
    options = {
        'scan_type': '',
        'os_detect': False,
        'port_option': '',
        'custom_ports': '',
        'dummy_bot': False,
        'verbose': False,
        'service_detection': False,
        'script_scan': False,
        'timing': 3
    }
    
    while True:
        print(f"\n{Fore.CYAN}{scan_type} Scanning:{Style.RESET_ALL}")
        target = input("Enter target IP/Range: ")
        
        if not is_valid_ip(target):
            print(f"{Fore.RED}[✘] Invalid IP format! Try again.{Style.RESET_ALL}")
            continue
        
        # Get scan options
        print("\n[?] Configure scan options:")
        
        # Scan type
        print("\n[?] Choose the type of scan:")
        print("[1] SYN scan (-sS) - Default, faster but requires root/admin")
        print("[2] TCP connect scan (-sT) - More compatible, no special privileges")
        print("[3] UDP scan (-sU) - Scan UDP ports")
        print("[4] Comprehensive scan (-sS -sV -sC) - Detailed but slower")
        choice = input("Select option [1]: ") or "1"
        
        if choice == '1':
            options['scan_type'] = "-sS"
        elif choice == '2':
            options['scan_type'] = "-sT" 
        elif choice == '3':
            options['scan_type'] = "-sU"
        elif choice == '4':
            options['scan_type'] = "-sS -sV -sC"
        
        # OS detection
        choice = input("\n[?] Perform OS detection? (y/n) [n]: ") or "n"
        options['os_detect'] = (choice.lower() == 'y')
        
        # Service version detection
        choice = input("\n[?] Perform service version detection? (-sV) (y/n) [n]: ") or "n"
        options['service_detection'] = (choice.lower() == 'y')
        
        # Port options
        print("\n[?] Port scanning options:")
        print("[1] Scan all ports (-p-) - Thorough but slow")
        print("[2] Scan only common ports (--top-ports 1000) - Faster")
        print("[3] Specify custom ports")
        port_choice = input("Select option [2]: ") or "2"
        
        if port_choice == '1':
            options['port_option'] = 'all'
        elif port_choice == '2':
            options['port_option'] = 'common'
        elif port_choice == '3':
            options['custom_ports'] = input("Enter specific ports to scan (comma-separated): ")
            options['port_option'] = 'custom'
        
        # Timing template
        print("\n[?] Scan timing template (higher = faster but noisier):")
        print("[0] Paranoid (0) - Extremely slow, for IDS evasion")
        print("[1] Sneaky (1) - Quite slow, for IDS evasion")
        print("[2] Polite (2) - Slows down to consume less bandwidth")
        print("[3] Normal (3) - Default Nmap timing")
        print("[4] Aggressive (4) - Faster, assumes reliable network")
        print("[5] Insane (5) - Very fast, assumes extremely reliable network")
        timing_choice = input("Select option [3]: ") or "3"
        if timing_choice in ["0", "1", "2", "3", "4", "5"]:
            options['timing'] = int(timing_choice)
        
        # Script scanning
        choice = input("\n[?] Run default scripts? (--script=default) (y/n) [n]: ") or "n"
        options['script_scan'] = (choice.lower() == 'y')
        
        # Verbosity
        choice = input("\n[?] Verbose output? (-v) (y/n) [n]: ") or "n"
        options['verbose'] = (choice.lower() == 'y')
        
        # Dummy bot
        choice = input("\n[?] Use a dummy bot network for privacy? (-D RND:10) (y/n) [n]: ") or "n"
        options['dummy_bot'] = (choice.lower() == 'y')
        
        # Build scan arguments
        scan_args = build_scan_arguments(options)
        
        # Confirm scan
        print(f"\n{Fore.YELLOW}[!] Ready to scan {target} with arguments: {scan_args}{Style.RESET_ALL}")
        confirm = input("Proceed with scan? (y/n) [y]: ") or "y"
        if confirm.lower() != 'y':
            continue
        
        # Run scan
        results = scanner.scan(target, scan_args)
        
        if 'error' in results:
            print(f"\n{Fore.RED}[✘] {results['error']}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[✔] Scan completed in {results['duration']}{Style.RESET_ALL}")
            print("\nScan Results:")
            print(results['data'])
        
        # Save options
        print("\n[?] Save options:")
        save_choice = input("Do you want to save the results? (y/n) [y]: ") or "y"
        if save_choice.lower() == 'y':
            filename = input("Enter filename (or press Enter for default 'scan_results.txt'): ") or DEFAULT_FILENAME
            format_choice = input("Save format (txt/json) [txt]: ") or "txt"
            save_results(results, filename, format_choice)
        
        # Return or exit
        print(f"\n{Fore.CYAN}[?] What next?{Style.RESET_ALL}")
        print("[0] Return to Main Menu")
        print("[1] Run another scan")
        print("[99] Exit")
        choice = input("\nSelect an option [0]: ") or "0"
        if choice == '0':
            return
        elif choice == '99':
            print(f"\n{Fore.YELLOW}[!] Exiting...{Style.RESET_ALL}")
            sys.exit(0)
        # If '1', continue loop

def show_scan_history(scanner):
    if not scanner.results_history:
        print(f"\n{Fore.YELLOW}[!] No scan history available.{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}Scan History:{Style.RESET_ALL}")
    for i, result in enumerate(scanner.results_history):
        print(f"[{i+1}] Target: {result['target']} - {result['timestamp']} ({result['duration']})")
    
    choice = input("\nEnter number to view details, or 0 to return: ")
    if choice == '0':
        return
    
    try:
        index = int(choice) - 1
        if 0 <= index < len(scanner.results_history):
            result = scanner.results_history[index]
            print(f"\n{Fore.GREEN}Scan Details:{Style.RESET_ALL}")
            print(f"Target: {result['target']}")
            print(f"Arguments: {result['arguments']}")
            print(f"Timestamp: {result['timestamp']}")
            print(f"Duration: {result['duration']}")
            print("\nResults:")
            print(result['data'])
            
            save_choice = input("\nSave this result? (y/n) [n]: ") or "n"
            if save_choice.lower() == 'y':
                filename = input("Enter filename: ") or f"scan_{index+1}.txt"
                format_choice = input("Save format (txt/json) [txt]: ") or "txt"
                save_results(result, filename, format_choice)
        else:
            print(f"{Fore.RED}[✘] Invalid selection.{Style.RESET_ALL}")
    except ValueError:
        print(f"{Fore.RED}[✘] Invalid input.{Style.RESET_ALL}")

def check_requirements():
    """Check if nmap is installed and python-nmap has permissions"""
    try:
        # Check if running as root/admin
        is_admin = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        
        # Test nmap import
        import nmap
        scanner = nmap.PortScanner()
        
        # Try a simple scan to check permissions
        try:
            scanner.scan('127.0.0.1', arguments='-sT -p 80')
            nmap_works = True
        except nmap.PortScannerError:
            nmap_works = False
        
        if not is_admin and not nmap_works:
            print(f"{Fore.YELLOW}[!] Warning: Some scan types (like SYN scan) require root/admin privileges.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Consider running this script with elevated privileges for full functionality.{Style.RESET_ALL}")
        
        return True
    except ImportError:
        print(f"{Fore.RED}[✘] Error: python-nmap module not found.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Install it with: pip install python-nmap{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}[✘] Error checking requirements: {str(e)}{Style.RESET_ALL}")
        return False

def main_menu():
    # Create scanner instance
    scanner = NmapScanner()
    
    # Check requirements
    if not check_requirements():
        choice = input(f"\n{Fore.YELLOW}[?] Continue anyway? (y/n) [n]: {Style.RESET_ALL}") or "n"
        if choice.lower() != 'y':
            sys.exit(1)
    
    while True:
        print(f"\n{Fore.CYAN}==== Network Scanner Tool ===={Style.RESET_ALL}")
        print(f"{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
        print("[1] Network/Router Scanning")
        print("[2] Host/Device Scanning")
        print("[3] Web Server Vulnerability Scanning")
        print("[4] View Scan History")
        print("[5] About & Help")
        print("[99] Exit")
        
        choice = input("\nSelect an option: ")
        
        if choice == '1':
            scan_menu("Network/Router", scanner)
        elif choice == '2':
            scan_menu("Host/Device", scanner)
        elif choice == '3':
            scan_menu("Web Server", scanner)
        elif choice == '4':
            show_scan_history(scanner)
        elif choice == '5':
            show_help()
        elif choice == '99':
            print(f"\n{Fore.YELLOW}[!] Exiting...{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}[✘] Invalid option! Try again.{Style.RESET_ALL}")

def show_help():
    print(f"\n{Fore.CYAN}==== About & Help ===={Style.RESET_ALL}")
    print("This tool is a Python wrapper for Nmap, providing an interactive interface for network scanning.")
    print("\nKey Features:")
    print("- Multiple scan types (SYN, TCP, UDP)")
    print("- OS and service detection")
    print("- Port scanning options")
    print("- Scan history tracking")
    print("- Result saving in multiple formats")
    
    print(f"\n{Fore.YELLOW}[!] Important Notes:{Style.RESET_ALL}")
    print("1. Some scan types (like SYN scan) require root/admin privileges")
    print("2. Network scanning without permission may be illegal in some jurisdictions")
    print("3. Always ensure you have permission to scan the target network/hosts")
    
    input(f"\n{Fore.CYAN}Press Enter to return to main menu...{Style.RESET_ALL}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("-t", "--target", help="Target IP or range (CIDR notation)")
    parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated or range)")
    parser.add_argument("-s", "--scan", choices=["syn", "tcp", "udp"], help="Scan type")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--format", choices=["txt", "json"], default="txt", help="Output format")
    
    return parser.parse_args()

if __name__ == "__main__":
    try:
        # Check for command line arguments
        args = parse_arguments()
        
        if args.target:
            # Command line mode
            scanner = NmapScanner()
            options = {
                'scan_type': f"-s{args.scan.upper()}" if args.scan else "-sS",
                'custom_ports': args.ports if args.ports else "",
            }
            scan_args = build_scan_arguments(options)
            
            print(f"{Fore.BLUE}[*] Running in command line mode{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[*] Target: {args.target}, Args: {scan_args}{Style.RESET_ALL}")
            
            results = scanner.scan(args.target, scan_args)
            
            if 'error' in results:
                print(f"{Fore.RED}[✘] {results['error']}{Style.RESET_ALL}")
                sys.exit(1)
            
            print(f"{Fore.GREEN}[✔] Scan completed in {results['duration']}{Style.RESET_ALL}")
            
            if args.output:
                save_results(results, args.output, args.format)
            else:
                print("\nResults:")
                print(results['data'])
        else:
            # Interactive mode
            main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled by user!{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[✘] Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)