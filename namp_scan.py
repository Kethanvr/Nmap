import nmap
from colorama import Fore, Style, init
import os
import sys
import re

# Initialize colorama
init(autoreset=True)

DEFAULT_FILENAME = "scan_results.txt"

def save_results(results, filename=DEFAULT_FILENAME):
    with open(filename, "w") as file:
        file.write(results)
    print(f"{Fore.GREEN}\n[✔] Scan results saved as {filename}{Style.RESET_ALL}")

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
    return bool(pattern.match(ip))

def use_dummy_bot():
    choice = input("\n[?] Do you want to use a dummy bot network for privacy? (y/n): ")
    return "-D RND:10" if choice.lower() == 'y' else ""

def get_os_detection():
    choice = input("\n[?] Do you want to perform OS detection? (y/n): ")
    return "-O" if choice.lower() == 'y' else ""

def get_port_scan():
    choice = input("\n[?] Do you want to perform a port scan? (y/n): ")
    if choice.lower() == 'y':
        scan_type = input("\n[1] Scan all ports (-p-)")
        scan_type += "\n[2] Scan only common ports (--top-ports 1000)\nSelect option: "
        scan_choice = input(scan_type)
        return "-p-" if scan_choice == '1' else "--top-ports 1000"
    return ""

def get_scan_type():
    print("\n[?] Choose the type of scan:")
    print("[1] SYN scan (-sS)")
    print("[2] TCP connect scan (-sT)")
    print("[3] UDP scan (-sU)")
    choice = input("Select option: ")
    return "-sS" if choice == '1' else "-sT" if choice == '2' else "-sU" if choice == '3' else ""

def get_custom_ports():
    choice = input("\n[?] Enter specific ports to scan (comma-separated) or press Enter for default: ")
    return f"-p {choice}" if choice else ""

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target, extra_args):
        try:
            self.nm.scan(hosts=target, arguments=extra_args)
            return self.nm.csv() if self.nm.all_hosts() else "No results found!"
        except nmap.PortScannerError:
            return "Scan error! Check target format."

def scan_menu(scan_type):
    while True:
        print(f"\n{Fore.CYAN}{scan_type} Scanning:{Style.RESET_ALL}")
        target = input("Enter target IP/Range: ")
        if not is_valid_ip(target):
            print(f"{Fore.RED}Invalid IP format! Try again.{Style.RESET_ALL}")
            continue

        os_detect = get_os_detection()
        port_scan = get_port_scan()
        scan_type = get_scan_type()
        custom_ports = get_custom_ports()
        dummy_bot = use_dummy_bot()

        scan_args = f"{os_detect} {port_scan} {scan_type} {custom_ports} {dummy_bot}".strip()
        scanner = NmapScanner()
        results = scanner.scan(target, scan_args)

        print("\nScan Results:")
        print(results)

        save_choice = input("\n[?] Do you want to save the results? (y/n): ")
        if save_choice.lower() == 'y':
            filename = input("Enter filename (or press Enter for default 'scan_results.txt'): ") or DEFAULT_FILENAME
            save_results(results, filename)

        choice = input("\n[0] Return to Main Menu | [99] Exit: ")
        if choice == '0':
            return
        elif choice == '99':
            sys.exit()

def main_menu():
    while True:
        print(f"\n{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
        print("[1] Router Scanning")
        print("[2] Connected Devices Scanning")
        print("[3] Web Server Scanning")
        print("[99] Exit")
        
        choice = input("\nSelect an option: ")
        if choice in ['1', '2', '3']:
            scan_menu("Router" if choice == '1' else "Devices" if choice == '2' else "Web Server")
        elif choice == '99':
            print(f"{Fore.YELLOW}Exiting...{Style.RESET_ALL}")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid option! Try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user!{Style.RESET_ALL}")
        sys.exit()
