import nmap
from colorama import Fore, Style, init
import os
import sys
import re

# Initialize colorama
init(autoreset=True)

# Default scan result file
DEFAULT_FILENAME = "scan_results.txt"

# Function to save results
def save_results(results, filename=DEFAULT_FILENAME):
    with open(filename, "w") as file:
        file.write(results)
    print(f"{Fore.GREEN}\n[✔] Scan results saved as {filename}{Style.RESET_ALL}")

# Function to validate IP

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
    return bool(pattern.match(ip))

# Function to handle dummy bot network selection
def use_dummy_bot():
    choice = input("\n[?] Do you want to use a dummy bot network for privacy? (y/n): ")
    return "-D RND:10" if choice.lower() == 'y' else ""

# Router Scanner Class
class RouterScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_routers(self, target, extra_args):
        try:
            self.nm.scan(hosts=target, arguments=f'-sn --traceroute {extra_args}')
            return self.nm.csv() if self.nm.all_hosts() else "No routers found!"
        except nmap.PortScannerError:
            return "Scan error! Check target format."

# Connected Devices Scanner Class
class DeviceScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_devices(self, target, extra_args):
        try:
            self.nm.scan(hosts=target, arguments=f'-sn {extra_args}')
            devices = [host for host in self.nm.all_hosts()]
            return "\n".join(devices) if devices else "No devices found!"
        except nmap.PortScannerError:
            return "Scan error! Check network range."

# Web Server Scanner Class
class WebScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_webserver(self, target, extra_args):
        try:
            self.nm.scan(hosts=target, arguments=f'-Pn -sV {extra_args}')
            scan_results = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]['name']
                        scan_results.append(f"Port {port}/{proto}: {service}")
            return "\n".join(scan_results) if scan_results else "No open ports found!"
        except nmap.PortScannerError:
            return "Scan error! Check target address."

# Function for scanning menu
def scan_menu(scan_type, scanner_class):
    while True:
        print(f"\n{Fore.CYAN}{scan_type} Scanning:{Style.RESET_ALL}")
        target = input("Enter target IP/Range: ")

        if not is_valid_ip(target):
            print(f"{Fore.RED}Invalid IP format! Try again.{Style.RESET_ALL}")
            continue

        extra_args = use_dummy_bot()
        scanner = scanner_class()
        results = scanner.scan_routers(target, extra_args) if scan_type == "Router" else \
                  scanner.scan_devices(target, extra_args) if scan_type == "Devices" else \
                  scanner.scan_webserver(target, extra_args)

        print("\nScan Results:")
        print(results)

        # Ask user to save the results
        save_choice = input("\n[?] Do you want to save the results? (y/n): ")
        if save_choice.lower() == 'y':
            filename = input("Enter filename (or press Enter for default 'scan_results.txt'): ") or DEFAULT_FILENAME
            save_results(results, filename)

        choice = input("\n[0] Return to Main Menu | [99] Exit: ")
        if choice == '0':
            return
        elif choice == '99':
            sys.exit()

# Main Menu
def main_menu():
    while True:
        print(f"\n{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
        print("[1] Router Scanning")
        print("[2] Connected Devices Scanning")
        print("[3] Web Server Scanning")
        print("[99] Exit")

        choice = input("\nSelect an option: ")
        if choice == '1':
            scan_menu("Router", RouterScanner)
        elif choice == '2':
            scan_menu("Devices", DeviceScanner)
        elif choice == '3':
            scan_menu("Web Server", WebScanner)
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
