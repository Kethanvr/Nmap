import os
import nmap
from pyfiglet import figlet_format
from datetime import datetime
import sys

# --- Core Configuration ---
DEFAULT_FILENAME = "scan_result.txt"
DISCLAIMER = "WARNING: Use only on networks you own or have explicit authorization to scan!"

class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def show_banner(self):
        os.system("clear" if os.name == "posix" else "cls")
        print("\033[91m" + figlet_format("Kethan VR", font="slant") + "\033[0m")
        print("\033[94m" + "Scanner Pro".center(50) + "\033[0m")
        print(f"\n\033[91m{DISCLAIMER}\033[0m\n")

    def run_scan(self, target: str, params: str, filename: str) -> bool:
        try:
            if not target:
                raise ValueError("Target cannot be empty")
                
            print(f"\n🔍 Scanning {target} with parameters: {params}")
            self.scanner.scan(target, arguments=params)
            
            with open(filename, 'w') as report:
                report.write(f"Nmap Scan Report ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\n")
                report.write("="*50 + "\n")
                report.write(f"Target: {target}\nScan Type: {params}\n\n")
                
                if not self.scanner.all_hosts():
                    report.write("No hosts found!\n")
                    print("⚠️ No hosts responded to the scan")
                    return False
                
                for host in self.scanner.all_hosts():
                    report.write(f"Host: {host}\nStatus: {self.scanner[host].state()}\n")
                    
                    # OS Detection with error handling
                    osmatches = self.scanner[host].get('osmatch', [])
                    report.write(f"OS: {osmatches[0]['name'] if osmatches else 'Could not be determined'}")
                    report.write(f" (Accuracy: {osmatches[0]['accuracy']}%)" if osmatches else "\n")
                    
                    # Port/Service Information
                    for proto in self.scanner[host].all_protocols():
                        report.write(f"\n{proto.upper()} Services:\n")
                        ports = sorted(self.scanner[host][proto].keys())
                        for port in ports:
                            service = self.scanner[host][proto][port]
                            report.write(f"Port {port}: {service['name']} ({service['state']})\n")
                            if 'product' in service and service['product']:
                                report.write(f"    Service: {service['product']} {service.get('version', '')}\n")
                            if 'script' in service:
                                for script, output in service['script'].items():
                                    report.write(f"    {script}: {output.strip()}\n")
            
            print(f"\n✅ Results saved to '{filename}'")
            return True
            
        except nmap.PortScannerError as e:
            print(f"❌ Scan failed: {str(e)}")
            return False
        except PermissionError:
            print("❌ Permission denied: Run with sudo/admin privileges")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")
            return False

    def web_scan_menu(self, target: str):
        web_scans = {
            "1": ("Basic Web Scan", "-p 80,443,8080,8443 --script=http-title"),
            "2": ("Full Web Audit", "-p 80,443 --script=http*"),
            "3": ("CMS Detection", "--script=http-cms*"),
            "4": ("Vuln Check (XSS/SQLi)", "--script=http-sql*,http-xss*"),
            "5": ("Dir Bruteforce Check", "--script=http-enum")
        }
        
        while True:
            self.show_banner()
            print("\n🕸️ Web Application Scanning Options:")
            for key, (desc, _) in web_scans.items():
                print(f"{key}. {desc}")
            print("6. Return to Main Menu")
            
            choice = input("\nChoose option (1-6): ")
            if choice == "6":
                return
            
            if choice not in web_scans:
                print("❌ Invalid choice!")
                continue
                
            fname = input(f"Save as [Enter for '{DEFAULT_FILENAME}']: ") or DEFAULT_FILENAME
            desc, params = web_scans[choice]
            self.run_scan(target, params, fname)
            input("\nPress Enter to continue...")

    def main_menu(self):
        scans = {
            "1": ("Comprehensive Network Scan", "-A -O -p- -sV --script=vuln"),
            "3": ("Custom TCP Scan", "-sS -p-"),
            "4": ("Service Version Detection", "-sV -O")
        }
        
        while True:
            self.show_banner()
            print("Main Menu:")
            for key, (desc, _) in scans.items():
                print(f"{key}. {desc}")
            print("2. Web Application Scan")
            print("0. Exit")
            
            choice = input("\nChoose an option (0-4): ")
            
            if choice == "0":
                print("\n🔒 Exiting Kethan VR Scanner Pro - Stay ethical!")
                break
                
            target = input("\n🎯 Enter target (IP/range/URL): ").strip()
            if not target:
                print("❌ Target cannot be empty!")
                continue
                
            fname = input(f"Save as [Enter for '{DEFAULT_FILENAME}']: ") or DEFAULT_FILENAME
            
            if choice == "2":
                self.web_scan_menu(target)
            elif choice in scans:
                desc, params = scans[choice]
                self.run_scan(target, params, fname)
            else:
                print("⚠️ Invalid option!")
                
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()