from core.base import ToolModule
from core.colors import Colors
import subprocess
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class GoBusterModule(ToolModule):
    def __init__(self):
        self._wordlists = {
            # Default system wordlists
            "common": "/usr/share/wordlists/dirb/common.txt",
            "big": "/usr/share/wordlists/dirb/big.txt",
            "directory-list-2.3-medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "directory-list-2.3-small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            
            # SecLists wordlists
            "quickhits": "/usr/share/seclists/Discovery/Web-Content/quickhits.txt",
            "raft-large-files": "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
            "raft-large-directories": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
            "common-api-endpoints": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
            "subdomains-top1million": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "vhosts": "/usr/share/seclists/Discovery/DNS/vhosts-default.txt"
        }
        super().__init__()

    def _get_name(self) -> str:
        return "GoBuster"

    def _get_category(self) -> str:
        return "Web"

    def _get_command(self) -> str:
        return "gobuster"

    def _get_description(self) -> str:
        return "Directory/file, DNS, and vhost brute-forcing tool written in Go"

    def _get_dependencies(self) -> List[str]:
        return ["gobuster"]

    def _get_script_path(self) -> str:
        """Returns path to script if applicable"""
        return ""  # GoBuster is a binary, no script needed

    def get_help(self) -> dict:
        return {
            "title": "GoBuster - Directory/DNS Enumeration Tool",
            "usage": "use gobuster",
            "desc": "A versatile tool for brute-forcing URIs, DNS subdomains, and virtual hosts",
            "modes": {
                "Guided": "Interactive mode that guides through scan configuration",
                "Direct": "Direct command execution with full gobuster syntax"
            },
            "options": {
                "dir": "Directory/file enumeration mode",
                "dns": "DNS subdomain enumeration mode",
                "vhost": "Virtual host enumeration mode",
                "-u": "Target URL",
                "-w": "Wordlist path",
                "-t": "Number of threads (default 10)",
                "-x": "File extensions to search for",
                "-s": "Positive status codes (default 200,204,301,302,307,401,403)",
                "--proxy": "Proxy to use [http(s)://host:port]",
                "-o": "Output file"
            },
            "examples": [
                "gobuster dir -u http://example.com -w wordlist.txt",
                "gobuster dns -d example.com -w subdomains.txt",
                "gobuster vhost -u http://example.com -w vhosts.txt",
                "gobuster dir -u http://example.com -w wordlist.txt -x php,html,txt",
                "gobuster dir -u http://example.com -w wordlist.txt --proxy http://proxy:3128"
            ],
            "notes": [
                "Different modes (dir, dns, vhost) require different parameters",
                "Use appropriate wordlists for each mode",
                "Consider using lower thread count for stability",
                "Some servers might block excessive requests"
            ]
        }

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Returns installation commands for different package managers"""
        base_commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y gobuster seclists"
            ],
            'yum': [
                "sudo yum update",
                "sudo yum install -y epel-release",
                "sudo yum install -y gobuster git",
                "git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists"
            ],
            'dnf': [
                "sudo dnf update",
                "sudo dnf install -y gobuster git",
                "git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S gobuster git --noconfirm",
                "git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists"
            ]
        }
        
        commands = base_commands.get(pkg_manager, [])
        
        # Add SecLists extraction command if needed
        if pkg_manager == 'apt':
            commands.append("sudo gunzip -r /usr/share/seclists/")
            
        return commands

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Returns update commands for different package managers"""
        return self._get_install_command(pkg_manager)  # Same as install for gobuster

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Returns uninstallation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get remove -y gobuster seclists",
                "sudo apt-get autoremove -y"
            ],
            'yum': [
                "sudo yum remove -y gobuster",
                "sudo rm -rf /usr/share/seclists",
                "sudo yum autoremove -y"
            ],
            'dnf': [
                "sudo dnf remove -y gobuster",
                "sudo rm -rf /usr/share/seclists",
                "sudo dnf autoremove -y"
            ],
            'pacman': [
                "sudo pacman -Rs gobuster --noconfirm",
                "sudo rm -rf /usr/share/seclists"
            ]
        }
        return commands.get(pkg_manager, [])

    def _show_banner(self):
        """Display the module banner"""
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║             GOBUSTER                      ║
║     "Directory/DNS Enumeration Tool"      ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _get_mode(self) -> Optional[str]:
        """Get scanning mode"""
        print(f"\n{Colors.CYAN}[*] Available Modes:{Colors.ENDC}")
        modes = {
            "1": ("dir", "Directory/file enumeration"),
            "2": ("dns", "DNS subdomain enumeration"),
            "3": ("vhost", "Virtual host enumeration")
        }

        for key, (mode, desc) in modes.items():
            print(f"{Colors.GREEN}{key}:{Colors.ENDC} {mode} - {desc}")

        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select mode (1-3): {Colors.ENDC}").strip()
            if choice in modes:
                return modes[choice][0]
            print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")

    def _get_target(self, mode: str) -> Optional[str]:
        """Get target based on mode"""
        prompt = ""
        param = ""
        if mode == "dir" or mode == "vhost":
            prompt = "Target URL (e.g., http://example.com): "
            param = "-u"
        elif mode == "dns":
            prompt = "Target domain (e.g., example.com): "
            param = "-d"

        while True:
            target = input(f"\n{Colors.BOLD}[+] {prompt}{Colors.ENDC}").strip()
            if not target:
                print(f"{Colors.FAIL}[!] Target is required{Colors.ENDC}")
                continue
            return f"{param} {target}"
    
    def _get_wordlist(self) -> Optional[str]:
            """Get and validate wordlist path"""
            print(f"\n{Colors.CYAN}[*] Available Wordlists:{Colors.ENDC}")
            
            # Display available wordlists with status
            for i, (name, path) in enumerate(self._wordlists.items(), 1):
                exists = "✓" if Path(path).exists() else "✗"
                print(f"{Colors.GREEN}{i}:{Colors.ENDC} {name} [{exists}] - {path}")
            print(f"{Colors.GREEN}{len(self._wordlists) + 1}:{Colors.ENDC} Custom wordlist")

            while True:
                choice = input(f"\n{Colors.BOLD}[+] Select wordlist (1-{len(self._wordlists) + 1}): {Colors.ENDC}").strip()
                
                if choice == str(len(self._wordlists) + 1):
                    # Handle custom wordlist path
                    custom_path = input(f"{Colors.BOLD}[+] Enter wordlist path: {Colors.ENDC}").strip()
                    if not custom_path:
                        print(f"{Colors.FAIL}[!] Path is required{Colors.ENDC}")
                        continue
                    
                    path = Path(custom_path)
                    if path.exists() and path.is_file():
                        return f"-w {path.absolute()}"
                    print(f"{Colors.FAIL}[!] File not found: {custom_path}{Colors.ENDC}")
                else:
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(self._wordlists):
                            path = Path(list(self._wordlists.values())[idx])
                            if path.exists():
                                return f"-w {path}"
                            print(f"{Colors.FAIL}[!] Wordlist not found: {path}{Colors.ENDC}")
                        else:
                            print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                    except ValueError:
                        print(f"{Colors.FAIL}[!] Invalid input{Colors.ENDC}")
                
                retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
                if retry == 'n':
                    return None

    def _get_extensions(self) -> str:
        """Get file extensions for directory mode"""
        if input(f"\n{Colors.BOLD}[+] Add file extensions? (y/N): {Colors.ENDC}").lower() == 'y':
            extensions = input(f"{Colors.BOLD}[+] Enter extensions (comma-separated, e.g., php,html,txt): {Colors.ENDC}").strip()
            if extensions:
                return f"-x {extensions}"
        return ""

    def _get_threads(self) -> str:
        """Get number of threads"""
        if input(f"\n{Colors.BOLD}[+] Change number of threads? (default: 10) (y/N): {Colors.ENDC}").lower() == 'y':
            while True:
                try:
                    threads = int(input(f"{Colors.BOLD}[+] Enter number of threads (1-50): {Colors.ENDC}"))
                    if 1 <= threads <= 50:
                        return f"-t {threads}"
                    print(f"{Colors.FAIL}[!] Thread count must be between 1 and 50{Colors.ENDC}")
                except ValueError:
                    print(f"{Colors.FAIL}[!] Invalid input{Colors.ENDC}")
        return ""

    def _get_output_file(self) -> str:
        """Configure output file"""
        if input(f"\n{Colors.BOLD}[+] Save results to file? (y/N): {Colors.ENDC}").lower() == 'y':
            while True:
                filename = input(f"{Colors.BOLD}[+] Enter filename: {Colors.ENDC}").strip()
                if filename:
                    # Create output directory if it doesn't exist
                    output_dir = Path("gobuster_scans")
                    output_dir.mkdir(exist_ok=True)
                    return f"-o {output_dir / filename}"
                print(f"{Colors.FAIL}[!] Filename is required{Colors.ENDC}")
        return ""

    def _execute_gobuster(self, command: str) -> bool:
        """
        Execute gobuster with real-time output
        
        Returns:
            bool: True if user wants to perform another scan, False otherwise
        """
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )

            # Show real-time output
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())

            # Check for errors
            if process.returncode != 0:
                stderr = process.stderr.read()
                if stderr:
                    print(f"{Colors.FAIL}[!] Errors during scan:{Colors.ENDC}")
                    print(stderr)
            else:
                print(f"\n{Colors.GREEN}[✓] Scan completed successfully{Colors.ENDC}")

            # Ask user if they want to perform another scan
            while True:
                choice = input(f"\n{Colors.BOLD}[?] Would you like to perform another scan? (y/N): {Colors.ENDC}").lower()
                if choice in ['y', 'n', '']:
                    return choice == 'y'
                print(f"{Colors.FAIL}[!] Please enter 'y' for yes or 'n' for no{Colors.ENDC}")

        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
            process.terminate()
            return False
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error during scan: {e}{Colors.ENDC}")
            return False

    def run_guided(self) -> None:
        """Interactive guided mode for gobuster"""
        self._show_banner()

        while True:
            try:
                # Get scan mode
                mode = self._get_mode()
                if not mode:
                    return

                # Get target
                target = self._get_target(mode)
                if not target:
                    return

                # Get wordlist
                wordlist = self._get_wordlist()
                if not wordlist:
                    return

                # Build command parts list
                command_parts = ["gobuster", mode, target, wordlist]

                # Mode-specific options
                if mode == "dir":
                    # File extensions
                    extensions = self._get_extensions()
                    if extensions:
                        command_parts.append(extensions)

                # Common options
                # Threads
                threads = self._get_threads()
                if threads:
                    command_parts.append(threads)

                # Output file
                output_file = self._get_output_file()
                if output_file:
                    command_parts.append(output_file)

                # Build final command
                command = " ".join(command_parts)
                
                print(f"\n{Colors.CYAN}[*] Scan Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 30)
                print(f"Mode: {mode}")
                print(f"Command: {command}")

                if input(f"\n{Colors.BOLD}[+] Start scan? (Y/n): {Colors.ENDC}").lower() != 'n':
                    print(f"\n{Colors.CYAN}[*] Executing scan...{Colors.ENDC}")
                    if not self._execute_gobuster(command):
                        break
                else:
                    print(f"\n{Colors.WARNING}[!] Scan cancelled by user{Colors.ENDC}")
                    if input(f"\n{Colors.BOLD}[?] Would you like to configure another scan? (y/N): {Colors.ENDC}").lower() != 'y':
                        break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for gobuster"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter gobuster commands directly{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  help     - Show gobuster help")
        print("  modes    - Show available modes")
        print("  wordlist - Show available wordlists")
        print("  examples - Show usage examples")
        print("  exit     - Exit to main menu")
        
        while True:
            try:
                command = input(f"\n{Colors.BOLD}gobuster > {Colors.ENDC}").strip()
                
                if not command:
                    continue
                    
                if command.lower() == 'exit':
                    break
                    
                elif command.lower() == 'help':
                    subprocess.run(['gobuster', '--help'])
                    
                elif command.lower() == 'modes':
                    print(f"\n{Colors.CYAN}[*] Available Modes:{Colors.ENDC}")
                    print("  dir   - Directory/file enumeration mode")
                    print("  dns   - DNS subdomain enumeration mode")
                    print("  vhost - Virtual host enumeration mode")
                    print("\nUse 'gobuster <mode> --help' for mode-specific help")
                    
                elif command.lower() == 'wordlist':
                    print(f"\n{Colors.CYAN}[*] Available Wordlists:{Colors.ENDC}")
                    print(f"\n{Colors.GREEN}Directory Bruteforcing:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if "directories" in name.lower() or "files" in name.lower():
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}: {path}")
                            
                    print(f"\n{Colors.GREEN}DNS/Subdomain:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if "dns" in name.lower() or "subdomains" in name.lower():
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}: {path}")
                            
                    print(f"\n{Colors.GREEN}Virtual Hosts:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if "vhosts" in name.lower():
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}: {path}")
                            
                    print(f"\n{Colors.GREEN}Other:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if not any(x in name.lower() for x in ["directories", "files", "dns", "subdomains", "vhosts"]):
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}: {path}")
                    
                elif command.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] Usage Examples:{Colors.ENDC}")
                    
                    print(f"\n{Colors.GREEN}1. Directory Enumeration{Colors.ENDC}")
                    print("Basic scan:")
                    print("  gobuster dir -u http://example.com -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt")
                    print("\nWith file extensions:")
                    print("  gobuster dir -u http://example.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x php,txt,html")
                    
                    print(f"\n{Colors.GREEN}2. DNS Subdomain Enumeration{Colors.ENDC}")
                    print("Basic scan:")
                    print("  gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
                    print("\nWith specific resolver:")
                    print("  gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r 8.8.8.8")
                    
                    print(f"\n{Colors.GREEN}3. Virtual Host Discovery{Colors.ENDC}")
                    print("Basic scan:")
                    print("  gobuster vhost -u http://example.com -w /usr/share/seclists/Discovery/DNS/vhosts-default.txt")
                    
                    print(f"\n{Colors.GREEN}4. Advanced Options{Colors.ENDC}")
                    print("With proxy:")
                    print("  gobuster dir -u http://example.com -w wordlist.txt --proxy http://proxy:3128")
                    print("\nWith custom status codes:")
                    print("  gobuster dir -u http://example.com -w wordlist.txt -s 200,204,301,302,307,401,403")
                    print("\nWith increased threads:")
                    print("  gobuster dir -u http://example.com -w wordlist.txt -t 50")
                    
                else:
                    # If not a special command, execute as gobuster command
                    if not command.startswith('gobuster '):
                        command = f"gobuster {command}"
                        
                    try:
                        if not self._execute_gobuster(command):
                            break
                    except subprocess.CalledProcessError as e:
                        print(f"{Colors.FAIL}[!] Error executing command: {e}{Colors.ENDC}")
                        if e.stderr:
                            print(f"Error details: {e.stderr.decode()}")
                            
            except KeyboardInterrupt:
                print("\n")
                continue
            except Exception as e:
                print(f"{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
                continue
