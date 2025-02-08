from core.base import ToolModule
from core.colors import Colors
import subprocess
import platform
import os
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class NiktoModule(ToolModule):
    def __init__(self):
        self._scan_tuning = {
            "1": "File Upload",
            "2": "Misconfiguration / Default Files",
            "3": "Information Disclosure",
            "4": "Injection (XSS/Script/HTML)",
            "5": "Remote File Retrieval",
            "6": "Denial of Service",
            "7": "WebService",
            "8": "Command Execution",
            "9": "SQL Injection",
            "0": "Authentication Bypass"
        }
        self._output_dir = Path.home() / "nikto_results"
        super().__init__()

    def _get_name(self) -> str:
        return "Nikto"

    def _get_category(self) -> str:
        return "Web"

    def _get_command(self) -> str:
        return "nikto"

    def _get_description(self) -> str:
        return "Web server scanner for dangerous files/CGIs, outdated software and other problems"

    def _get_dependencies(self) -> List[str]:
        return ["nikto"]

    def _get_script_path(self) -> str:
        """Returns path to script if applicable"""
        return ""  # Nikto is installed as a package

    def get_help(self) -> dict:
        return {
            "title": "Nikto - Web Server Scanner",
            "usage": "use nikto",
            "desc": "Comprehensive web server security scanner that checks for vulnerabilities and misconfigurations",
            "modes": {
                "Guided": "Interactive mode that guides through scan configuration",
                "Direct": "Direct command execution with full nikto syntax"
            },
            "options": {
                "-h": "Target hostname",
                "-p": "Target port",
                "-ssl": "Force SSL mode",
                "-nossl": "Disable SSL mode",
                "-id": "HTTP authentication (user:pass)",
                "-plugins": "List of plugins to run (comma separated)",
                "-Tuning": "Scan tuning options",
                "-timeout": "Set a timeout value",
                "-proxy": "Use a proxy",
                "-useragent": "Set a custom User-Agent",
                "-evasion": "Evasion mode",
                "-output": "Output file",
                "-Format": "Output format (txt, csv, xml, html)"
            },
            "examples": [
                "nikto -h example.com",
                "nikto -h example.com -ssl -p 443",
                "nikto -h example.com -Tuning 1234",
                "nikto -h example.com -id admin:password",
                "nikto -h example.com -proxy localhost:8080"
            ],
            "notes": [
                "Default scan may take significant time",
                "Use tuning options to focus the scan",
                "Some tests may trigger IDS/IPS alerts",
                "Consider legal implications before scanning"
            ]
        }

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Returns installation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y nikto"
            ],
            'yum': [
                "sudo yum update",
                "sudo yum install -y nikto"
            ],
            'dnf': [
                "sudo dnf update",
                "sudo dnf install -y nikto"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S nikto --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Returns update commands for different package managers"""
        commands = self._get_install_command(pkg_manager)
        commands.append("nikto -update")
        return commands

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Returns uninstallation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get remove -y nikto",
                "sudo apt-get autoremove -y"
            ],
            'yum': [
                "sudo yum remove -y nikto",
                "sudo yum autoremove -y"
            ],
            'dnf': [
                "sudo dnf remove -y nikto",
                "sudo dnf autoremove -y"
            ],
            'pacman': [
                "sudo pacman -Rs nikto --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _show_banner(self):
        """Display the module banner"""
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║               NIKTO                       ║
║        "Web Server Scanner"              ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _get_target(self) -> Optional[str]:
        """Get and validate target hostname"""
        while True:
            target = input(f"\n{Colors.BOLD}[+] Enter target hostname/IP: {Colors.ENDC}").strip()
            if target:
                return f"-h {target}"
            
            print(f"{Colors.FAIL}[!] Target is required{Colors.ENDC}")
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_port_options(self) -> str:
        """Configure port and SSL options"""
        options = []
        
        if input(f"\n{Colors.BOLD}[+] Specify port? (y/N): {Colors.ENDC}").lower() == 'y':
            port = input(f"{Colors.BOLD}[+] Enter port number: {Colors.ENDC}").strip()
            if port.isdigit():
                options.append(f"-p {port}")
                
                # If port is 443, suggest SSL
                if port == "443" and input(f"{Colors.BOLD}[+] Enable SSL for port 443? (Y/n): {Colors.ENDC}").lower() != 'n':
                    options.append("-ssl")
        else:
            # Ask about SSL if port not specified
            ssl_choice = input(f"{Colors.BOLD}[+] Force SSL mode? (y/N): {Colors.ENDC}").lower()
            if ssl_choice == 'y':
                options.append("-ssl")
            elif input(f"{Colors.BOLD}[+] Disable SSL mode? (y/N): {Colors.ENDC}").lower() == 'y':
                options.append("-nossl")
                
        return " ".join(options)

    def _get_authentication(self) -> str:
        """Configure authentication options"""
        if input(f"\n{Colors.BOLD}[+] Use HTTP authentication? (y/N): {Colors.ENDC}").lower() == 'y':
            user = input(f"{Colors.BOLD}[+] Enter username: {Colors.ENDC}").strip()
            if user:
                password = input(f"{Colors.BOLD}[+] Enter password: {Colors.ENDC}").strip()
                return f"-id {user}:{password}"
        return ""

    def _get_scan_tuning(self) -> str:
        """Configure scan tuning options"""
        if input(f"\n{Colors.BOLD}[+] Configure scan tuning? (y/N): {Colors.ENDC}").lower() == 'y':
            print(f"\n{Colors.CYAN}[*] Available Tuning Options:{Colors.ENDC}")
            for key, desc in self._scan_tuning.items():
                print(f"{Colors.GREEN}{key}:{Colors.ENDC} {desc}")
            
            print("\nEnter numbers for tests to include (e.g., 134)")
            print("Add '-' before numbers to exclude those tests")
            tuning = input(f"\n{Colors.BOLD}[+] Enter tuning string: {Colors.ENDC}").strip()
            if tuning:
                return f"-Tuning {tuning}"
        return ""

    def _get_evasion_options(self) -> str:
        """Configure evasion techniques"""
        if input(f"\n{Colors.BOLD}[+] Use evasion techniques? (y/N): {Colors.ENDC}").lower() == 'y':
            print(f"\n{Colors.CYAN}[*] Evasion Techniques:{Colors.ENDC}")
            print("1: Random URI encoding")
            print("2: Directory self-reference (/./)")
            print("3: Premature URL ending")
            print("4: Prepend long random string")
            print("5: Fake parameter")
            print("6: TAB as request spacer")
            print("7: Change the case of the URL")
            print("8: Use Windows directory separator \\")
            
            techniques = input(f"\n{Colors.BOLD}[+] Enter technique numbers (e.g., 1234): {Colors.ENDC}").strip()
            if techniques:
                return f"-evasion {techniques}"
        return ""
    
    def _get_proxy_options(self) -> str:
            """Configure proxy settings"""
            if input(f"\n{Colors.BOLD}[+] Use a proxy? (y/N): {Colors.ENDC}").lower() == 'y':
                print("\n1. HTTP proxy")
                print("2. SOCKS proxy")
                
                choice = input(f"\n{Colors.BOLD}[+] Select proxy type (1-2): {Colors.ENDC}").strip()
                proxy = input(f"{Colors.BOLD}[+] Enter proxy (host:port): {Colors.ENDC}").strip()
                
                if proxy:
                    if choice == "2":
                        return f"-proxy socks5://{proxy}"
                    return f"-proxy {proxy}"
            return ""

    def _get_output_options(self) -> str:
        """Configure output options"""
        options = []
        
        # Create output directory
        self._output_dir.mkdir(exist_ok=True)
        
        # Output format
        print(f"\n{Colors.CYAN}[*] Available Output Formats:{Colors.ENDC}")
        print("1. Text (Default)")
        print("2. CSV")
        print("3. XML")
        print("4. HTML")
        
        choice = input(f"\n{Colors.BOLD}[+] Select output format (1-4): {Colors.ENDC}").strip()
        format_map = {"1": "txt", "2": "csv", "3": "xml", "4": "htm"}
        
        if choice in format_map:
            ext = format_map[choice]
            filename = f"nikto_scan_{int(time.time())}.{ext}"
            output_file = self._output_dir / filename
            options.extend(["-o", str(output_file), "-Format", ext])
            
        # Verbosity level
        print(f"\n{Colors.CYAN}[*] Verbosity Levels:{Colors.ENDC}")
        print("1. Normal (Default)")
        print("2. Verbose")
        print("3. Debug")
        
        choice = input(f"\n{Colors.BOLD}[+] Select verbosity level (1-3): {Colors.ENDC}").strip()
        if choice == "2":
            options.append("-verbose")
        elif choice == "3":
            options.append("-debug")
            
        return " ".join(options)

    def _get_advanced_options(self) -> List[str]:
        """Configure advanced options"""
        options = []
        
        if input(f"\n{Colors.BOLD}[+] Configure advanced options? (y/N): {Colors.ENDC}").lower() == 'y':
            # Custom User-Agent
            if input(f"{Colors.BOLD}[+] Use custom User-Agent? (y/N): {Colors.ENDC}").lower() == 'y':
                agent = input(f"{Colors.BOLD}[+] Enter User-Agent string: {Colors.ENDC}").strip()
                if agent:
                    options.append(f"-useragent \"{agent}\"")
            
            # Request timeout
            if input(f"{Colors.BOLD}[+] Set request timeout? (y/N): {Colors.ENDC}").lower() == 'y':
                timeout = input(f"{Colors.BOLD}[+] Enter timeout in seconds: {Colors.ENDC}").strip()
                if timeout.isdigit():
                    options.append(f"-timeout {timeout}")
            
            # No 404 checks
            if input(f"{Colors.BOLD}[+] Disable 404 checks? (y/N): {Colors.ENDC}").lower() == 'y':
                options.append("-no404")
            
            # Follow redirects
            if input(f"{Colors.BOLD}[+] Follow redirects? (y/N): {Colors.ENDC}").lower() == 'y':
                options.append("-followredirects")
            
            # Cookies
            if input(f"{Colors.BOLD}[+] Set cookies? (y/N): {Colors.ENDC}").lower() == 'y':
                cookies = input(f"{Colors.BOLD}[+] Enter cookies (name=value;...): {Colors.ENDC}").strip()
                if cookies:
                    options.append(f"-Cookies \"{cookies}\"")
        
        return options

    def _execute_nikto(self, command: str) -> bool:
        """
        Execute nikto with real-time output
        
        Returns:
            bool: True if user wants to perform another scan, False otherwise
        """
        try:
            # Add basic options to all scans
            if "-Save" not in command:
                command += " -Save resume.txt"  # Enable scan resume capability
            
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
                if self._output_dir.exists():
                    print(f"{Colors.CYAN}[*] Results saved in: {self._output_dir}{Colors.ENDC}")

            # Ask user if they want to perform another scan
            while True:
                choice = input(f"\n{Colors.BOLD}[?] Would you like to perform another scan? (y/N): {Colors.ENDC}").lower()
                if choice in ['y', 'n', '']:
                    return choice == 'y'
                print(f"{Colors.FAIL}[!] Please enter 'y' for yes or 'n' for no{Colors.ENDC}")

        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] You can resume this scan later using -resume{Colors.ENDC}")
            process.terminate()
            return False
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error during scan: {e}{Colors.ENDC}")
            return False

    def run_guided(self) -> None:
        """Interactive guided mode for nikto"""
        self._show_banner()

        while True:
            try:
                # Step 1: Get target
                target = self._get_target()
                if not target:
                    return

                # Build command parts list
                command_parts = ["nikto"]
                command_parts.append(target)

                # Step 2: Get port/SSL options
                port_opts = self._get_port_options()
                if port_opts:
                    command_parts.append(port_opts)

                # Step 3: Authentication
                auth_opts = self._get_authentication()
                if auth_opts:
                    command_parts.append(auth_opts)

                # Step 4: Scan tuning
                tuning = self._get_scan_tuning()
                if tuning:
                    command_parts.append(tuning)

                # Step 5: Evasion options
                evasion = self._get_evasion_options()
                if evasion:
                    command_parts.append(evasion)

                # Step 6: Proxy configuration
                proxy = self._get_proxy_options()
                if proxy:
                    command_parts.append(proxy)

                # Step 7: Output options
                output_opts = self._get_output_options()
                if output_opts:
                    command_parts.append(output_opts)

                # Step 8: Advanced options
                command_parts.extend(self._get_advanced_options())

                # Build final command
                command = " ".join(command_parts)

                # Show scan summary
                print(f"\n{Colors.CYAN}[*] Scan Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 30)
                print(f"Target: {target}")
                print(f"Command: {command}")

                if input(f"\n{Colors.BOLD}[+] Start scan? (Y/n): {Colors.ENDC}").lower() != 'n':
                    print(f"\n{Colors.CYAN}[*] Executing scan...{Colors.ENDC}")
                    print(f"{Colors.CYAN}[*] Press Ctrl+C to pause scan (can be resumed later){Colors.ENDC}")
                    if not self._execute_nikto(command):
                        break
                else:
                    print(f"\n{Colors.WARNING}[!] Scan cancelled by user{Colors.ENDC}")
                    if input(f"\n{Colors.BOLD}[?] Would you like to configure another scan? (y/N): {Colors.ENDC}").lower() != 'y':
                        break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for nikto"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter nikto commands directly{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  help     - Show nikto help")
        print("  plugins  - Show available plugins")
        print("  examples - Show usage examples")
        print("  resume   - Resume previous scan")
        print("  update   - Update nikto database")
        print("  exit     - Exit to main menu")
        
        while True:
            try:
                command = input(f"\n{Colors.BOLD}nikto > {Colors.ENDC}").strip()
                
                if not command:
                    continue
                    
                if command.lower() == 'exit':
                    break
                    
                elif command.lower() == 'help':
                    subprocess.run(['nikto', '-H'])
                    
                elif command.lower() == 'plugins':
                    subprocess.run(['nikto', '-list-plugins'])
                    
                elif command.lower() == 'update':
                    print(f"\n{Colors.CYAN}[*] Updating nikto database...{Colors.ENDC}")
                    subprocess.run(['nikto', '-update'])
                    
                elif command.lower() == 'resume':
                    if Path('resume.txt').exists():
                        if not self._execute_nikto('nikto -resume resume.txt'):
                            break
                    else:
                        print(f"{Colors.FAIL}[!] No resume file found{Colors.ENDC}")
                    
                elif command.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] Usage Examples:{Colors.ENDC}")
                    
                    print(f"\n{Colors.GREEN}1. Basic Scan{Colors.ENDC}")
                    print("nikto -h example.com")
                    
                    print(f"\n{Colors.GREEN}2. SSL Scan{Colors.ENDC}")
                    print("nikto -h example.com -ssl -p 443")
                    
                    print(f"\n{Colors.GREEN}3. Authentication{Colors.ENDC}")
                    print("nikto -h example.com -id admin:password")
                    
                    print(f"\n{Colors.GREEN}4. Tuning Options{Colors.ENDC}")
                    print("nikto -h example.com -Tuning 123 # File Upload + Default Files + Info Disclosure")
                    
                    print(f"\n{Colors.GREEN}5. Evasion Techniques{Colors.ENDC}")
                    print("nikto -h example.com -evasion 12 # Random URI encoding + Directory self-reference")
                    
                    print(f"\n{Colors.GREEN}6. Proxy Usage{Colors.ENDC}")
                    print("nikto -h example.com -proxy localhost:8080")
                    
                    print(f"\n{Colors.GREEN}7. Output Options{Colors.ENDC}")
                    print("nikto -h example.com -o scan.html -Format htm")
                    
                    print(f"\n{Colors.GREEN}8. Advanced Options{Colors.ENDC}")
                    print("nikto -h example.com -useragent 'Custom Agent' -timeout 10")
                    
                else:
                    # If not a special command, execute as nikto command
                    if not command.startswith('nikto '):
                        command = f"nikto {command}"
                        
                    try:
                        if not self._execute_nikto(command):
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
