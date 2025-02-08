from core.base import ToolModule
from core.colors import Colors
import subprocess
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class SQLMapModule(ToolModule):
    def __init__(self):
        self._tamper_scripts = {
            "between": "Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #'",
            "charencode": "URL-encodes all characters in a given payload",
            "space2comment": "Replaces space character with comments",
            "space2dash": "Replaces space character with dash comment",
            "space2hash": "Replaces space character with hash comment",
            "uppercase": "Replaces each letter with its uppercase version",
            "lowercase": "Replaces each letter with its lowercase version",
            "base64encode": "Base64-encodes all characters in a given payload",
            "hex2char": "Replaces each hexadecimal encoded character with its actual character",
            "randomcase": "Replaces each letter with random case version"
        }
        self._output_dir = Path.home() / "sqlmap_results"
        super().__init__()

    def _get_name(self) -> str:
        return "SQLMap"

    def _get_category(self) -> str:
        return "Web"

    def _get_command(self) -> str:
        return "sqlmap"

    def _get_description(self) -> str:
        return "Automatic SQL injection and database takeover tool"

    def _get_dependencies(self) -> List[str]:
        return ["sqlmap", "python3"]

    def _get_script_path(self) -> str:
        """Returns path to script if applicable"""
        return ""  # SQLMap is installed as a package

    def get_help(self) -> dict:
        return {
            "title": "SQLMap - Automated SQL Injection Tool",
            "usage": "use sqlmap",
            "desc": "Powerful tool for detecting and exploiting SQL injection vulnerabilities",
            "modes": {
                "Guided": "Interactive mode that guides through target configuration and attack options",
                "Direct": "Direct command execution with full sqlmap syntax"
            },
            "options": {
                "-u URL": "Target URL",
                "-r FILE": "Load HTTP request from file",
                "--data DATA": "Data string to be sent through POST",
                "--method METHOD": "HTTP method (GET/POST)",
                "--level N": "Level of tests (1-5, default 1)",
                "--risk N": "Risk of tests (1-3, default 1)",
                "--tamper SCRIPT": "Use given script(s) for tampering",
                "--dbms DBMS": "Force specific DBMS",
                "--batch": "Never ask for user input",
                "--random-agent": "Use random User-Agent",
                "--proxy URL": "Use proxy (HTTP/SOCKS)",
                "-v LEVEL": "Verbosity level (0-6)",
                "--threads N": "Max number of concurrent threads",
                "--output-dir DIR": "Custom output directory path"
            },
            "examples": [
                "sqlmap -u \"http://target.com/page.php?id=1\"",
                "sqlmap -u \"http://target.com\" --data=\"id=1\"",
                "sqlmap -r request.txt",
                "sqlmap -u \"http://target.com\" --tamper=space2comment",
                "sqlmap -u \"http://target.com\" --risk=3 --level=5"
            ],
            "notes": [
                "Start with low level/risk values and increase if needed",
                "Some options might trigger WAF/IPS alerts",
                "Use tamper scripts to bypass protections",
                "Consider legal implications before testing"
            ]
        }

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Returns installation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y sqlmap python3-pip"
            ],
            'yum': [
                "sudo yum update",
                "sudo yum install -y epel-release",
                "sudo yum install -y sqlmap python3-pip"
            ],
            'dnf': [
                "sudo dnf update",
                "sudo dnf install -y sqlmap python3-pip"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S sqlmap python3-pip --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Returns update commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install --only-upgrade sqlmap"
            ],
            'yum': [
                "sudo yum update sqlmap"
            ],
            'dnf': [
                "sudo dnf update sqlmap"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S sqlmap"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Returns uninstallation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get remove -y sqlmap",
                "sudo apt-get autoremove -y"
            ],
            'yum': [
                "sudo yum remove -y sqlmap",
                "sudo yum autoremove -y"
            ],
            'dnf': [
                "sudo dnf remove -y sqlmap",
                "sudo dnf autoremove -y"
            ],
            'pacman': [
                "sudo pacman -Rs sqlmap --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _show_banner(self):
        """Display the module banner"""
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║              SQLMAP                       ║
║     "Automated SQL Injection Tool"        ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _get_target(self) -> Optional[str]:
        """Get and validate target"""
        print(f"\n{Colors.CYAN}[*] Target Configuration{Colors.ENDC}")
        print("1. URL (-u)")
        print("2. Request file (-r)")
        print("3. Burp log file (-l)")
        
        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select target type (1-3): {Colors.ENDC}").strip()
            
            if choice == "1":
                url = input(f"{Colors.BOLD}[+] Enter target URL: {Colors.ENDC}").strip()
                if url:
                    # Add POST data if needed
                    if input(f"{Colors.BOLD}[+] Add POST data? (y/N): {Colors.ENDC}").lower() == 'y':
                        data = input(f"{Colors.BOLD}[+] Enter POST data: {Colors.ENDC}").strip()
                        if data:
                            return f"-u \"{url}\" --data=\"{data}\""
                    return f"-u \"{url}\""
                
            elif choice in ["2", "3"]:
                file_path = input(f"{Colors.BOLD}[+] Enter file path: {Colors.ENDC}").strip()
                if file_path:
                    path = Path(file_path)
                    if path.exists() and path.is_file():
                        flag = "-r" if choice == "2" else "-l"
                        return f"{flag} \"{path.absolute()}\""
                    print(f"{Colors.FAIL}[!] File not found: {file_path}{Colors.ENDC}")
            
            else:
                print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
            
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_test_options(self) -> List[str]:
            """Configure testing options"""
            options = []
            
            # Risk level
            print(f"\n{Colors.CYAN}[*] Risk Level Configuration{Colors.ENDC}")
            print("1. Low (Default)")
            print("2. Medium")
            print("3. High")
            
            choice = input(f"\n{Colors.BOLD}[+] Select risk level (1-3): {Colors.ENDC}").strip()
            if choice in ["2", "3"]:
                options.append(f"--risk={choice}")

            # Test level
            print(f"\n{Colors.CYAN}[*] Test Level Configuration{Colors.ENDC}")
            print("1. Basic (Default)")
            print("2. Advanced")
            print("3. Full")
            
            choice = input(f"\n{Colors.BOLD}[+] Select test level (1-3): {Colors.ENDC}").strip()
            if choice == "2":
                options.append("--level=3")
            elif choice == "3":
                options.append("--level=5")

            return options

    def _get_tamper_scripts(self) -> str:
        """Configure tamper scripts"""
        if input(f"\n{Colors.BOLD}[+] Use tamper scripts? (y/N): {Colors.ENDC}").lower() == 'y':
            print(f"\n{Colors.CYAN}[*] Available Tamper Scripts:{Colors.ENDC}")
            for name, desc in self._tamper_scripts.items():
                print(f"• {Colors.GREEN}{name}{Colors.ENDC}: {desc}")
            
            scripts = input(f"\n{Colors.BOLD}[+] Enter script names (comma-separated): {Colors.ENDC}").strip()
            if scripts:
                return f"--tamper={scripts}"
        return ""

    def _get_dbms_options(self) -> str:
        """Configure DBMS options"""
        if input(f"\n{Colors.BOLD}[+] Specify DBMS type? (y/N): {Colors.ENDC}").lower() == 'y':
            print(f"\n{Colors.CYAN}[*] Common DBMS Types:{Colors.ENDC}")
            dbms_types = {
                "1": "MySQL",
                "2": "PostgreSQL",
                "3": "Microsoft SQL Server",
                "4": "Oracle",
                "5": "SQLite"
            }
            
            for key, dbms in dbms_types.items():
                print(f"{key}. {dbms}")
            
            choice = input(f"\n{Colors.BOLD}[+] Select DBMS (1-5): {Colors.ENDC}").strip()
            if choice in dbms_types:
                return f"--dbms={dbms_types[choice]}"
        return ""

    def _get_enumeration_options(self) -> List[str]:
        """Configure enumeration options"""
        options = []
        print(f"\n{Colors.CYAN}[*] Enumeration Options:{Colors.ENDC}")
        
        if input(f"{Colors.BOLD}[+] Enumerate databases? (y/N): {Colors.ENDC}").lower() == 'y':
            options.append("--dbs")
            
        if input(f"{Colors.BOLD}[+] Enumerate tables? (y/N): {Colors.ENDC}").lower() == 'y':
            options.append("--tables")
            
        if input(f"{Colors.BOLD}[+] Dump tables content? (y/N): {Colors.ENDC}").lower() == 'y':
            if input(f"{Colors.BOLD}[+] Dump all tables? (y/N): {Colors.ENDC}").lower() == 'y':
                options.append("--dump-all")
            else:
                options.append("--dump")
                
        if input(f"{Colors.BOLD}[+] Search for specific columns? (y/N): {Colors.ENDC}").lower() == 'y':
            columns = input(f"{Colors.BOLD}[+] Enter column names (comma-separated): {Colors.ENDC}").strip()
            if columns:
                options.append(f"-C {columns}")
                
        return options

    def _get_advanced_options(self) -> List[str]:
        """Configure advanced options"""
        options = []
        
        if input(f"\n{Colors.BOLD}[+] Configure advanced options? (y/N): {Colors.ENDC}").lower() == 'y':
            if input(f"{Colors.BOLD}[+] Use random User-Agent? (y/N): {Colors.ENDC}").lower() == 'y':
                options.append("--random-agent")
                
            if input(f"{Colors.BOLD}[+] Configure proxy? (y/N): {Colors.ENDC}").lower() == 'y':
                proxy = input(f"{Colors.BOLD}[+] Enter proxy URL (e.g., http://127.0.0.1:8080): {Colors.ENDC}").strip()
                if proxy:
                    options.append(f"--proxy={proxy}")
                    
            if input(f"{Colors.BOLD}[+] Configure threads? (y/N): {Colors.ENDC}").lower() == 'y':
                threads = input(f"{Colors.BOLD}[+] Enter number of threads (1-10): {Colors.ENDC}").strip()
                if threads.isdigit() and 1 <= int(threads) <= 10:
                    options.append(f"--threads={threads}")
                    
            if input(f"{Colors.BOLD}[+] Enable verbosity? (y/N): {Colors.ENDC}").lower() == 'y':
                print("1. Basic")
                print("2. Verbose")
                print("3. Very verbose")
                choice = input(f"{Colors.BOLD}[+] Select verbosity level (1-3): {Colors.ENDC}").strip()
                if choice in ["1", "2", "3"]:
                    options.append(f"-v {choice}")
                    
        return options

    def _execute_sqlmap(self, command: str) -> bool:
        """
        Execute sqlmap with real-time output
        
        Returns:
            bool: True if user wants to perform another scan, False otherwise
        """
        try:
            # Add output directory to command
            self._output_dir.mkdir(exist_ok=True)
            command += f" --output-dir=\"{self._output_dir}\""
            
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
                print(f"{Colors.CYAN}[*] Results saved in: {self._output_dir}{Colors.ENDC}")

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
        """Interactive guided mode for sqlmap"""
        self._show_banner()

        while True:
            try:
                # Step 1: Get target
                target = self._get_target()
                if not target:
                    return

                # Step 2: Get test options
                test_options = self._get_test_options()

                # Step 3: Get tamper scripts
                tamper = self._get_tamper_scripts()
                if tamper:
                    test_options.append(tamper)

                # Step 4: Get DBMS options
                dbms = self._get_dbms_options()
                if dbms:
                    test_options.append(dbms)

                # Step 5: Get enumeration options
                enum_options = self._get_enumeration_options()
                test_options.extend(enum_options)

                # Step 6: Get advanced options
                adv_options = self._get_advanced_options()
                test_options.extend(adv_options)

                # Build command
                command_parts = ["sqlmap"]
                command_parts.append(target)
                command_parts.extend(test_options)
                command_parts.append("--batch")  # Add batch mode to avoid user interaction

                command = " ".join(command_parts)

                # Show summary
                print(f"\n{Colors.CYAN}[*] Scan Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 30)
                print(f"Target: {target}")
                if test_options:
                    print("Options:")
                    for opt in test_options:
                        print(f"  • {opt}")

                if input(f"\n{Colors.BOLD}[+] Start scan? (Y/n): {Colors.ENDC}").lower() != 'n':
                    print(f"\n{Colors.CYAN}[*] Executing scan...{Colors.ENDC}")
                    if not self._execute_sqlmap(command):
                        break
                else:
                    print(f"\n{Colors.WARNING}[!] Scan cancelled by user{Colors.ENDC}")
                    if input(f"\n{Colors.BOLD}[?] Would you like to configure another scan? (y/N): {Colors.ENDC}").lower() != 'y':
                        break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for sqlmap"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter sqlmap commands directly{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  help     - Show sqlmap help")
        print("  tamper   - Show available tamper scripts")
        print("  examples - Show usage examples")
        print("  exit     - Exit to main menu")
        
        while True:
            try:
                command = input(f"\n{Colors.BOLD}sqlmap > {Colors.ENDC}").strip()
                
                if not command:
                    continue
                    
                if command.lower() == 'exit':
                    break
                    
                elif command.lower() == 'help':
                    subprocess.run(['sqlmap', '-hh'])
                    
                elif command.lower() == 'tamper':
                    print(f"\n{Colors.CYAN}[*] Available Tamper Scripts:{Colors.ENDC}")
                    for name, desc in self._tamper_scripts.items():
                        print(f"\n{Colors.GREEN}{name}{Colors.ENDC}")
                        print(f"  {desc}")
                    
                elif command.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] Usage Examples:{Colors.ENDC}")
                    
                    print(f"\n{Colors.GREEN}1. Basic GET-based Injection{Colors.ENDC}")
                    print("sqlmap -u \"http://target.com/page.php?id=1\"")
                    
                    print(f"\n{Colors.GREEN}2. POST-based Injection{Colors.ENDC}")
                    print("sqlmap -u \"http://target.com/login.php\" --data=\"user=admin&pass=test\"")
                    
                    print(f"\n{Colors.GREEN}3. From Request File{Colors.ENDC}")
                    print("sqlmap -r request.txt")
                    
                    print(f"\n{Colors.GREEN}4. Database Enumeration{Colors.ENDC}")
                    print("sqlmap -u \"http://target.com/?id=1\" --dbs --tables --dump")
                    
                    print(f"\n{Colors.GREEN}5. With Tamper Scripts{Colors.ENDC}")
                    print("sqlmap -u \"http://target.com\" --tamper=space2comment,between")
                    
                    print(f"\n{Colors.GREEN}6. Advanced Options{Colors.ENDC}")
                    print("sqlmap -u \"http://target.com\" --risk=3 --level=5 --random-agent")
                    
                    print(f"\n{Colors.GREEN}7. Specific DBMS{Colors.ENDC}")
                    print("sqlmap -u \"http://target.com\" --dbms=mysql --batch")
                    
                else:
                    # If not a special command, execute as sqlmap command
                    if not command.startswith('sqlmap '):
                        command = f"sqlmap {command}"
                        
                    try:
                        if not self._execute_sqlmap(command):
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
