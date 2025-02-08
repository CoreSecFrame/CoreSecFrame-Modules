from core.base import ToolModule
from core.colors import Colors
import subprocess
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class HydraModule(ToolModule):
    def __init__(self):
        self._wordlists = {
            "rockyou": "/usr/share/wordlists/rockyou.txt",
            "fasttrack": "/usr/share/wordlists/fasttrack.txt",
            "fern-wifi": "/usr/share/wordlists/fern-wifi/common.txt"
        }
        
        self._protocols = {
            "ssh": "SSH protocol",
            "ftp": "FTP protocol",
            "mysql": "MySQL database",
            "smb": "Samba/SMB protocol",
            "postgres": "PostgreSQL database",
            "rdp": "Remote Desktop Protocol",
            "telnet": "Telnet protocol",
            "http-get": "HTTP GET method",
            "http-post-form": "HTTP POST form",
            "http-basic": "HTTP basic auth",
            "https-get": "HTTPS GET method",
            "https-post-form": "HTTPS POST form",
            "vnc": "VNC remote access"
        }
        
        self._output_dir = Path.home() / "hydra_results"
        super().__init__()

    def _get_name(self) -> str:
        return "Hydra"

    def _get_category(self) -> str:
        return "Cracking"

    def _get_command(self) -> str:
        return "hydra"

    def _get_description(self) -> str:
        return "Fast network logon cracker supporting multiple protocols"

    def _get_dependencies(self) -> List[str]:
        return ["hydra"]

    def _get_script_path(self) -> str:
        """Returns path to script if applicable"""
        return ""  # Hydra is a binary, no script needed

    def get_help(self) -> dict:
        return {
            "title": "Hydra - Network Login Cracker",
            "usage": "use hydra",
            "desc": "Fast and flexible login cracker supporting multiple protocols and services",
            "modes": {
                "Guided": "Interactive mode that guides through attack configuration",
                "Direct": "Direct command execution with full hydra syntax"
            },
            "options": {
                "-l LOGIN": "Single login name",
                "-L FILE": "File with login names",
                "-p PASS": "Single password",
                "-P FILE": "File with passwords",
                "-C FILE": "File with colon separated user:pass pairs",
                "-e nsr": "Try empty/login/reversed login password",
                "-t TASKS": "Number of parallel tasks",
                "-s PORT": "Target port number",
                "-o FILE": "Write output to file",
                "-f": "Stop after first valid password found",
                "-v": "Verbose mode"
            },
            "examples": [
                "hydra -l admin -P wordlist.txt 10.0.0.1 ssh",
                "hydra -L users.txt -P pass.txt ftp://192.168.1.1",
                "hydra -l admin -P wordlist.txt http-post-form://example.com/login",
                "hydra -C creds.txt ssh://10.0.0.1",
                "hydra -l root -P wordlist.txt mysql://localhost"
            ],
            "notes": [
                "Some protocols require specific input formats",
                "Use proper thread count to avoid server lockouts",
                "Consider using -f flag for production systems",
                "HTTP form attacks require proper request format"
            ]
        }

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Returns installation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y hydra"
            ],
            'yum': [
                "sudo yum update",
                "sudo yum install -y epel-release",
                "sudo yum install -y hydra"
            ],
            'dnf': [
                "sudo dnf update",
                "sudo dnf install -y hydra"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S hydra --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Returns update commands for different package managers"""
        return self._get_install_command(pkg_manager)  # Same as install for hydra

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Returns uninstallation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get remove -y hydra",
                "sudo apt-get autoremove -y"
            ],
            'yum': [
                "sudo yum remove -y hydra",
                "sudo yum autoremove -y"
            ],
            'dnf': [
                "sudo dnf remove -y hydra",
                "sudo dnf autoremove -y"
            ],
            'pacman': [
                "sudo pacman -Rs hydra --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _show_banner(self):
        """Display the module banner"""
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║              HYDRA                        ║
║      "Network Login Cracker"             ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _get_protocol(self) -> Optional[str]:
        """Get and validate protocol"""
        print(f"\n{Colors.CYAN}[*] Available Protocols:{Colors.ENDC}")
        
        # Group protocols by type
        web_protocols = {k: v for k, v in self._protocols.items() if 'http' in k}
        db_protocols = {k: v for k, v in self._protocols.items() if 'sql' in k or k == 'postgres'}
        remote_protocols = {k: v for k, v in self._protocols.items() if k in ['ssh', 'telnet', 'vnc', 'rdp']}
        file_protocols = {k: v for k, v in self._protocols.items() if k in ['ftp', 'smb']}
        
        print(f"\n{Colors.GREEN}Web Protocols:{Colors.ENDC}")
        for protocol, desc in web_protocols.items():
            print(f"  • {protocol}: {desc}")
            
        print(f"\n{Colors.GREEN}Database Protocols:{Colors.ENDC}")
        for protocol, desc in db_protocols.items():
            print(f"  • {protocol}: {desc}")
            
        print(f"\n{Colors.GREEN}Remote Access Protocols:{Colors.ENDC}")
        for protocol, desc in remote_protocols.items():
            print(f"  • {protocol}: {desc}")
            
        print(f"\n{Colors.GREEN}File Transfer Protocols:{Colors.ENDC}")
        for protocol, desc in file_protocols.items():
            print(f"  • {protocol}: {desc}")
            
        while True:
            protocol = input(f"\n{Colors.BOLD}[+] Enter protocol: {Colors.ENDC}").strip().lower()
            if protocol in self._protocols:
                return protocol
            print(f"{Colors.FAIL}[!] Invalid protocol{Colors.ENDC}")
            
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_target(self) -> Optional[str]:
        """Get target information"""
        while True:
            target = input(f"\n{Colors.BOLD}[+] Enter target (IP/hostname): {Colors.ENDC}").strip()
            if target:
                # Optional port specification
                if input(f"{Colors.BOLD}[+] Specify custom port? (y/N): {Colors.ENDC}").lower() == 'y':
                    port = input(f"{Colors.BOLD}[+] Enter port number: {Colors.ENDC}").strip()
                    if port.isdigit():
                        return f"{target} -s {port}"
                return target
            
            print(f"{Colors.FAIL}[!] Target is required{Colors.ENDC}")
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_credentials_mode(self) -> Optional[Tuple[List[str], bool]]:
        """Configure credentials mode and get related options"""
        print(f"\n{Colors.CYAN}[*] Credentials Mode:{Colors.ENDC}")
        print("1. Single username")
        print("2. Username list")
        print("3. Username:password combinations file")
        
        options = []
        stop_first = False
        
        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select mode (1-3): {Colors.ENDC}").strip()
            
            if choice == "1":
                username = input(f"{Colors.BOLD}[+] Enter username: {Colors.ENDC}").strip()
                if username:
                    options.append(f"-l {username}")
                    break
            
            elif choice == "2":
                userlist = input(f"{Colors.BOLD}[+] Enter path to username list: {Colors.ENDC}").strip()
                if userlist and Path(userlist).is_file():
                    options.append(f"-L {userlist}")
                    break
                print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
            
            elif choice == "3":
                combos = input(f"{Colors.BOLD}[+] Enter path to combinations file: {Colors.ENDC}").strip()
                if combos and Path(combos).is_file():
                    options.append(f"-C {combos}")
                    return options, stop_first
                print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
            
            else:
                print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
            
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None, False
        
        # If not using combo file, get password options
        if choice != "3":
            print(f"\n{Colors.CYAN}[*] Password Options:{Colors.ENDC}")
            print("1. Single password")
            print("2. Password list")
            print("3. Try empty/username/reversed username")
            
            while True:
                pass_choice = input(f"\n{Colors.BOLD}[+] Select option (1-3): {Colors.ENDC}").strip()
                
                if pass_choice == "1":
                    password = input(f"{Colors.BOLD}[+] Enter password: {Colors.ENDC}").strip()
                    if password:
                        options.append(f"-p {password}")
                        break
                
                elif pass_choice == "2":
                    print(f"\n{Colors.CYAN}[*] Available Wordlists:{Colors.ENDC}")
                    for i, (name, path) in enumerate(self._wordlists.items(), 1):
                        exists = "✓" if Path(path).exists() else "✗"
                        print(f"{Colors.GREEN}{i}:{Colors.ENDC} {name} [{exists}] - {path}")
                    print(f"{Colors.GREEN}{len(self._wordlists) + 1}:{Colors.ENDC} Custom wordlist")
                    
                    wordlist_choice = input(f"\n{Colors.BOLD}[+] Select wordlist (1-{len(self._wordlists) + 1}): {Colors.ENDC}").strip()
                    
                    if wordlist_choice == str(len(self._wordlists) + 1):
                        custom_path = input(f"{Colors.BOLD}[+] Enter wordlist path: {Colors.ENDC}").strip()
                        if custom_path and Path(custom_path).is_file():
                            options.append(f"-P {custom_path}")
                            break
                        print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
                    else:
                        try:
                            idx = int(wordlist_choice) - 1
                            if 0 <= idx < len(self._wordlists):
                                path = Path(list(self._wordlists.values())[idx])
                                if path.exists():
                                    options.append(f"-P {path}")
                                    break
                                print(f"{Colors.FAIL}[!] Wordlist not found: {path}{Colors.ENDC}")
                            else:
                                print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                        except ValueError:
                            print(f"{Colors.FAIL}[!] Invalid input{Colors.ENDC}")
                
                elif pass_choice == "3":
                    options.append("-e nsr")
                    break
                
                else:
                    print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                    
                retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
                if retry == 'n':
                    return None, False
        
        # Ask if should stop after first valid password
        if input(f"\n{Colors.BOLD}[+] Stop after finding first valid password? (y/N): {Colors.ENDC}").lower() == 'y':
            stop_first = True
            
        return options, stop_first

    def _get_http_form_options(self) -> Optional[str]:
            """Configure HTTP form options"""
            print(f"\n{Colors.CYAN}[*] HTTP Form Configuration{Colors.ENDC}")
            
            # Get URL path
            path = input(f"{Colors.BOLD}[+] Enter login form path (e.g., /login.php): {Colors.ENDC}").strip()
            if not path:
                return None
                
            # Get form method
            print("\n1. GET")
            print("2. POST")
            method = input(f"{Colors.BOLD}[+] Select form method (1-2): {Colors.ENDC}").strip()
            if method not in ["1", "2"]:
                return None
                
            # Get form data
            print(f"\n{Colors.CYAN}[*] Form Data Configuration{Colors.ENDC}")
            print("Example: user=^USER^&pass=^PASS^:F=Login failed")
            print("Use ^USER^ and ^PASS^ as placeholders")
            print("Add :F=text to specify failed login message")
            form_data = input(f"{Colors.BOLD}[+] Enter form data: {Colors.ENDC}").strip()
            if not form_data:
                return None
                
            # Build the HTTP form string
            protocol = "http-get-form" if method == "1" else "http-post-form"
            return f"{protocol}:\"{path}:{form_data}\""

    def _get_advanced_options(self) -> List[str]:
        """Configure advanced options"""
        options = []
        
        if input(f"\n{Colors.BOLD}[+] Configure advanced options? (y/N): {Colors.ENDC}").lower() == 'y':
            # Task count
            if input(f"{Colors.BOLD}[+] Set number of parallel tasks? (y/N): {Colors.ENDC}").lower() == 'y':
                tasks = input(f"{Colors.BOLD}[+] Enter number of tasks (1-64): {Colors.ENDC}").strip()
                if tasks.isdigit() and 1 <= int(tasks) <= 64:
                    options.append(f"-t {tasks}")
            
            # Connection timeout
            if input(f"{Colors.BOLD}[+] Set custom timeout? (y/N): {Colors.ENDC}").lower() == 'y':
                timeout = input(f"{Colors.BOLD}[+] Enter timeout in seconds (1-60): {Colors.ENDC}").strip()
                if timeout.isdigit() and 1 <= int(timeout) <= 60:
                    options.append(f"-w {timeout}")
            
            # Verbose mode
            if input(f"{Colors.BOLD}[+] Enable verbose mode? (y/N): {Colors.ENDC}").lower() == 'y':
                verbose = input(f"{Colors.BOLD}[+] Enter verbosity level (1-5): {Colors.ENDC}").strip()
                if verbose.isdigit() and 1 <= int(verbose) <= 5:
                    options.append(f"-{'v' * int(verbose)}")
            
            # SSL Options for HTTPS
            if input(f"{Colors.BOLD}[+] Configure SSL options? (y/N): {Colors.ENDC}").lower() == 'y':
                options.append("-S")  # Enable SSL
                if input(f"{Colors.BOLD}[+] Disable SSL certificate verification? (y/N): {Colors.ENDC}").lower() == 'y':
                    options.append("-s")
                
        return options

    def _execute_hydra(self, command: str) -> bool:
        """
        Execute hydra with real-time output
        
        Returns:
            bool: True if user wants to perform another attack, False otherwise
        """
        try:
            # Create output directory if needed
            self._output_dir.mkdir(exist_ok=True)
            output_file = self._output_dir / f"hydra_{int(time.time())}.txt"
            command += f" -o {output_file}"
            
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
                    print(f"{Colors.FAIL}[!] Errors during attack:{Colors.ENDC}")
                    print(stderr)
            else:
                print(f"\n{Colors.GREEN}[✓] Attack completed successfully{Colors.ENDC}")
                if output_file.exists():
                    print(f"{Colors.CYAN}[*] Results saved to: {output_file}{Colors.ENDC}")

            # Ask user if they want to perform another attack
            while True:
                choice = input(f"\n{Colors.BOLD}[?] Would you like to perform another attack? (y/N): {Colors.ENDC}").lower()
                if choice in ['y', 'n', '']:
                    return choice == 'y'
                print(f"{Colors.FAIL}[!] Please enter 'y' for yes or 'n' for no{Colors.ENDC}")

        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Attack interrupted by user{Colors.ENDC}")
            process.terminate()
            return False
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error during attack: {e}{Colors.ENDC}")
            return False

    def run_guided(self) -> None:
        """Interactive guided mode for hydra"""
        self._show_banner()

        while True:
            try:
                # Step 1: Get protocol
                protocol = self._get_protocol()
                if not protocol:
                    return
                    
                # Step 2: Get target
                target = self._get_target()
                if not target:
                    return
                    
                # Step 3: Get credentials options
                cred_options, stop_first = self._get_credentials_mode()
                if not cred_options:
                    return
                    
                # Build base command
                command_parts = ["hydra"]
                command_parts.extend(cred_options)
                if stop_first:
                    command_parts.append("-f")
                    
                # Step 4: Protocol-specific options
                if "http" in protocol:
                    form_options = self._get_http_form_options()
                    if not form_options:
                        return
                    command_parts.append(form_options)
                else:
                    command_parts.append(protocol)
                    
                # Step 5: Advanced options
                command_parts.extend(self._get_advanced_options())
                
                # Add target (should be last)
                command_parts.append(target)
                
                # Build final command
                command = " ".join(command_parts)
                
                # Show attack summary
                print(f"\n{Colors.CYAN}[*] Attack Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 30)
                print(f"Protocol: {protocol}")
                print(f"Target: {target}")
                print(f"Command: {command}")
                
                if input(f"\n{Colors.BOLD}[+] Start attack? (Y/n): {Colors.ENDC}").lower() != 'n':
                    print(f"\n{Colors.CYAN}[*] Executing attack...{Colors.ENDC}")
                    if not self._execute_hydra(command):
                        break
                else:
                    print(f"\n{Colors.WARNING}[!] Attack cancelled by user{Colors.ENDC}")
                    if input(f"\n{Colors.BOLD}[?] Would you like to configure another attack? (y/N): {Colors.ENDC}").lower() != 'y':
                        break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for hydra"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter hydra commands directly{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  help     - Show hydra help")
        print("  protocols- Show supported protocols")
        print("  examples - Show usage examples")
        print("  wordlist - Show available wordlists")
        print("  exit     - Exit to main menu")
        
        while True:
            try:
                command = input(f"\n{Colors.BOLD}hydra > {Colors.ENDC}").strip()
                
                if not command:
                    continue
                    
                if command.lower() == 'exit':
                    break
                    
                elif command.lower() == 'help':
                    subprocess.run(['hydra', '-h'])
                    
                elif command.lower() == 'protocols':
                    print(f"\n{Colors.CYAN}[*] Supported Protocols:{Colors.ENDC}")
                    print(f"\n{Colors.GREEN}Web Protocols:{Colors.ENDC}")
                    for protocol, desc in self._protocols.items():
                        if 'http' in protocol:
                            print(f"  • {Colors.BOLD}{protocol}{Colors.ENDC}: {desc}")
                    
                    print(f"\n{Colors.GREEN}Database Protocols:{Colors.ENDC}")
                    for protocol, desc in self._protocols.items():
                        if 'sql' in protocol or protocol == 'postgres':
                            print(f"  • {Colors.BOLD}{protocol}{Colors.ENDC}: {desc}")
                    
                    print(f"\n{Colors.GREEN}Remote Access Protocols:{Colors.ENDC}")
                    for protocol, desc in self._protocols.items():
                        if protocol in ['ssh', 'telnet', 'vnc', 'rdp']:
                            print(f"  • {Colors.BOLD}{protocol}{Colors.ENDC}: {desc}")
                    
                    print(f"\n{Colors.GREEN}File Transfer Protocols:{Colors.ENDC}")
                    for protocol, desc in self._protocols.items():
                        if protocol in ['ftp', 'smb']:
                            print(f"  • {Colors.BOLD}{protocol}{Colors.ENDC}: {desc}")
                    
                elif command.lower() == 'wordlist':
                    print(f"\n{Colors.CYAN}[*] Available Wordlists:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        exists = "✓" if Path(path).exists() else "✗"
                        print(f"  [{exists}] {name}: {path}")
                    
                elif command.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] Usage Examples:{Colors.ENDC}")
                    
                    print(f"\n{Colors.GREEN}1. SSH Bruteforce{Colors.ENDC}")
                    print("Single user, password list:")
                    print("  hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.1")
                    print("\nUser list, single password:")
                    print("  hydra -L users.txt -p password123 ssh://10.0.0.1")
                    
                    print(f"\n{Colors.GREEN}2. FTP Attack{Colors.ENDC}")
                    print("Username:password combinations file:")
                    print("  hydra -C creds.txt ftp://192.168.1.1")
                    
                    print(f"\n{Colors.GREEN}3. HTTP Form Post{Colors.ENDC}")
                    print("Basic form:")
                    print('  hydra -l admin -P pass.txt 10.0.0.1 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Login failed"')
                    print("\nWith custom port:")
                    print('  hydra -l admin -P pass.txt 10.0.0.1 -s 8080 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Login failed"')
                    
                    print(f"\n{Colors.GREEN}4. MySQL Database{Colors.ENDC}")
                    print("  hydra -l root -P passwords.txt mysql://localhost")
                    
                    print(f"\n{Colors.GREEN}5. RDP Attack{Colors.ENDC}")
                    print("  hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.1.1")
                    
                    print(f"\n{Colors.GREEN}6. Advanced Options{Colors.ENDC}")
                    print("With SSL and 4 threads:")
                    print("  hydra -S -t 4 -l admin -P pass.txt https-post-form://10.0.0.1")
                    print("\nVerbose mode with timeout:")
                    print("  hydra -v -t 1 -w 30 -l root -P pass.txt ssh://10.0.0.1")
                    
                else:
                    # If not a special command, execute as hydra command
                    if not command.startswith('hydra '):
                        command = f"hydra {command}"
                        
                    try:
                        if not self._execute_hydra(command):
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
