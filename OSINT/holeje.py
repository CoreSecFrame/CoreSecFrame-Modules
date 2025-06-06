#!/usr/bin/env python3
# modules/osint/holehe.py

import subprocess
import shutil
import re
import sys
import os
from pathlib import Path
from typing import List, Optional

# Try different import methods
try:
    from core.base import ToolModule
    from core.colors import Colors
except ImportError:
    try:
        from modules.core.base import ToolModule
        from modules.core.colors import Colors
    except ImportError:
        # Create minimal fallback classes if imports fail
        class ToolModule:
            def __init__(self):
                pass
            def _get_name(self) -> str:
                return ""
            def _get_category(self) -> str:
                return ""
            def _get_command(self) -> str:
                return ""
            def _get_description(self) -> str:
                return ""
            def _get_dependencies(self) -> List[str]:
                return []
            def check_installation(self) -> bool:
                return False
            def run_guided(self) -> None:
                pass
            def run_direct(self) -> None:
                pass
            def get_help(self) -> dict:
                return {}
        
        class Colors:
            CYAN = '\033[96m'
            GREEN = '\033[92m'
            WARNING = '\033[93m'
            FAIL = '\033[91m'
            ENDC = '\033[0m'
            BOLD = '\033[1m'

class Holehe(ToolModule):
    def __init__(self):
        super().__init__()

    def _get_name(self) -> str:
        return "holehe"

    def _get_category(self) -> str:
        return "OSINT"

    def _get_command(self) -> str:
        return "holehe"

    def _get_description(self) -> str:
        return "Email to associated accounts finder for OSINT investigations"

    def _get_dependencies(self) -> List[str]:
        return ["python3", "python3-pip", "pipx"]

    def _get_script_path(self) -> str:
        return "holehe"

    def _find_holehe_command(self) -> Optional[str]:
        """Find the correct holehe command"""
        
        # Option 1: Direct command (if in PATH)
        if shutil.which("holehe"):
            return "holehe"
        
        # Option 2: Python module
        try:
            result = subprocess.run(
                ["python3", "-c", "import holehe"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return "python3 -m holehe"
        except:
            pass
        
        # Option 3: pipx run
        try:
            result = subprocess.run(
                ["pipx", "list"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and "holehe" in result.stdout:
                return "pipx run holehe"
        except:
            pass
        
        return None

    def check_installation(self) -> bool:
        """Check if holehe is properly installed"""
        try:
            command = self._find_holehe_command()
            if not command:
                return False
            
            # Test the command
            if command.startswith("python3 -m"):
                test_cmd = ["python3", "-m", "holehe", "--help"]
            elif command.startswith("pipx run"):
                test_cmd = ["pipx", "run", "holehe", "--help"]
            else:
                test_cmd = [command, "--help"]
            
            result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return result.returncode == 0
            
        except Exception:
            return False

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        commands = {
            'apt': [
                "apt-get update",
                "apt-get install -y python3 python3-pip pipx",
                "pipx install holehe",
                "pipx ensurepath"
            ],
            'yum': [
                "yum update -y",
                "yum install -y python3 python3-pip",
                "python3 -m pip install --user pipx",
                "pipx install holehe",
                "pipx ensurepath"
            ],
            'dnf': [
                "dnf update -y", 
                "dnf install -y python3 python3-pip",
                "python3 -m pip install --user pipx",
                "pipx install holehe",
                "pipx ensurepath"
            ],
            'pacman': [
                "pacman -Sy",
                "pacman -S python python-pip --noconfirm",
                "python3 -m pip install --user pipx",
                "pipx install holehe",
                "pipx ensurepath"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        commands = {
            'apt': ["pipx upgrade holehe"],
            'yum': ["pipx upgrade holehe"],
            'dnf': ["pipx upgrade holehe"],
            'pacman': ["pipx upgrade holehe"]
        }
        return commands.get(pkg_manager, [])

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        commands = {
            'apt': ["pipx uninstall holehe"],
            'yum': ["pipx uninstall holehe"],
            'dnf': ["pipx uninstall holehe"],
            'pacman': ["pipx uninstall holehe"]
        }
        return commands.get(pkg_manager, [])

    def get_help(self) -> dict:
        return {
            "title": "Holehe - Email Account Finder",
            "usage": "use holehe",
            "desc": "Email to associated accounts finder for OSINT investigations",
            "modes": {
                "Guided": "Interactive mode for email analysis",
                "Direct": "Direct CLI execution with custom parameters"
            },
            "options": {
                "--email": "Target email address for analysis (required)",
                "--output": "Output file to save results",
                "--json": "Output results in JSON format"
            },
            "examples": [
                'holehe test@gmail.com',
                'holehe user@example.com --output results.txt',
                'holehe target@domain.com --json'
            ]
        }

    def _show_banner(self):
        print(f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║                HOLEHE                    ║
║         "Email Account Finder"           ║
║            pipx Version                  ║
╚══════════════════════════════════════════╝{Colors.ENDC}''')

    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def _get_emails(self) -> Optional[str]:
        while True:
            emails = input(f"\n{Colors.BOLD}[+] Enter email address to analyze: {Colors.ENDC}").strip()
            if emails:
                if self._validate_email(emails):
                    return emails
                else:
                    print(f"{Colors.FAIL}[!] Invalid email format{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}[!] Email address is required{Colors.ENDC}")
            
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_cli_options(self) -> List[str]:
        options = []
        
        # Output file
        if input(f"\n{Colors.BOLD}[+] Save results to file? (y/N): {Colors.ENDC}").lower() == 'y':
            filename = input(f"{Colors.BOLD}[+] Enter filename (default: holehe_results.txt): {Colors.ENDC}").strip()
            if not filename:
                filename = "holehe_results.txt"
            options.extend(["--output", filename])
        
        # JSON output
        if input(f"{Colors.BOLD}[+] Output in JSON format? (y/N): {Colors.ENDC}").lower() == 'y':
            options.append("--json")
        
        return options

    def _execute_cli(self, email: str, options: List[str]) -> bool:
        """Execute Holehe with automatic command detection"""
        try:
            # Find the correct command
            command = self._find_holehe_command()
            if not command:
                print(f"{Colors.FAIL}[!] Holehe command not found{Colors.ENDC}")
                print(f"{Colors.WARNING}[*] Installation might be incomplete{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Trying alternative installation methods...{Colors.ENDC}")
                
                # Try to reinstall
                try:
                    subprocess.run(["pipx", "install", "holehe", "--force"], 
                                 capture_output=True, timeout=60)
                    subprocess.run(["pipx", "ensurepath"], capture_output=True, timeout=10)
                    
                    # Try again
                    command = self._find_holehe_command()
                    if not command:
                        return False
                except:
                    return False
            
            # Build the command
            if command.startswith("python3 -m"):
                cmd = ["python3", "-m", "holehe", email] + options
            elif command.startswith("pipx run"):
                cmd = ["pipx", "run", "holehe", email] + options
            else:
                cmd = [command, email] + options
            
            print(f"\n{Colors.CYAN}[*] Executing Holehe...{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Using command: {command}{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Analyzing email: {email}{Colors.ENDC}")
            
            if options:
                print(f"{Colors.CYAN}[*] Options: {' '.join(options)}{Colors.ENDC}")
            
            # Execute with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Print output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
            
            return_code = process.wait()
            
            if return_code == 0:
                print(f"\n{Colors.GREEN}[✓] Analysis completed successfully{Colors.ENDC}")
                return True
            else:
                print(f"\n{Colors.FAIL}[!] Analysis failed with return code {return_code}{Colors.ENDC}")
                return False
                
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Analysis interrupted by user{Colors.ENDC}")
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
            return False
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error during CLI execution: {e}{Colors.ENDC}")
            return False

    def run_guided(self) -> None:
        """Interactive guided mode for holehe"""
        self._show_banner()

        while True:
            try:
                print(f"\n{Colors.CYAN}[*] CLI Mode - Email Account Analysis{Colors.ENDC}")
                
                # Check if command is available
                command = self._find_holehe_command()
                if command:
                    print(f"{Colors.GREEN}[✓] Found holehe at: {command}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] Holehe command not found{Colors.ENDC}")
                    print(f"{Colors.CYAN}[*] Will attempt to locate or reinstall during execution{Colors.ENDC}")
                
                email = self._get_emails()
                if not email:
                    print(f"{Colors.WARNING}[!] No email provided{Colors.ENDC}")
                    continue
                
                options = self._get_cli_options()
                
                print(f"\n{Colors.CYAN}[*] Analysis Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 30)
                print(f"Email: {email}")
                if options:
                    print(f"Options: {' '.join(options)}")
                
                if input(f"\n{Colors.BOLD}[+] Start analysis? (Y/n): {Colors.ENDC}").lower() != 'n':
                    if self._execute_cli(email, options):
                        print(f"{Colors.GREEN}[✓] Email analysis completed{Colors.ENDC}")

                if input(f"\n{Colors.BOLD}[?] Would you like to analyze another email? (y/N): {Colors.ENDC}").lower() != 'y':
                    break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for holehe"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter holehe commands{Colors.ENDC}")
        
        # Show current command status
        command = self._find_holehe_command()
        if command:
            print(f"{Colors.GREEN}[✓] Holehe found: {command}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] Holehe command not found{Colors.ENDC}")
        
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  help        - Show holehe help")
        print("  test        - Test installation")
        print("  exit        - Exit to main menu")
        
        while True:
            try:
                command_input = input(f"\n{Colors.BOLD}holehe > {Colors.ENDC}").strip()
                
                if not command_input:
                    continue
                    
                if command_input.lower() == 'exit':
                    break
                    
                elif command_input.lower() == 'test':
                    print(f"{Colors.CYAN}[*] Testing holehe installation...{Colors.ENDC}")
                    if self.check_installation():
                        print(f"{Colors.GREEN}[✓] Holehe is working properly{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Holehe is not working properly{Colors.ENDC}")
                
                elif command_input.lower() == 'help':
                    command = self._find_holehe_command()
                    if command:
                        if command.startswith("python3 -m"):
                            subprocess.run(["python3", "-m", "holehe", "--help"])
                        elif command.startswith("pipx run"):
                            subprocess.run(["pipx", "run", "holehe", "--help"])
                        else:
                            subprocess.run([command, "--help"])
                    else:
                        print(f"{Colors.FAIL}[!] Holehe not available{Colors.ENDC}")
                
                else:
                    # Execute as holehe command
                    if self._validate_email(command_input):
                        email = command_input
                        if self._execute_cli(email, []):
                            print(f"{Colors.GREEN}[✓] Analysis completed{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Invalid email format or unknown command{Colors.ENDC}")
                        
            except KeyboardInterrupt:
                print()
                continue

# For backward compatibility
def get_tool():
    """Legacy function to get tool instance"""
    return Holehe()

if __name__ == "__main__":
    tool = Holehe()
    
    if len(sys.argv) > 1 and sys.argv[1] == "direct":
        tool.run_direct()
    else:
        tool.run_guided()