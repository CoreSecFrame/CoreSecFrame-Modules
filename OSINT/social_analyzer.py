from core.base import ToolModule
from core.colors import Colors
import subprocess
import os
import shutil
from pathlib import Path
from typing import List, Dict, Optional

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
            
class SocialAnalyzerModule(ToolModule):
    def __init__(self):
        super().__init__()

    def _get_name(self) -> str:
        return "social-analyzer"

    def _get_category(self) -> str:
        return "OSINT"

    def _get_command(self) -> str:
        return "social-analyzer"

    def _get_description(self) -> str:
        return "OSINT tool for analyzing and finding social media accounts by username"

    def _get_dependencies(self) -> List[str]:
        return ["python3", "python3-pip", "pipx"]

    def _get_script_path(self) -> str:
        return "social-analyzer"

    def get_help(self) -> dict:
        return {
            "title": "Social Analyzer - OSINT Social Media Tool",
            "usage": "use social-analyzer",
            "desc": "API, CLI & Web App for analyzing and finding a person's profile across social media platforms",
            "modes": {
                "Guided": "Interactive mode for CLI usage",
                "Direct": "Direct CLI execution with custom parameters"
            },
            "options": {
                "--username": "Target username(s) for analysis (required)",
                "--websites": "Specific websites to search (space separated)",
                "--metadata": "Extract metadata using pypi QeeqBox OSINT",
                "--top": "Number of top websites to check",
                "--type": "Account type filter",
                "--logs": "Enable logging",
                "--screenshots": "Take screenshots",
                "--output": "Output format",
                "--filter": "Filter results (good, maybe, bad)",
                "--timeout": "Timeout between requests"
            },
            "examples": [
                'social-analyzer --username "johndoe"',
                'social-analyzer --username "johndoe" --metadata',
                'social-analyzer --username "johndoe" --top 100'
            ]
        }

    def _find_social_analyzer_command(self) -> Optional[str]:
        """Find the correct social-analyzer command"""
        
        # Option 1: Direct command (if in PATH)
        if shutil.which("social-analyzer"):
            return "social-analyzer"
        
        # Option 2: Python module
        try:
            result = subprocess.run(
                ["python3", "-c", "import social_analyzer"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return "python3 -m social_analyzer"
        except:
            pass
        
        # Option 3: pipx bin directory
        possible_paths = [
            Path.home() / ".local/bin/social-analyzer",
            Path("/usr/local/bin/social-analyzer"),
            Path("/opt/pipx/venvs/social-analyzer/bin/social-analyzer")
        ]
        
        for path in possible_paths:
            if path.exists() and path.is_file():
                return str(path)
        
        # Option 4: Check pipx list and find the path
        try:
            result = subprocess.run(
                ["pipx", "list", "--include-injected"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and "social-analyzer" in result.stdout:
                # Try to extract the path from pipx output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'social-analyzer' in line and 'bin' in line:
                        # This is a heuristic to find the bin path
                        parts = line.split()
                        for part in parts:
                            if 'bin' in part and 'social-analyzer' in part:
                                return part
        except:
            pass
        
        return None

    def check_installation(self) -> bool:
        """Check if social-analyzer is properly installed"""
        try:
            command = self._find_social_analyzer_command()
            if not command:
                return False
            
            # Test the command
            if command.startswith("python3 -m"):
                test_cmd = ["python3", "-m", "social_analyzer", "--help"]
            else:
                test_cmd = [command, "--help"] if not " " in command else command.split() + ["--help"]
            
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
                "pipx install social-analyzer",
                "pipx ensurepath"
            ],
            'yum': [
                "yum update -y",
                "yum install -y python3 python3-pip",
                "python3 -m pip install --user pipx",
                "pipx install social-analyzer",
                "pipx ensurepath"
            ],
            'dnf': [
                "dnf update -y", 
                "dnf install -y python3 python3-pip",
                "python3 -m pip install --user pipx",
                "pipx install social-analyzer",
                "pipx ensurepath"
            ],
            'pacman': [
                "pacman -Sy",
                "pacman -S python python-pip --noconfirm",
                "python3 -m pip install --user pipx",
                "pipx install social-analyzer",
                "pipx ensurepath"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        commands = {
            'apt': ["pipx upgrade social-analyzer"],
            'yum': ["pipx upgrade social-analyzer"],
            'dnf': ["pipx upgrade social-analyzer"],
            'pacman': ["pipx upgrade social-analyzer"]
        }
        return commands.get(pkg_manager, [])

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        commands = {
            'apt': ["pipx uninstall social-analyzer"],
            'yum': ["pipx uninstall social-analyzer"],
            'dnf': ["pipx uninstall social-analyzer"],
            'pacman': ["pipx uninstall social-analyzer"]
        }
        return commands.get(pkg_manager, [])

    def _show_banner(self):
        print(f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║           SOCIAL ANALYZER                ║
║      "OSINT Social Media Tool"           ║
║            pipx Version                  ║
╚══════════════════════════════════════════╝{Colors.ENDC}''')

    def _get_usernames(self) -> Optional[str]:
        while True:
            usernames = input(f"\n{Colors.BOLD}[+] Enter username(s) (comma-separated): {Colors.ENDC}").strip()
            if usernames:
                username_list = [u.strip() for u in usernames.split(',') if u.strip()]
                if username_list:
                    return ','.join(username_list)
            
            print(f"{Colors.FAIL}[!] At least one username is required{Colors.ENDC}")
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_cli_options(self) -> List[str]:
        options = []
        
        # Include metadata
        if input(f"\n{Colors.BOLD}[+] Include metadata in results? (y/N): {Colors.ENDC}").lower() == 'y':
            options.append("--metadata")
        
        # Top sites limit
        if input(f"{Colors.BOLD}[+] Limit number of sites to check? (y/N): {Colors.ENDC}").lower() == 'y':
            while True:
                try:
                    top = int(input(f"{Colors.BOLD}[+] Enter number of top sites (1-1000): {Colors.ENDC}"))
                    if 1 <= top <= 1000:
                        options.extend(["--top", str(top)])
                        break
                    print(f"{Colors.FAIL}[!] Number must be between 1 and 1000{Colors.ENDC}")
                except ValueError:
                    print(f"{Colors.FAIL}[!] Invalid number{Colors.ENDC}")
        
        # Specific websites
        if input(f"\n{Colors.BOLD}[+] Target specific websites? (y/N): {Colors.ENDC}").lower() == 'y':
            print(f"{Colors.CYAN}[*] Enter websites separated by spaces{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Examples: twitter facebook instagram linkedin{Colors.ENDC}")
            websites = input(f"{Colors.BOLD}[+] Websites: {Colors.ENDC}").strip()
            if websites:
                options.extend(["--websites", websites])
        
        # Account type filter
        if input(f"\n{Colors.BOLD}[+] Filter by account type? (y/N): {Colors.ENDC}").lower() == 'y':
            print(f"\n{Colors.CYAN}[*] Available account types:{Colors.ENDC}")
            types = ["adult", "music", "gaming", "business", "news"]
            for i, acc_type in enumerate(types, 1):
                print(f"{i}. {acc_type}")
            
            try:
                choice = int(input(f"\n{Colors.BOLD}[+] Select type (1-{len(types)}): {Colors.ENDC}")) - 1
                if 0 <= choice < len(types):
                    options.extend(["--type", types[choice]])
            except ValueError:
                print(f"{Colors.WARNING}[!] Invalid choice, skipping filter{Colors.ENDC}")
        
        # Enable logging
        if input(f"\n{Colors.BOLD}[+] Enable detailed logging? (y/N): {Colors.ENDC}").lower() == 'y':
            options.append("--logs")
            
        return options

    def _execute_cli(self, usernames: str, options: List[str]) -> bool:
        """Execute Social Analyzer with automatic command detection"""
        try:
            # Find the correct command
            command = self._find_social_analyzer_command()
            if not command:
                print(f"{Colors.FAIL}[!] Social-analyzer command not found{Colors.ENDC}")
                print(f"{Colors.WARNING}[*] Installation might be incomplete{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Trying alternative installation methods...{Colors.ENDC}")
                
                # Try to reinstall
                try:
                    subprocess.run(["pipx", "install", "social-analyzer", "--force"], 
                                 capture_output=True, timeout=60)
                    subprocess.run(["pipx", "ensurepath"], capture_output=True, timeout=10)
                    
                    # Try again
                    command = self._find_social_analyzer_command()
                    if not command:
                        return False
                except:
                    return False
            
            # Build the command
            if command.startswith("python3 -m"):
                cmd = ["python3", "-m", "social_analyzer", "--username", usernames] + options
            else:
                if " " in command:
                    cmd = command.split() + ["--username", usernames] + options
                else:
                    cmd = [command, "--username", usernames] + options
            
            print(f"\n{Colors.CYAN}[*] Executing Social Analyzer...{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Using command: {command}{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Analyzing usernames: {usernames}{Colors.ENDC}")
            
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
        """Interactive guided mode for social-analyzer"""
        self._show_banner()

        while True:
            try:
                print(f"\n{Colors.CYAN}[*] CLI Mode - Social Media Username Analysis{Colors.ENDC}")
                
                # Check if command is available
                command = self._find_social_analyzer_command()
                if command:
                    print(f"{Colors.GREEN}[✓] Found social-analyzer at: {command}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] Social-analyzer command not found{Colors.ENDC}")
                    print(f"{Colors.CYAN}[*] Will attempt to locate or reinstall during execution{Colors.ENDC}")
                
                usernames = self._get_usernames()
                if not usernames:
                    print(f"{Colors.WARNING}[!] No usernames provided{Colors.ENDC}")
                    continue
                
                options = self._get_cli_options()
                
                print(f"\n{Colors.CYAN}[*] Analysis Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 30)
                print(f"Usernames: {usernames}")
                if options:
                    print(f"Options: {' '.join(options)}")
                
                if input(f"\n{Colors.BOLD}[+] Start analysis? (Y/n): {Colors.ENDC}").lower() != 'n':
                    if self._execute_cli(usernames, options):
                        print(f"{Colors.GREEN}[✓] CLI analysis completed{Colors.ENDC}")

                if input(f"\n{Colors.BOLD}[?] Would you like to perform another analysis? (y/N): {Colors.ENDC}").lower() != 'y':
                    break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for social-analyzer"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter social-analyzer commands{Colors.ENDC}")
        
        # Show current command status
        command = self._find_social_analyzer_command()
        if command:
            print(f"{Colors.GREEN}[✓] Social-analyzer found: {command}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] Social-analyzer command not found{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Available troubleshooting commands: fix, install{Colors.ENDC}")
        
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  help        - Show social-analyzer help")
        print("  test        - Test installation")
        print("  fix         - Try to fix installation issues")
        print("  install     - Reinstall social-analyzer")
        print("  examples    - Show usage examples")
        print("  exit        - Exit to main menu")
        
        while True:
            try:
                command_input = input(f"\n{Colors.BOLD}social-analyzer > {Colors.ENDC}").strip()
                
                if not command_input:
                    continue
                    
                if command_input.lower() == 'exit':
                    break
                    
                elif command_input.lower() == 'test':
                    print(f"{Colors.CYAN}[*] Testing social-analyzer installation...{Colors.ENDC}")
                    command = self._find_social_analyzer_command()
                    if command:
                        print(f"{Colors.GREEN}[✓] Found: {command}{Colors.ENDC}")
                        
                        # Test execution
                        try:
                            if command.startswith("python3 -m"):
                                test_cmd = ["python3", "-m", "social_analyzer", "--help"]
                            else:
                                test_cmd = [command, "--help"] if not " " in command else command.split() + ["--help"]
                            
                            result = subprocess.run(test_cmd, capture_output=True, timeout=10)
                            if result.returncode == 0:
                                print(f"{Colors.GREEN}[✓] Command execution test passed{Colors.ENDC}")
                            else:
                                print(f"{Colors.FAIL}[!] Command execution test failed{Colors.ENDC}")
                        except Exception as e:
                            print(f"{Colors.FAIL}[!] Test failed: {e}{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Social-analyzer not found{Colors.ENDC}")
                
                elif command_input.lower() == 'fix':
                    print(f"{Colors.CYAN}[*] Attempting to fix installation...{Colors.ENDC}")
                    try:
                        # Ensure path
                        subprocess.run(["pipx", "ensurepath"], capture_output=True, timeout=10)
                        print(f"{Colors.GREEN}[✓] Path configuration updated{Colors.ENDC}")
                        
                        # Check again
                        command = self._find_social_analyzer_command()
                        if command:
                            print(f"{Colors.GREEN}[✓] Fixed! Found: {command}{Colors.ENDC}")
                        else:
                            print(f"{Colors.WARNING}[!] Still not found, try 'install' command{Colors.ENDC}")
                    except Exception as e:
                        print(f"{Colors.FAIL}[!] Fix failed: {e}{Colors.ENDC}")
                
                elif command_input.lower() == 'install':
                    print(f"{Colors.CYAN}[*] Reinstalling social-analyzer...{Colors.ENDC}")
                    try:
                        subprocess.run(["pipx", "install", "social-analyzer", "--force"], timeout=120)
                        subprocess.run(["pipx", "ensurepath"], timeout=10)
                        print(f"{Colors.GREEN}[✓] Reinstallation completed{Colors.ENDC}")
                        
                        # Verify
                        command = self._find_social_analyzer_command()
                        if command:
                            print(f"{Colors.GREEN}[✓] Verified: {command}{Colors.ENDC}")
                        else:
                            print(f"{Colors.WARNING}[!] Still having issues{Colors.ENDC}")
                    except Exception as e:
                        print(f"{Colors.FAIL}[!] Reinstall failed: {e}{Colors.ENDC}")
                
                elif command_input.lower() == 'help':
                    command = self._find_social_analyzer_command()
                    if command:
                        if command.startswith("python3 -m"):
                            subprocess.run(["python3", "-m", "social_analyzer", "--help"])
                        else:
                            subprocess.run([command, "--help"] if not " " in command else command.split() + ["--help"])
                    else:
                        print(f"{Colors.FAIL}[!] Social-analyzer not available{Colors.ENDC}")
                
                elif command_input.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] Usage Examples:{Colors.ENDC}")
                    examples = [
                        ('Basic Search', '--username "johndoe"'),
                        ('With Metadata', '--username "johndoe" --metadata'),
                        ('Limited Sites', '--username "johndoe" --top 50'),
                        ('Specific Sites', '--username "johndoe" --websites "twitter facebook"')
                    ]
                    
                    for i, (title, cmd) in enumerate(examples, 1):
                        print(f"\n{Colors.GREEN}{i}. {title}{Colors.ENDC}")
                        print(f"   {cmd}")
                
                else:
                    # Execute as social-analyzer command
                    command = self._find_social_analyzer_command()
                    if not command:
                        print(f"{Colors.FAIL}[!] Social-analyzer not available{Colors.ENDC}")
                        print(f"{Colors.WARNING}[*] Try 'fix' or 'install' first{Colors.ENDC}")
                        continue
                    
                    try:
                        if command_input.startswith('--'):
                            args = command_input.split()
                        else:
                            args = ["--username", command_input]
                        
                        if command.startswith("python3 -m"):
                            cmd = ["python3", "-m", "social_analyzer"] + args
                        else:
                            cmd = [command] + args if not " " in command else command.split() + args
                        
                        print(f"{Colors.CYAN}[*] Executing: {' '.join(cmd)}{Colors.ENDC}")
                        subprocess.run(cmd)
                        
                    except KeyboardInterrupt:
                        print(f"\n{Colors.WARNING}[!] Command interrupted{Colors.ENDC}")
                    except Exception as e:
                        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
                        
            except KeyboardInterrupt:
                print("\n")
                continue
            except Exception as e:
                print(f"{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
                continue