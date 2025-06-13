from core.base import ToolModule
from core.colors import Colors
import subprocess
import platform
import os
import json
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class WPScanModule(ToolModule):
    def __init__(self):
        self._output_dir = Path.home() / "wpscan_results"
        self._api_tokens_file = Path.home() / ".wpscan" / "scan.yml"
        self._enumerate_options = {
            "u": "Users",
            "p": "Plugins", 
            "t": "Themes",
            "tt": "Timthumbs",
            "cb": "Config backups",
            "dbe": "Db exports",
            "vp": "Vulnerable plugins",
            "vt": "Vulnerable themes",
            "ap": "All plugins",
            "at": "All themes"
        }
        super().__init__()

    def _get_name(self) -> str:
        return "WPScan"

    def _get_category(self) -> str:
        return "Web"

    def _get_command(self) -> str:
        return "wpscan"

    def _get_description(self) -> str:
        return "WordPress security scanner to identify vulnerabilities in WordPress sites"

    def _get_dependencies(self) -> List[str]:
        return ["wpscan", "ruby", "gem"]

    def _get_script_path(self) -> str:
        """Returns path to script if applicable"""
        return ""  # WPScan is installed as a gem

    def get_help(self) -> dict:
        return {
            "title": "WPScan - WordPress Security Scanner",
            "usage": "use wpscan",
            "desc": "WordPress security scanner that identifies vulnerabilities, themes, plugins, and users",
            "modes": {
                "Guided": "Interactive mode with step-by-step configuration",
                "Direct": "Direct command execution with full wpscan syntax"
            },
            "options": {
                "--url URL": "Target WordPress URL",
                "--enumerate": "Enumerate users, plugins, themes, etc.",
                "--usernames": "Wordlist for username enumeration",
                "--passwords": "Wordlist for password attacks",
                "--api-token": "WPVulnDB API token for vulnerability data",
                "--force": "Forces WPScan to not check if target is running WordPress",
                "--detection-mode": "Passive/Mixed/Aggressive detection mode",
                "--user-agent": "Custom User-Agent",
                "--random-user-agent": "Use random User-Agent",
                "--wp-content-dir": "Custom wp-content directory",
                "--wp-plugins-dir": "Custom wp-plugins directory",
                "--output": "Output file (formats: cli, json, cli-no-colour)",
                "--format": "Output format"
            },
            "examples": [
                "use wpscan",
                "wpscan --url https://example.com",
                "wpscan --url https://example.com --enumerate u,p,t",
                "wpscan --url https://example.com --api-token YOUR_TOKEN",
                "wpscan --url https://example.com --usernames users.txt --passwords passwords.txt"
            ],
            "notes": [
                "Obtain API token from WPVulnDB for vulnerability data",
                "Use responsibly and only on sites you own or have permission to test",
                "Different detection modes: passive (default), mixed, aggressive",
                "Results are saved to ~/wpscan_results/ directory"
            ]
        }

    def check_installation(self) -> bool:
        """Check if WPScan is installed"""
        try:
            result = subprocess.run(['wpscan', '--version'], 
                                 capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Returns installation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y ruby ruby-dev build-essential",
                "sudo gem install wpscan"
            ],
            'yum': [
                "sudo yum install -y ruby ruby-devel gcc gcc-c++ make",
                "sudo gem install wpscan"
            ],
            'dnf': [
                "sudo dnf install -y ruby ruby-devel gcc gcc-c++ make",
                "sudo gem install wpscan"
            ],
            'pacman': [
                "sudo pacman -S ruby base-devel",
                "sudo gem install wpscan"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Returns update commands"""
        return ["sudo gem update wpscan"]

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Returns uninstallation commands"""
        return ["sudo gem uninstall wpscan"]

    def _show_banner(self):
        """Display the module banner"""
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║              WPSCAN                       ║
║     "WordPress Security Scanner"          ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _get_target_url(self) -> Optional[str]:
        """Get and validate target WordPress URL"""
        print(f"\n{Colors.CYAN}[*] Target Configuration{Colors.ENDC}")
        
        while True:
            url = input(f"{Colors.BOLD}[+] Enter WordPress URL: {Colors.ENDC}").strip()
            
            if not url:
                print(f"{Colors.FAIL}[!] URL cannot be empty{Colors.ENDC}")
                continue
                
            # Add http:// if no protocol specified
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            # Basic URL validation
            if '.' not in url or ' ' in url:
                print(f"{Colors.FAIL}[!] Invalid URL format{Colors.ENDC}")
                continue
                
            return url

    def _configure_enumeration(self) -> str:
        """Configure enumeration options"""
        print(f"\n{Colors.CYAN}[*] Enumeration Configuration{Colors.ENDC}")
        print("Available enumeration options:")
        
        for key, desc in self._enumerate_options.items():
            print(f"  {Colors.BOLD}{key:3}{Colors.ENDC} - {desc}")
        
        print(f"\nExamples:")
        print(f"  u,p,t    - Users, Plugins, Themes")
        print(f"  vp,vt    - Only vulnerable plugins and themes")
        print(f"  ap,at    - All plugins and themes (slower)")
        
        enumerate = input(f"\n{Colors.BOLD}[+] Enumeration options (Enter for u,p,t): {Colors.ENDC}").strip()
        
        if not enumerate:
            enumerate = "u,p,t"
            
        return f"--enumerate {enumerate}"

    def _configure_detection_mode(self) -> str:
        """Configure detection mode"""
        print(f"\n{Colors.CYAN}[*] Detection Mode{Colors.ENDC}")
        print("1. Passive (default, stealthy)")
        print("2. Mixed (balanced)")
        print("3. Aggressive (thorough, more detectable)")
        
        while True:
            choice = input(f"{Colors.BOLD}[+] Select detection mode (1-3, Enter for passive): {Colors.ENDC}").strip()
            
            if not choice or choice == "1":
                return "--detection-mode passive"
            elif choice == "2":
                return "--detection-mode mixed"
            elif choice == "3":
                return "--detection-mode aggressive"
            else:
                print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")

    def _configure_api_token(self) -> str:
        """Configure WPVulnDB API token"""
        print(f"\n{Colors.CYAN}[*] API Token Configuration{Colors.ENDC}")
        print("WPVulnDB API token provides vulnerability data")
        print("Register at: https://wpscan.com/register")
        
        # Check if token already exists
        if self._api_tokens_file.exists():
            print(f"{Colors.GREEN}[+] API token file found{Colors.ENDC}")
            use_existing = input(f"{Colors.BOLD}[+] Use existing token? (Y/n): {Colors.ENDC}").strip()
            if use_existing.lower() != 'n':
                return ""
        
        token = input(f"{Colors.BOLD}[+] Enter API token (Enter to skip): {Colors.ENDC}").strip()
        
        if token:
            return f"--api-token {token}"
        else:
            print(f"{Colors.WARNING}[!] Scanning without API token (limited vulnerability data){Colors.ENDC}")
            return ""

    def _configure_output(self) -> Tuple[str, Path]:
        """Configure output options"""
        print(f"\n{Colors.CYAN}[*] Output Configuration{Colors.ENDC}")
        
        # Create output directory
        self._output_dir.mkdir(exist_ok=True)
        
        # Generate output filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = self._output_dir / f"wpscan_{timestamp}.json"
        
        print(f"Output file: {Colors.GREEN}{output_file}{Colors.ENDC}")
        
        return f"--output {output_file} --format json", output_file

    def _configure_additional_options(self) -> List[str]:
        """Configure additional options"""
        options = []
        
        print(f"\n{Colors.CYAN}[*] Additional Options{Colors.ENDC}")
        
        # Verbose output (always enabled for better feedback)
        options.append("--verbose")
        print(f"{Colors.GREEN}[+] Verbose output enabled (recommended){Colors.ENDC}")
        
        # Random User-Agent
        if input(f"{Colors.BOLD}[+] Use random User-Agent? (Y/n): {Colors.ENDC}").strip().lower() != 'n':
            options.append("--random-user-agent")
        
        # Force scan
        if input(f"{Colors.BOLD}[+] Force scan (skip WordPress detection)? (y/N): {Colors.ENDC}").strip().lower() == 'y':
            options.append("--force")
        
        # Disable SSL verification
        if input(f"{Colors.BOLD}[+] Disable SSL certificate verification? (y/N): {Colors.ENDC}").strip().lower() == 'y':
            options.append("--disable-tls-checks")
        
        # Request timeout
        timeout = input(f"{Colors.BOLD}[+] Request timeout in seconds (Enter for default): {Colors.ENDC}").strip()
        if timeout and timeout.isdigit():
            options.extend(["--request-timeout", timeout])
        
        # Throttle requests
        throttle = input(f"{Colors.BOLD}[+] Throttle between requests in milliseconds (Enter for none): {Colors.ENDC}").strip()
        if throttle and throttle.isdigit():
            options.extend(["--throttle", throttle])
        
        # Max threads (correct parameter name)
        threads = input(f"{Colors.BOLD}[+] Number of threads (Enter for default 5): {Colors.ENDC}").strip()
        if threads and threads.isdigit() and int(threads) > 0:
            options.extend(["--max-threads", threads])
        else:
            options.extend(["--max-threads", "5"])  # Default for better performance
        
        # Connect timeout
        connect_timeout = input(f"{Colors.BOLD}[+] Connection timeout in seconds (Enter for 10): {Colors.ENDC}").strip()
        if connect_timeout and connect_timeout.isdigit():
            options.extend(["--connect-timeout", connect_timeout])
        else:
            options.extend(["--connect-timeout", "10"])  # Faster timeout for responsiveness
        
        return options

    def _configure_authentication(self) -> List[str]:
        """Configure authentication options"""
        options = []
        
        print(f"\n{Colors.CYAN}[*] Authentication (Optional){Colors.ENDC}")
        
        if input(f"{Colors.BOLD}[+] Configure authentication? (y/N): {Colors.ENDC}").strip().lower() == 'y':
            print("\nAuthentication methods:")
            print("1. HTTP Basic Authentication")
            print("2. WordPress login")
            print("3. Custom headers")
            
            auth_choice = input(f"{Colors.BOLD}[+] Select method (1-3): {Colors.ENDC}").strip()
            
            if auth_choice == "1":
                username = input(f"{Colors.BOLD}[+] HTTP username: {Colors.ENDC}").strip()
                password = input(f"{Colors.BOLD}[+] HTTP password: {Colors.ENDC}").strip()
                if username and password:
                    options.extend(["--http-auth", f"{username}:{password}"])
            
            elif auth_choice == "2":
                username = input(f"{Colors.BOLD}[+] WordPress username: {Colors.ENDC}").strip()
                password = input(f"{Colors.BOLD}[+] WordPress password: {Colors.ENDC}").strip()
                if username and password:
                    options.extend(["--username", username, "--password", password])
            
            elif auth_choice == "3":
                header = input(f"{Colors.BOLD}[+] Custom header (format: 'Name: Value'): {Colors.ENDC}").strip()
                if header and ':' in header:
                    options.extend(["--headers", header])
        
        return options

    def run_guided(self) -> None:
        """Execute the tool in guided mode"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}WPScan Guided Configuration{Colors.ENDC}")
        print("=" * 40)
        
        # Get target URL
        target_url = self._get_target_url()
        if not target_url:
            print(f"{Colors.FAIL}[!] Target URL is required{Colors.ENDC}")
            return
        
        # Build command
        command = ["wpscan", "--url", target_url]
        
        # Configure enumeration
        enum_options = self._configure_enumeration()
        command.extend(enum_options.split())
        
        # Configure detection mode
        detection_mode = self._configure_detection_mode()
        command.extend(detection_mode.split())
        
        # Configure API token
        api_token = self._configure_api_token()
        if api_token:
            command.extend(api_token.split())
        
        # Configure output
        output_options, output_file = self._configure_output()
        command.extend(output_options.split())
        
        # Additional options
        additional_options = self._configure_additional_options()
        command.extend(additional_options)
        
        # Authentication
        auth_options = self._configure_authentication()
        command.extend(auth_options)
        
        # Show final command
        print(f"\n{Colors.CYAN}[*] Final Command{Colors.ENDC}")
        print(f"{Colors.BOLD}{' '.join(command)}{Colors.ENDC}")
        
        # Show estimated time info
        print(f"\n{Colors.CYAN}[*] Scan Information{Colors.ENDC}")
        print(f"• Verbose output: {Colors.GREEN}Enabled{Colors.ENDC} (real-time progress)")
        print(f"• Output will be colored for better readability")
        print(f"• Scan progress will be visible immediately")
        if "--throttle" in ' '.join(command):
            print(f"• Throttling enabled: slower but stealthier")
        print(f"• Press Ctrl+C to stop scan at any time")
        
        # Confirm execution
        if input(f"\n{Colors.BOLD}[+] Execute scan? (Y/n): {Colors.ENDC}").strip().lower() == 'n':
            print(f"{Colors.WARNING}[!] Scan cancelled{Colors.ENDC}")
            return
        
        # Execute scan
        self._execute_scan(command, output_file)

    def run_direct(self, args: List[str]) -> None:
        """Execute the tool in direct mode"""
        self._show_banner()
        
        if not args:
            print(f"{Colors.FAIL}[!] No arguments provided for direct mode{Colors.ENDC}")
            print(f"Usage: wpscan --url https://target.com [options]")
            return
        
        # Build command with wpscan prefix
        command = ["wpscan"] + args
        
        print(f"\n{Colors.CYAN}[*] Executing Command{Colors.ENDC}")
        print(f"{Colors.BOLD}{' '.join(command)}{Colors.ENDC}")
        
        # Execute directly
        self._execute_scan(command)

    def _execute_scan(self, command: List[str], output_file: Optional[Path] = None) -> None:
        """Execute the WPScan command with real-time verbose output"""
        print(f"\n{Colors.CYAN}[*] Starting WPScan{Colors.ENDC}")
        print(f"Command: {' '.join(command)}")
        
        # Add verbose flag if not present
        if "--verbose" not in command and "-v" not in command:
            command.append("--verbose")
        
        try:
            # Start the scan with real-time output
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            print(f"\n{Colors.GREEN}[+] Scan started... (Press Ctrl+C to stop){Colors.ENDC}")
            print("-" * 60)
            
            # Stream output in real-time with color coding
            output_lines = []
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    stripped_line = line.rstrip()
                    output_lines.append(stripped_line)
                    
                    # Color code different types of output
                    colored_line = self._colorize_output(stripped_line)
                    print(colored_line)
                    
                    # Flush output immediately for real-time display
                    import sys
                    sys.stdout.flush()
            
            # Wait for process to complete
            return_code = process.wait()
            
            print("-" * 60)
            
            if return_code == 0:
                print(f"{Colors.GREEN}[+] Scan completed successfully{Colors.ENDC}")
                
                if output_file and output_file.exists():
                    print(f"{Colors.GREEN}[+] Results saved to: {output_file}{Colors.ENDC}")
                    self._display_results_summary(output_file)
            else:
                print(f"{Colors.FAIL}[!] Scan completed with errors (exit code: {return_code}){Colors.ENDC}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error during scan: {str(e)}{Colors.ENDC}")

    def _validate_wpscan_parameters(self, command: List[str]) -> List[str]:
        """Validate and fix WPScan parameters for compatibility"""
        # Check WPScan version to handle parameter differences
        try:
            result = subprocess.run(['wpscan', '--help'], 
                                 capture_output=True, text=True, timeout=5)
            help_text = result.stdout
            
            # Remove problematic parameters if not supported
            validated_command = []
            i = 0
            while i < len(command):
                current_param = command[i]
                
                # Check if this parameter exists in help
                if current_param.startswith('--'):
                    param_name = current_param[2:]  # Remove --
                    
                    # Some parameters that might not exist in all versions
                    problematic_params = ['max-threads', 'connect-timeout']
                    
                    if param_name in problematic_params and param_name not in help_text:
                        print(f"{Colors.WARNING}[!] Parameter {current_param} not supported, skipping...{Colors.ENDC}")
                        # Skip this parameter and its value
                        if i + 1 < len(command) and not command[i + 1].startswith('--'):
                            i += 1  # Skip the value too
                    else:
                        validated_command.append(current_param)
                        # Add the value if it exists and doesn't start with --
                        if i + 1 < len(command) and not command[i + 1].startswith('--'):
                            i += 1
                            validated_command.append(command[i])
                else:
                    validated_command.append(current_param)
                
                i += 1
            
            return validated_command
            
        except Exception:
            # If we can't check, just return original command
            return command
        """Apply color coding to WPScan output for better readability"""
        line_lower = line.lower()
        
        # Error messages
        if any(keyword in line_lower for keyword in ['error', 'failed', 'timeout', 'connection refused']):
            return f"{Colors.FAIL}{line}{Colors.ENDC}"
        
        # Warnings
        elif any(keyword in line_lower for keyword in ['warning', 'could not', 'unable to', 'skipping']):
            return f"{Colors.WARNING}{line}{Colors.ENDC}"
        
        # Vulnerabilities found
        elif any(keyword in line_lower for keyword in ['vulnerability', 'vulnerabilities', 'cve-', 'exploit']):
            return f"{Colors.FAIL}{line}{Colors.ENDC}"
        
        # Interesting findings
        elif any(keyword in line_lower for keyword in ['interesting', 'found', 'detected', 'identified']):
            return f"{Colors.GREEN}{line}{Colors.ENDC}"
        
        # Plugin/Theme enumeration
        elif any(keyword in line_lower for keyword in ['plugin', 'theme', 'enumerating']):
            return f"{Colors.CYAN}{line}{Colors.ENDC}"
        
        # User enumeration
        elif any(keyword in line_lower for keyword in ['user', 'username', 'login']):
            return f"{Colors.BOLD}{line}{Colors.ENDC}"
        
        # Progress indicators
        elif any(keyword in line_lower for keyword in ['[+]', '[*]', '[i]']):
            if '[+]' in line:
                return f"{Colors.GREEN}{line}{Colors.ENDC}"
            elif '[*]' in line:
                return f"{Colors.CYAN}{line}{Colors.ENDC}"
            else:
                return f"{Colors.BOLD}{line}{Colors.ENDC}"
        
        # Default
        else:
            return line

    def _display_results_summary(self, output_file: Path) -> None:
        """Display a summary of scan results"""
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            print(f"\n{Colors.CYAN}[*] Scan Results Summary{Colors.ENDC}")
            print("=" * 30)
            
            # WordPress version
            if 'version' in data:
                version = data['version']
                print(f"WordPress Version: {Colors.BOLD}{version.get('number', 'Unknown')}{Colors.ENDC}")
                if version.get('interesting_entries'):
                    print(f"Version Detection: {len(version['interesting_entries'])} indicators found")
            
            # Vulnerabilities
            if 'vulnerabilities' in data and data['vulnerabilities']:
                vuln_count = len(data['vulnerabilities'])
                print(f"{Colors.FAIL}Vulnerabilities: {vuln_count} found{Colors.ENDC}")
            
            # Users
            if 'users' in data:
                user_count = len(data['users'])
                print(f"Users Found: {Colors.BOLD}{user_count}{Colors.ENDC}")
                for user in data['users'][:5]:  # Show first 5 users
                    print(f"  - {user.get('username', 'Unknown')}")
                if user_count > 5:
                    print(f"  ... and {user_count - 5} more")
            
            # Plugins
            if 'plugins' in data:
                plugin_count = len(data['plugins'])
                print(f"Plugins Found: {Colors.BOLD}{plugin_count}{Colors.ENDC}")
                
                vulnerable_plugins = [p for p in data['plugins'].values() 
                                    if p.get('vulnerabilities')]
                if vulnerable_plugins:
                    print(f"{Colors.FAIL}Vulnerable Plugins: {len(vulnerable_plugins)}{Colors.ENDC}")
            
            # Themes
            if 'themes' in data:
                theme_count = len(data['themes'])
                print(f"Themes Found: {Colors.BOLD}{theme_count}{Colors.ENDC}")
                
                vulnerable_themes = [t for t in data['themes'].values() 
                                   if t.get('vulnerabilities')]
                if vulnerable_themes:
                    print(f"{Colors.FAIL}Vulnerable Themes: {len(vulnerable_themes)}{Colors.ENDC}")
            
            print(f"\n{Colors.GREEN}[+] Full results available in: {output_file}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Could not parse results file: {str(e)}{Colors.ENDC}")

    def run(self, args: List[str] = None) -> None:
        """Main entry point for the module"""
        if not self.check_installation():
            print(f"{Colors.FAIL}[!] WPScan is not installed{Colors.ENDC}")
            print(f"Install with: sudo gem install wpscan")
            return
        
        if args:
            self.run_direct(args)
        else:
            self.run_guided()