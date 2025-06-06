#!/usr/bin/env python3
# modules/osint/metagoofil.py

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

class Metagoofil(ToolModule):
    def __init__(self):
        super().__init__()

    def _get_name(self) -> str:
        return "metagoofil"

    def _get_category(self) -> str:
        return "OSINT"

    def _get_command(self) -> str:
        return "metagoofil"

    def _get_description(self) -> str:
        return "Document metadata extraction tool for OSINT investigations"

    def _get_dependencies(self) -> List[str]:
        return ["python3", "python3-pip", "python3-venv", "git"]

    def _get_script_path(self) -> str:
        return "/opt/metagoofil/metagoofil.py"

    def _find_metagoofil_path(self) -> Optional[str]:
        """Find the metagoofil installation path"""
        possible_paths = [
            "/opt/metagoofil/metagoofil.py",
            "/usr/local/bin/metagoofil/metagoofil.py",
            Path.home() / "tools/metagoofil/metagoofil.py",
            "./metagoofil/metagoofil.py"
        ]
        
        for path in possible_paths:
            if Path(path).exists():
                return str(path)
        
        return None

    def check_installation(self) -> bool:
        """Check if metagoofil is properly installed"""
        try:
            metagoofil_path = self._find_metagoofil_path()
            if not metagoofil_path:
                return False
            
            # Check if the script exists and is executable
            script_path = Path(metagoofil_path)
            if not script_path.exists():
                return False
            
            # Check if requirements are installed by testing imports
            venv_python = script_path.parent / ".venv/bin/python"
            if venv_python.exists():
                # Test with virtual environment
                result = subprocess.run(
                    [str(venv_python), str(script_path), "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                # Test with system python
                result = subprocess.run(
                    ["python3", str(script_path), "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            
            return result.returncode == 0
            
        except Exception:
            return False

    def _install_metagoofil(self) -> bool:
        """Install metagoofil from GitHub"""
        try:
            print(f"{Colors.CYAN}[*] Installing Metagoofil...{Colors.ENDC}")
            
            # Create installation directory
            install_dir = "/opt/metagoofil"
            
            print(f"{Colors.CYAN}[*] Creating installation directory: {install_dir}{Colors.ENDC}")
            subprocess.run(["sudo", "mkdir", "-p", install_dir], check=True)
            
            # Clone the repository
            print(f"{Colors.CYAN}[*] Cloning Metagoofil repository...{Colors.ENDC}")
            subprocess.run([
                "sudo", "git", "clone", 
                "https://github.com/opsdisk/metagoofil.git", 
                install_dir
            ], check=True)
            
            # Change ownership to current user
            current_user = subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip()
            subprocess.run(["sudo", "chown", "-R", f"{current_user}:{current_user}", install_dir], check=True)
            
            # Create virtual environment
            print(f"{Colors.CYAN}[*] Creating virtual environment...{Colors.ENDC}")
            venv_path = f"{install_dir}/.venv"
            subprocess.run(["python3", "-m", "venv", venv_path], check=True, cwd=install_dir)
            
            # Install requirements
            print(f"{Colors.CYAN}[*] Installing Python requirements...{Colors.ENDC}")
            pip_path = f"{venv_path}/bin/pip"
            subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True, cwd=install_dir)
            
            # Make script executable
            script_path = f"{install_dir}/metagoofil.py"
            subprocess.run(["chmod", "+x", script_path], check=True)
            
            print(f"{Colors.GREEN}[✓] Metagoofil installed successfully{Colors.ENDC}")
            
            # Verify installation
            if self.check_installation():
                print(f"{Colors.GREEN}[✓] Installation verified{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.WARNING}[!] Installation completed but verification failed{Colors.ENDC}")
                return False
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Failed to install Metagoofil: {e}{Colors.ENDC}")
            return False

    def _check_proxychains_config(self) -> bool:
        """Check if proxychains is properly configured"""
        try:
            config_file = "/etc/proxychains4.conf"
            if not Path(config_file).exists():
                return False
            
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Check if there are any proxy entries
            proxy_lines = [line for line in content.split('\n') 
                          if line.strip() and not line.strip().startswith('#') 
                          and any(proxy_type in line for proxy_type in ['socks4', 'socks5', 'http'])]
            
            return len(proxy_lines) > 0
            
        except Exception:
            return False

    def _show_proxychains_setup(self):
        """Show proxychains setup instructions"""
        print(f"\n{Colors.CYAN}[*] PROXYCHAINS SETUP GUIDE{Colors.ENDC}")
        print("="*50)
        print(f"{Colors.YELLOW}Current issue: Connection refused to proxy servers{Colors.ENDC}")
        print()
        print(f"{Colors.CYAN}Option 1: Setup Tor (Recommended){Colors.ENDC}")
        print(f"{Colors.GREEN}sudo apt install tor{Colors.ENDC}")
        print(f"{Colors.GREEN}sudo systemctl start tor{Colors.ENDC}")
        print(f"{Colors.GREEN}sudo systemctl enable tor{Colors.ENDC}")
        print()
        print(f"{Colors.CYAN}Option 2: Use SSH SOCKS tunnels{Colors.ENDC}")
        print(f"{Colors.GREEN}ssh -D 9050 user@your-server.com{Colors.ENDC}")
        print(f"{Colors.GREEN}ssh -D 9051 user@another-server.com{Colors.ENDC}")
        print()
        print(f"{Colors.CYAN}Option 3: Edit proxychains config{Colors.ENDC}")
        print(f"{Colors.GREEN}sudo nano /etc/proxychains4.conf{Colors.ENDC}")
        print("Add working proxy servers in [ProxyList] section:")
        print("  socks4 127.0.0.1 9050")
        print("  socks5 proxy-server.com 1080")
        print("  http proxy-server.com 8080")
        print()
        print(f"{Colors.WARNING}Note: Free public proxies are often unreliable{Colors.ENDC}")
        print("="*50)

    def _test_proxychains(self) -> bool:
        """Test if proxychains is working"""
        try:
            print(f"{Colors.CYAN}[*] Testing proxychains configuration...{Colors.ENDC}")
            
            # Test with a simple curl command
            result = subprocess.run(
                ["proxychains4", "curl", "-s", "--connect-timeout", "10", "https://httpbin.org/ip"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[✓] Proxychains is working{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.FAIL}[!] Proxychains test failed{Colors.ENDC}")
                if "Connection refused" in result.stderr:
                    print(f"{Colors.WARNING}[!] Proxy server connection refused{Colors.ENDC}")
                return False
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Proxychains test error: {e}{Colors.ENDC}")
            return False

    def _install_proxychains(self) -> bool:
        """Install proxychains4"""
        try:
            print(f"{Colors.CYAN}[*] Installing proxychains4...{Colors.ENDC}")
            subprocess.run(["sudo", "apt", "install", "proxychains4", "-y"], check=True)
            return True
        except Exception as e:
            print(f"{Colors.FAIL}[!] Failed to install proxychains4: {e}{Colors.ENDC}")
            return False

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Return installation commands"""
        commands = {
            'apt': [
                "apt-get update",
                "apt-get install -y python3 python3-pip python3-venv git proxychains4",
                "rm -rf /opt/metagoofil",
                "git clone https://github.com/opsdisk/metagoofil.git /opt/metagoofil",
                "python3 -m venv /opt/metagoofil/.venv",
                "/opt/metagoofil/.venv/bin/pip install -r /opt/metagoofil/requirements.txt",
                "chmod +x /opt/metagoofil/metagoofil.py",
                "chown -R $(whoami):$(whoami) /opt/metagoofil"
            ],
            'yum': [
                "yum update -y",
                "yum install -y python3 python3-pip git",
                "rm -rf /opt/metagoofil",
                "git clone https://github.com/opsdisk/metagoofil.git /opt/metagoofil",
                "python3 -m venv /opt/metagoofil/.venv",
                "/opt/metagoofil/.venv/bin/pip install -r /opt/metagoofil/requirements.txt",
                "chmod +x /opt/metagoofil/metagoofil.py",
                "chown -R $(whoami):$(whoami) /opt/metagoofil"
            ],
            'dnf': [
                "dnf update -y", 
                "dnf install -y python3 python3-pip git",
                "rm -rf /opt/metagoofil",
                "git clone https://github.com/opsdisk/metagoofil.git /opt/metagoofil",
                "python3 -m venv /opt/metagoofil/.venv",
                "/opt/metagoofil/.venv/bin/pip install -r /opt/metagoofil/requirements.txt",
                "chmod +x /opt/metagoofil/metagoofil.py",
                "chown -R $(whoami):$(whoami) /opt/metagoofil"
            ],
            'pacman': [
                "pacman -Sy",
                "pacman -S python python-pip git --noconfirm",
                "rm -rf /opt/metagoofil",
                "git clone https://github.com/opsdisk/metagoofil.git /opt/metagoofil",
                "python3 -m venv /opt/metagoofil/.venv",
                "/opt/metagoofil/.venv/bin/pip install -r /opt/metagoofil/requirements.txt",
                "chmod +x /opt/metagoofil/metagoofil.py",
                "chown -R $(whoami):$(whoami) /opt/metagoofil"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Return update commands"""
        return [
            "cd /opt/metagoofil",
            "git pull origin master",
            ".venv/bin/pip install -r requirements.txt"
        ]

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Return uninstallation commands"""
        return [
            "rm -rf /opt/metagoofil",
            "rm -rf ~/tools/metagoofil"
        ]

    def get_help(self) -> dict:
        return {
            "title": "Metagoofil - Document Metadata Extraction",
            "usage": "use metagoofil",
            "desc": "Document metadata extraction tool for OSINT investigations. Searches for and downloads documents from a target domain, then extracts metadata.",
            "modes": {
                "Guided": "Interactive mode for document metadata extraction",
                "Direct": "Direct CLI execution with advanced options"
            },
            "options": {
                "-d DOMAIN": "Target domain to search (required)",
                "-t FILE_TYPES": "File types to search (required) - pdf,doc,xls,ppt,etc",
                "-f": "Save files to disk (optional)",
                "-e DELAY": "Delay between searches in seconds",
                "-l SEARCH_MAX": "Maximum number of search results",
                "-n DOWNLOAD_FILE_LIMIT": "Maximum number of files to download per type",
                "-o SAVE_DIRECTORY": "Directory to save files",
                "-i URL_TIMEOUT": "URL timeout in seconds",
                "-r NUMBER_OF_THREADS": "Number of download threads",
                "-u USER_AGENT": "Custom user agent string",
                "-w": "Write detailed metadata to file"
            },
            "examples": [
                'python metagoofil.py -d example.com -t pdf,doc -f',
                'proxychains4 python metagoofil.py -d target.com -t pdf,doc,xls -f -e 5',
                'python metagoofil.py -d company.com -t pdf -l 100 -n 10 -o ./docs'
            ]
        }

    def _show_banner(self):
        print(f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║              METAGOOFIL                  ║
║       "Document Metadata Extraction"    ║
║            Python Tool                   ║
╚══════════════════════════════════════════╝{Colors.ENDC}''')

    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format"""
        # Remove protocol if present
        domain = domain.replace('http://', '').replace('https://', '')
        # Basic domain validation
        pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, domain) is not None

    def _get_target_domain(self) -> Optional[str]:
        """Get and validate target domain from user"""
        while True:
            print(f"\n{Colors.CYAN}[*] Domain Examples:{Colors.ENDC}")
            print("  example.com")
            print("  company.org")
            print("  university.edu")
            
            domain = input(f"\n{Colors.BOLD}[+] Enter target domain: {Colors.ENDC}").strip()
            
            if not domain:
                print(f"{Colors.FAIL}[!] Domain is required{Colors.ENDC}")
                retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
                if retry == 'n':
                    return None
                continue
            
            # Clean domain
            domain = domain.replace('http://', '').replace('https://', '').strip('/')
                
            if self._validate_domain(domain):
                return domain
            else:
                print(f"{Colors.FAIL}[!] Invalid domain format{Colors.ENDC}")
                retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
                if retry == 'n':
                    return None

    def _get_file_types(self) -> str:
        """Get file types to search from user"""
        print(f"\n{Colors.CYAN}[*] Common file types:{Colors.ENDC}")
        print("1. pdf,doc,xls,ppt (Office documents)")
        print("2. pdf (PDF only)")
        print("3. doc,docx (Word documents)")
        print("4. xls,xlsx (Excel files)")
        print("5. Custom (specify your own)")
        
        choice = input(f"\n{Colors.BOLD}[+] Choose file types (1-5): {Colors.ENDC}").strip()
        
        if choice == "1":
            return "pdf,doc,xls,ppt"
        elif choice == "2":
            return "pdf"
        elif choice == "3":
            return "doc,docx"
        elif choice == "4":
            return "xls,xlsx"
        elif choice == "5":
            custom = input(f"{Colors.BOLD}[+] Enter file types (comma-separated): {Colors.ENDC}").strip()
            return custom if custom else "pdf,doc,xls"
        else:
            return "pdf,doc,xls"

    def _get_search_options(self) -> dict:
        """Get search options from user"""
        options = {}
        
        # Download files
        if input(f"\n{Colors.BOLD}[+] Download files to disk? (Y/n): {Colors.ENDC}").lower() != 'n':
            options['save_files'] = True
            
            # Output directory
            output_dir = input(f"{Colors.BOLD}[+] Output directory (default: ./downloads): {Colors.ENDC}").strip()
            options['save_directory'] = output_dir if output_dir else "./downloads"
        
        # Write metadata to file
        if input(f"{Colors.BOLD}[+] Write detailed metadata to file? (y/N): {Colors.ENDC}").lower() == 'y':
            options['write_metadata'] = True
        
        # Search limits
        if input(f"{Colors.BOLD}[+] Set search limits? (y/N): {Colors.ENDC}").lower() == 'y':
            try:
                search_max = int(input(f"{Colors.BOLD}[+] Max search results (default: 100): {Colors.ENDC}") or "100")
                options['search_max'] = search_max
                
                if options.get('save_files'):
                    download_limit = int(input(f"{Colors.BOLD}[+] Max downloads per file type (default: 10): {Colors.ENDC}") or "10")
                    options['download_file_limit'] = download_limit
            except ValueError:
                print(f"{Colors.WARNING}[!] Using default limits{Colors.ENDC}")
        
        # Delay between searches
        if input(f"{Colors.BOLD}[+] Set delay between searches? (y/N): {Colors.ENDC}").lower() == 'y':
            try:
                delay = int(input(f"{Colors.BOLD}[+] Delay in seconds (default: 5): {Colors.ENDC}") or "5")
                options['delay'] = delay
            except ValueError:
                print(f"{Colors.WARNING}[!] Using default delay{Colors.ENDC}")
        
        # Advanced options
        if input(f"{Colors.BOLD}[+] Configure advanced options? (y/N): {Colors.ENDC}").lower() == 'y':
            # URL timeout
            try:
                timeout = int(input(f"{Colors.BOLD}[+] URL timeout in seconds (default: 15): {Colors.ENDC}") or "15")
                options['url_timeout'] = timeout
            except ValueError:
                pass
            
            # Number of threads
            try:
                threads = int(input(f"{Colors.BOLD}[+] Number of download threads (default: 8): {Colors.ENDC}") or "8")
                options['threads'] = threads
            except ValueError:
                pass
            
            # Custom user agent
            user_agent = input(f"{Colors.BOLD}[+] Custom user agent (leave empty for default): {Colors.ENDC}").strip()
            if user_agent:
                options['user_agent'] = user_agent
        
        return options

    def _execute_metagoofil(self, domain: str, file_types: str, options: dict, use_proxychains: bool = False) -> bool:
        """Execute metagoofil with given parameters"""
        try:
            metagoofil_path = self._find_metagoofil_path()
            if not metagoofil_path:
                print(f"{Colors.FAIL}[!] Metagoofil not found{Colors.ENDC}")
                return False
            
            script_path = Path(metagoofil_path)
            venv_python = script_path.parent / ".venv/bin/python"
            
            # Build command
            if venv_python.exists():
                cmd = [str(venv_python), str(script_path)]
            else:
                cmd = ["python3", str(script_path)]
            
            # Add required parameters
            cmd.extend(["-d", domain, "-t", file_types])
            
            # Add optional parameters based on corrected syntax
            if options.get('save_files'):
                cmd.append("-f")
                if options.get('save_directory'):
                    cmd.extend(["-o", options['save_directory']])
            
            if options.get('write_metadata'):
                cmd.append("-w")
            
            if options.get('search_max'):
                cmd.extend(["-l", str(options['search_max'])])
            
            if options.get('download_file_limit'):
                cmd.extend(["-n", str(options['download_file_limit'])])
            
            if options.get('delay'):
                cmd.extend(["-e", str(options['delay'])])
            
            if options.get('url_timeout'):
                cmd.extend(["-i", str(options['url_timeout'])])
            
            if options.get('threads'):
                cmd.extend(["-r", str(options['threads'])])
            
            if options.get('user_agent'):
                cmd.extend(["-u", options['user_agent']])
            
            # Add proxychains if requested
            if use_proxychains:
                if shutil.which("proxychains4"):
                    cmd = ["proxychains4"] + cmd
                    print(f"{Colors.CYAN}[*] Using proxychains4 to avoid IP blocking{Colors.ENDC}")
                    print(f"{Colors.WARNING}[*] Note: Ensure proxy servers are running and configured{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] Proxychains4 not available, running without proxy{Colors.ENDC}")
                    use_proxychains = False
            
            print(f"\n{Colors.CYAN}[*] Executing Metagoofil...{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Target: {domain}{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] File types: {file_types}{Colors.ENDC}")
            if use_proxychains:
                print(f"{Colors.CYAN}[*] Using proxychains: {'Yes' if 'proxychains4' in cmd else 'No'}{Colors.ENDC}")
            
            # Execute with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                cwd=script_path.parent
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
                print(f"\n{Colors.GREEN}[✓] Metagoofil scan completed successfully{Colors.ENDC}")
                
                # Show downloaded files info
                if options.get('save_files') and options.get('save_directory'):
                    output_path = Path(options['save_directory'])
                    if output_path.exists():
                        files = list(output_path.glob('*'))
                        print(f"{Colors.GREEN}[✓] Downloaded {len(files)} files to {output_path}{Colors.ENDC}")
                
                return True
            else:
                print(f"\n{Colors.FAIL}[!] Scan failed with return code {return_code}{Colors.ENDC}")
                if return_code == 1:
                    print(f"{Colors.WARNING}[!] Tip: If getting HTTP 429 errors, try using proxychains{Colors.ENDC}")
                return False
                
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
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
            print(f"{Colors.FAIL}[!] Error during execution: {e}{Colors.ENDC}")
            return False

    def run_guided(self) -> None:
        """Interactive guided mode for metagoofil"""
        self._show_banner()

        while True:
            try:
                print(f"\n{Colors.CYAN}[*] Document Metadata Extraction{Colors.ENDC}")
                
                # Check if metagoofil is installed
                if not self.check_installation():
                    print(f"{Colors.WARNING}[!] Metagoofil not found{Colors.ENDC}")
                    
                    if input(f"\n{Colors.BOLD}[+] Install Metagoofil now? (Y/n): {Colors.ENDC}").lower() != 'n':
                        if self._install_metagoofil():
                            print(f"{Colors.GREEN}[✓] Installation successful{Colors.ENDC}")
                        else:
                            print(f"{Colors.FAIL}[!] Installation failed{Colors.ENDC}")
                            break
                    else:
                        break
                else:
                    print(f"{Colors.GREEN}[✓] Metagoofil is installed and ready{Colors.ENDC}")
                
                # Get target domain
                domain = self._get_target_domain()
                if not domain:
                    continue
                
                # Get file types
                file_types = self._get_file_types()
                
                # Get search options
                options = self._get_search_options()
                
                # Proxychains option
                use_proxychains = False
                if input(f"\n{Colors.BOLD}[+] Use proxychains to avoid IP blocking? (y/N): {Colors.ENDC}").lower() == 'y':
                    if shutil.which("proxychains4"):
                        # Test proxychains configuration
                        if self._test_proxychains():
                            use_proxychains = True
                        else:
                            print(f"{Colors.WARNING}[!] Proxychains not working properly{Colors.ENDC}")
                            self._show_proxychains_setup()
                            
                            if input(f"{Colors.BOLD}[+] Continue without proxychains? (Y/n): {Colors.ENDC}").lower() == 'n':
                                continue
                    else:
                        print(f"{Colors.WARNING}[!] Proxychains4 not installed{Colors.ENDC}")
                        if input(f"{Colors.BOLD}[+] Install proxychains4? (y/N): {Colors.ENDC}").lower() == 'y':
                            if self._install_proxychains():
                                self._show_proxychains_setup()
                                print(f"{Colors.CYAN}[*] Please configure proxychains and try again{Colors.ENDC}")
                                continue
                
                # Show configuration
                print(f"\n{Colors.CYAN}[*] Scan Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 40)
                print(f"Domain: {domain}")
                print(f"File types: {file_types}")
                print(f"Download files: {'Yes' if options.get('save_files') else 'No'}")
                if options.get('save_directory'):
                    print(f"Save directory: {options['save_directory']}")
                if options.get('write_metadata'):
                    print(f"Write metadata: Yes")
                if options.get('search_max'):
                    print(f"Search limit: {options['search_max']}")
                if options.get('download_file_limit'):
                    print(f"Download limit: {options['download_file_limit']}")
                if options.get('delay'):
                    print(f"Delay: {options['delay']} seconds")
                if options.get('url_timeout'):
                    print(f"URL timeout: {options['url_timeout']} seconds")
                if options.get('threads'):
                    print(f"Threads: {options['threads']}")
                if options.get('user_agent'):
                    print(f"User agent: {options['user_agent']}")
                print(f"Use proxychains: {'Yes' if use_proxychains else 'No'}")
                
                # Confirm and execute
                if input(f"\n{Colors.BOLD}[+] Start scan? (Y/n): {Colors.ENDC}").lower() != 'n':
                    if self._execute_metagoofil(domain, file_types, options, use_proxychains):
                        print(f"{Colors.GREEN}[✓] Document metadata extraction completed{Colors.ENDC}")

                # Ask for another scan
                if input(f"\n{Colors.BOLD}[?] Scan another domain? (y/N): {Colors.ENDC}").lower() != 'y':
                    break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for metagoofil"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Metagoofil Commands{Colors.ENDC}")
        
        # Show current installation status
        if self.check_installation():
            metagoofil_path = self._find_metagoofil_path()
            print(f"{Colors.GREEN}[✓] Metagoofil found: {metagoofil_path}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] Metagoofil not found{Colors.ENDC}")
        
        # Check proxychains status
        if shutil.which("proxychains4"):
            if self._check_proxychains_config():
                print(f"{Colors.GREEN}[✓] Proxychains4: Available and configured{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}[!] Proxychains4: Available but not configured{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[!] Proxychains4: Not installed{Colors.ENDC}")
        
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  -d <domain> -t <types> -f             - Basic scan with download")
        print("  proxychains4 python metagoofil.py ... - Use with proxychains")
        print("  help                                   - Show metagoofil help")
        print("  test                                   - Test installation")
        print("  test-proxy                             - Test proxychains setup")
        print("  setup-proxy                           - Show proxy setup guide")
        print("  install                                - Install Metagoofil")
        print("  install-proxychains                    - Install proxychains4")
        print("  examples                               - Show usage examples")
        print("  exit                                   - Exit direct mode")
        
        while True:
            try:
                command_input = input(f"\n{Colors.BOLD}metagoofil > {Colors.ENDC}").strip()
                
                if not command_input:
                    continue
                    
                if command_input.lower() == 'exit':
                    break
                    
                elif command_input.lower() == 'test':
                    print(f"{Colors.CYAN}[*] Testing Metagoofil installation...{Colors.ENDC}")
                    if self.check_installation():
                        print(f"{Colors.GREEN}[✓] Metagoofil is working properly{Colors.ENDC}")
                        metagoofil_path = self._find_metagoofil_path()
                        print(f"{Colors.GREEN}[✓] Located at: {metagoofil_path}{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Metagoofil is not working properly{Colors.ENDC}")
                
                elif command_input.lower() == 'test-proxy':
                    if shutil.which("proxychains4"):
                        self._test_proxychains()
                    else:
                        print(f"{Colors.FAIL}[!] Proxychains4 not installed{Colors.ENDC}")
                
                elif command_input.lower() == 'setup-proxy':
                    self._show_proxychains_setup()
                
                elif command_input.lower() == 'install':
                    self._install_metagoofil()
                
                elif command_input.lower() == 'install-proxychains':
                    self._install_proxychains()
                
                elif command_input.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] Usage Examples:{Colors.ENDC}")
                    examples = [
                        ('Basic scan with download', '-d example.com -t pdf,doc -f'),
                        ('With proxychains', 'proxychains4 python metagoofil.py -d target.com -t pdf -f'),
                        ('Limited results', '-d company.com -t pdf -l 50 -n 5'),
                        ('With delay and timeout', '-d site.org -t doc,xls -f -e 10 -i 30'),
                        ('Custom output and metadata', '-d domain.com -t pdf -f -o ./documents -w'),
                        ('Multi-threaded download', '-d company.com -t pdf,doc -f -r 4'),
                        ('Custom user agent', '-d target.com -t pdf -f -u "Custom Bot 1.0"')
                    ]
                    
                    for i, (title, cmd) in enumerate(examples, 1):
                        print(f"\n{Colors.GREEN}{i}. {title}{Colors.ENDC}")
                        print(f"   python metagoofil.py {cmd}")
                
                elif command_input.lower() == 'help':
                    metagoofil_path = self._find_metagoofil_path()
                    if metagoofil_path:
                        script_path = Path(metagoofil_path)
                        venv_python = script_path.parent / ".venv/bin/python"
                        
                        if venv_python.exists():
                            subprocess.run([str(venv_python), str(script_path), "--help"])
                        else:
                            subprocess.run(["python3", str(script_path), "--help"])
                    else:
                        print(f"{Colors.FAIL}[!] Metagoofil not available{Colors.ENDC}")
                
                else:
                    # Execute as metagoofil command
                    metagoofil_path = self._find_metagoofil_path()
                    if not metagoofil_path:
                        print(f"{Colors.FAIL}[!] Metagoofil not available{Colors.ENDC}")
                        print(f"{Colors.WARNING}[*] Try 'install' first{Colors.ENDC}")
                        continue
                    
                    try:
                        script_path = Path(metagoofil_path)
                        venv_python = script_path.parent / ".venv/bin/python"
                        
                        # Handle proxychains commands
                        if command_input.startswith('proxychains4'):
                            if not shutil.which("proxychains4"):
                                print(f"{Colors.FAIL}[!] Proxychains4 not installed{Colors.ENDC}")
                                continue
                            
                            # Test proxychains before using
                            print(f"{Colors.CYAN}[*] Testing proxychains configuration...{Colors.ENDC}")
                            if not self._test_proxychains():
                                print(f"{Colors.WARNING}[!] Proxychains not working properly{Colors.ENDC}")
                                self._show_proxychains_setup()
                                if input(f"{Colors.BOLD}[+] Continue anyway? (y/N): {Colors.ENDC}").lower() != 'y':
                                    continue
                            
                            # Parse proxychains command
                            parts = command_input.split()
                            if 'python' in command_input and 'metagoofil.py' in command_input:
                                # Extract arguments after metagoofil.py
                                try:
                                    script_index = parts.index('metagoofil.py')
                                    args = parts[script_index + 1:]
                                except ValueError:
                                    args = []
                                
                                if venv_python.exists():
                                    cmd = ["proxychains4", str(venv_python), str(script_path)] + args
                                else:
                                    cmd = ["proxychains4", "python3", str(script_path)] + args
                            else:
                                print(f"{Colors.FAIL}[!] Invalid proxychains command format{Colors.ENDC}")
                                print(f"{Colors.CYAN}[*] Example: proxychains4 python metagoofil.py -d example.com -t pdf -f{Colors.ENDC}")
                                continue
                        else:
                            # Regular command - parse arguments
                            args = command_input.split()
                            
                            if venv_python.exists():
                                cmd = [str(venv_python), str(script_path)] + args
                            else:
                                cmd = ["python3", str(script_path)] + args
                        
                        print(f"{Colors.CYAN}[*] Executing: {' '.join(cmd)}{Colors.ENDC}")
                        
                        # Check for HTTP 429 warning
                        if not command_input.startswith('proxychains4') and '-d' in command_input:
                            print(f"{Colors.WARNING}[*] Note: If you get HTTP 429 errors, use proxychains4{Colors.ENDC}")
                        
                        # Execute from the metagoofil directory
                        subprocess.run(cmd, cwd=script_path.parent)
                        
                    except KeyboardInterrupt:
                        print(f"\n{Colors.WARNING}[!] Command interrupted{Colors.ENDC}")
                    except Exception as e:
                        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
                        
            except KeyboardInterrupt:
                print()
                continue

# For backward compatibility
def get_tool():
    """Legacy function to get tool instance"""
    return Metagoofil()

if __name__ == "__main__":
    tool = Metagoofil()
    
    if len(sys.argv) > 1 and sys.argv[1] == "direct":
        tool.run_direct()
    else:
        tool.run_guided()