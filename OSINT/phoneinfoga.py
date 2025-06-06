#!/usr/bin/env python3
# modules/osint/phoneinfoga.py

import subprocess
import shutil
import re
import sys
import os
import requests
import json
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

class Phoneinfoga(ToolModule):
    def __init__(self):
        super().__init__()

    def _get_name(self) -> str:
        return "phoneinfoga"

    def _get_category(self) -> str:
        return "OSINT"

    def _get_command(self) -> str:
        return "phoneinfoga"

    def _get_description(self) -> str:
        return "Advanced information gathering and OSINT framework for phone numbers"

    def _get_dependencies(self) -> List[str]:
        return ["curl", "wget", "tar"]

    def _get_script_path(self) -> str:
        return "phoneinfoga"

    def _get_latest_release_info(self) -> Optional[dict]:
        """Get the latest release information from GitHub"""
        try:
            url = "https://api.github.com/repos/sundowndev/phoneinfoga/releases/latest"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"{Colors.WARNING}[!] Could not fetch release info: {e}{Colors.ENDC}")
            return None

    def _get_download_url(self) -> Optional[str]:
        """Get the download URL for the appropriate architecture"""
        release_info = self._get_latest_release_info()
        if not release_info:
            return None
        
        # Detect architecture
        arch_output = subprocess.run(["uname", "-m"], capture_output=True, text=True)
        arch = arch_output.stdout.strip()
        
        # Map architecture names to PhoneInfoga naming convention
        arch_mapping = {
            'x86_64': 'x86_64',
            'amd64': 'x86_64',
            'i386': 'i386',
            'i686': 'i386',
            'armv7l': 'arm',
            'aarch64': 'arm64'
        }
        
        target_arch = arch_mapping.get(arch, 'x86_64')
        
        # Look for Linux tar.gz in assets (format: phoneinfoga_Linux_x86_64.tar.gz)
        for asset in release_info.get('assets', []):
            asset_name = asset['name']
            if ('Linux' in asset_name and 
                target_arch in asset_name and 
                asset_name.endswith('.tar.gz')):
                return asset['browser_download_url']
        
        # Fallback to x86_64 if exact match not found
        for asset in release_info.get('assets', []):
            asset_name = asset['name']
            if ('Linux' in asset_name and 
                'x86_64' in asset_name and 
                asset_name.endswith('.tar.gz')):
                return asset['browser_download_url']
        
        return None

    def _find_phoneinfoga_command(self) -> Optional[str]:
        """Find the correct phoneinfoga command"""
        
        # Option 1: Direct command (if in PATH)
        if shutil.which("phoneinfoga"):
            return "phoneinfoga"
        
        # Option 2: Local installation in /usr/local/bin
        local_path = Path("/usr/local/bin/phoneinfoga")
        if local_path.exists() and local_path.is_file():
            return str(local_path)
        
        # Option 3: User local bin
        user_local = Path.home() / ".local/bin/phoneinfoga"
        if user_local.exists() and user_local.is_file():
            return str(user_local)
        
        # Option 4: Current directory
        current_dir = Path("./phoneinfoga")
        if current_dir.exists() and current_dir.is_file():
            return str(current_dir)
        
        return None

    def check_installation(self) -> bool:
        """Check if phoneinfoga is properly installed"""
        try:
            command = self._find_phoneinfoga_command()
            if not command:
                return False
            
            # Test the command
            result = subprocess.run(
                [command, "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return result.returncode == 0
            
        except Exception:
            return False

    def _download_and_install_binary(self) -> bool:
        """Download and install the binary from GitHub releases"""
        try:
            print(f"{Colors.CYAN}[*] Downloading PhoneInfoga binary...{Colors.ENDC}")
            
            download_url = self._get_download_url()
            if not download_url:
                print(f"{Colors.FAIL}[!] Could not find suitable binary for your system{Colors.ENDC}")
                return False
            
            print(f"{Colors.CYAN}[*] Download URL: {download_url}{Colors.ENDC}")
            
            # Download the tar.gz file
            response = requests.get(download_url, timeout=120)
            response.raise_for_status()
            
            # Save to temporary file
            temp_file = "/tmp/phoneinfoga.tar.gz"
            with open(temp_file, 'wb') as f:
                f.write(response.content)
            
            print(f"{Colors.CYAN}[*] Extracting archive...{Colors.ENDC}")
            
            # Create temporary extraction directory
            extract_dir = "/tmp/phoneinfoga_extract"
            if Path(extract_dir).exists():
                subprocess.run(["rm", "-rf", extract_dir])
            os.makedirs(extract_dir)
            
            # Extract the tar.gz file
            subprocess.run([
                "tar", "-xzf", temp_file, "-C", extract_dir
            ], check=True)
            
            # Find the phoneinfoga binary in extracted files
            phoneinfoga_binary = None
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file == "phoneinfoga" or file.startswith("phoneinfoga"):
                        file_path = os.path.join(root, file)
                        # Check if it's executable or make it executable
                        if os.path.isfile(file_path):
                            os.chmod(file_path, 0o755)
                            phoneinfoga_binary = file_path
                            break
                if phoneinfoga_binary:
                    break
            
            if not phoneinfoga_binary:
                print(f"{Colors.FAIL}[!] Could not find phoneinfoga binary in extracted files{Colors.ENDC}")
                return False
            
            print(f"{Colors.CYAN}[*] Installing binary to /usr/local/bin...{Colors.ENDC}")
            
            # Move to /usr/local/bin
            subprocess.run(["sudo", "cp", phoneinfoga_binary, "/usr/local/bin/phoneinfoga"], check=True)
            subprocess.run(["sudo", "chmod", "+x", "/usr/local/bin/phoneinfoga"], check=True)
            
            # Cleanup
            subprocess.run(["rm", "-rf", temp_file, extract_dir])
            
            print(f"{Colors.GREEN}[✓] PhoneInfoga binary installed successfully{Colors.ENDC}")
            
            # Verify installation
            if self.check_installation():
                print(f"{Colors.GREEN}[✓] Installation verified successfully{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.WARNING}[!] Installation completed but verification failed{Colors.ENDC}")
                return False
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Failed to download/install binary: {e}{Colors.ENDC}")
            # Cleanup on error
            try:
                subprocess.run(["rm", "-rf", "/tmp/phoneinfoga.tar.gz", "/tmp/phoneinfoga_extract"])
            except:
                pass
            return False

    def _install_from_source(self) -> bool:
        """Install PhoneInfoga from source code"""
        try:
            print(f"{Colors.CYAN}[*] Installing PhoneInfoga from source...{Colors.ENDC}")
            
            # Check if Go is installed
            if not shutil.which("go"):
                print(f"{Colors.FAIL}[!] Go is required but not installed{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Install Go with: sudo apt install golang-go{Colors.ENDC}")
                return False
            
            # Clone the repository
            temp_dir = "/tmp/phoneinfoga_build"
            if Path(temp_dir).exists():
                subprocess.run(["rm", "-rf", temp_dir])
            
            subprocess.run([
                "git", "clone", 
                "https://github.com/sundowndev/phoneinfoga.git", 
                temp_dir
            ], check=True)
            
            # Build the binary
            old_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                subprocess.run(["go", "build", "-o", "phoneinfoga", "."], check=True)
                
                # Move to /usr/local/bin
                subprocess.run(["sudo", "mv", "phoneinfoga", "/usr/local/bin/"], check=True)
                
                print(f"{Colors.GREEN}[✓] PhoneInfoga compiled and installed successfully{Colors.ENDC}")
                return True
                
            finally:
                os.chdir(old_cwd)
                subprocess.run(["rm", "-rf", temp_dir])
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Failed to install from source: {e}{Colors.ENDC}")
            return False

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Return installation commands"""
        commands = {
            'apt': [
                "apt-get update",
                "apt-get install -y curl wget git golang-go tar",
                "mkdir -p /tmp/phoneinfoga_install",
                "wget -O /tmp/phoneinfoga_install/phoneinfoga.tar.gz 'https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz'",
                "tar -xzf /tmp/phoneinfoga_install/phoneinfoga.tar.gz -C /tmp/phoneinfoga_install/",
                "chmod +x /tmp/phoneinfoga_install/phoneinfoga",
                "cp /tmp/phoneinfoga_install/phoneinfoga /usr/local/bin/",
                "rm -rf /tmp/phoneinfoga_install"
            ],
            'yum': [
                "yum update -y",
                "yum install -y curl wget git golang tar",
                "mkdir -p /tmp/phoneinfoga_install",
                "wget -O /tmp/phoneinfoga_install/phoneinfoga.tar.gz 'https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz'",
                "tar -xzf /tmp/phoneinfoga_install/phoneinfoga.tar.gz -C /tmp/phoneinfoga_install/",
                "chmod +x /tmp/phoneinfoga_install/phoneinfoga",
                "cp /tmp/phoneinfoga_install/phoneinfoga /usr/local/bin/",
                "rm -rf /tmp/phoneinfoga_install"
            ],
            'dnf': [
                "dnf update -y", 
                "dnf install -y curl wget git golang tar",
                "mkdir -p /tmp/phoneinfoga_install",
                "wget -O /tmp/phoneinfoga_install/phoneinfoga.tar.gz 'https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz'",
                "tar -xzf /tmp/phoneinfoga_install/phoneinfoga.tar.gz -C /tmp/phoneinfoga_install/",
                "chmod +x /tmp/phoneinfoga_install/phoneinfoga",
                "cp /tmp/phoneinfoga_install/phoneinfoga /usr/local/bin/",
                "rm -rf /tmp/phoneinfoga_install"
            ],
            'pacman': [
                "pacman -Sy",
                "pacman -S curl wget git go tar --noconfirm",
                "mkdir -p /tmp/phoneinfoga_install",
                "wget -O /tmp/phoneinfoga_install/phoneinfoga.tar.gz 'https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz'",
                "tar -xzf /tmp/phoneinfoga_install/phoneinfoga.tar.gz -C /tmp/phoneinfoga_install/",
                "chmod +x /tmp/phoneinfoga_install/phoneinfoga",
                "cp /tmp/phoneinfoga_install/phoneinfoga /usr/local/bin/",
                "rm -rf /tmp/phoneinfoga_install"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Return update commands"""
        return ["echo 'Update PhoneInfoga using the reinstall option'"]

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Return uninstallation commands"""
        return [
            "rm -f /usr/local/bin/phoneinfoga",
            "rm -f ~/.local/bin/phoneinfoga",
            "rm -f ./phoneinfoga"
        ]

    def get_help(self) -> dict:
        return {
            "title": "PhoneInfoga - Phone Number OSINT",
            "usage": "use phoneinfoga",
            "desc": "Advanced information gathering and OSINT framework for phone numbers using only free resources.",
            "modes": {
                "Guided": "Interactive mode for phone number analysis",
                "Direct": "Direct CLI execution with native phoneinfoga commands"
            },
            "options": {
                "scan -n <number>": "Scan a phone number",
                "scanners": "Display list of loaded scanners",
                "serve": "Serve web client",
                "version": "Print current version"
            },
            "examples": [
                'phoneinfoga scan -n "+1234567890"',
                'phoneinfoga scanners',
                'phoneinfoga serve',
                'phoneinfoga version'
            ]
        }

    def _show_banner(self):
        print(f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║              PHONEINFOGA                 ║
║        "Phone Number OSINT"              ║
║            Binary Version                ║
╚══════════════════════════════════════════╝{Colors.ENDC}''')

    def _validate_phone_number(self, phone: str) -> bool:
        """Validate phone number format (international format expected)"""
        # Basic validation for international format
        pattern = r'^\+[1-9]\d{1,14}$'
        return re.match(pattern, phone) is not None

    def _get_phone_number(self) -> Optional[str]:
        """Get and validate phone number from user"""
        while True:
            print(f"\n{Colors.CYAN}[*] Phone Number Format Examples:{Colors.ENDC}")
            print("  +1234567890    (US)")
            print("  +34612345678   (Spain)")
            print("  +447912345678  (UK)")
            print("  +33123456789   (France)")
            
            phone = input(f"\n{Colors.BOLD}[+] Enter phone number (international format): {Colors.ENDC}").strip()
            
            if not phone:
                print(f"{Colors.FAIL}[!] Phone number is required{Colors.ENDC}")
                retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
                if retry == 'n':
                    return None
                continue
            
            # Add + if missing
            if not phone.startswith('+'):
                phone = '+' + phone
                
            if self._validate_phone_number(phone):
                return phone
            else:
                print(f"{Colors.FAIL}[!] Invalid phone number format{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Use international format: +[country_code][number]{Colors.ENDC}")
                retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
                if retry == 'n':
                    return None

    def _execute_phoneinfoga_scan(self, phone: str) -> bool:
        """Execute PhoneInfoga scan command"""
        try:
            command = self._find_phoneinfoga_command()
            if not command:
                print(f"{Colors.FAIL}[!] PhoneInfoga command not found{Colors.ENDC}")
                return False
            
            # Build scan command: phoneinfoga scan -n "+1234567890"
            cmd = [command, "scan", "-n", phone]
            
            print(f"\n{Colors.CYAN}[*] Executing PhoneInfoga scan...{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Command: {' '.join(cmd)}{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Target: {phone}{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] This may take a moment...{Colors.ENDC}")
            
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
                print(f"\n{Colors.GREEN}[✓] Scan completed successfully{Colors.ENDC}")
                return True
            else:
                print(f"\n{Colors.FAIL}[!] Scan failed with return code {return_code}{Colors.ENDC}")
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
        """Interactive guided mode for phoneinfoga"""
        self._show_banner()

        while True:
            try:
                print(f"\n{Colors.CYAN}[*] Phone Number OSINT Analysis{Colors.ENDC}")
                
                # Check if command is available
                command = self._find_phoneinfoga_command()
                if command:
                    print(f"{Colors.GREEN}[✓] Found PhoneInfoga at: {command}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] PhoneInfoga not found{Colors.ENDC}")
                    print(f"{Colors.CYAN}[*] Please install PhoneInfoga first using the web interface{Colors.ENDC}")
                    
                    # Offer installation options
                    install_choice = input(f"\n{Colors.BOLD}[+] Try to install now? (y/N): {Colors.ENDC}").lower()
                    if install_choice == 'y':
                        print(f"\n{Colors.CYAN}[*] Installation Options:{Colors.ENDC}")
                        print("1. Download binary (recommended)")
                        print("2. Compile from source")
                        
                        method = input(f"\n{Colors.BOLD}[+] Choose method (1-2): {Colors.ENDC}").strip()
                        
                        if method == "1":
                            if self._download_and_install_binary():
                                print(f"{Colors.GREEN}[✓] Installation successful{Colors.ENDC}")
                                continue
                        elif method == "2":
                            if self._install_from_source():
                                print(f"{Colors.GREEN}[✓] Installation successful{Colors.ENDC}")
                                continue
                        
                        print(f"{Colors.FAIL}[!] Installation failed{Colors.ENDC}")
                    
                    break
                
                # Get phone number
                phone = self._get_phone_number()
                if not phone:
                    print(f"{Colors.WARNING}[!] No phone number provided{Colors.ENDC}")
                    continue
                
                # Show scan information
                print(f"\n{Colors.CYAN}[*] Scan Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 30)
                print(f"Target: {phone}")
                print(f"Tool: PhoneInfoga scan")
                print(f"Scanners: All available (free resources)")
                
                # Confirm and execute
                if input(f"\n{Colors.BOLD}[+] Start scan? (Y/n): {Colors.ENDC}").lower() != 'n':
                    if self._execute_phoneinfoga_scan(phone):
                        print(f"{Colors.GREEN}[✓] Phone number analysis completed{Colors.ENDC}")

                # Ask for another scan
                if input(f"\n{Colors.BOLD}[?] Scan another number? (y/N): {Colors.ENDC}").lower() != 'y':
                    break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for phoneinfoga"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Native PhoneInfoga Commands{Colors.ENDC}")
        
        # Show current command status
        command = self._find_phoneinfoga_command()
        if command:
            print(f"{Colors.GREEN}[✓] PhoneInfoga found: {command}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] PhoneInfoga not found{Colors.ENDC}")
        
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  scan -n \"+1234567890\"              - Scan phone number")
        print("  scanners                           - Display list of loaded scanners")
        print("  serve                              - Start web interface (port 5000)")
        print("  serve -p 8080                      - Start web interface on custom port")
        print("  version                            - Show version")
        print("  help                               - Show phoneinfoga help")
        print("  test                               - Test installation")
        print("  install                            - Install PhoneInfoga")
        print("  web                                - Start web interface (port 5000)")
        print("  web 8080                           - Start web interface on port 8080")
        print("  ports                              - Show common alternative ports")
        print("  exit                               - Exit direct mode")
        
        while True:
            try:
                command_input = input(f"\n{Colors.BOLD}phoneinfoga > {Colors.ENDC}").strip()
                
                if not command_input:
                    continue
                    
                if command_input.lower() == 'exit':
                    break
                    
                elif command_input.lower() == 'test':
                    print(f"{Colors.CYAN}[*] Testing PhoneInfoga installation...{Colors.ENDC}")
                    if self.check_installation():
                        print(f"{Colors.GREEN}[✓] PhoneInfoga is working properly{Colors.ENDC}")
                        # Show version
                        command = self._find_phoneinfoga_command()
                        if command:
                            subprocess.run([command, "version"])
                    else:
                        print(f"{Colors.FAIL}[!] PhoneInfoga is not working properly{Colors.ENDC}")
                
                elif command_input.lower() == 'install':
                    print(f"\n{Colors.CYAN}[*] Installation Options:{Colors.ENDC}")
                    print("1. Download binary (recommended)")
                    print("2. Compile from source")
                    
                    method = input(f"\n{Colors.BOLD}[+] Choose method (1-2): {Colors.ENDC}").strip()
                    
                    if method == "1":
                        self._download_and_install_binary()
                    elif method == "2":
                        self._install_from_source()
                
                elif command_input.lower().startswith('web'):
                    # Handle web command with optional port
                    parts = command_input.split()
                    port = "8080"  # Default alternative port
                    
                    if len(parts) > 1:
                        try:
                            port = str(int(parts[1]))  # Validate port number
                        except ValueError:
                            print(f"{Colors.FAIL}[!] Invalid port number: {parts[1]}{Colors.ENDC}")
                            continue
                    
                    command = self._find_phoneinfoga_command()
                    if command:
                        print(f"{Colors.CYAN}[*] Starting PhoneInfoga web interface...{Colors.ENDC}")
                        print(f"{Colors.CYAN}[*] Port: {port}{Colors.ENDC}")
                        print(f"{Colors.CYAN}[*] Access at: http://localhost:{port}{Colors.ENDC}")
                        print(f"{Colors.WARNING}[*] Press Ctrl+C to stop{Colors.ENDC}")
                        subprocess.run([command, "serve", "-p", port])
                    else:
                        print(f"{Colors.FAIL}[!] PhoneInfoga not available{Colors.ENDC}")
                
                elif command_input.lower() == 'ports':
                    print(f"\n{Colors.CYAN}[*] Common Alternative Ports:{Colors.ENDC}")
                    print("  8080  - HTTP alternative (recommended)")
                    print("  8000  - Development server")
                    print("  3000  - Node.js applications")
                    print("  8888  - Jupyter/development")
                    print("  9000  - General purpose")
                    print("  8081  - HTTP alternative")
                    print("  4000  - Development server")
                    print(f"\n{Colors.YELLOW}[*] Usage examples:{Colors.ENDC}")
                    print("  web 8080")
                    print("  serve -p 8000")
                
                elif command_input.lower() == 'scanners':
                    command = self._find_phoneinfoga_command()
                    if command:
                        subprocess.run([command, "scanners"])
                    else:
                        print(f"{Colors.FAIL}[!] PhoneInfoga not available{Colors.ENDC}")
                
                elif command_input.lower() == 'version':
                    command = self._find_phoneinfoga_command()
                    if command:
                        subprocess.run([command, "version"])
                    else:
                        print(f"{Colors.FAIL}[!] PhoneInfoga not available{Colors.ENDC}")
                
                elif command_input.lower() == 'help':
                    command = self._find_phoneinfoga_command()
                    if command:
                        subprocess.run([command, "--help"])
                    else:
                        print(f"{Colors.FAIL}[!] PhoneInfoga not available{Colors.ENDC}")
                
                else:
                    # Execute as native phoneinfoga command
                    command = self._find_phoneinfoga_command()
                    if not command:
                        print(f"{Colors.FAIL}[!] PhoneInfoga not available{Colors.ENDC}")
                        print(f"{Colors.WARNING}[*] Try 'install' first{Colors.ENDC}")
                        continue
                    
                    try:
                        # Special handling for serve command with port
                        if command_input.startswith('serve'):
                            parts = command_input.split()
                            if len(parts) == 1:
                                # Default serve command
                                print(f"{Colors.WARNING}[!] Port 5000 might be occupied by CoreSecFrame{Colors.ENDC}")
                                print(f"{Colors.CYAN}[*] Tip: Use 'serve -p 8080' for alternative port{Colors.ENDC}")
                                if input(f"{Colors.BOLD}[+] Continue anyway? (y/N): {Colors.ENDC}").lower() != 'y':
                                    continue
                            
                            # Execute serve command
                            cmd = [command] + parts
                            print(f"{Colors.CYAN}[*] Starting PhoneInfoga web interface...{Colors.ENDC}")
                            if '-p' in parts:
                                port_index = parts.index('-p') + 1
                                if port_index < len(parts):
                                    print(f"{Colors.CYAN}[*] Port: {parts[port_index]}{Colors.ENDC}")
                                    print(f"{Colors.CYAN}[*] Access at: http://localhost:{parts[port_index]}{Colors.ENDC}")
                            else:
                                print(f"{Colors.CYAN}[*] Port: 5000 (default){Colors.ENDC}")
                                print(f"{Colors.CYAN}[*] Access at: http://localhost:5000{Colors.ENDC}")
                            print(f"{Colors.WARNING}[*] Press Ctrl+C to stop{Colors.ENDC}")
                        else:
                            # Parse other commands normally
                            args = command_input.split()
                            cmd = [command] + args
                            print(f"{Colors.CYAN}[*] Executing: {' '.join(cmd)}{Colors.ENDC}")
                        
                        subprocess.run(cmd)
                        
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
    return Phoneinfoga()

if __name__ == "__main__":
    tool = Phoneinfoga()
    
    if len(sys.argv) > 1 and sys.argv[1] == "direct":
        tool.run_direct()
    else:
        tool.run_guided()