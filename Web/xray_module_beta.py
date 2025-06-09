from core.base import ToolModule
from core.colors import Colors
import subprocess
import platform
import os
import shutil
import requests
import zipfile
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
import time

class XrayModule(ToolModule):
    def __init__(self):
        self._binary_url = "https://github.com/chaitin/xray/releases/download/1.9.10/xray_linux_amd64.zip"
        self._install_dir = Path("/opt/xray")
        self._binary_path = self._install_dir / "xray_linux_amd64"
        super().__init__()

    def _get_name(self) -> str:
        return "Xray"

    def _get_category(self) -> str:
        return "Web"

    def _get_command(self) -> str:
        return "xray"

    def _get_description(self) -> str:
        return "Powerful security scanner for web applications - supports crawler, proxy, and direct URL scanning"

    def _get_dependencies(self) -> List[str]:
        return ["wget", "unzip", "curl"]

    def _get_script_path(self) -> str:
        return str(self._binary_path)

    def get_help(self) -> dict:
        return {
            "title": "Xray - Web Security Scanner",
            "usage": "use xray",
            "desc": "Fast and powerful web vulnerability scanner",
            "modes": {
                "Guided": "Step-by-step scanning options",
                "Direct": "Direct command execution"
            },
            "options": {
                "--basic-crawler": "Crawl and scan website",
                "--listen": "HTTP proxy mode for passive scanning",
                "--url": "Scan single URL",
                "--plugins": "Specify plugins (cmd-injection,sqldet,xss,etc)",
                "--html-output": "HTML report output",
                "--json-output": "JSON results output",
                "--text-output": "Text results output"
            },
            "examples": [
                "xray webscan --basic-crawler http://example.com --html-output report.html",
                "xray webscan --listen 127.0.0.1:7777 --html-output proxy.html",
                "xray webscan --url http://example.com --json-output result.json",
                "xray webscan --plugins cmd-injection,sqldet --url http://example.com"
            ]
        }

    def check_installation(self) -> bool:
        """Check if Xray is installed"""
        return self._binary_path.exists() and os.access(self._binary_path, os.X_OK)

    def _install_xray(self) -> bool:
        """Simple Xray installation"""
        try:
            print(f"{Colors.CYAN}[*] Installing Xray...{Colors.ENDC}")
            
            # Create directory
            subprocess.run(["sudo", "mkdir", "-p", str(self._install_dir)], check=True)
            
            # Download and extract
            temp_dir = Path(tempfile.mkdtemp())
            zip_path = temp_dir / "xray.zip"
            
            print(f"{Colors.CYAN}[*] Downloading from GitHub...{Colors.ENDC}")
            response = requests.get(self._binary_url, timeout=120)
            response.raise_for_status()
            
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            
            print(f"{Colors.CYAN}[*] Extracting...{Colors.ENDC}")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find and copy binary
            binary_file = temp_dir / "xray_linux_amd64"
            if binary_file.exists():
                subprocess.run(["sudo", "cp", str(binary_file), str(self._binary_path)], check=True)
                subprocess.run(["sudo", "chmod", "+x", str(self._binary_path)], check=True)
                subprocess.run(["sudo", "chown", "-R", f"{os.getenv('USER')}:{os.getenv('USER')}", str(self._install_dir)], check=True)
            else:
                return False
            
            # Cleanup
            shutil.rmtree(temp_dir)
            
            print(f"{Colors.GREEN}[✓] Xray installed successfully{Colors.ENDC}")
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Installation failed: {e}{Colors.ENDC}")
            return False

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Installation commands"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y wget unzip curl",
                f"sudo mkdir -p {self._install_dir}",
                f"wget -O /tmp/xray.zip {self._binary_url}",
                f"unzip /tmp/xray.zip -d /tmp/",
                f"sudo cp /tmp/xray_linux_amd64 {self._binary_path}",
                f"sudo chmod +x {self._binary_path}",
                f"sudo chown -R $(whoami):$(whoami) {self._install_dir}",
                "rm -f /tmp/xray.zip /tmp/xray_linux_amd64"
            ],
            'yum': [
                "sudo yum update -y",
                "sudo yum install -y wget unzip curl",
                f"sudo mkdir -p {self._install_dir}",
                f"wget -O /tmp/xray.zip {self._binary_url}",
                f"unzip /tmp/xray.zip -d /tmp/",
                f"sudo cp /tmp/xray_linux_amd64 {self._binary_path}",
                f"sudo chmod +x {self._binary_path}",
                f"sudo chown -R $(whoami):$(whoami) {self._install_dir}",
                "rm -f /tmp/xray.zip /tmp/xray_linux_amd64"
            ],
            'dnf': [
                "sudo dnf update -y",
                "sudo dnf install -y wget unzip curl",
                f"sudo mkdir -p {self._install_dir}",
                f"wget -O /tmp/xray.zip {self._binary_url}",
                f"unzip /tmp/xray.zip -d /tmp/",
                f"sudo cp /tmp/xray_linux_amd64 {self._binary_path}",
                f"sudo chmod +x {self._binary_path}",
                f"sudo chown -R $(whoami):$(whoami) {self._install_dir}",
                "rm -f /tmp/xray.zip /tmp/xray_linux_amd64"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S wget unzip curl --noconfirm",
                f"sudo mkdir -p {self._install_dir}",
                f"wget -O /tmp/xray.zip {self._binary_url}",
                f"unzip /tmp/xray.zip -d /tmp/",
                f"sudo cp /tmp/xray_linux_amd64 {self._binary_path}",
                f"sudo chmod +x {self._binary_path}",
                f"sudo chown -R $(whoami):$(whoami) {self._install_dir}",
                "rm -f /tmp/xray.zip /tmp/xray_linux_amd64"
            ]
        }
        return commands.get(pkg_manager, commands['apt'])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        return self._get_install_command(pkg_manager)

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        return [f"rm -rf {self._install_dir}"]

    def _show_banner(self):
        """Show banner"""
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║                 XRAY                      ║
║         "Web Security Scanner"           ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _execute_xray(self, command: List[str]) -> bool:
        """Execute Xray command"""
        try:
            print(f"\n{Colors.CYAN}[*] Executing: {' '.join(command)}{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] Press Ctrl+C to stop{Colors.ENDC}")
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                cwd=str(self._install_dir)
            )
            
            # Real-time output
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
                print(f"\n{Colors.FAIL}[!] Scan failed with code {return_code}{Colors.ENDC}")
                return False
                
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Scan interrupted{Colors.ENDC}")
            try:
                process.terminate()
            except:
                pass
            return False
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
            return False

    def run_guided(self) -> None:
        """Guided mode based on quick guide examples"""
        self._show_banner()

        # Check installation
        if not self.check_installation():
            print(f"{Colors.WARNING}[!] Xray not installed{Colors.ENDC}")
            if input(f"{Colors.BOLD}[+] Install now? (Y/n): {Colors.ENDC}").lower() != 'n':
                if not self._install_xray():
                    return
            else:
                return

        print(f"{Colors.GREEN}[✓] Xray ready{Colors.ENDC}")

        while True:
            try:
                print(f"\n{Colors.CYAN}[*] Scan Options (based on Quick Guide):{Colors.ENDC}")
                print(f"{Colors.GREEN}1.{Colors.ENDC} Basic crawler scan (crawl website and scan)")
                print(f"{Colors.GREEN}2.{Colors.ENDC} HTTP proxy mode (passive scanning)")
                print(f"{Colors.GREEN}3.{Colors.ENDC} Single URL scan (no crawler)")
                print(f"{Colors.GREEN}4.{Colors.ENDC} Custom plugins scan")
                print(f"{Colors.GREEN}5.{Colors.ENDC} Multiple output formats")

                choice = input(f"\n{Colors.BOLD}[+] Select option (1-5): {Colors.ENDC}").strip()

                if choice == "1":
                    # Basic crawler scan
                    url = input(f"{Colors.BOLD}[+] Enter URL to crawl: {Colors.ENDC}").strip()
                    if not url:
                        continue
                    
                    output_file = f"xray_crawler_{int(time.time())}.html"
                    command = [str(self._binary_path), "webscan", "--basic-crawler", url, "--html-output", output_file]

                elif choice == "2":
                    # HTTP proxy mode
                    proxy_addr = input(f"{Colors.BOLD}[+] Proxy address (default 127.0.0.1:7777): {Colors.ENDC}").strip()
                    if not proxy_addr:
                        proxy_addr = "127.0.0.1:7777"
                    
                    output_file = f"xray_proxy_{int(time.time())}.html"
                    command = [str(self._binary_path), "webscan", "--listen", proxy_addr, "--html-output", output_file]
                    
                    print(f"{Colors.CYAN}[*] Set your browser proxy to: http://{proxy_addr}{Colors.ENDC}")
                    print(f"{Colors.CYAN}[*] Browse websites and Xray will scan automatically{Colors.ENDC}")

                elif choice == "3":
                    # Single URL scan
                    url = input(f"{Colors.BOLD}[+] Enter URL to scan: {Colors.ENDC}").strip()
                    if not url:
                        continue
                    
                    output_file = f"xray_single_{int(time.time())}.html"
                    command = [str(self._binary_path), "webscan", "--url", url, "--html-output", output_file]

                elif choice == "4":
                    # Custom plugins
                    url = input(f"{Colors.BOLD}[+] Enter URL: {Colors.ENDC}").strip()
                    if not url:
                        continue
                    
                    print(f"{Colors.CYAN}[*] Available plugins: cmd-injection, sqldet, xss, xxe, baseline, etc.{Colors.ENDC}")
                    plugins = input(f"{Colors.BOLD}[+] Enter plugins (comma-separated): {Colors.ENDC}").strip()
                    if not plugins:
                        plugins = "cmd-injection,sqldet"
                    
                    output_file = f"xray_custom_{int(time.time())}.html"
                    command = [str(self._binary_path), "webscan", "--plugins", plugins, "--url", url, "--html-output", output_file]

                elif choice == "5":
                    # Multiple outputs
                    url = input(f"{Colors.BOLD}[+] Enter URL: {Colors.ENDC}").strip()
                    if not url:
                        continue
                    
                    timestamp = int(time.time())
                    command = [
                        str(self._binary_path), "webscan", "--url", url,
                        "--text-output", f"result_{timestamp}.txt",
                        "--json-output", f"result_{timestamp}.json", 
                        "--html-output", f"report_{timestamp}.html"
                    ]

                else:
                    print(f"{Colors.FAIL}[!] Invalid option{Colors.ENDC}")
                    continue

                # Execute the scan
                print(f"\n{Colors.CYAN}[*] Command: {' '.join(command)}{Colors.ENDC}")
                if input(f"{Colors.BOLD}[+] Start scan? (Y/n): {Colors.ENDC}").lower() != 'n':
                    self._execute_xray(command)

                if input(f"\n{Colors.BOLD}[?] Another scan? (y/N): {Colors.ENDC}").lower() != 'y':
                    break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Cancelled{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct mode with simple commands"""
        self._show_banner()
        
        if not self.check_installation():
            print(f"{Colors.WARNING}[!] Xray not installed{Colors.ENDC}")
            if input(f"{Colors.BOLD}[+] Install now? (Y/n): {Colors.ENDC}").lower() != 'n':
                if not self._install_xray():
                    return
            else:
                return

        print(f"{Colors.GREEN}[✓] Xray ready at: {self._binary_path}{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter xray commands{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Quick Examples:{Colors.ENDC}")
        print("  webscan --basic-crawler http://example.com --html-output report.html")
        print("  webscan --listen 127.0.0.1:7777 --html-output proxy.html")
        print("  webscan --url http://example.com --json-output result.json")
        print("  webscan --plugins cmd-injection,sqldet --url http://example.com")
        print("  version")
        print("  help")
        print("  exit")

        while True:
            try:
                command_input = input(f"\n{Colors.BOLD}xray > {Colors.ENDC}").strip()
                
                if not command_input:
                    continue
                    
                if command_input.lower() == 'exit':
                    break
                    
                elif command_input.lower() == 'help':
                    subprocess.run([str(self._binary_path), "-h"], cwd=str(self._install_dir))
                    
                elif command_input.lower() == 'version':
                    subprocess.run([str(self._binary_path), "version"], cwd=str(self._install_dir))
                    
                else:
                    # Execute as xray command
                    args = command_input.split()
                    cmd = [str(self._binary_path)] + args
                    self._execute_xray(cmd)
                        
            except KeyboardInterrupt:
                print()
                continue