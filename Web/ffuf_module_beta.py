from core.base import ToolModule
from core.colors import Colors
import subprocess
import platform
import os
import json
import requests
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class FFUFModule(ToolModule):
    def __init__(self):
        self._wordlists = {
            # Directory Discovery - Dirb/Dirbuster (estándar)
            "common": "/usr/share/wordlists/dirb/common.txt",
            "big": "/usr/share/wordlists/dirb/big.txt", 
            "directory-list-2.3-medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "directory-list-2.3-small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            
            # SecLists - Web Content Discovery
            "raft-large-files": "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
            "raft-large-directories": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
            "raft-medium-directories": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "raft-small-directories": "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
            "quickhits": "/usr/share/seclists/Discovery/Web-Content/quickhits.txt",
            
            # Parameter Discovery
            "burp-parameter-names": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
            
            # API Discovery
            "api-endpoints": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
            "api-seen-in-wild": "/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt",
            "common-api-endpoints-mazen160": "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
            "api-actions": "/usr/share/seclists/Discovery/Web-Content/api/actions.txt",
            "api-objects": "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
            
            # LFI Specific
            "lfi-jhaddix": "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
            "lfi-gracefulsecurity-linux": "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
            "lfi-gracefulsecurity-windows": "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
            "default-web-root-directory-linux": "/usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt",
            "default-web-root-directory-windows": "/usr/share/seclists/Discovery/Web-Content/default-web-root-directory-windows.txt",
            
            # Subdomain Discovery
            "subdomains-top1million-5000": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "subdomains-top1million-20000": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "subdomains-top1million-110000": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            
            # File Extensions
            "web-extensions": "/usr/share/seclists/Discovery/Web-Content/web-extensions.txt",
            "common-extensions": "/usr/share/seclists/Discovery/Web-Content/Common-Exts.txt",
            
            # Backup and Sensitive Files
            "backup-files": "/usr/share/seclists/Discovery/Web-Content/backup-files.txt",
            "sensitive-files": "/usr/share/seclists/Discovery/Web-Content/sensitive-files.txt",
            "Common-DB-Backups": "/usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt",
            
            # Technology Specific
            "apache": "/usr/share/seclists/Discovery/Web-Content/Apache.txt",
            "nginx": "/usr/share/seclists/Discovery/Web-Content/Nginx.txt",
            "tomcat": "/usr/share/seclists/Discovery/Web-Content/tomcat.txt",
            "iis": "/usr/share/seclists/Discovery/Web-Content/IIS.txt",
            "spring-boot": "/usr/share/seclists/Discovery/Web-Content/spring-boot.txt",
            
            # CMS Specific
            "wordpress": "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.txt",
            "drupal": "/usr/share/seclists/Discovery/Web-Content/CMS/drupal.txt",
            "joomla": "/usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt",
            
            # GraphQL
            "graphql": "/usr/share/seclists/Discovery/Web-Content/graphql.txt",
            
            # Common Usernames (para user enumeration)
            "usernames": "/usr/share/seclists/Usernames/Names/names.txt",
            "xato-net-10-million-usernames": "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
        }
        
        # URLs de descarga para diccionarios específicos si no existen localmente
        self._wordlists_urls = {
            "lfi-jhaddix": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
            "lfi-gracefulsecurity-linux": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
            "lfi-gracefulsecurity-windows": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
            "default-web-root-directory-linux": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/default-web-root-directory-linux.txt",
            "default-web-root-directory-windows": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/default-web-root-directory-windows.txt",
            "burp-parameter-names": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
            "api-endpoints": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
            "common-api-endpoints-mazen160": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt"
        }
        
        self._output_dir = Path.home() / "ffuf_results"
        super().__init__()

    def _get_name(self) -> str:
        return "FFUF"

    def _get_category(self) -> str:
        return "Web"

    def _get_command(self) -> str:
        return "ffuf"

    def _get_description(self) -> str:
        return "Fast web fuzzer written in Go for directory, file, parameter discovery and LFI testing"

    def _get_dependencies(self) -> List[str]:
        return ["ffuf"]

    def _get_script_path(self) -> str:
        """Returns path to script if applicable"""
        return ""  # FFUF is a binary, no script needed

    def get_help(self) -> dict:
        return {
            "title": "FFUF - Fast Web Fuzzer",
            "usage": "use ffuf",
            "desc": "High-performance web fuzzer for directory enumeration, parameter discovery, LFI testing and more",
            "modes": {
                "Guided": "Interactive mode with predefined fuzzing profiles",
                "Direct": "Direct command execution with full ffuf syntax"
            },
            "options": {
                "-u URL": "Target URL",
                "-w WORDLIST": "Wordlist file",
                "-H HEADER": "Header to add (format: 'Name: Value')",
                "-X METHOD": "HTTP method to use",
                "-d DATA": "POST data",
                "-t THREADS": "Number of threads (default 40)",
                "-fs SIZE": "Filter responses by size",
                "-fc CODE": "Filter responses by status code",
                "-fw WORDS": "Filter responses by word count",
                "-fl LINES": "Filter responses by line count",
                "-fr REGEX": "Filter responses by regex",
                "-mc CODE": "Match responses by status code",
                "-ms SIZE": "Match responses by size",
                "-mw WORDS": "Match responses by word count",
                "-ml LINES": "Match responses by line count",
                "-mr REGEX": "Match responses by regex",
                "-o FILE": "Output file",
                "-of FORMAT": "Output format (json, ejson, html, md, csv, ecsv)",
                "-se": "Stop on spurious errors",
                "-sf": "Stop when > 95% of responses are filtered"
            },
            "profiles": {
                "Directory Discovery": "Basic directory enumeration",
                "Parameter Discovery": "Find hidden parameters",
                "LFI Testing": "Local file inclusion fuzzing",
                "Extension Discovery": "File extension enumeration",
                "Subdomain Discovery": "Virtual host/subdomain enumeration",
                "API Endpoint Discovery": "REST API endpoint discovery",
                "Backup File Discovery": "Find backup and sensitive files"
            },
            "examples": [
                'ffuf -u http://example.com/FUZZ -w wordlist.txt',
                'ffuf -u http://example.com/?FUZZ=value -w parameters.txt',
                'ffuf -u http://example.com/page.php?file=../../../../FUZZ -w lfi-wordlist.txt',
                'ffuf -u http://example.com/file.FUZZ -w extensions.txt',
                'ffuf -H "Host: FUZZ.example.com" -u http://example.com -w subdomains.txt'
            ],
            "notes": [
                "Use filters (-fs, -fc, -fw) to reduce false positives",
                "Adjust thread count (-t) based on target capacity",
                "Save results with -o for later analysis",
                "Use different wordlists for different attack types"
            ]
        }

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Returns installation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y ffuf seclists"
            ],
            'yum': [
                "sudo yum update",
                "sudo yum install -y epel-release",
                "sudo yum install -y ffuf",
                "git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists"
            ],
            'dnf': [
                "sudo dnf update",
                "sudo dnf install -y ffuf",
                "git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S ffuf git --noconfirm",
                "git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Returns update commands for different package managers"""
        return self._get_install_command(pkg_manager)

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Returns uninstallation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get remove -y ffuf seclists",
                "sudo apt-get autoremove -y"
            ],
            'yum': [
                "sudo yum remove -y ffuf",
                "sudo rm -rf /usr/share/seclists",
                "sudo yum autoremove -y"
            ],
            'dnf': [
                "sudo dnf remove -y ffuf",
                "sudo rm -rf /usr/share/seclists",
                "sudo dnf autoremove -y"
            ],
            'pacman': [
                "sudo pacman -Rs ffuf --noconfirm",
                "sudo rm -rf /usr/share/seclists"
            ]
        }
        return commands.get(pkg_manager, [])

    def _show_banner(self):
        """Display the module banner"""
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║               FFUF                        ║
║        "Fast Web Fuzzer"                 ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _download_wordlist(self, name: str, url: str, save_path: str) -> bool:
        """Download a wordlist if it doesn't exist"""
        try:
            if Path(save_path).exists():
                return True
                
            print(f"{Colors.CYAN}[*] Downloading {name} wordlist...{Colors.ENDC}")
            
            # Create directory if it doesn't exist
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            print(f"{Colors.GREEN}[✓] Downloaded {name} to {save_path}{Colors.ENDC}")
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Failed to download {name}: {e}{Colors.ENDC}")
            return False

    def _ensure_wordlist_exists(self, wordlist_path: str, wordlist_name: str = None) -> str:
        """Ensure wordlist exists, download if needed"""
        path = Path(wordlist_path)
        
        if path.exists():
            return str(path)
        
        # Try to download from known URLs if it's a recognized wordlist
        if wordlist_name and wordlist_name in self._wordlists_urls:
            url = self._wordlists_urls[wordlist_name]
            if self._download_wordlist(wordlist_name, url, wordlist_path):
                return wordlist_path
        
        # Check alternative paths
        alternative_paths = [
            f"/usr/share/wordlists/{path.name}",
            f"/opt/wordlists/{path.name}",
            f"{Path.home()}/wordlists/{path.name}"
        ]
        
        for alt_path in alternative_paths:
            if Path(alt_path).exists():
                return alt_path
        
        return ""

    def _get_target_url(self) -> Optional[str]:
        """Get and validate target URL"""
        while True:
            url = input(f"\n{Colors.BOLD}[+] Enter target URL (include FUZZ placeholder): {Colors.ENDC}").strip()
            if not url:
                print(f"{Colors.FAIL}[!] URL is required{Colors.ENDC}")
                continue
            
            if 'FUZZ' not in url:
                print(f"{Colors.WARNING}[!] URL should contain FUZZ placeholder{Colors.ENDC}")
                add_fuzz = input(f"{Colors.BOLD}[+] Add FUZZ automatically? (Y/n): {Colors.ENDC}").lower()
                if add_fuzz != 'n':
                    if '?' in url:
                        url += "&FUZZ=value"
                    else:
                        url += "/FUZZ"
                else:
                    continue
            
            return url

    def _get_fuzzing_profile(self) -> Tuple[str, Dict]:
        """Get fuzzing profile and its configuration"""
        print(f"\n{Colors.CYAN}[*] Select Fuzzing Profile:{Colors.ENDC}")
        profiles = {
            "1": ("Directory Discovery", "dir", "Enumerate directories and files"),
            "2": ("Parameter Discovery", "param", "Find hidden GET/POST parameters"),
            "3": ("LFI Testing", "lfi", "Local File Inclusion fuzzing"),
            "4": ("Extension Discovery", "ext", "Discover file extensions"),
            "5": ("Subdomain/VHost Discovery", "vhost", "Virtual host enumeration"),
            "6": ("API Endpoint Discovery", "api", "REST API endpoint discovery"),
            "7": ("Backup File Discovery", "backup", "Find backup and sensitive files"),
            "8": ("Custom Profile", "custom", "Define custom fuzzing options")
        }

        for key, (name, _, desc) in profiles.items():
            print(f"{Colors.GREEN}{key}:{Colors.ENDC} {name} - {desc}")

        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select profile (1-8): {Colors.ENDC}").strip()
            if choice in profiles:
                profile_name, profile_type, _ = profiles[choice]
                return profile_name, self._get_profile_config(profile_type)
            print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")

    def _get_profile_config(self, profile_type: str) -> Dict:
        """Get configuration for specific profile"""
        config = {}
        
        if profile_type == "dir":
            config['suggested_wordlists'] = ["common", "raft-large-directories", "directory-list-2.3-medium", "quickhits"]
            config['suggested_url'] = "http://target.com/FUZZ"
            config['suggested_filters'] = ["-fc 404"]
            
        elif profile_type == "param":
            config['suggested_wordlists'] = ["burp-parameter-names"]
            config['suggested_url'] = "http://target.com/page.php?FUZZ=value"
            config['suggested_filters'] = ["-fs 2287"]  # Common default page size
            
        elif profile_type == "lfi":
            config['suggested_wordlists'] = ["lfi-jhaddix", "default-web-root-directory-linux", "lfi-gracefulsecurity-linux"]
            config['suggested_url'] = "http://target.com/page.php?file=../../../../FUZZ"
            config['suggested_filters'] = ["-fs 2287", "-fc 404"]
            
        elif profile_type == "ext":
            config['suggested_wordlists'] = ["web-extensions", "common-extensions"]
            config['suggested_url'] = "http://target.com/file.FUZZ"
            config['suggested_filters'] = ["-fc 404,403"]
            
        elif profile_type == "vhost":
            config['suggested_wordlists'] = ["subdomains-top1million-5000", "subdomains-top1million-20000"]
            config['suggested_url'] = "http://target.com"
            config['suggested_headers'] = ["-H 'Host: FUZZ.target.com'"]
            config['suggested_filters'] = ["-fs 0"]
            
        elif profile_type == "api":
            config['suggested_wordlists'] = ["api-endpoints", "api-seen-in-wild", "common-api-endpoints-mazen160", "raft-large-files"]
            config['suggested_url'] = "http://target.com/api/FUZZ"
            config['suggested_filters'] = ["-fc 404", "-mc 200,201,202,204,301,302,307,401,403,500"]
            
        elif profile_type == "backup":
            config['suggested_wordlists'] = ["backup-files", "sensitive-files", "Common-DB-Backups"]
            config['suggested_url'] = "http://target.com/FUZZ"
            config['suggested_filters'] = ["-fc 404", "-mc 200"]
            
        else:  # custom
            config['suggested_wordlists'] = ["common", "raft-large-directories", "burp-parameter-names", "api-endpoints"]
            config['suggested_url'] = "http://target.com/FUZZ"
            config['suggested_filters'] = ["-fc 404"]
            
        return config

    def _get_wordlist_selection(self, suggested_wordlists: List[str]) -> str:
        """Get wordlist selection with suggestions"""
        print(f"\n{Colors.CYAN}[*] Suggested wordlists for this profile:{Colors.ENDC}")
        for i, name in enumerate(suggested_wordlists, 1):
            path = self._wordlists.get(name, "")
            exists = "✓" if path and Path(path).exists() else "✗"
            print(f"{Colors.GREEN}{i}:{Colors.ENDC} {name} [{exists}]")
        
        print(f"{Colors.GREEN}{len(suggested_wordlists) + 1}:{Colors.ENDC} Choose from all available wordlists")
        print(f"{Colors.GREEN}{len(suggested_wordlists) + 2}:{Colors.ENDC} Custom wordlist path")

        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select wordlist (1-{len(suggested_wordlists) + 2}): {Colors.ENDC}").strip()
            
            try:
                choice_int = int(choice)
                if 1 <= choice_int <= len(suggested_wordlists):
                    name = suggested_wordlists[choice_int - 1]
                    path = self._wordlists.get(name, "")
                    final_path = self._ensure_wordlist_exists(path, name)
                    if final_path:
                        return final_path
                    print(f"{Colors.FAIL}[!] Wordlist not found: {path}{Colors.ENDC}")
                    
                elif choice_int == len(suggested_wordlists) + 1:
                    return self._show_all_wordlists()
                    
                elif choice_int == len(suggested_wordlists) + 2:
                    custom_path = input(f"{Colors.BOLD}[+] Enter wordlist path: {Colors.ENDC}").strip()
                    if custom_path and Path(custom_path).exists():
                        return custom_path
                    print(f"{Colors.FAIL}[!] File not found: {custom_path}{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                    
            except ValueError:
                print(f"{Colors.FAIL}[!] Invalid input{Colors.ENDC}")

    def _show_all_wordlists(self) -> str:
        """Show all available wordlists"""
        print(f"\n{Colors.CYAN}[*] All Available Wordlists:{Colors.ENDC}")
        
        for i, (name, path) in enumerate(self._wordlists.items(), 1):
            exists = "✓" if Path(path).exists() else "✗"
            print(f"{Colors.GREEN}{i}:{Colors.ENDC} {name} [{exists}] - {path}")
        
        print(f"{Colors.GREEN}{len(self._wordlists) + 1}:{Colors.ENDC} Custom wordlist path")
        
        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select wordlist (1-{len(self._wordlists) + 1}): {Colors.ENDC}").strip()
            
            try:
                choice_int = int(choice)
                if 1 <= choice_int <= len(self._wordlists):
                    name = list(self._wordlists.keys())[choice_int - 1]
                    path = self._wordlists[name]
                    final_path = self._ensure_wordlist_exists(path, name)
                    if final_path:
                        return final_path
                    print(f"{Colors.FAIL}[!] Wordlist not found: {path}{Colors.ENDC}")
                    
                elif choice_int == len(self._wordlists) + 1:
                    custom_path = input(f"{Colors.BOLD}[+] Enter wordlist path: {Colors.ENDC}").strip()
                    if custom_path and Path(custom_path).exists():
                        return custom_path
                    print(f"{Colors.FAIL}[!] File not found: {custom_path}{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                    
            except ValueError:
                print(f"{Colors.FAIL}[!] Invalid input{Colors.ENDC}")

    def _get_advanced_options(self, config: Dict) -> List[str]:
        """Get advanced fuzzing options"""
        options = []
        
        # Filters
        if input(f"\n{Colors.BOLD}[+] Configure filters? (Y/n): {Colors.ENDC}").lower() != 'n':
            print(f"\n{Colors.CYAN}[*] Suggested filters for this profile:{Colors.ENDC}")
            suggested_filters = config.get('suggested_filters', [])
            for filter_opt in suggested_filters:
                print(f"  • {filter_opt}")
            
            if input(f"{Colors.BOLD}[+] Use suggested filters? (Y/n): {Colors.ENDC}").lower() != 'n':
                options.extend(suggested_filters)
            else:
                # Manual filter configuration
                print(f"\n{Colors.CYAN}[*] Filter Options:{Colors.ENDC}")
                print("  -fc: Filter by status code (e.g., -fc 404,403)")
                print("  -fs: Filter by response size (e.g., -fs 2287)")
                print("  -fw: Filter by word count")
                print("  -fl: Filter by line count")
                print("  -fr: Filter by regex pattern")
                
                custom_filter = input(f"{Colors.BOLD}[+] Enter filter options: {Colors.ENDC}").strip()
                if custom_filter:
                    options.extend(custom_filter.split())
        
        # Headers
        if config.get('suggested_headers'):
            if input(f"\n{Colors.BOLD}[+] Add suggested headers? (y/N): {Colors.ENDC}").lower() == 'y':
                options.extend(config['suggested_headers'])
        
        if input(f"{Colors.BOLD}[+] Add custom headers? (y/N): {Colors.ENDC}").lower() == 'y':
            header = input(f"{Colors.BOLD}[+] Enter header (format: 'Name: Value'): {Colors.ENDC}").strip()
            if header:
                options.extend(["-H", f"'{header}'"])
        
        # HTTP method
        if input(f"\n{Colors.BOLD}[+] Change HTTP method? (default: GET) (y/N): {Colors.ENDC}").lower() == 'y':
            method = input(f"{Colors.BOLD}[+] Enter HTTP method (POST, PUT, DELETE, etc.): {Colors.ENDC}").strip().upper()
            if method:
                options.extend(["-X", method])
                
                if method == "POST":
                    data = input(f"{Colors.BOLD}[+] Enter POST data (use FUZZ for parameter): {Colors.ENDC}").strip()
                    if data:
                        options.extend(["-d", f"'{data}'"])
        
        # Threads
        if input(f"\n{Colors.BOLD}[+] Change thread count? (default: 40) (y/N): {Colors.ENDC}").lower() == 'y':
            try:
                threads = int(input(f"{Colors.BOLD}[+] Enter thread count (1-200): {Colors.ENDC}"))
                if 1 <= threads <= 200:
                    options.extend(["-t", str(threads)])
            except ValueError:
                print(f"{Colors.WARNING}[!] Invalid thread count, using default{Colors.ENDC}")
        
        # Output options
        if input(f"\n{Colors.BOLD}[+] Save output to file? (Y/n): {Colors.ENDC}").lower() != 'n':
            self._output_dir.mkdir(exist_ok=True)
            
            # Output format
            print(f"\n{Colors.CYAN}[*] Output formats:{Colors.ENDC}")
            formats = {"1": "json", "2": "html", "3": "csv", "4": "md"}
            for key, fmt in formats.items():
                print(f"{key}. {fmt}")
            
            format_choice = input(f"{Colors.BOLD}[+] Select format (1-4, default: json): {Colors.ENDC}").strip()
            output_format = formats.get(format_choice, "json")
            
            import time
            timestamp = str(int(time.time()))
            output_file = self._output_dir / f"ffuf_scan_{timestamp}.{output_format}"
            
            options.extend(["-o", str(output_file), "-of", output_format])
        
        # Proxy
        if input(f"\n{Colors.BOLD}[+] Use proxy? (y/N): {Colors.ENDC}").lower() == 'y':
            proxy = input(f"{Colors.BOLD}[+] Enter proxy URL (e.g., http://127.0.0.1:8080): {Colors.ENDC}").strip()
            if proxy:
                options.extend(["-x", proxy])
        
        return options

    def _execute_ffuf(self, command: str) -> bool:
        """
        Execute ffuf with real-time output
        
        Returns:
            bool: True if user wants to perform another scan, False otherwise
        """
        try:
            print(f"{Colors.CYAN}[*] Starting FFUF scan...{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Press Ctrl+C to interrupt{Colors.ENDC}\n")
            
            # Try different execution methods for better output handling
            try:
                # Method 1: Direct execution with real-time output
                import os
                import select
                import sys
                
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=0,  # Unbuffered
                    preexec_fn=os.setsid if hasattr(os, 'setsid') else None
                )

                # Real-time output handling
                while True:
                    # Check if process is still running
                    if process.poll() is not None:
                        # Process finished, read remaining output
                        remaining = process.stdout.read()
                        if remaining:
                            print(remaining, end='')
                        break
                    
                    # Read available output
                    try:
                        # Use select on Unix systems for non-blocking read
                        if hasattr(select, 'select'):
                            ready, _, _ = select.select([process.stdout], [], [], 0.1)
                            if ready:
                                line = process.stdout.readline()
                                if line:
                                    print(line, end='')
                        else:
                            # Fallback for Windows
                            line = process.stdout.readline()
                            if line:
                                print(line, end='')
                            else:
                                import time
                                time.sleep(0.1)
                    except:
                        # If select fails, use simple readline
                        line = process.stdout.readline()
                        if line:
                            print(line, end='')

                return_code = process.returncode
                
            except Exception as method1_error:
                print(f"{Colors.WARNING}[!] Real-time method failed, using simple execution...{Colors.ENDC}")
                
                # Method 2: Simple execution without real-time output
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                # Print all output at once
                if result.stdout:
                    print(result.stdout)
                if result.stderr:
                    print(result.stderr)
                    
                return_code = result.returncode

            # Check results
            if return_code == 0:
                print(f"\n{Colors.GREEN}[✓] Scan completed successfully{Colors.ENDC}")
                if self._output_dir.exists() and any(self._output_dir.glob("ffuf_scan_*")):
                    print(f"{Colors.CYAN}[*] Results saved in: {self._output_dir}{Colors.ENDC}")
            else:
                print(f"\n{Colors.WARNING}[!] Scan completed with return code: {return_code}{Colors.ENDC}")

            # Ask user if they want to perform another scan
            while True:
                choice = input(f"\n{Colors.BOLD}[?] Would you like to perform another scan? (y/N): {Colors.ENDC}").lower()
                if choice in ['y', 'n', '']:
                    return choice == 'y'
                print(f"{Colors.FAIL}[!] Please enter 'y' for yes or 'n' for no{Colors.ENDC}")

        except subprocess.TimeoutExpired:
            print(f"\n{Colors.WARNING}[!] Scan timed out after 5 minutes{Colors.ENDC}")
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
            return False
            
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
            try:
                if 'process' in locals():
                    process.terminate()
                    process.wait(timeout=5)
            except:
                try:
                    if 'process' in locals():
                        process.kill()
                except:
                    pass
            return False
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error during scan: {e}{Colors.ENDC}")
            return False

    def run_guided(self) -> None:
        """Interactive guided mode for ffuf"""
        self._show_banner()

        while True:
            try:
                # Step 1: Get fuzzing profile
                profile_name, config = self._get_fuzzing_profile()
                
                # Step 2: Get target URL
                if config.get('suggested_url'):
                    print(f"\n{Colors.CYAN}[*] Suggested URL format: {config['suggested_url']}{Colors.ENDC}")
                
                target_url = self._get_target_url()
                if not target_url:
                    return

                # Step 3: Get wordlist
                wordlist = self._get_wordlist_selection(config.get('suggested_wordlists', []))
                if not wordlist:
                    return

                # Step 4: Get advanced options
                advanced_options = self._get_advanced_options(config)

                # Build command
                command_parts = ["ffuf", "-u", f'"{target_url}"', "-w", wordlist]
                command_parts.extend(advanced_options)
                
                command = " ".join(command_parts)

                # Show scan summary
                print(f"\n{Colors.CYAN}[*] Scan Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 40)
                print(f"Profile: {profile_name}")
                print(f"Target: {target_url}")
                print(f"Wordlist: {wordlist}")
                if advanced_options:
                    print(f"Options: {' '.join(advanced_options)}")
                print(f"Command: {command}")

                if input(f"\n{Colors.BOLD}[+] Start scan? (Y/n): {Colors.ENDC}").lower() != 'n':
                    print(f"\n{Colors.CYAN}[*] Executing scan...{Colors.ENDC}")
                    if not self._execute_ffuf(command):
                        break
                else:
                    print(f"\n{Colors.WARNING}[!] Scan cancelled by user{Colors.ENDC}")
                    if input(f"\n{Colors.BOLD}[?] Would you like to configure another scan? (y/N): {Colors.ENDC}").lower() != 'y':
                        break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for ffuf"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter ffuf commands directly{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  help      - Show ffuf help")
        print("  wordlists - Show available wordlists")
        print("  examples  - Show usage examples")
        print("  profiles  - Show predefined profiles")
        print("  test      - Test FFUF installation")
        print("  debug     - Debug mode for troubleshooting")
        print("  exit      - Exit to main menu")
        
        while True:
            try:
                command = input(f"\n{Colors.BOLD}ffuf > {Colors.ENDC}").strip()
                
                if not command:
                    continue
                    
                if command.lower() == 'exit':
                    break
                    
                elif command.lower() == 'help':
                    subprocess.run(['ffuf', '-h'])
                    
                elif command.lower() == 'test':
                    print(f"{Colors.CYAN}[*] Testing FFUF installation...{Colors.ENDC}")
                    try:
                        result = subprocess.run(['ffuf', '-V'], capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            print(f"{Colors.GREEN}[✓] FFUF is working correctly{Colors.ENDC}")
                            print(f"Version: {result.stdout.strip()}")
                        else:
                            print(f"{Colors.FAIL}[!] FFUF test failed{Colors.ENDC}")
                            print(f"Error: {result.stderr}")
                    except Exception as e:
                        print(f"{Colors.FAIL}[!] FFUF not found or not working: {e}{Colors.ENDC}")
                
                elif command.lower() == 'debug':
                    print(f"{Colors.CYAN}[*] Debug Mode - Testing with simple command{Colors.ENDC}")
                    simple_command = 'ffuf -u "https://httpbin.org/status/FUZZ" -w <(echo -e "200\\n404\\n500") -mc 200 -v'
                    print(f"Testing command: {simple_command}")
                    
                    try:
                        # Use a simpler test that should always work
                        import tempfile
                        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                            temp_file.write("200\n404\n500\n")
                            temp_file_path = temp_file.name
                        
                        test_cmd = f'ffuf -u "https://httpbin.org/status/FUZZ" -w {temp_file_path} -mc 200 -v -t 1'
                        print(f"Actual command: {test_cmd}")
                        
                        result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True, timeout=30)
                        print(f"Return code: {result.returncode}")
                        print(f"STDOUT:\n{result.stdout}")
                        if result.stderr:
                            print(f"STDERR:\n{result.stderr}")
                            
                        # Cleanup
                        os.unlink(temp_file_path)
                        
                    except Exception as e:
                        print(f"{Colors.FAIL}[!] Debug test failed: {e}{Colors.ENDC}")
                    
                elif command.lower() == 'wordlists':
                    print(f"\n{Colors.CYAN}[*] Available Wordlists by Category:{Colors.ENDC}")
                    
                    print(f"\n{Colors.GREEN}Directory Discovery:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if any(x in name.lower() for x in ['directory', 'common', 'big', 'raft', 'quickhits']):
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}")
                    
                    print(f"\n{Colors.GREEN}Parameter Discovery:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if 'parameter' in name.lower() or 'burp' in name.lower():
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}")
                    
                    print(f"\n{Colors.GREEN}LFI Testing:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if any(x in name.lower() for x in ['lfi', 'web-root', 'default-web']):
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}")
                    
                    print(f"\n{Colors.GREEN}API Discovery:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if any(x in name.lower() for x in ['api', 'graphql']):
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}")
                    
                    print(f"\n{Colors.GREEN}Subdomain/VHost Discovery:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if any(x in name.lower() for x in ['subdomain', 'subdomains']):
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}")
                    
                    print(f"\n{Colors.GREEN}Extensions & Files:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if any(x in name.lower() for x in ['extension', 'backup', 'sensitive']):
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}")
                    
                    print(f"\n{Colors.GREEN}Technology Specific:{Colors.ENDC}")
                    for name, path in self._wordlists.items():
                        if any(x in name.lower() for x in ['apache', 'nginx', 'tomcat', 'iis', 'spring', 'wordpress', 'drupal', 'joomla']):
                            exists = "✓" if Path(path).exists() else "✗"
                            print(f"  [{exists}] {name}")
                    
                elif command.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] FFUF Usage Examples:{Colors.ENDC}")
                    
                    print(f"\n{Colors.GREEN}1. Directory Discovery{Colors.ENDC}")
                    print("Basic directory enumeration:")
                    print("  ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt")
                    print("\nWith status code filtering:")
                    print("  ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -fc 404,403")
                    
                    print(f"\n{Colors.GREEN}2. Parameter Discovery{Colors.ENDC}")
                    print("Find hidden GET parameters:")
                    print("  ffuf -u 'http://target.com/page.php?FUZZ=value' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 2287")
                    print("\nPOST parameter discovery:")
                    print("  ffuf -u http://target.com/login.php -X POST -d 'FUZZ=value' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt")
                    
                    print(f"\n{Colors.GREEN}3. LFI Testing (from cheatsheet){Colors.ENDC}")
                    print("Basic LFI fuzzing:")
                    print("  ffuf -u 'http://target.com/page.php?file=../../../../FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 2287")
                    print("\nWebroot path fuzzing:")
                    print("  ffuf -u 'http://target.com/page.php?file=../../../../FUZZ/index.php' -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt")
                    print("\nServer configuration fuzzing:")
                    print("  ffuf -u 'http://target.com/page.php?file=../../../../FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt")
                    
                    print(f"\n{Colors.GREEN}4. Extension Discovery{Colors.ENDC}")
                    print("Find file extensions:")
                    print("  ffuf -u http://target.com/file.FUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -fc 404")
                    
                    print(f"\n{Colors.GREEN}5. Virtual Host Discovery{Colors.ENDC}")
                    print("Subdomain enumeration:")
                    print("  ffuf -H 'Host: FUZZ.target.com' -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0")
                    
                    print(f"\n{Colors.GREEN}6. API Endpoint Discovery{Colors.ENDC}")
                    print("REST API fuzzing:")
                    print("  ffuf -u http://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,400,401,403,500")
                    print("\nAPI with Mazen160 wordlist:")
                    print("  ffuf -u http://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt")
                    
                    print(f"\n{Colors.GREEN}7. Advanced Filtering{Colors.ENDC}")
                    print("Multiple filters:")
                    print("  ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404,403 -fs 1234 -fw 97")
                    print("\nRegex filtering:")
                    print("  ffuf -u http://target.com/FUZZ -w wordlist.txt -fr 'Error|Not Found'")
                    
                    print(f"\n{Colors.GREEN}8. Output and Reporting{Colors.ENDC}")
                    print("JSON output:")
                    print("  ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.json -of json")
                    print("\nHTML report:")
                    print("  ffuf -u http://target.com/FUZZ -w wordlist.txt -o report.html -of html")
                    
                elif command.lower() == 'profiles':
                    print(f"\n{Colors.CYAN}[*] Predefined Profiles:{Colors.ENDC}")
                    
                    print(f"\n{Colors.GREEN}Directory Discovery Profile:{Colors.ENDC}")
                    print("  URL: http://target.com/FUZZ")
                    print("  Wordlist: common.txt, raft-large-directories.txt, directory-list-2.3-medium.txt")
                    print("  Filters: -fc 404")
                    
                    print(f"\n{Colors.GREEN}Parameter Discovery Profile:{Colors.ENDC}")
                    print("  URL: http://target.com/page.php?FUZZ=value")
                    print("  Wordlist: burp-parameter-names.txt")
                    print("  Filters: -fs 2287")
                    
                    print(f"\n{Colors.GREEN}LFI Testing Profile:{Colors.ENDC}")
                    print("  URL: http://target.com/page.php?file=../../../../FUZZ")
                    print("  Wordlist: LFI-Jhaddix.txt, default-web-root-directory-linux.txt, LFI-gracefulsecurity-linux.txt")
                    print("  Filters: -fs 2287 -fc 404")
                    
                    print(f"\n{Colors.GREEN}Extension Discovery Profile:{Colors.ENDC}")
                    print("  URL: http://target.com/file.FUZZ")
                    print("  Wordlist: web-extensions.txt, common-extensions.txt")
                    print("  Filters: -fc 404,403")
                    
                    print(f"\n{Colors.GREEN}VHost Discovery Profile:{Colors.ENDC}")
                    print("  URL: http://target.com")
                    print("  Headers: -H 'Host: FUZZ.target.com'")
                    print("  Wordlist: subdomains-top1million-5000.txt")
                    print("  Filters: -fs 0")
                    
                    print(f"\n{Colors.GREEN}API Discovery Profile:{Colors.ENDC}")
                    print("  URL: http://target.com/api/FUZZ")
                    print("  Wordlist: api-endpoints.txt, common-api-endpoints-mazen160.txt")
                    print("  Matchers: -mc 200,201,202,204,301,302,307,401,403,500")
                    
                    print(f"\n{Colors.GREEN}Backup Files Profile:{Colors.ENDC}")
                    print("  URL: http://target.com/FUZZ")
                    print("  Wordlist: backup-files.txt, sensitive-files.txt")
                    print("  Matchers: -mc 200")
                    
                else:
                    # If not a special command, execute as ffuf command
                    if not command.startswith('ffuf '):
                        command = f"ffuf {command}"
                        
                    try:
                        if not self._execute_ffuf(command):
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