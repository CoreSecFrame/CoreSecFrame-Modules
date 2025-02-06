from core.base import ToolModule
from core.colors import Colors
import subprocess
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class JohnModule(ToolModule):
    def __init__(self):
        self._wordlists = {
            "rockyou": "/usr/share/wordlists/rockyou.txt",
            "password": "/usr/share/john/password.lst",
            "fasttrack": "/usr/share/wordlists/fasttrack.txt"
        }
        super().__init__()

    def _get_name(self) -> str:
        return "John"

    def _get_category(self) -> str:
        return "Cracking"

    def _get_command(self) -> str:
        return "john"

    def _get_description(self) -> str:
        return "Advanced password cracking and hash identification tool"

    def _get_dependencies(self) -> List[str]:
        return ["john"]

    def _get_script_path(self) -> str:
        """Returns path to script if applicable"""
        return ""  # John is a binary, no script needed

    def get_help(self) -> dict:
        return {
            "title": "John the Ripper - Password Cracker",
            "usage": "use john",
            "desc": "Advanced password cracker supporting multiple hash types and attack modes",
            "modes": {
                "Guided": "Interactive mode with predefined cracking profiles",
                "Direct": "Direct command execution with full john syntax"
            },
            "options": {
                "--wordlist": "Specify wordlist file",
                "--rules": "Enable word mangling rules",
                "--incremental": "Incremental (brute-force) mode",
                "--format": "Hash format specification",
                "--session": "Name or path for session",
                "--show": "Show cracked passwords",
                "--restore": "Restore previous session",
                "--status": "Show session status"
            },
            "examples": [
                "john --wordlist=/wordlists/rockyou.txt hash.txt",
                "john --format=raw-md5 --wordlist=wordlist.txt hash.txt",
                "john --incremental hash.txt",
                "john --show hash.txt",
                "john --restore=session1"
            ],
            "notes": [
                "Some hash formats require format specification",
                "Use --show to view cracked passwords",
                "Sessions can be restored after interruption",
                "Use rules to improve success rate"
            ]
        }

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Returns installation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y john"
            ],
            'yum': [
                "sudo yum update",
                "sudo yum install -y john"
            ],
            'dnf': [
                "sudo dnf update",
                "sudo dnf install -y john"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S john --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Returns update commands for different package managers"""
        return self._get_install_command(pkg_manager)  # Same as install for john

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Returns uninstallation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get remove -y john",
                "sudo apt-get autoremove -y"
            ],
            'yum': [
                "sudo yum remove -y john",
                "sudo yum autoremove -y"
            ],
            'dnf': [
                "sudo dnf remove -y john",
                "sudo dnf autoremove -y"
            ],
            'pacman': [
                "sudo pacman -Rs john --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _show_banner(self):
        """Display the module banner"""
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║           JOHN THE RIPPER                ║
║      "Advanced Password Cracker"         ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _get_hash_file(self) -> Optional[str]:
        """Get and validate hash file path"""
        while True:
            file_path = input(f"\n{Colors.BOLD}[+] Path to hash file: {Colors.ENDC}").strip()
            if not file_path:
                print(f"{Colors.FAIL}[!] Hash file is required{Colors.ENDC}")
                continue

            path = Path(file_path)
            if path.exists() and path.is_file():
                return str(path.absolute())
            print(f"{Colors.FAIL}[!] File not found: {file_path}{Colors.ENDC}")
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_wordlist(self) -> Optional[str]:
        """Get and validate wordlist path"""
        print(f"\n{Colors.CYAN}[*] Available Wordlists:{Colors.ENDC}")
        
        # Display available wordlists with status
        for i, (name, path) in enumerate(self._wordlists.items(), 1):
            exists = "✓" if Path(path).exists() else "✗"
            print(f"{Colors.GREEN}{i}:{Colors.ENDC} {name} [{exists}] - {path}")
        print(f"{Colors.GREEN}4:{Colors.ENDC} Custom wordlist")

        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select wordlist (1-4): {Colors.ENDC}").strip()
            
            if choice == "4":
                # Handle custom wordlist path
                custom_path = input(f"{Colors.BOLD}[+] Enter wordlist path: {Colors.ENDC}").strip()
                if not custom_path:
                    print(f"{Colors.FAIL}[!] Path is required{Colors.ENDC}")
                    continue
                
                path = Path(custom_path)
                if path.exists() and path.is_file():
                    return str(path.absolute())
                print(f"{Colors.FAIL}[!] File not found: {custom_path}{Colors.ENDC}")
            else:
                try:
                    # Handle pre-defined wordlist selection
                    idx = int(choice) - 1
                    if 0 <= idx < len(self._wordlists):
                        path = Path(list(self._wordlists.values())[idx])
                        if path.exists():
                            return str(path)
                        print(f"{Colors.FAIL}[!] Wordlist not found: {path}{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                except ValueError:
                    print(f"{Colors.FAIL}[!] Invalid input{Colors.ENDC}")
            
            # Ask to retry or return None
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_cracking_profile(self) -> Tuple[str, str]:
        """Get cracking profile and its options"""
        print(f"\n{Colors.CYAN}[*] Select Cracking Profile:{Colors.ENDC}")
        profiles = {
            "1": ("Wordlist", "--wordlist=", "Basic dictionary attack"),
            "2": ("Wordlist + Rules", "--wordlist= --rules", "Dictionary attack with word mangling"),
            "3": ("Quick Incremental", "--incremental:Alpha", "Quick brute-force (A-Z, a-z)"),
            "4": ("Full Incremental", "--incremental", "Full brute-force (all characters)"),
            "5": ("Wordlist + Masks", "--wordlist= --mask=?a?a?a", "Dictionary + mask attack"),
            "6": ("Session Recovery", "--restore", "Restore previous session"),
            "7": ("Show Cracked", "--show", "Show cracked passwords"),
            "8": ("Custom", "", "Custom options")
        }

        for key, (name, _, desc) in profiles.items():
            print(f"{Colors.GREEN}{key}:{Colors.ENDC} {name} - {desc}")

        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select profile (1-8): {Colors.ENDC}").strip()
            if choice in profiles:
                return profiles[choice][0], profiles[choice][1]
            print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")

    def _handle_format_selection(self) -> str:
        """Handle hash format selection"""
        print(f"\n{Colors.CYAN}[*] Common Hash Formats:{Colors.ENDC}")
        formats = {
            "1": "raw-md5",
            "2": "raw-sha1",
            "3": "raw-sha256",
            "4": "raw-sha512",
            "5": "bcrypt",
            "6": "nt",
            "7": "descrypt",
            "8": "Auto-detect"
        }

        for key, format_name in formats.items():
            print(f"{Colors.GREEN}{key}:{Colors.ENDC} {format_name}")

        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select format (1-8): {Colors.ENDC}").strip()
            if choice in formats:
                return f"--format={formats[choice]}" if choice != "8" else ""
            print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")

    def _execute_john(self, command: str) -> None:
        """Execute john with real-time output"""
        try:
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
                    print(f"{Colors.FAIL}[!] Errors during execution:{Colors.ENDC}")
                    print(stderr)
            else:
                print(f"\n{Colors.GREEN}[✓] Operation completed successfully{Colors.ENDC}")

                # Show cracked passwords if not just showing results
                if "--show" not in command:
                    hash_file = command.split()[-1]
                    print(f"\n{Colors.CYAN}[*] Cracked passwords:{Colors.ENDC}")
                    subprocess.run(f"john --show {hash_file}", shell=True)

        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Operation interrupted by user{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] You can restore this session later using --restore{Colors.ENDC}")
            process.terminate()
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error during execution: {e}{Colors.ENDC}")

    def run_guided(self) -> None:
        """Interactive guided mode for john"""
        self._show_banner()

        try:
            # Step 1: Initialize attack
            print(f"\n{Colors.CYAN}[*] Attack Configuration{Colors.ENDC}")
            print(f"{Colors.CYAN}=" * 30)

            # Step 2: Get hash file
            print(f"\n{Colors.CYAN}[*] Step 1: Select Hash File{Colors.ENDC}")
            hash_file = self._get_hash_file()
            if not hash_file:
                return

            # Step 3: Choose attack type
            print(f"\n{Colors.CYAN}[*] Step 2: Select Attack Method{Colors.ENDC}")
            profiles = {
                "1": ("Basic Wordlist", "--wordlist=", "Dictionary attack with common passwords"),
                "2": ("Advanced Wordlist", "--wordlist= --rules", "Dictionary attack with word mangling"),
                "3": ("Targeted Bruteforce", "--mask=?a?a?a?a?a", "Fixed-length character combinations"),
                "4": ("Full Bruteforce", "--incremental", "Try all possible combinations"),
                "5": ("Quick Check", "--wordlist= --rules=NT", "Fast check with basic ruleset"),
                "6": ("Show Results", "--show", "Display cracked passwords"),
                "7": ("Custom Attack", "", "Define custom options")
            }

            for key, (name, _, desc) in profiles.items():
                print(f"{Colors.GREEN}{key}:{Colors.ENDC} {name}")
                print(f"   {Colors.SUBTLE}{desc}{Colors.ENDC}")

            while True:
                choice = input(f"\n{Colors.BOLD}[+] Select attack (1-7): {Colors.ENDC}").strip()
                if choice in profiles:
                    profile_name, profile_opts = profiles[choice][0:2]
                    break
                print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")

            # Step 4: Configure attack
            command_parts = ["john"]
            
            if profile_name == "Show Results":
                command_parts.extend(["--show", hash_file])
            else:
                # Format selection
                print(f"\n{Colors.CYAN}[*] Step 3: Hash Format Configuration{Colors.ENDC}")
                if input(f"{Colors.BOLD}[+] Would you like to specify the hash format? (y/N): {Colors.ENDC}").lower() == 'y':
                    format_opt = self._handle_format_selection()
                    if format_opt:
                        command_parts.append(format_opt)

                # Wordlist selection for dictionary-based attacks
                if "wordlist" in profile_opts:
                    print(f"\n{Colors.CYAN}[*] Step 4: Wordlist Selection{Colors.ENDC}")
                    wordlist = self._get_wordlist()
                    if not wordlist:
                        return
                    command_parts.append(f"--wordlist={wordlist}")

                # Rules and additional options
                if profile_name not in ["Show Results", "Full Bruteforce"]:
                    print(f"\n{Colors.CYAN}[*] Step 5: Additional Options{Colors.ENDC}")
                    
                    if "rules" not in profile_opts and input(f"{Colors.BOLD}[+] Enable word mangling rules? (y/N): {Colors.ENDC}").lower() == 'y':
                        command_parts.append("--rules")

                    if input(f"{Colors.BOLD}[+] Save session for later resumption? (y/N): {Colors.ENDC}").lower() == 'y':
                        session_name = input(f"{Colors.BOLD}[+] Enter session name: {Colors.ENDC}").strip() or "john_session"
                        command_parts.append(f"--session={session_name}")

                # Custom options
                if profile_name == "Custom Attack":
                    print(f"\n{Colors.CYAN}[*] Available Options:{Colors.ENDC}")
                    print("  --rules=RULESET   Specify rule set (eg: NT, Extra, All)")
                    print("  --incremental     Enable brute-force mode")
                    print("  --mask=?a?a?a     Define character pattern")
                    print("  --session=name    Save session for recovery")
                    print("  --fork=N          Enable parallel processing")
                    
                    custom_opts = input(f"\n{Colors.BOLD}[+] Enter additional options: {Colors.ENDC}").strip()
                    if custom_opts:
                        command_parts.extend(custom_opts.split())

                # Add hash file as final argument
                command_parts.append(hash_file)

            # Step 5: Execute attack
            command = " ".join(command_parts)
            print(f"\n{Colors.CYAN}[*] Attack Summary{Colors.ENDC}")
            print(f"{Colors.CYAN}=" * 30)
            print(f"Attack Type: {profile_name}")
            print(f"Target File: {hash_file}")
            print(f"Command: {command}")

            if input(f"\n{Colors.BOLD}[+] Start attack? (Y/n): {Colors.ENDC}").lower() != 'n':
                print(f"\n{Colors.CYAN}[*] Executing attack...{Colors.ENDC}")
                self._execute_john(command)
            else:
                print(f"\n{Colors.WARNING}[!] Attack cancelled by user{Colors.ENDC}")

        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] You can restore an interrupted session using --restore{Colors.ENDC}")

    def run_direct(self) -> None:
        """Direct command execution mode for john"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter john commands directly{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  help     - Show john help")
        print("  formats  - Show supported hash formats")
        print("  status   - Show session status")
        print("  examples - Show usage examples")
        print("  exit     - Exit to main menu")
        
        while True:
            try:
                command = input(f"\n{Colors.BOLD}john > {Colors.ENDC}").strip()
                
                if not command:
                    continue
                    
                if command.lower() == 'exit':
                    break
                    
                elif command.lower() == 'help':
                    subprocess.run(['john', '--help=1'])
                    
                elif command.lower() == 'formats':
                    subprocess.run(['john', '--list=formats'])
                    
                elif command.lower() == 'status':
                    # First check if there's an active session
                    result = subprocess.run(['john', '--status'], capture_output=True, text=True)
                    if "No password hashes loaded" in result.stderr:
                        print(f"{Colors.WARNING}[!] No active session found{Colors.ENDC}")
                    else:
                        print(result.stdout)
                    
                elif command.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] Common Usage Examples:{Colors.ENDC}")
                    print(f"\n{Colors.GREEN}1. Basic Wordlist Attack{Colors.ENDC}")
                    print("Description: Simple dictionary attack using a wordlist")
                    print("Command: john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt")
                    
                    print(f"\n{Colors.GREEN}2. Wordlist with Rules{Colors.ENDC}")
                    print("Description: Dictionary attack with word mangling rules")
                    print("Command: john --wordlist=wordlist.txt --rules hash.txt")
                    print("Command: john --wordlist=wordlist.txt --rules=KoreLogic hash.txt")
                    
                    print(f"\n{Colors.GREEN}3. Format-Specific Attack{Colors.ENDC}")
                    print("Description: Attack specifying hash format")
                    print("Command: john --format=raw-md5 hash.txt")
                    print("Command: john --format=bcrypt hash.txt")
                    
                    print(f"\n{Colors.GREEN}4. Incremental (Brute-Force) Attack{Colors.ENDC}")
                    print("Description: Try all possible character combinations")
                    print("Command: john --incremental hash.txt")
                    print("Command: john --incremental:Alpha hash.txt")
                    
                    print(f"\n{Colors.GREEN}5. Mask Attack{Colors.ENDC}")
                    print("Description: Attack using specific pattern")
                    print("Command: john --mask='?d?d?d?d?d?d' hash.txt  # 6 digits")
                    print("Command: john --mask='?u?l?l?l?d?d' hash.txt  # Upper+3lower+2digits")
                    
                    print(f"\n{Colors.GREEN}6. Multiple Attack Modes{Colors.ENDC}")
                    print("Description: Combine different attack methods")
                    print("Command: john --wordlist=wordlist.txt --rules --incremental hash.txt")
                    
                    print(f"\n{Colors.GREEN}7. Session Management{Colors.ENDC}")
                    print("Description: Save and restore cracking sessions")
                    print("Command: john --session=mysession hash.txt")
                    print("Command: john --restore=mysession")
                    
                    print(f"\n{Colors.GREEN}8. Show Results{Colors.ENDC}")
                    print("Description: Display cracked passwords")
                    print("Command: john --show hash.txt")
                    print("Command: john --show --format=raw-md5 hash.txt")
                    
                    print(f"\n{Colors.CYAN}[*] Additional Tips:{Colors.ENDC}")
                    print("• Use --fork=N for parallel processing")
                    print("• Use --list=formats to see supported hash types")
                    print("• Use --status to check progress")
                    print("• Use Ctrl+C to pause and save session")
                    
                else:
                    # If not a special command, execute as john command
                    if not command.startswith('john '):
                        command = f"john {command}"
                        
                    try:
                        self._execute_john(command)
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
