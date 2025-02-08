from core.base import ToolModule
from core.colors import Colors
import subprocess
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class YersiniaModule(ToolModule):
    def __init__(self):
        self._protocols = {
            "cdp": "Cisco Discovery Protocol",
            "dhcp": "Dynamic Host Configuration Protocol",
            "dot1q": "IEEE 802.1Q",
            "dot1x": "IEEE 802.1X",
            "dtp": "Dynamic Trunking Protocol",
            "hsrp": "Hot Standby Router Protocol",
            "isl": "Inter-Switch Link Protocol",
            "stp": "Spanning Tree Protocol",
            "vtp": "VLAN Trunking Protocol"
        }
        
        self._attacks = {
            "cdp": ["sending", "flooding"],
            "dhcp": ["discover", "release", "decline", "request", "starvation"],
            "dot1q": ["adding", "flooding"],
            "dot1x": ["mab"],
            "dtp": ["desegregation", "native", "negotiation"],
            "hsrp": ["becoming-active", "coup", "hello"],
            "isl": ["flooding"],
            "stp": ["conf-corruption", "root-role", "tcn"],
            "vtp": ["add-domain", "corruption", "pruning", "summ", "client"]
        }
        
        self._output_dir = Path.home() / "yersinia_results"
        super().__init__()

    def _get_name(self) -> str:
        return "Yersinia"

    def _get_category(self) -> str:
        return "Network"

    def _get_command(self) -> str:
        return "yersinia"

    def _get_description(self) -> str:
        return "Network protocol attack and analyzer tool"

    def _get_dependencies(self) -> List[str]:
        return ["yersinia"]

    def _get_script_path(self) -> str:
        """Returns path to script if applicable"""
        return ""  # Yersinia is a binary

    def get_help(self) -> dict:
        return {
            "title": "Yersinia - Network Protocol Attacks",
            "usage": "use yersinia",
            "desc": "Framework for performing layer 2 attacks on network protocols",
            "modes": {
                "Guided": "Interactive mode that guides through attack configuration",
                "Direct": "Direct command execution with full yersinia syntax"
            },
            "options": {
                "-h": "Show help",
                "-l": "List available protocols",
                "-m": "Protocol mode",
                "-G": "Launch graphical interface",
                "-I": "Interactive mode",
                "-D": "Daemon mode",
                "-attack": "Attack mode",
                "-interface": "Network interface",
                "-mac": "MAC address",
                "-help": "Protocol help"
            },
            "examples": [
                "yersinia -G",
                "yersinia -I",
                "yersinia dhcp -attack 1",
                "yersinia stp -attack 2 -interface eth0",
                "yersinia -l"
            ],
            "notes": [
                "Requires root/sudo privileges",
                "Some attacks may disrupt network services",
                "Use with caution in production environments",
                "Consider legal implications before testing"
            ]
        }

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Returns installation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y yersinia"
            ],
            'yum': [
                "sudo yum update",
                "sudo yum install -y epel-release",
                "sudo yum install -y yersinia"
            ],
            'dnf': [
                "sudo dnf update",
                "sudo dnf install -y yersinia"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S yersinia --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Returns update commands for different package managers"""
        return self._get_install_command(pkg_manager)  # Same as install for yersinia

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Returns uninstallation commands for different package managers"""
        commands = {
            'apt': [
                "sudo apt-get remove -y yersinia",
                "sudo apt-get autoremove -y"
            ],
            'yum': [
                "sudo yum remove -y yersinia",
                "sudo yum autoremove -y"
            ],
            'dnf': [
                "sudo dnf remove -y yersinia",
                "sudo dnf autoremove -y"
            ],
            'pacman': [
                "sudo pacman -Rs yersinia --noconfirm"
            ]
        }
        return commands.get(pkg_manager, [])

    def _show_banner(self):
        """Display the module banner"""
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║              YERSINIA                     ║
║      "Network Protocol Attacks"          ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _get_protocol(self) -> Optional[str]:
        """Get and validate protocol"""
        print(f"\n{Colors.CYAN}[*] Available Protocols:{Colors.ENDC}")
        
        # Group and display protocols by category
        categories = {
            "Cisco Protocols": ["cdp", "isl"],
            "VLAN Protocols": ["dot1q", "vtp"],
            "Switching Protocols": ["dtp", "stp"],
            "Authentication Protocols": ["dot1x"],
            "Network Services": ["dhcp", "hsrp"]
        }
        
        for category, protocols in categories.items():
            print(f"\n{Colors.GREEN}{category}:{Colors.ENDC}")
            for proto in protocols:
                print(f"  • {proto}: {self._protocols[proto]}")
            
        while True:
            protocol = input(f"\n{Colors.BOLD}[+] Select protocol: {Colors.ENDC}").strip().lower()
            if protocol in self._protocols:
                return protocol
                
            print(f"{Colors.FAIL}[!] Invalid protocol{Colors.ENDC}")
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_interface(self) -> Optional[str]:
        """Get and validate network interface"""
        try:
            # Get list of available interfaces
            interfaces = []
            for interface in os.listdir('/sys/class/net/'):
                # Skip loopback
                if interface != 'lo':
                    interfaces.append(interface)
            
            if not interfaces:
                print(f"{Colors.FAIL}[!] No network interfaces found{Colors.ENDC}")
                return None
            
            print(f"\n{Colors.CYAN}[*] Available Interfaces:{Colors.ENDC}")
            for i, interface in enumerate(interfaces, 1):
                print(f"{Colors.GREEN}{i}:{Colors.ENDC} {interface}")
            
            while True:
                choice = input(f"\n{Colors.BOLD}[+] Select interface (1-{len(interfaces)}): {Colors.ENDC}").strip()
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(interfaces):
                        return interfaces[idx]
                except ValueError:
                    pass
                    
                print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
                if retry == 'n':
                    return None
                    
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error getting interfaces: {e}{Colors.ENDC}")
            return None

    def _get_attack_type(self, protocol: str) -> Optional[int]:
        """Get and validate attack type for protocol"""
        if protocol not in self._attacks:
            return None
            
        print(f"\n{Colors.CYAN}[*] Available Attacks for {protocol.upper()}:{Colors.ENDC}")
        for i, attack in enumerate(self._attacks[protocol], 1):
            print(f"{Colors.GREEN}{i}:{Colors.ENDC} {attack}")
            
        while True:
            choice = input(f"\n{Colors.BOLD}[+] Select attack (1-{len(self._attacks[protocol])}): {Colors.ENDC}").strip()
            try:
                attack_num = int(choice)
                if 1 <= attack_num <= len(self._attacks[protocol]):
                    return attack_num
            except ValueError:
                pass
                
            print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
            retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
            if retry == 'n':
                return None

    def _get_mac_address(self) -> str:
            """Configure MAC address options"""
            if input(f"\n{Colors.BOLD}[+] Use custom MAC address? (y/N): {Colors.ENDC}").lower() == 'y':
                while True:
                    mac = input(f"{Colors.BOLD}[+] Enter MAC address (XX:XX:XX:XX:XX:XX): {Colors.ENDC}").strip()
                    if len(mac) == 17 and all(c in '0123456789ABCDEFabcdef:' for c in mac):
                        return f"-mac {mac}"
                    print(f"{Colors.FAIL}[!] Invalid MAC address format{Colors.ENDC}")
                    retry = input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower()
                    if retry == 'n':
                        break
            return ""

    def _get_advanced_options(self, protocol: str) -> List[str]:
        """Configure protocol-specific advanced options"""
        options = []
        
        if protocol == "dhcp":
            if input(f"\n{Colors.BOLD}[+] Configure DHCP options? (y/N): {Colors.ENDC}").lower() == 'y':
                # DHCP Server IP
                server = input(f"{Colors.BOLD}[+] Enter DHCP server IP (optional): {Colors.ENDC}").strip()
                if server:
                    options.append(f"-server {server}")
                    
                # Request specific IP
                request_ip = input(f"{Colors.BOLD}[+] Enter IP to request (optional): {Colors.ENDC}").strip()
                if request_ip:
                    options.append(f"-request {request_ip}")
                    
        elif protocol in ["stp", "rstp"]:
            if input(f"\n{Colors.BOLD}[+] Configure STP options? (y/N): {Colors.ENDC}").lower() == 'y':
                # Bridge priority
                priority = input(f"{Colors.BOLD}[+] Enter bridge priority (0-65535, optional): {Colors.ENDC}").strip()
                if priority.isdigit() and 0 <= int(priority) <= 65535:
                    options.append(f"-priority {priority}")
                    
        elif protocol == "vtp":
            if input(f"\n{Colors.BOLD}[+] Configure VTP options? (y/N): {Colors.ENDC}").lower() == 'y':
                # Domain name
                domain = input(f"{Colors.BOLD}[+] Enter VTP domain name (optional): {Colors.ENDC}").strip()
                if domain:
                    options.append(f"-domain {domain}")
                    
                # VTP password
                password = input(f"{Colors.BOLD}[+] Enter VTP password (optional): {Colors.ENDC}").strip()
                if password:
                    options.append(f"-password {password}")
                    
        elif protocol == "hsrp":
            if input(f"\n{Colors.BOLD}[+] Configure HSRP options? (y/N): {Colors.ENDC}").lower() == 'y':
                # Virtual IP
                virtual_ip = input(f"{Colors.BOLD}[+] Enter virtual IP (optional): {Colors.ENDC}").strip()
                if virtual_ip:
                    options.append(f"-virtual {virtual_ip}")
                    
                # Group number
                group = input(f"{Colors.BOLD}[+] Enter HSRP group number (0-255, optional): {Colors.ENDC}").strip()
                if group.isdigit() and 0 <= int(group) <= 255:
                    options.append(f"-group {group}")
        
        return options

    def _execute_yersinia(self, command: str) -> bool:
        """
        Execute yersinia with real-time output
        
        Returns:
            bool: True if user wants to perform another attack, False otherwise
        """
        try:
            # Create output directory if needed
            self._output_dir.mkdir(exist_ok=True)
            
            # Add logging to all attacks
            log_file = self._output_dir / f"yersinia_{int(time.time())}.log"
            command += f" -log {log_file}"
            
            # Execute with sudo if not already present
            if not command.startswith('sudo '):
                command = f"sudo {command}"
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )

            print(f"\n{Colors.CYAN}[*] Attack started...{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Press Ctrl+C to stop{Colors.ENDC}")

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
                if log_file.exists():
                    print(f"{Colors.CYAN}[*] Log saved to: {log_file}{Colors.ENDC}")

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
        """Interactive guided mode for yersinia"""
        self._show_banner()

        while True:
            try:
                # Step 1: Get protocol
                protocol = self._get_protocol()
                if not protocol:
                    return

                # Step 2: Get interface
                interface = self._get_interface()
                if not interface:
                    return

                # Step 3: Get attack type
                attack_num = self._get_attack_type(protocol)
                if not attack_num:
                    return

                # Build command parts list
                command_parts = ["yersinia", protocol, "-attack", str(attack_num), "-interface", interface]

                # Step 4: MAC address options
                mac_opt = self._get_mac_address()
                if mac_opt:
                    command_parts.append(mac_opt)

                # Step 5: Protocol-specific options
                command_parts.extend(self._get_advanced_options(protocol))

                # Build final command
                command = " ".join(command_parts)

                # Show attack summary
                print(f"\n{Colors.CYAN}[*] Attack Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 30)
                print(f"Protocol: {protocol}")
                print(f"Interface: {interface}")
                print(f"Attack: {self._attacks[protocol][attack_num-1]}")
                print(f"Command: {command}")

                # Warning based on protocol
                if protocol in ["stp", "hsrp", "vtp"]:
                    print(f"\n{Colors.WARNING}[!] Warning: This attack may disrupt network services{Colors.ENDC}")

                if input(f"\n{Colors.BOLD}[+] Start attack? (Y/n): {Colors.ENDC}").lower() != 'n':
                    print(f"\n{Colors.CYAN}[*] Executing attack...{Colors.ENDC}")
                    if not self._execute_yersinia(command):
                        break
                else:
                    print(f"\n{Colors.WARNING}[!] Attack cancelled by user{Colors.ENDC}")
                    if input(f"\n{Colors.BOLD}[?] Would you like to configure another attack? (y/N): {Colors.ENDC}").lower() != 'y':
                        break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
                break

    def run_direct(self) -> None:
        """Direct command execution mode for yersinia"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Enter yersinia commands directly{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  help     - Show yersinia help")
        print("  list     - List supported protocols")
        print("  examples - Show usage examples")
        print("  exit     - Exit to main menu")
        
        while True:
            try:
                command = input(f"\n{Colors.BOLD}yersinia > {Colors.ENDC}").strip()
                
                if not command:
                    continue
                    
                if command.lower() == 'exit':
                    break
                    
                elif command.lower() == 'help':
                    subprocess.run(['yersinia', '-h'])
                    
                elif command.lower() == 'list':
                    print(f"\n{Colors.CYAN}[*] Supported Protocols:{Colors.ENDC}")
                    for proto, desc in self._protocols.items():
                        print(f"\n{Colors.GREEN}{proto}:{Colors.ENDC}")
                        print(f"  Description: {desc}")
                        print(f"  Attacks:")
                        for attack in self._attacks[proto]:
                            print(f"    • {attack}")
                    
                elif command.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] Usage Examples:{Colors.ENDC}")
                    
                    print(f"\n{Colors.GREEN}1. DHCP Attacks{Colors.ENDC}")
                    print("DHCP starvation:")
                    print("  yersinia dhcp -attack 5 -interface eth0")
                    
                    print(f"\n{Colors.GREEN}2. STP Attacks{Colors.ENDC}")
                    print("Root role taking:")
                    print("  yersinia stp -attack 2 -interface eth0")
                    
                    print(f"\n{Colors.GREEN}3. CDP Attacks{Colors.ENDC}")
                    print("CDP flooding:")
                    print("  yersinia cdp -attack 2 -interface eth0")
                    
                    print(f"\n{Colors.GREEN}4. DTP Attacks{Colors.ENDC}")
                    print("VLAN hopping:")
                    print("  yersinia dtp -attack 1 -interface eth0")
                    
                    print(f"\n{Colors.GREEN}5. HSRP Attacks{Colors.ENDC}")
                    print("HSRP spoofing:")
                    print("  yersinia hsrp -attack 1 -interface eth0")
                    
                    print(f"\n{Colors.GREEN}6. Advanced Usage{Colors.ENDC}")
                    print("With custom MAC:")
                    print("  yersinia dhcp -attack 1 -interface eth0 -mac 00:11:22:33:44:55")
                    print("\nWith logging:")
                    print("  yersinia stp -attack 1 -interface eth0 -log capture.pcap")
                    
                else:
                    # If not a special command, execute as yersinia command
                    if not command.startswith('yersinia '):
                        command = f"yersinia {command}"
                        
                    try:
                        if not self._execute_yersinia(command):
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
