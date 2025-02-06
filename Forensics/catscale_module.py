from core.base import ToolModule
from core.colors import Colors
import subprocess
import os
import shutil
from pathlib import Path
from typing import List, Dict, Optional
import paramiko
import getpass

class CatScaleModule(ToolModule):
    def __init__(self):
        self.repo_url = "https://github.com/sPROFFEs/LinuxCatScale"
        self.scripts_dir = Path(__file__).parent.parent.parent / "scripts" / "Forensics" / "LinuxCatScale"
        super().__init__()
  
    def _get_name(self):
        return "catscale"

    def _get_category(self) -> str:
        return "Forensics"

    def _get_command(self):
        return "catscale"

    def _get_description(self):
        return "Forensics tool for Linux that captures mobile data, logs, configurations and hashes files"

    def _get_dependencies(self):
        return ["tar", "sha1sum", "find", "grep"]

    def _get_script_path(self) -> str:
        """Returns path to script"""
        return str(self.scripts_dir / "Cat-Scale.sh")

    def get_help(self) -> dict:
        """
        Proporciona la documentación de ayuda específica de Cat-Scale
        """
        return {
            "title": "Cat-Scale - Recolección Forense Linux",
            "usage": "use catscale",
            "desc": "Herramienta para recolección forense en sistemas Linux que captura datos volátiles, logs, configuraciones y realiza hashes de archivos.",
            "modes": {
                "Guiado": "Modo interactivo que solicita la información necesaria paso a paso",
                "Directo": "Modo que acepta todos los parámetros en la línea de comandos"
            },
            "options": {
                "-o OUTDIR": "Directorio donde guardar el archivo comprimido",
                "--remote HOST": "Host remoto para recolección",
                "--user USER": "Usuario SSH para conexión remota",
                "--key KEY": "Ruta a la clave SSH (opcional)",
                "--password": "Usar autenticación por contraseña"
            },
            "examples": [
                "use catscale",
                "catscale -o /forensics",
                "catscale --remote 192.168.1.10 --user admin --password"
            ],
            "notes": [
                "La herramienta generará un archivo comprimido con la evidencia recolectada",
                "En modo remoto, el archivo se descargará automáticamente al sistema local",
                "Se incluye un script de descompresión para organizar la evidencia"
            ]
        }

    def check_installation(self) -> bool:
        """Verifies tool installation and requirements"""
        scripts_dir = self.scripts_dir
        
        # List of required files
        required_files = [
            "Cat-Scale.sh",
            "patterns",
            "Cat-Scale-logstash.conf"
        ]
        
        # Verify that directory exists
        if not scripts_dir.exists() or not scripts_dir.is_dir():
            self._installed = False
            return False
            
        # Verify that all required files exist
        for file in required_files:
            if not (scripts_dir / file).exists():
                self._installed = False
                return False
                
        # Verify script permissions
        script_path = scripts_dir / "Cat-Scale.sh"
        if not os.access(script_path, os.X_OK):
            try:
                os.chmod(script_path, 0o755)
            except:
                self._installed = False
                return False
        
        self._installed = True
        return True


    def _get_install_command(self, pkg_manager: str) -> List[str]:
        """Returns installation commands for different package managers"""
        
        # Create category-specific scripts directory
        self.scripts_dir.mkdir(parents=True, exist_ok=True)
        
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y coreutils findutils grep git rename",
                f"git clone {self.repo_url} {self.scripts_dir}",
                f"chmod +x {self.scripts_dir}/Cat-Scale.sh"
            ],
            'yum': [
                "sudo yum update -y",
                "sudo yum install -y coreutils findutils grep git rename",
                f"git clone {self.repo_url} {self.scripts_dir}",
                f"chmod +x {self.scripts_dir}/Cat-Scale.sh"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S coreutils findutils grep git rename --noconfirm",
                f"git clone {self.repo_url} {self.scripts_dir}",
                f"chmod +x {self.scripts_dir}/Cat-Scale.sh"
            ]
        }
        return commands.get(pkg_manager, [])

    def _get_update_command(self, pkg_manager: str) -> dict:
        """Diccionario de comandos de actualización por gestor de paquetes"""
        commands = {
            'apt': [
                "sudo apt-get update",
                "sudo apt-get install -y coreutils findutils grep git rename",
                f"mkdir -p {self.scripts_dir}",
                f"rm -rf {self.scripts_dir}/LinuxCatScale",
                f"cd {self.scripts_dir} && git clone {self.repo_url}"
            ],
            'yum': [
                "sudo yum update -y",
                "sudo yum install -y coreutils findutils grep git rename",
                f"mkdir -p {self.scripts_dir}",
                f"rm -rf {self.scripts_dir}/LinuxCatScale",
                f"cd {self.scripts_dir} && git clone {self.repo_url}"
            ],
            'dnf': [
                "sudo dnf update -y",
                "sudo dnf install -y coreutils findutils grep git rename",
                f"mkdir -p {self.scripts_dir}",
                f"rm -rf {self.scripts_dir}/LinuxCatScale",
                f"cd {self.scripts_dir} && git clone {self.repo_url}"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S coreutils findutils grep git rename",
                f"mkdir -p {self.scripts_dir}",
                f"rm -rf {self.scripts_dir}/LinuxCatScale",
                f"cd {self.scripts_dir} && git clone {self.repo_url}"
            ]
        }
        return commands.get(pkg_manager, {})

    def _get_uninstall_command(self, pkg_manager: str) -> dict:
        """Diccionario de comandos de desinstalación por gestor de paquetes"""
        commands = {
            'apt': [
                f"rm -rf {self.scripts_dir}",
            ],
            'yum': [
                f"rm -rf {self.scripts_dir}",
            ],
            'dnf': [
                f"rm -rf {self.scripts_dir}",
            ],
            'pacman': [
                f"rm -rf {self.scripts_dir}",
            ]
        }
        return commands.get(pkg_manager, {})

    def _get_remote_file_path(self, stdout_data: str, prefix: str = None) -> str:
        """Extracts compressed file name from script output"""
        import re
        
        prefix = prefix or 'catscale_'
        escaped_prefix = re.escape(prefix)
        pattern = f'{escaped_prefix}[a-zA-Z0-9_-]+-\\d{{8}}-\\d{{4}}\\.tar\\.gz'
        
        matches = re.findall(pattern, stdout_data)
        return matches[-1] if matches else None


    def run_guided(self) -> None:
        """Executes tool in guided mode"""
        print("\nCat-Scale Configuration")
        print("------------------------")
        
        is_remote = input("\nDo you want to run collection on a remote system? (y/N): ").lower() == 'y'
        
        if is_remote:
            host = input("\nEnter remote host: ").strip()
            user = input("Enter SSH user: ").strip()
            
            auth_method = input("Use password authentication? (y/N): ").lower() == 'y'
            
            options = ["--remote", host, "--user", user]
            if auth_method:
                options.append("--password")
            else:
                key_path = input("Enter SSH key path: ").strip()
                options.extend(["--key", key_path])
                
            self._execute_remote(options)
        else:
            save_path = input("\nEnter path to save compressed file (Enter for current directory): ").strip()
            options = ["-o", save_path] if save_path else []
            
            # Using base class run_script method
            cmd = ["sudo", self._get_script_path()] + options
            if self.run_script(cmd):
                self._handle_output_file(save_path)


    def run_direct(self) -> None:
        """Executes tool in direct mode"""
        print(f"\n{Colors.CYAN}[*] ATTENTION: These options are only available for LOCAL EXECUTION{Colors.ENDC}")
        print("  -d OUTDIR           Output directory")
        print("  -o OUTROOT          Output root directory")
        print("  -p PREFIX           Output file prefix")
        print(f"\n{Colors.CYAN}[*] ATTENTION: These options are only available for REMOTE EXECUTION{Colors.ENDC}")
        print("  --remote <HOST>       Remote host")
        print("  --user <USER>         Remote user")
        print("  --key <KEY>           Remote key path (optional)")
        print("  --password            (press enter and write your password)")
        
        try:
            options = input(f"\n{Colors.BOLD}Insert options: {Colors.ENDC}").split()
            
            if "--remote" in options:
                self._execute_remote(options)
            else:
                cmd = ["sudo", self._get_script_path()] + options
                if self.run_script(cmd):
                    self._handle_output_file(None)
                    
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
        except Exception as e:
            print(f"Error executing command: {e}")



    def _handle_output_file(self, save_path: str = None) -> None:
        """Handles the generated output file"""
        try:
            # Find generated file
            prefix = None
            for i, opt in enumerate(save_path.split() if save_path else []):
                if opt == '-p' and i + 1 < len(save_path.split()):
                    prefix = save_path.split()[i + 1]
                    break
                    
            pattern = f"{prefix or 'catscale_'}*.tar.gz"
            matches = list(Path(".").glob(pattern))
            
            if matches:
                latest_file = max(matches, key=lambda p: p.stat().st_mtime)
                print(f"\nGenerated file: {latest_file}")
                self._handle_decompression_script(str(latest_file))
            else:
                print("Generated file not found.")
                
        except Exception as e:
            print(f"Error handling output file: {e}")


    def _handle_decompression_script(self, compressed_file_path: str) -> None:
        """Handles the decompression script copy and execution"""
        try:
            compressed_file = Path(compressed_file_path).resolve()
            target_dir = compressed_file.parent
            decompress_script = Path(self._get_script_path()).parent / "Extract-Cat-Scale.sh"
            target_script = target_dir / "Extract-Cat-Scale.sh"
            
            if not decompress_script.exists():
                print("\nWarning: Decompression script not found.")
                return
                    
            print("\nA script to decompress and organize the file has been detected.")
            copy_script = input("Do you want to copy the decompression script to the file folder? (y/N): ").lower() == 'y'
            
            if copy_script:
                # Copy script using shutil
                os.makedirs(str(target_dir), exist_ok=True)
                shutil.copy2(str(decompress_script), str(target_script))
                os.chmod(str(target_script), 0o755)
                print(f"\nScript copied to: {target_script}")
                
                execute_script = input("Do you want to execute the decompression script now? (y/N): ").lower() == 'y'
                
                if execute_script:
                    print("\nExecuting decompression script...")
                    try:
                        # Store current directory
                        original_dir = os.getcwd()
                        
                        try:
                            # Change to target directory
                            os.chdir(str(target_dir))
                            
                            if not compressed_file.exists():
                                raise FileNotFoundError(f"File not found: {compressed_file.name}")
                                
                            # Use base class run_script method
                            cmd = ["sudo", str(target_script)]
                            if not self.run_script(cmd):
                                raise Exception("Decompression script execution failed")
                                
                            print("Decompression completed successfully.")
                            
                        finally:
                            # Return to original directory
                            os.chdir(original_dir)
                            
                    except Exception as e:
                        print(f"Error during decompression: {e}")
                else:
                    print(f"\nYou can execute the script later with:")
                    print(f"cd {target_dir} && sudo ./Extract-Cat-Scale.sh")
            else:
                print(f"\nScript available at: {decompress_script}")
                print("You can copy and execute it later with:")
                print(f"cd /path/to/file && sudo ./Extract-Cat-Scale.sh")
                    
        except Exception as e:
            print(f"\nError handling decompression script: {e}")

    def cleanup_tmux_session(self):
        """
        Overriding the base cleanup method to ensure proper cleanup after remote operations
        """
        try:
            # First close SSH if it's open
            if hasattr(self, '_ssh_manager') and self._ssh_manager:
                self.close_ssh()
                
            # Then perform normal tmux cleanup
            super().cleanup_tmux_session()
                
        except Exception as e:
            print(f"Error during cleanup: {e}")



    def _execute_remote(self, options: list) -> None:
        """Executes script on remote system via SSH"""
        def remote_execution():
            remote_script = "/tmp/Cat-Scale.sh"
            try:
                # Extract SSH options
                remote_host = next((options[i+1] for i, opt in enumerate(options) if opt == "--remote" and i+1 < len(options)), None)
                remote_user = next((options[i+1] for i, opt in enumerate(options) if opt == "--user" and i+1 < len(options)), None)
                key_path = next((options[i+1] for i, opt in enumerate(options) if opt == "--key" and i+1 < len(options)), None)
                use_password = "--password" in options
                
                # Clean options list
                options_clean = []
                skip_next = False
                for i, opt in enumerate(options):
                    if skip_next:
                        skip_next = False
                        continue
                    if opt in ["--remote", "--user", "--key", "--password"]:
                        if opt != "--password":
                            skip_next = True
                        continue
                    options_clean.append(opt)
                
                if not remote_host or not remote_user:
                    print("Error: Remote host and user are required")
                    return
                    
                # Connect using base SSH manager
                success, error_msg = self.connect_ssh(
                    host=remote_host,
                    user=remote_user,
                    use_password=use_password,
                    key_path=key_path
                )
                
                if not success:
                    print(f"Could not establish connection: {error_msg}")
                    return
                
                try:
                    # Transfer files using base SSH manager
                    script_path = Path(self._get_script_path())
                    repo_path = script_path.parent
                    
                    print("\nUploading necessary files...")
                    upload_files = [
                        (str(script_path), remote_script),
                        (str(repo_path / 'patterns'), '/tmp/patterns'),
                        (str(repo_path / 'Cat-Scale-logstash.conf'), '/tmp/Cat-Scale-logstash.conf')
                    ]
                    
                    for local, remote in upload_files:
                        if not self.upload_file(local, remote):
                            raise Exception(f"Failed to upload {local}")
                    
                    # Set permissions and execute
                    self.execute_remote_command(f"chmod 755 {remote_script}", use_sudo=True)
                    
                    print(f"\nExecuting Cat-Scale on {remote_host}...")
                    exit_status, stdout, stderr = self.execute_remote_command(
                        f"{remote_script} {' '.join(options_clean)}",
                        use_sudo=True
                    )
                    
                    if exit_status != 0:
                        print(f"Error executing remote script: {stderr}")
                        return
                        
                    print(stdout)
                    
                    # Handle output file
                    remote_file = self._get_remote_file_path(stdout)
                    if remote_file:
                        print("\nScript generated file:", remote_file)
                        default_path = os.path.join(os.getcwd(), "forensics", remote_file)
                        local_path = input(f"Enter path to save file [{default_path}]: ").strip() or default_path
                        
                        if self.download_file(remote_file, local_path):
                            print(f"File saved to: {local_path}")
                            
                            # Cleanup remote files
                            cleanup_files = [remote_file, remote_script, '/tmp/patterns', '/tmp/Cat-Scale-logstash.conf']
                            self.execute_remote_command(f"rm -f {' '.join(cleanup_files)}", use_sudo=True)
                            
                            self._handle_decompression_script(local_path)
                        else:
                            print("Could not download file.")
                    else:
                        print("Could not determine generated file name.")
                        self.execute_remote_command(f"rm -f {remote_script} /tmp/patterns /tmp/Cat-Scale-logstash.conf", use_sudo=True)
                
                except Exception as e:
                    print(f"Error in remote execution: {e}")
                
            finally:
                self.close_ssh()
                
        # Execute with cleanup using base method
        self.execute_with_cleanup(remote_execution)
