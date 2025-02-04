# modules/john_module.py
from core.base import ToolModule
from typing import List
import subprocess
import platform
import os
from pathlib import Path


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class JohnModule(ToolModule):
    def _get_name(self) -> str:
        return "John"

    def _get_command(self) -> str:
        return "john"

    def _get_description(self) -> str:
        return "Herramienta avanzada de cracking de contraseñas"

    def _get_dependencies(self) -> List[str]:
        return ["john"]

    def get_help(self) -> dict:
        """
        Proporciona la documentación de ayuda específica de john
        """
        return {
            "title": "TEST",
            "usage": "TEST",
            "desc": "TEST",
            "modes": {
                "Guiado": "Modo interactivo que solicita la información necesaria paso a paso",
                "Directo": "Modo que acepta todos los parámetros en la línea de comandos"
            },
            "options": {
                "TEST": "TEST",
            },
            "examples": [
                "TEST"
            ],
            "notes": [
                "TEST"
            ]
        }

    def _show_banner(self):
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║         JOHN THE RIPPER CRACKER          ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _get_hash_file(self) -> str:
        """Solicita y valida el archivo de hashes"""
        while True:
            file_path = input(f"{Colors.BOLD}[+] Ruta al archivo de hashes: {Colors.ENDC}").strip()
            if not file_path:
                print(f"{Colors.FAIL}[!] Debes especificar un archivo{Colors.ENDC}")
                continue

            path = Path(file_path)
            if path.exists() and path.is_file():
                return str(path.absolute())
            print(f"{Colors.FAIL}[!] El archivo no existe{Colors.ENDC}")

    def _get_wordlist(self) -> str:
        """Solicita y valida el diccionario"""
        default_wordlists = {
            "1": "/usr/share/wordlists/rockyou.txt",
            "2": "/usr/share/john/password.lst",
            "3": "/usr/share/wordlists/fasttrack.txt",
            "4": "custom"
        }

        print(f"\n{Colors.CYAN}[*] Diccionarios disponibles:{Colors.ENDC}")
        print(f"{Colors.GREEN}1:{Colors.ENDC} RockYou")
        print(f"{Colors.GREEN}2:{Colors.ENDC} Password.lst (John)")
        print(f"{Colors.GREEN}3:{Colors.ENDC} Fasttrack")
        print(f"{Colors.GREEN}4:{Colors.ENDC} Personalizado")

        while True:
            choice = input(f"\n{Colors.BOLD}[+] Selecciona diccionario (1-4): {Colors.ENDC}").strip()
            if choice not in default_wordlists:
                print(f"{Colors.FAIL}[!] Opción no válida{Colors.ENDC}")
                continue

            if choice == "4":
                while True:
                    custom_path = input(f"{Colors.BOLD}[+] Ruta al diccionario: {Colors.ENDC}").strip()
                    if not custom_path:
                        print(f"{Colors.FAIL}[!] Debes especificar un archivo{Colors.ENDC}")
                        continue

                    path = Path(custom_path)
                    if path.exists() and path.is_file():
                        return str(path.absolute())
                    print(f"{Colors.FAIL}[!] El archivo no existe{Colors.ENDC}")
            else:
                return default_wordlists[choice]

    def _get_format(self) -> str:
        """Solicita el formato del hash"""
        print(f"\n{Colors.CYAN}[*] Formatos comunes:{Colors.ENDC}")
        formats = {
            "1": "",  # Auto-detect
            "2": "--format=md5",
            "3": "--format=sha1",
            "4": "--format=sha256",
            "5": "--format=sha512",
            "6": "--format=nt",
            "7": "--format=raw-md5"
        }

        print(f"{Colors.GREEN}1:{Colors.ENDC} Auto-detectar")
        print(f"{Colors.GREEN}2:{Colors.ENDC} MD5")
        print(f"{Colors.GREEN}3:{Colors.ENDC} SHA1")
        print(f"{Colors.GREEN}4:{Colors.ENDC} SHA256")
        print(f"{Colors.GREEN}5:{Colors.ENDC} SHA512")
        print(f"{Colors.GREEN}6:{Colors.ENDC} NT (Windows)")
        print(f"{Colors.GREEN}7:{Colors.ENDC} Raw-MD5")

        while True:
            choice = input(f"\n{Colors.BOLD}[+] Selecciona formato (1-7): {Colors.ENDC}").strip()
            if choice in formats:
                return formats[choice]
            print(f"{Colors.FAIL}[!] Opción no válida{Colors.ENDC}")

    def _get_options(self) -> str:
        """Solicita opciones adicionales"""
        options = []

        if input(f"\n{Colors.BOLD}[+] ¿Mostrar progreso? (S/n): {Colors.ENDC}").lower() != 'n':
            options.append("--progress=yes")

        if input(f"{Colors.BOLD}[+] ¿Usar reglas de John? (s/N): {Colors.ENDC}").lower() == 's':
            options.append("--rules=yes")

        if input(f"{Colors.BOLD}[+] ¿Mostrar tiempo estimado? (S/n): {Colors.ENDC}").lower() != 'n':
            options.append("--eta=yes")

        return " ".join(options)

    def run_guided(self) -> None:
        """Modo guiado para John the Ripper"""
        self._show_banner()

        try:
            # Solicitar información necesaria
            hash_file = self._get_hash_file()
            if not hash_file:
                return

            wordlist = self._get_wordlist()
            if not wordlist:
                return

            format_opt = self._get_format()
            additional_opts = self._get_options()

            # Construir comando
            command = f"john {format_opt} {additional_opts} --wordlist={wordlist} {hash_file}"

            print(f"\n{Colors.CYAN}[*] Ejecutando comando:{Colors.ENDC}")
            print(f"{Colors.BOLD}{command}{Colors.ENDC}\n")

            try:
                # Ejecutar John
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )

                # Mostrar salida en tiempo real
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(output.strip())

                # Verificar si hubo errores
                stderr = process.stderr.read()
                if stderr:
                    print(f"{Colors.FAIL}[!] Errores durante la ejecución:{Colors.ENDC}")
                    print(stderr)

                if process.returncode == 0:
                    print(f"\n{Colors.GREEN}[✓] Proceso completado{Colors.ENDC}")

                    # Mostrar resultados
                    print(f"\n{Colors.CYAN}[*] Mostrando contraseñas encontradas:{Colors.ENDC}")
                    show_cmd = f"john --show {hash_file}"
                    subprocess.run(show_cmd, shell=True)
                else:
                    print(f"\n{Colors.FAIL}[!] El proceso terminó con errores{Colors.ENDC}")

            except subprocess.SubprocessError as e:
                print(f"{Colors.FAIL}[!] Error ejecutando John: {e}{Colors.ENDC}")
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Proceso interrumpido por el usuario{Colors.ENDC}")
                if 'process' in locals():
                    process.terminate()

        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Operación cancelada por el usuario{Colors.ENDC}")
            return

    def run_direct(self) -> None:
        """Modo directo para John the Ripper"""
        self._show_banner()
        print(f"\n{Colors.CYAN}[*] Modo directo - Ingresa comandos de John{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Comandos útiles:{Colors.ENDC}")
        print("  - john [opciones] archivo_hash")
        print("  - john --show archivo_hash")
        print("  - john --list=formats")
        print("  - john --test")
        print(f"{Colors.CYAN}[*] Escribe 'exit' para volver al menú principal{Colors.ENDC}")

        while True:
            try:
                command = input(f"\n{Colors.BOLD}john > {Colors.ENDC}").strip()
                if not command:
                    continue
                if command.lower() == 'exit':
                    break
                if command:
                    if not command.startswith('john '):
                        command = f"john {command}"
                    self.execute_command(command)
            except KeyboardInterrupt:
                print("\n")
                break

    def show_formats(self):
        """Muestra los formatos soportados por John"""
        try:
            subprocess.run(["john", "--list=formats"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}[!] Error al listar formatos: {e}{Colors.ENDC}")
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Operación cancelada por el usuario{Colors.ENDC}")

    def show_statistics(self):
        """Muestra estadísticas de la sesión actual"""
        try:
            subprocess.run(["john", "--status"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}[!] Error al mostrar estadísticas: {e}{Colors.ENDC}")
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Operación cancelada por el usuario{Colors.ENDC}")