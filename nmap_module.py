# modules/nmap_module.py
from core.base import ToolModule
from typing import List
import subprocess
import platform
import os


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class NmapModule(ToolModule):
    def _get_name(self) -> str:
        return "Nmap"

    def _get_command(self) -> str:
        return "nmap"

    def _get_description(self) -> str:
        return "Scanner de puertos y análisis de red avanzado"

    def _get_dependencies(self) -> List[str]:
        return ["nmap"]

    def get_help(self) -> dict:
        """
        Proporciona la documentación de ayuda específica de nmap
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

    def get_package_install(self) -> dict:
        """
        Diccionario de comandos de instalación por gestor de paquetes
        """
        return {
            'apt': [
                "sudo apt update",
                "sudo apt install -y nmap"
            ],
            'yum': [
                "sudo yum update",
                "sudo yum install -y nmap"
            ],
            'dnf': [
                "sudo dnf update",
                "sudo dnf install -y nmap"
            ],
            'pacman': [
                "sudo pacman -Sy",
                "sudo pacman -S nmap"
            ]
        }

    def get_package_update(self) -> dict:
        """
        Diccionario de comandos de actualización por gestor de paquetes
        """
        return {
            'apt': [
                "sudo apt update",
                "sudo apt install -y nmap"
            ],
            'yum': [
                "sudo yum update -y nmap"
            ],
            'dnf': [
                "sudo dnf update -y nmap"
            ],
            'pacman': [
                "sudo pacman -Syu nmap"
            ]
        }

    def get_package_remove(self) -> dict:
        """
        Diccionario de comandos de desinstalación por gestor de paquetes
        """
        return {
            'apt': [
                "sudo apt-get remove -y nmap",
                "sudo apt-get autoremove -y"
            ],
            'yum': [
                "sudo yum remove -y nmap",
                "sudo yum autoremove -y"
            ],
            'dnf': [
                "sudo dnf remove -y nmap",
                "sudo dnf autoremove -y"
            ],
            'pacman': [
                "sudo pacman -R nmap"
            ]
        }

    def _show_banner(self):
        banner = f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║              NMAP SCANNER               ║
╚══════════════════════════════════════════╝{Colors.ENDC}'''
        print(banner)

    def _get_target(self) -> str:
        """Solicita y valida el objetivo del escaneo"""
        while True:
            target = input(f"{Colors.BOLD}[+] Objetivo (IP/dominio/rango): {Colors.ENDC}").strip()
            if target:
                return target
            print(f"{Colors.FAIL}[!] Error: Debes especificar un objetivo{Colors.ENDC}")

    def _get_scan_type(self) -> str:
        """Muestra menú de tipos de escaneo y retorna la opción seleccionada"""
        print(f"\n{Colors.CYAN}[*] Tipos de escaneo disponibles:{Colors.ENDC}")
        options = {
            "1": ("Escaneo rápido", "--top-ports 100 -T4"),
            "2": ("Escaneo común", "--top-ports 1000"),
            "3": ("Escaneo completo", "-p-"),
            "4": ("Escaneo sigiloso", "-sS -T2"),
            "5": ("Detección de versiones", "-sV"),
            "6": ("Escaneo agresivo", "-A"),
            "7": ("Personalizado", "")
        }

        for key, (name, _) in options.items():
            print(f"{Colors.GREEN}{key}:{Colors.ENDC} {name}")

        while True:
            try:
                choice = input(f"\n{Colors.BOLD}[+] Selecciona tipo de escaneo (1-7): {Colors.ENDC}").strip()
                if choice in options:
                    return options[choice][1]
                print(f"{Colors.FAIL}[!] Opción no válida{Colors.ENDC}")
            except KeyboardInterrupt:
                print("\n")
                return ""

    def _get_additional_options(self) -> str:
        """Solicita opciones adicionales para el escaneo"""
        options = []

        try:
            if input(f"\n{Colors.BOLD}[+] ¿Detectar sistema operativo? (s/N): {Colors.ENDC}").lower() == 's':
                options.append("-O")

            if input(f"{Colors.BOLD}[+] ¿Ejecutar scripts por defecto? (s/N): {Colors.ENDC}").lower() == 's':
                options.append("-sC")

            if input(f"{Colors.BOLD}[+] ¿Mostrar solo puertos abiertos? (s/N): {Colors.ENDC}").lower() == 's':
                options.append("--open")

            timing = input(f"{Colors.BOLD}[+] Velocidad de escaneo (0-5, Enter para default): {Colors.ENDC}").strip()
            if timing and timing in "012345":
                options.append(f"-T{timing}")

            return " ".join(options)
        except KeyboardInterrupt:
            print("\n")
            return ""

    def _get_output_options(self) -> str:
        """Configura opciones de salida"""
        options = []

        try:
            if input(f"\n{Colors.BOLD}[+] ¿Guardar resultado en archivo? (s/N): {Colors.ENDC}").lower() == 's':
                filename = input(f"{Colors.BOLD}[+] Nombre del archivo (sin extensión): {Colors.ENDC}").strip()
                if filename:
                    options.extend(["-oN", f"{filename}.txt", "-oX", f"{filename}.xml"])

            return " ".join(options)
        except KeyboardInterrupt:
            print("\n")
            return ""

    def run_guided(self) -> None:
        """Modo guiado mejorado para Nmap"""
        self._show_banner()

        try:
            # Recopilar información
            target = self._get_target()
            if not target:
                return

            scan_type = self._get_scan_type()
            if not scan_type:
                return

            additional_opts = self._get_additional_options()
            output_opts = self._get_output_options()

            # Construir y ejecutar comando
            command = f"nmap {scan_type} {additional_opts} {output_opts} {target}"

            print(f"\n{Colors.CYAN}[*] Ejecutando comando:{Colors.ENDC}")
            print(f"{Colors.BOLD}{command}{Colors.ENDC}\n")

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
                print(f"\n{Colors.GREEN}[✓] Escaneo completado exitosamente{Colors.ENDC}")
            else:
                print(f"\n{Colors.FAIL}[!] El escaneo terminó con errores{Colors.ENDC}")

        except subprocess.SubprocessError as e:
            print(f"{Colors.FAIL}[!] Error ejecutando Nmap: {e}{Colors.ENDC}")
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Escaneo interrumpido por el usuario{Colors.ENDC}")
            if 'process' in locals():
                process.terminate()

    def run_direct(self) -> None:
        """Modo directo mejorado para Nmap"""
        self._show_banner()
        print(f"\n{Colors.CYAN}[*] Modo directo - Ingresa comando Nmap completo{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Ejemplo: nmap -sS -sV -O <objetivo>{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Escribe 'exit' para volver al menú principal{Colors.ENDC}")

        while True:
            try:
                command = input(f"\n{Colors.BOLD}nmap > {Colors.ENDC}").strip()
                if not command:
                    continue
                if command.lower() == 'exit':
                    break
                if command:
                    if not command.startswith('nmap '):
                        command = f"nmap {command}"
                    self.execute_command(command)
            except KeyboardInterrupt:
                print("\n")
                break