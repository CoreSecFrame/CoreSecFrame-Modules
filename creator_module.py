from core.base import ToolModule
from core.colors import Colors
import subprocess
import os
from pathlib import Path
import re
import shutil
from typing import List, Dict, Optional

class ModuleGeneratorTool(ToolModule):
    def __init__(self):
        self.template_path = Path(__file__).parent.parent / "templates"
        super().__init__()

    def _get_name(self) -> str:
        return "createmodule"

    def _get_category(self) -> str:
        return "Development"

    def _get_command(self) -> str:
        return "createmodule"

    def _get_description(self) -> str:
        return "Tool for creating new framework modules with guided assistance"

    def _get_dependencies(self) -> List[str]:
        return []

    def _get_script_path(self) -> str:
        return ""

    def get_help(self) -> dict:
        return {
            "title": "Module Generator - Create New Framework Modules",
            "usage": "use createmodule",
            "desc": "Interactive tool to create new modules for the framework with step-by-step guidance",
            "modes": {
                "Guided": "Interactive mode that guides you through module creation",
                "Direct": "Create module directly with provided parameters"
            },
            "options": {
                "--name": "Module name (snake_case)",
                "--category": "Module category",
                "--description": "Module description",
                "--repo": "Git repository URL (optional)",
                "--deps": "Comma-separated dependencies"
            },
            "examples": [
                "use createmodule",
                "createmodule --name my_tool --category Forensics --description 'My tool description'"
            ],
            "notes": [
                "Generated modules follow framework best practices",
                "All required methods and properties are included",
                "Templates include proper error handling and documentation"
            ]
        }

    def check_installation(self) -> bool:
        """Always considered installed as it's a core tool"""
        self._installed = True
        return True

    def _get_install_command(self, pkg_manager: str) -> str:
        return ""

    def _get_update_command(self, pkg_manager: str) -> str:
        return ""

    def _get_uninstall_command(self, pkg_manager: str) -> str:
        return ""

    def _validate_module_name(self, name: str) -> bool:
        """
        Validates module name format
        
        Args:
            name: Proposed module name
            
        Returns:
            bool: True if valid, False otherwise
        """
        pattern = r'^[a-z][a-z0-9_]*$'
        if not re.match(pattern, name):
            print(f"{Colors.FAIL}[!] Invalid module name. Use snake_case (e.g. my_tool){Colors.ENDC}")
            return False
            
        # Check for existing module
        module_path = Path(__file__).parent / f"{name}_module.py"
        if module_path.exists():
            print(f"{Colors.FAIL}[!] Module {name} already exists{Colors.ENDC}")
            return False
            
        return True

    def _get_categories(self) -> List[str]:
        """Returns list of existing categories"""
        categories = set()
        modules_dir = Path(__file__).parent
        
        for file in modules_dir.glob('*_module.py'):
            if file.stem == self._get_name():
                continue
            
            try:
                with open(file, 'r') as f:
                    content = f.read()
                    # Look for category in _get_category method
                    match = re.search(r'def _get_category.*?return [\'"](.+?)[\'"]', content, re.DOTALL)
                    if match:
                        categories.add(match.group(1))
            except:
                continue
                
        return sorted(list(categories))

    def _generate_module_code(self, config: Dict) -> str:
            template = '''from core.base import ToolModule
    from core.colors import Colors
    import subprocess
    import os
    from pathlib import Path
    from typing import List, Dict, Optional

    class {class_name}(ToolModule):
        def __init__(self):
            {repo_init}
            super().__init__()

        def _get_name(self) -> str:
            return "{name}"

        def _get_category(self) -> str:
            return "{category}"

        def _get_command(self) -> str:
            return "{command}"

        def _get_description(self) -> str:
            return "{description}"

        def _get_dependencies(self) -> List[str]:
            return {dependencies}

        def _get_script_path(self) -> str:
            """Returns path to the main script if applicable"""
            {script_path}

        def get_help(self) -> dict:
            """Provides the help documentation"""
            return {{
                "title": "{title}",
                "usage": "use {name}",
                "desc": "{description}",
                "modes": {{
                    "Guided": "Interactive mode that guides through the process",
                    "Direct": "Direct execution with command line parameters"
                }},
                "options": {{
                    # Add your command options here
                }},
                "examples": [
                    f"use {name}",
                    # Add more usage examples
                ],
                "notes": [
                    # Add important notes about the tool
                ]
            }}

        def check_installation(self) -> bool:
            """
            Verifies tool installation and requirements
            
            Returns:
                bool: True if properly installed, False otherwise
            """
            try:
                # Verify dependencies
                for dep in self._get_dependencies():
                    if not shutil.which(dep):
                        self._installed = False
                        return False
                
                # Add your installation checks here
                
                self._installed = True
                return True
                
            except Exception as e:
                print(f"{{Colors.FAIL}}[!] Error checking installation: {{e}}{{Colors.ENDC}}")
                self._installed = False
                return False

        def _get_install_command(self, pkg_manager: str) -> str:
            """Returns installation command for package manager"""
            commands = {{
                'apt': [
                    # Add apt installation commands
                ],
                'yum': [
                    # Add yum installation commands
                ],
                'pacman': [
                    # Add pacman installation commands
                ]
            }}
            return commands.get(pkg_manager, [])

        def _get_update_command(self, pkg_manager: str) -> str:
            """Returns update command for package manager"""
            commands = {{
                'apt': [
                    # Add apt update commands
                ],
                'yum': [
                    # Add yum update commands
                ],
                'pacman': [
                    # Add pacman update commands
                ]
            }}
            return commands.get(pkg_manager, [])

        def _get_uninstall_command(self, pkg_manager: str) -> str:
            """Returns uninstallation command for package manager"""
            commands = {{
                'apt': [
                    # Add apt removal commands
                ],
                'yum': [
                    # Add yum removal commands
                ],
                'pacman': [
                    # Add pacman removal commands
                ]
            }}
            return commands.get(pkg_manager, [])

        def run_guided(self) -> None:
            """Executes tool in guided mode"""
            try:
                print(f"\\n{{Colors.CYAN}}[*] Starting {{self.name}} in guided mode...{{Colors.ENDC}}")
                
                # Add your guided mode implementation
                
            except KeyboardInterrupt:
                print("\\nOperation cancelled by user")
            except Exception as e:
                print(f"{{Colors.FAIL}}[!] Error in guided mode: {{e}}{{Colors.ENDC}}")

        def run_direct(self) -> None:
            """Executes tool in direct mode"""
            try:
                print(f"\\n{{Colors.CYAN}}[*] Starting {{self.name}} in direct mode...{{Colors.ENDC}}")
                
                # Show available options
                print("\\nAvailable options:")
                # Add your options here
                
                options = input(f"\\n{{Colors.BOLD}}Insert options: {{Colors.ENDC}}").split()
                
                # Add your direct mode implementation
                
            except KeyboardInterrupt:
                print("\\nOperation cancelled by user")
            except Exception as e:
                print(f"{{Colors.FAIL}}[!] Error in direct mode: {{e}}{{Colors.ENDC}}")


    """
    Implementation Guide
    ==================

    1. Available Core Utilities
    -------------------------

    A. Terminal Management:
        # Run a command in a tmux session
        self.run_script(["your", "command", "here"])
        
        # Open interactive terminal
        self.open_interactive_terminal("session-name")
        
        # Clean up tmux sessions
        self.cleanup_tmux_session()

    B. SSH Capabilities:
        # Establish SSH connection
        success, error = self.connect_ssh(
            host="remote_host",
            user="username",
            use_password=True  # or use key_path="/path/to/key"
        )
        
        # Execute remote commands
        exit_code, stdout, stderr = self.execute_remote_command(
            "your_command",
            use_sudo=True  # if sudo is needed
        )
        
        # File transfer
        self.upload_file("/local/path", "/remote/path")
        self.download_file("/remote/path", "/local/path")
        
        # Close connection
        self.close_ssh()

    C. Package Management:
        # Get system package manager commands
        pkg_manager, commands = self.get_package_manager()
        
        # Execute package commands
        self._run_command("your_command")

    2. Best Practices
    ----------------

    Error Handling:
    - Always use try/except blocks
    - Provide meaningful error messages
    - Clean up resources in finally blocks

    User Interaction:
    - Use Colors.* for consistent styling
    - Provide progress feedback
    - Handle KeyboardInterrupt

    Resource Management:
    - Clean up temporary files
    - Close connections properly
    - Use context managers when possible

    Documentation:
    - Keep help documentation updated
    - Include usage examples
    - Document command options

    3. Available Colors
    ------------------
    Colors.CYAN     - Main information
    Colors.SUCCESS  - Success messages
    Colors.FAIL     - Error messages
    Colors.WARNING  - Warnings
    Colors.BOLD     - Important input/options
    Colors.SUBTLE   - Additional information
    """
    '''
            
            # Process repository initialization if provided
            repo_init = f'self.repo_url = "{config["repo_url"]}"' if config.get("repo_url") else "pass"
            
            # Process script path
            if config.get("has_script"):
                script_path = f'return str(Path(__file__).parent.parent / "modules" / "scripts" / "{config["name"]}" / "main.sh")'
            else:
                script_path = 'return ""'
                
            # Generate class name
            class_name = ''.join(word.title() for word in config["name"].split('_')) + 'Module'
            
            # Format dependencies list
            deps = config.get("dependencies", [])
            deps_str = str(deps) if deps else "[]"
            
            return template.format(
                class_name=class_name,
                name=config["name"],
                category=config["category"],
                command=config["name"],
                description=config["description"],
                dependencies=deps_str,
                title=f"{config['name'].title()} - {config['description']}",
                repo_init=repo_init,
                script_path=script_path
            )

    def _create_module_structure(self, config: Dict) -> None:
        """
        Creates module file structure
        
        Args:
            config: Module configuration
        """
        try:
            module_dir = Path(__file__).parent
            module_file = module_dir / f"{config['name']}_module.py"
            
            # Generate and write module code
            code = self._generate_module_code(config)
            with open(module_file, 'w') as f:
                f.write(code)
                
            print(f"{Colors.SUCCESS}[✓] Module file created: {module_file}{Colors.ENDC}")
            
            # Create script directory if needed
            if config.get("has_script"):
                scripts_dir = module_dir.parent / "modules" / "scripts" / config["name"]
                scripts_dir.mkdir(parents=True, exist_ok=True)
                
                # Create main script file
                script_file = scripts_dir / "main.sh"
                with open(script_file, 'w') as f:
                    f.write('#!/bin/bash\n\n# Add your script implementation here\n')
                os.chmod(script_file, 0o755)
                
                print(f"{Colors.SUCCESS}[✓] Script directory created: {scripts_dir}{Colors.ENDC}")
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error creating module structure: {e}{Colors.ENDC}")
            raise

    def run_guided(self) -> None:
            """Executes generator in guided mode"""
            try:
                print(f"\n{Colors.CYAN}[*] Module Generator - Guided Mode{Colors.ENDC}")
                print(f"{Colors.CYAN}[*] Follow the steps to create a new module{Colors.ENDC}\n")
                
                config = {}
                
                # Get module name
                while True:
                    name = input(f"{Colors.BOLD}Module name (snake_case): {Colors.ENDC}").strip()
                    if self._validate_module_name(name):
                        config["name"] = name
                        break
                        
                # Get or select category
                existing_categories = self._get_categories()
                print(f"\n{Colors.CYAN}[*] Existing categories:{Colors.ENDC}")
                for i, cat in enumerate(existing_categories, 1):
                    print(f"{i}. {cat}")
                print(f"0. Create new category")
                
                while True:
                    try:
                        choice = input(f"\n{Colors.BOLD}Select category (0-{len(existing_categories)}): {Colors.ENDC}")
                        if choice == "0":
                            category = input(f"{Colors.BOLD}New category name: {Colors.ENDC}").strip()
                            if category:
                                config["category"] = category
                                break
                        else:
                            idx = int(choice) - 1
                            if 0 <= idx < len(existing_categories):
                                config["category"] = existing_categories[idx]
                                break
                        print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                    except ValueError:
                        print(f"{Colors.FAIL}[!] Invalid input{Colors.ENDC}")
                        
                # Get description
                while True:
                    description = input(f"\n{Colors.BOLD}Module description: {Colors.ENDC}").strip()
                    if description:
                        config["description"] = description
                        break
                    print(f"{Colors.FAIL}[!] Description is required{Colors.ENDC}")
                    
                # Get repository URL if applicable
                repo_url = input(f"\n{Colors.BOLD}Git repository URL (optional): {Colors.ENDC}").strip()
                if repo_url:
                    config["repo_url"] = repo_url
                    
                # Get dependencies
                deps = input(f"\n{Colors.BOLD}Dependencies (comma-separated, optional): {Colors.ENDC}").strip()
                if deps:
                    config["dependencies"] = [d.strip() for d in deps.split(",")]
                    
                # Ask about script directory
                config["has_script"] = input(f"\n{Colors.BOLD}Create script directory? (y/N): {Colors.ENDC}").lower() == 'y'
                
                # Show summary and confirm
                print(f"\n{Colors.CYAN}[*] Module Configuration Summary:{Colors.ENDC}")
                print(f"  • Name: {config['name']}")
                print(f"  • Category: {config['category']}")
                print(f"  • Description: {config['description']}")
                if config.get("repo_url"):
                    print(f"  • Repository: {config['repo_url']}")
                if config.get("dependencies"):
                    print(f"  • Dependencies: {', '.join(config['dependencies'])}")
                print(f"  • Script Directory: {'Yes' if config['has_script'] else 'No'}")
                
                if input(f"\n{Colors.BOLD}Create module? (Y/n): {Colors.ENDC}").lower() != 'n':
                    # Create module
                    module_path = Path(__file__).parent / f"{config['name']}_module.py"
                    self._create_module_structure(config)
                    print(f"\n{Colors.SUCCESS}[✓] Module created successfully!{Colors.ENDC}")
                    
                    # Ask about editor
                    if input(f"\n{Colors.BOLD}Would you like to open the module in a code editor? (Y/n): {Colors.ENDC}").lower() != 'n':
                        self._open_editor_session(str(module_path))
                    
                    # Show implementation guide
                    if input(f"\n{Colors.BOLD}Would you like to see the implementation guide? (Y/n): {Colors.ENDC}").lower() != 'n':
                        self._show_implementation_guide(config['name'])
                    else:
                        print(f"\n{Colors.CYAN}[*] You can view the guide later with 'help createmodule'{Colors.ENDC}")
                else:
                    print(f"\n{Colors.WARNING}[!] Module creation cancelled{Colors.ENDC}")

                    
            except KeyboardInterrupt:
                print("\nOperation cancelled by user")
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error in guided mode: {e}{Colors.ENDC}")

    def run_direct(self) -> None:
        """Executes generator in direct mode"""
        try:
            print(f"\n{Colors.CYAN}[*] Module Generator - Direct Mode{Colors.ENDC}")
            print("Available options:")
            print("  --name        Module name (required)")
            print("  --category    Module category (required)")
            print("  --desc        Module description (required)")
            print("  --repo        Git repository URL (optional)")
            print("  --deps        Comma-separated dependencies (optional)")
            print("  --script      Create script directory (optional)")
            
            options = input(f"\n{Colors.BOLD}Insert options: {Colors.ENDC}").split()
            
            # Parse options
            config = {}
            i = 0
            while i < len(options):
                opt = options[i]
                if i + 1 >= len(options):
                    print(f"{Colors.FAIL}[!] Missing value for {opt}{Colors.ENDC}")
                    return
                    
                if opt == '--name':
                    name = options[i + 1]
                    if not self._validate_module_name(name):
                        return
                    config['name'] = name
                elif opt == '--category':
                    config['category'] = options[i + 1]
                elif opt == '--desc':
                    config['description'] = options[i + 1]
                elif opt == '--repo':
                    config['repo_url'] = options[i + 1]
                elif opt == '--deps':
                    config['dependencies'] = [d.strip() for d in options[i + 1].split(',')]
                elif opt == '--script':
                    config['has_script'] = True
                    i -= 1  # No value needed
                i += 2
                
            # Validate required fields
            required = ['name', 'category', 'description']
            missing = [field for field in required if field not in config]
            if missing:
                print(f"{Colors.FAIL}[!] Missing required fields: {', '.join(missing)}{Colors.ENDC}")
                return
                
            # Create module
            module_path = Path(__file__).parent / f"{config['name']}_module.py"
            self._create_module_structure(config)
            print(f"\n{Colors.SUCCESS}[✓] Module created successfully!{Colors.ENDC}")
            
            # Offer editor
            print(f"\n{Colors.CYAN}[*] Module created at: {module_path}{Colors.ENDC}")
            if input(f"{Colors.BOLD}Open in code editor? (Y/n): {Colors.ENDC}").lower() != 'n':
                self._open_editor_session(str(module_path))
            
            # Show implementation guide
            self._show_implementation_guide(config['name'])
            
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error in direct mode: {e}{Colors.ENDC}")


    def _check_editor(self, editor: str) -> bool:
        """
        Verifies if an editor is installed
        
        Args:
            editor: Name of the editor to check
            
        Returns:
            bool: True if editor is installed, False otherwise
        """
        return shutil.which(editor) is not None


    def _open_editor_session(self, module_path: str) -> None:
            """
            Opens the selected code editor in the current session
            
            Args:
                module_path: Path to the module file to edit
            """
            editors = {
                'neovim': {
                    'command': 'nvim',
                    'description': 'Modern, powerful Vim-based editor',
                    'install': {
                        'apt': 'sudo apt-get install neovim',
                        'yum': 'sudo yum install neovim',
                        'pacman': 'sudo pacman -S neovim'
                    }
                },
                'helix': {
                    'command': 'hx',
                    'description': 'Modern terminal editor with advanced features',
                    'install': {
                        'apt': 'sudo add-apt-repository ppa:helix-editor/helix && sudo apt-get update && sudo apt-get install helix',
                        'yum': 'sudo yum install helix',
                        'pacman': 'sudo pacman -S helix'
                    }
                },
                'micro': {
                    'command': 'micro',
                    'description': 'User-friendly, intuitive editor',
                    'install': {
                        'apt': 'sudo apt-get install micro',
                        'yum': 'sudo yum install micro',
                        'pacman': 'sudo pacman -S micro'
                    }
                }
            }

            print(f"\n{Colors.CYAN}[*] Available Code Editors:{Colors.ENDC}")
            for i, (name, info) in enumerate(editors.items(), 1):
                installed = "✓" if self._check_editor(info['command']) else "✗"
                print(f"{i}. {name} [{installed}] - {info['description']}")
            print("0. Cancel")

            while True:
                try:
                    choice = input(f"\n{Colors.BOLD}Select editor (0-{len(editors)}): {Colors.ENDC}")
                    if choice == "0":
                        return

                    idx = int(choice) - 1
                    if 0 <= idx < len(editors):
                        editor_name = list(editors.keys())[idx]
                        editor_info = editors[editor_name]
                        editor_cmd = editor_info['command']

                        # Check if editor is installed
                        if not self._check_editor(editor_cmd):
                            print(f"\n{Colors.WARNING}[!] {editor_name} is not installed{Colors.ENDC}")
                            
                            # Get package manager
                            pkg_manager = self.get_package_manager()[0]
                            if pkg_manager and pkg_manager in editor_info['install']:
                                install_cmd = editor_info['install'][pkg_manager]
                                print(f"\n{Colors.CYAN}[*] You can install it with:{Colors.ENDC}")
                                print(f"    {install_cmd}")
                                
                                if input(f"\n{Colors.BOLD}Install now? (y/N): {Colors.ENDC}").lower() == 'y':
                                    os.system(install_cmd)
                                    if not self._check_editor(editor_cmd):
                                        print(f"{Colors.FAIL}[!] Installation failed{Colors.ENDC}")
                                        continue
                                else:
                                    continue
                            else:
                                print(f"{Colors.FAIL}[!] Could not determine installation method{Colors.ENDC}")
                                continue

                        try:
                            # Simply execute the editor in the current session
                            print(f"\n{Colors.CYAN}[*] Opening {editor_name}...{Colors.ENDC}")
                            subprocess.run([editor_cmd, module_path], check=True)
                            print(f"\n{Colors.SUCCESS}[✓] Editor closed{Colors.ENDC}")
                            return True
                            
                        except subprocess.CalledProcessError as e:
                            print(f"{Colors.FAIL}[!] Error opening editor: {e}{Colors.ENDC}")
                            return False
                        except Exception as e:
                            print(f"{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
                            return False
                            
                    else:
                        print(f"{Colors.FAIL}[!] Invalid choice{Colors.ENDC}")
                except ValueError:
                    print(f"{Colors.FAIL}[!] Invalid input{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")




