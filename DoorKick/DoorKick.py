#!/usr/bin/env python3
"""
DoorKick - Initial Access Validation Toolkit
Main launcher for the modular toolkit
"""

import sys
import os
import importlib
import pkgutil
import argparse
from datetime import datetime
import time

# Add the current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.colors import *
from utils.helpers import *

class DoorKick:
    def __init__(self):
        self.target = None
        self.port = None
        self.results = []
        self.modules = {}
        self.load_modules()
        
    def load_modules(self):
        """Dynamically load all modules from the modules directory"""
        print(f"{INFO} Loading modules...", end="")
        
        try:
            # Import the modules package
            from modules import base_module
            
            # Walk through modules directory
            modules_dir = os.path.join(os.path.dirname(__file__), 'modules')
            module_files = [f[:-3] for f in os.listdir(modules_dir) 
                          if f.endswith('.py') and not f.startswith('__') 
                          and f != 'base_module.py']
            
            for module_name in module_files:
                try:
                    # Import the module
                    module = importlib.import_module(f'modules.{module_name}')
                    
                    # Find the class that inherits from BaseModule
                    for item in dir(module):
                        item_class = getattr(module, item)
                        if isinstance(item_class, type) and item != 'BaseModule':
                            if hasattr(item_class, '__bases__') and base_module.BaseModule in item_class.__bases__:
                                # Instantiate the module
                                module_instance = item_class(self)
                                self.modules[module_instance.name] = module_instance
                                break
                except Exception as e:
                    print(f"\n{WARNING} Failed to load {module_name}: {str(e)}")
            
            print(f"\r{SUCCESS} Loaded {len(self.modules)} modules    ")
            
        except Exception as e:
            print(f"\r{ERROR} Failed to load modules: {str(e)}")
    
    def banner(self):
        """Display the tool banner"""
        from utils.colors import banner
        print(banner())
        
        # Show stats
        print(f"{INFO} Target: {Y}{self.target if self.target else 'Not set'}{RESET}")
        print(f"{INFO} Modules loaded: {G}{len(self.modules)}{RESET}")
        print(f"{INFO} Time: {C}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
        print(f"{'─' * 60}\n")
    
    def menu(self):
        """Display the interactive menu"""
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            self.banner()
            
            print(f"{Y}{BRIGHT}[ MAIN MENU ]{RESET}\n")
            
            # Group modules by type
            module_list = list(self.modules.items())
            
            for idx, (name, module) in enumerate(module_list, 1):
                # Add some spacing between categories
                if idx == 5 or idx == 10:
                    print()
                
                # Format the name for display
                display_name = name.replace('Module', '').replace('_', ' ').title()
                print(f"  {G}{idx:2d}.{RESET} {display_name}")
            
            print(f"\n  {C}{len(module_list)+1:2d}.{RESET} Run ALL Modules")
            print(f"  {R}{len(module_list)+2:2d}.{RESET} Exit\n")
            
            choice = input(f"{Y}[?] Select option (1-{len(module_list)+2}): {RESET}")
            
            try:
                choice = int(choice)
                if 1 <= choice <= len(module_list):
                    # Run single module
                    module_name, module = module_list[choice-1]
                    self.run_module(module)
                    input(f"\n{C}[*] Press Enter to continue...{RESET}")
                    
                elif choice == len(module_list) + 1:
                    # Run all modules
                    self.run_all_modules()
                    input(f"\n{C}[*] Press Enter to continue...{RESET}")
                    
                elif choice == len(module_list) + 2:
                    # Exit
                    self.save_results()
                    print(f"\n{G}[+] Thanks for using DoorKick!{RESET}")
                    sys.exit(0)
                else:
                    print(f"{ERROR} Invalid option")
                    time.sleep(1)
                    
            except ValueError:
                print(f"{ERROR} Please enter a number")
                time.sleep(1)
    
    def run_module(self, module):
        """Run a single module"""
        print(f"\n{B}{'='*60}{RESET}")
        print(f"{Y}Running Module: {BRIGHT}{module.name}{RESET}")
        print(f"{B}{'='*60}{RESET}\n")
        
        try:
            module.run()
        except Exception as e:
            print(f"{ERROR} Module error: {str(e)}")
    
    def run_all_modules(self):
        """Run all modules sequentially"""
        print(f"\n{B}{'='*60}{RESET}")
        print(f"{Y}Running ALL Modules{RESET}")
        print(f"{B}{'='*60}{RESET}\n")
        
        for name, module in self.modules.items():
            print(f"\n{C}[*] Running: {name}{RESET}")
            print(f"{DIM}{'─'*40}{RESET}")
            try:
                module.run()
            except Exception as e:
                print(f"{ERROR} Module error: {str(e)}")
            time.sleep(1)
    
    def get_target(self):
        """Get or validate target"""
        if not self.target:
            self.target = input(f"{Y}[?] Enter target IP/host: {RESET}")
        return self.target
    
    def log_result(self, module, status, details):
        """Log results with timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Color-coded output
        if status in ["VULNERABLE", "RCE_POSSIBLE"]:
            status_color = R + BRIGHT
            prefix = "💀"
        elif status == "CONFIRMED":
            status_color = R + BRIGHT
            prefix = "🔥"
        elif status in ["MITIGATED", "PROTECTED"]:
            status_color = G + BRIGHT
            prefix = "🛡️"
        elif status == "POTENTIAL":
            status_color = Y + BRIGHT
            prefix = "⚠️"
        elif status == "SUSPECTED":
            status_color = Y + BRIGHT
            prefix = "❓"
        elif status == "ERROR":
            status_color = R
            prefix = "⛔"
        elif status == "INFO":
            status_color = C
            prefix = "ℹ️"
        else:
            status_color = G
            prefix = "✅"
        
        print(f"  {DIM}[{timestamp}]{RESET} {prefix} {status_color}[{status}]{RESET} {details}")
        
        # Store result
        self.results.append({
            'timestamp': timestamp,
            'module': module,
            'status': status,
            'details': details,
            'target': self.target
        })
    
    def save_results(self):
        """Save results to file"""
        if self.results:
            filename = f"doorkick_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write("="*60 + "\n")
                f.write(f"DOORKICK Results - Target: {self.target}\n")
                f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")
                
                for r in self.results:
                    f.write(f"[{r['timestamp']}] [{r['status']}] {r['module']}: {r['details']}\n")
            
            print(f"\n{G}[+] Results saved to: {filename}{RESET}")

def main():
    parser = argparse.ArgumentParser(description='DoorKick - Initial Access Toolkit')
    parser.add_argument('-t', '--target', help='Target IP/host')
    parser.add_argument('-m', '--module', type=int, help='Module number to run')
    parser.add_argument('-a', '--all', action='store_true', help='Run all modules')
    parser.add_argument('-l', '--list', action='store_true', help='List available modules')
    
    args = parser.parse_args()
    
    # Create tool instance
    tool = DoorKick()
    
    if args.target:
        tool.target = args.target
    
    if args.list:
        tool.banner()
        print(f"{Y}Available Modules:{RESET}\n")
        for idx, (name, module) in enumerate(tool.modules.items(), 1):
            print(f"  {G}{idx:2d}.{RESET} {name}")
        print()
        return
    
    if args.target:
        tool.banner()
        
        if args.module:
            # Run specific module by number
            module_list = list(tool.modules.items())
            if 1 <= args.module <= len(module_list):
                module_name, module = module_list[args.module-1]
                tool.run_module(module)
            else:
                print(f"{ERROR} Invalid module number")
        elif args.all:
            tool.run_all_modules()
        else:
            # Run interactive menu
            tool.menu()
    else:
        # Interactive mode if no target provided
        tool.get_target()
        tool.menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Y}[!] Interrupted by user{RESET}")
        sys.exit(0)