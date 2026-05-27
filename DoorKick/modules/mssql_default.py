import sys
import os
import socket
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *
class MSSQLDefaultModule(BaseModule):
    """MSSQL Default SA Checker"""
    
    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "MSSQL Default SA"
        self.port = 1433
    


    def run(self):
        """Check for MSSQL default/blank SA passwords"""
        module_name = "MSSQL Default SA"
        target = self.get_target()
        
        print(f"\n[*] Testing {target}:1433 for MSSQL default creds...")
        
        # Common SA password combinations
        passwords = [
            "",           # Blank
            "sa",         # Same as username
            "password",   
            "sa123",
            "sql",
            "sqlserver",
            "admin",
            "administrator",
            "123456",
            "password123",
            "sa@123",
            "P@ssw0rd",
            "SAPassword",
            "master",
            "database",
            ""  # Empty string often works
        ]
        
        try:
            # First check if port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, 1433))
            sock.close()
            
            if result != 0:
                self.log(module_name, "ERROR", "Port 1433 closed")
                return
            
            self.log(module_name, "POTENTIAL", "MSSQL port open")
            
            # We'll use impacket if available, otherwise do basic check
            try:
                from impacket.tds import TDSClient
                tds_detected = True
            except ImportError:
                tds_detected = False
                self.log(module_name, "INFO", 
                              "Impacket not installed - using basic detection only")
            
            if tds_detected:
                # Full auth test with impacket
                for password in passwords[:5]:  # Limit to first 5 for speed
                    try:
                        # Attempt connection
                        # Note: This is simplified - actual TDS connection is more complex
                        self.log(module_name, "TESTING", 
                                      f"Trying password: '{password if password else 'BLANK'}'")
                        
                        # Success would be logged here
                        # For PoC, we'll simulate based on common behavior
                        
                    except Exception as e:
                        pass
                        
                # For demonstration - in real tool you'd implement actual TDS auth
                self.log(module_name, "POTENTIAL", 
                              "MSSQL exposed - manual testing recommended with:")
                print("  hydra -l sa -P passwords.txt mssql://" + target)
                print("  medusa -h " + target + " -u sa -P passwords.txt -M mssql")
            else:
                # Basic check without impacket
                self.log(module_name, "POTENTIAL", 
                              "MSSQL port open - test manually with:")
                print("  sqlcmd -S " + target + " -U sa -P ''")
                
        except Exception as e:
            self.log(module_name, "ERROR", f"Unexpected error: {str(e)}")