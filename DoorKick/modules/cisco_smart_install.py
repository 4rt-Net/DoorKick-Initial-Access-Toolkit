#!/usr/bin/env python3
"""
Cisco Smart Install Checker
"""
import sys
import os
import socket
import struct

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *

class CiscoSmartInstallModule(BaseModule):
    
    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Cisco Smart Install"
        self.port = 4786
    
    def run(self):
        """Check for Cisco Smart Install vulnerability"""
        module_name = "Cisco Smart Install"
        target = self.get_target()
        
        print(f"\n[*] Testing {target}:4786 for Cisco Smart Install...")
        
        if not self.check_port(4786, timeout=3):
            self.log(module_name, "ERROR", "Port 4786 closed")
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 4786))
            
            # Valid SMI probe - Get Version Info
            # SMI message header: version(2) + type(2) + length(4)
            probe = struct.pack('>HHI', 1, 1, 0)
            sock.send(probe)
            
            response = sock.recv(1024)
            
            if len(response) > 8:
                version, msg_type, length = struct.unpack('>HHI', response[:8])
                
                if msg_type == 2 and length > 0:
                    self.log(module_name, "VULNERABLE", "Cisco Smart Install service detected")
                    
                    try:
                        info = response[8:min(100, 8+length)]
                        if info:
                            self.log(module_name, "INFO", f"Device info: {info[:50].decode('utf-8', errors='ignore')}")
                    except:
                        pass
                    
                    print(f"""
    [*] Cisco Smart Install Information:
    
    This service is known to be vulnerable to:
    - Configuration file disclosure (CVE-2018-0171)
    - Image file upload (CVE-2018-0169)
    - Remote code execution via crafted packets
    
    Remediation:
    - Disable SMI: no vstack
    - Or restrict access using ACLs
                    """)
                else:
                    self.log(module_name, "POTENTIAL", "Service responded but not standard SMI")
            else:
                self.log(module_name, "NOT VULNERABLE", "No valid SMI response")
            
            sock.close()
            
        except socket.timeout:
            self.log(module_name, "ERROR", "Connection timeout")
        except ConnectionRefusedError:
            self.log(module_name, "ERROR", "Port 4786 closed")
        except Exception as e:
            self.log(module_name, "ERROR", f"Unexpected error: {str(e)}")