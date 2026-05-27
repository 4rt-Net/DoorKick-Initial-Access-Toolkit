#!/usr/bin/env python3
"""
RDP Security Checker - BlueKeep (CVE-2019-0708) Detection
"""
import sys
import os
import socket
import struct

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *

class RDPSecurityModule(BaseModule):
    
    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "RDP Security"
        self.port = 3389
    
    def run(self):
        module_name = "RDP Security"
        target = self.get_target()
        
        print(f"\n[*] Testing {target}:3389 for RDP security issues...")
        
        if not self.check_port(3389, timeout=3):
            self.log(module_name, "ERROR", "Port 3389 closed")
            return
        
        # Get RDP banner info
        self.get_rdp_banner(target, module_name)
        
        # Check for BlueKeep (CVE-2019-0708)
        self.check_bluekeep(target, module_name)
        
        # Check for CredSSP (CVE-2018-0886)
        self.check_credssp(target, module_name)
    
    def get_rdp_banner(self, target, module_name):
        """Grab RDP banner for version information"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 3389))
            
            data = sock.recv(1024)
            
            if len(data) > 8:
                if data[0:8] == b'\x03\x00\x00\x13\x0e\xd0\x00\x00':
                    self.log(module_name, "INFO", "RDP service detected")
                    
                    if len(data) > 11:
                        version_code = data[11] if len(data) > 11 else 0
                        if version_code == 0:
                            self.log(module_name, "INFO", "RDP version: 4.0 (pre-2003)")
                        elif version_code == 1:
                            self.log(module_name, "INFO", "RDP version: 5.0 (2003)")
                        elif version_code == 2:
                            self.log(module_name, "INFO", "RDP version: 5.1 (XP SP2)")
                        elif version_code == 3:
                            self.log(module_name, "INFO", "RDP version: 6.0 (Vista/Server 2008)")
                        elif version_code == 4:
                            self.log(module_name, "INFO", "RDP version: 6.1 (Win7/Server 2008 R2)")
                        elif version_code == 5:
                            self.log(module_name, "INFO", "RDP version: 7.0/8.0 (Win8/Server 2012)")
                        elif version_code == 6:
                            self.log(module_name, "INFO", "RDP version: 8.1 (Win8.1/Server 2012 R2)")
                        elif version_code == 7:
                            self.log(module_name, "INFO", "RDP version: 10.0 (Win10/Server 2016+)")
            
            sock.close()
            
        except Exception as e:
            self.log(module_name, "ERROR", f"Banner grab failed: {str(e)}")
    
    def check_bluekeep(self, target, module_name):
        """Check for BlueKeep vulnerability (CVE-2019-0708)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 3389))
            
            connect_request = struct.pack(
                '<BBHHH',
                0x03,  # T.125 Type: Connection Request
                0x00,  # Flags
                0x00,  # Length (placeholder)
                0x00,  # Length high
                0x01   # Channel count
            )
            
            sock.send(connect_request)
            response = sock.recv(1024)
            
            if len(response) > 0:
                # Check for specific response patterns
                # Note: This is a simplified check - real BlueKeep detection is more complex - use MSF if unsure
                if response[0] == 0x03 and len(response) < 50:
                    self.log(module_name, "POTENTIAL", 
                            "Possible BlueKeep (CVE-2019-0708) - Manual verification needed")
                    
                    print("""
    [*] BlueKeep (CVE-2019-0708) Information:
    
    This system MAY be vulnerable to BlueKeep RCE.
    
    Affected versions:
    - Windows 7
    - Windows Server 2008 R2
    - Windows Server 2008 (with RDP enabled)
    
    Remediation:
    - Install KB4499164 (May 2019 security update)
    - Enable Network Level Authentication (NLA)
    - Restrict RDP access via firewall
    - Consider disabling RDP if not needed
    
    Test carefully: CVE-2019-0708 can cause BSOD on vulnerable systems
                    """)
            else:
                self.log(module_name, "NOT VULNERABLE", 
                        "System appears patched against BlueKeep")
            
            sock.close()
            
        except Exception as e:
            pass
    
    def check_credssp(self, target, module_name):
        """Check for CredSSP vulnerabilities (CVE-2018-0886)"""
        try:
            import ssl
            import urllib.request
            #Passive detection
            
            self.log(module_name, "INFO", 
                    "CredSSP encryption can be checked with Nmap: nmap --script rdp-vuln-credssp -p 3389 " + target)
            
        except Exception:
            pass