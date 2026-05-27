import sys
import os
import socket
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *
class NFSExportsModule(BaseModule):
    """NFS Exports Checker"""
    
    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "NFS Exports"
        self.port = 2049
    


    def run(self):
        """Check for world-readable NFS exports"""
        module_name = "NFS Exports"
        target = self.get_target()
        
        print(f"\n[*] Testing {target}:2049 for NFS...")
        
        try:
            # Check if port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, 2049))
            sock.close()
            
            if result != 0:
                # NFS can also run on UDP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, 2049))
                sock.close()
                
                if result != 0:
                    self.log(module_name, "ERROR", "Port 2049 closed")
                    return
            
            self.log(module_name, "POTENTIAL", "NFS port open")
            
            # Try to query mount daemon (port 111)
            self.query_nfs_mounts(target)
            
        except Exception as e:
            self.log(module_name, "ERROR", f"Unexpected error: {str(e)}")
    
    def query_nfs_mounts(self, target):
        """Query NFS mount daemon for exports"""
        import subprocess
        import tempfile
        import os
        
        module_name = "NFS Exports"
        
        # Try showmount command
        try:
            result = subprocess.run(['showmount', '-e', target], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and 'Export list' in result.stdout:
                exports = result.stdout.strip()
                self.log(module_name, "VULNERABLE", 
                              f"NFS exports accessible: {exports}")
                
                # Parse exports
                for line in exports.split('\n')[1:]:
                    if line.strip():
                        parts = line.split()
                        if parts:
                            export = parts[0]
                            self.log(module_name, "INFO", 
                                          f"Export found: {export}")
                            
                            # Try to mount (test without actually mounting)
                            self.test_nfs_mount(target, export)
                            
        except FileNotFoundError:
            # showmount not installed - use manual RPC query
            self.log(module_name, "INFO", 
                          "showmount not found - install nfs-common package")
            
            # Provide manual instructions
            print(f"""
    [*] Manual NFS Testing:
    
    1. Install tools:
       sudo apt-get install nfs-common
    
    2. List exports:
       showmount -e {target}
    
    3. Mount an export:
       sudo mount -t nfs {target}:/export /mnt/nfs -o nolock
       ls -la /mnt/nfs
    
    4. Check for sensitive files:
       - SSH keys (~/.ssh)
       - Configuration files
       - Database backups
       - Shadow files (if no_root_squash)
    
    5. If no_root_squash is enabled:
       # Create setuid binary
       cp /bin/bash ./bash-root
       chmod 4755 ./bash-root
       # Upload and execute with root privileges
            """)
    
    def test_nfs_mount(self, target, export):
        """Test if export is mountable"""
        module_name = "NFS Exports"
        
        # In a real tool, you'd attempt a mount
        # For PoC, we'll just note the path
        self.log(module_name, "RCE_POSSIBLE", 
                      f"Export {export} may be mountable - check permissions")