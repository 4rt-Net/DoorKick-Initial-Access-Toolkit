#!/usr/bin/env python3
"""
CouchDB Security Checker
"""
import sys
import os
import json
import urllib.request
import urllib.error
import ssl

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *

class CouchDBSecurityModule(BaseModule):
    
    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "CouchDB Security"
        self.port = 5984
    
    def run(self):
        """Check for CouchDB security issues"""
        module_name = "CouchDB Security"
        target = self.get_target()
        
        print(f"\n[*] Testing {target} for CouchDB...")
        
        ports = [5984, 6984]
        
        for port in ports:
            if not self.check_port(port, timeout=2):
                continue
                
            protocol = "https" if port == 6984 else "http"
            self.check_couchdb(target, port, protocol, module_name)
    
    def check_couchdb(self, target, port, protocol, module_name):
        """Check CouchDB endpoints"""
        context = None
        if protocol == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        try:
            # Check root endpoint
            url = f"{protocol}://{target}:{port}/"
            req = urllib.request.Request(url, method='GET')
            req.add_header('Accept', 'application/json')
            
            response = urllib.request.urlopen(req, timeout=5, context=context)
            data = json.loads(response.read().decode('utf-8', errors='ignore'))
            
            if 'couchdb' in str(data).lower() or 'version' in data:
                self.log(module_name, "VULNERABLE", f"CouchDB exposed at {url}")
                
                version = data.get('version', 'unknown')
                self.log(module_name, "INFO", f"Version: {version}")
                
                self.check_couchdb_auth(target, port, protocol, module_name)
                
                self.check_couchdb_cves(version, target, port, protocol, module_name)
                
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.log(module_name, "PROTECTED", "CouchDB requires authentication")
            else:
                self.log(module_name, "POTENTIAL", f"CouchDB responded with HTTP {e.code}")
        except Exception as e:
            pass
    
    def check_couchdb_auth(self, target, port, protocol, module_name):
        """Check if authentication is properly configured"""
        try:
            # Try to access _all_dbs endpoint (requires auth in modern versions of CouchDB)
            url = f"{protocol}://{target}:{port}/_all_dbs"
            req = urllib.request.Request(url, method='GET')
            req.add_header('Accept', 'application/json')
            
            context = None
            if protocol == "https":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            response = urllib.request.urlopen(req, timeout=5, context=context)
            
            if response.getcode() == 200:
                dbs = json.loads(response.read().decode())
                if isinstance(dbs, list):
                    self.log(module_name, "VULNERABLE", "No authentication - database list accessible")
                    if dbs:
                        self.log(module_name, "INFO", f"Found databases: {', '.join(dbs[:5])}")
            else:
                self.log(module_name, "PROTECTED", "Authentication appears to be configured")
                
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.log(module_name, "PROTECTED", "Authentication required")
            elif e.code == 403:
                self.log(module_name, "PROTECTED", "Access forbidden")
        except Exception:
            pass
    
    def check_couchdb_cves(self, version, target, port, protocol, module_name):
        """Check for known CVE versions"""
        # CVE-2017-12635 (auth bypass) - versions 1.7.x before 1.7.2, 2.x before 2.1.1
        # CVE-2017-12636 (RCE) - same affected versions
        
        vulnerable_versions = [
            ('1.0', '1.7.1'),
            ('2.0', '2.1.0')
        ]
        
        is_vulnerable = False
        for low, high in vulnerable_versions:
            if version >= low and version <= high:
                is_vulnerable = True
                break
        
        if is_vulnerable:
            self.log(module_name, "RCE_POSSIBLE", 
                    f"Version {version} may be vulnerable to CVE-2017-12635/12636")
            
            print(f"""
    [*] CouchDB Exploitation Notes:
    
    If authentication is disabled or bypassable:
    1. Query all databases: curl {url}/_all_dbs
    2. Read documents: curl {url}/database_name/_all_docs
    3. Write new documents: curl -X PUT {url}/database_name/doc_id -d '{{"key":"value"}}'
    
    For CVE-2017-12636 RCE (requires admin access):
    - Create malicious design document with JavaScript code
    - Command execution via require('child_process').exec()
    
    Mitigation: Upgrade to CouchDB 2.1.1+ or 1.7.2+
            """)