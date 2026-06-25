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
            self.log(module_name, "ERROR", f"CouchDB probe failed: {str(e)}")

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
            else:
                self.log(module_name, "ERROR", f"_all_dbs returned HTTP {e.code}")
        except Exception as e:
            self.log(module_name, "ERROR", f"Auth check failed: {str(e)}")
    
    def check_couchdb_cves(self, version, target, port, protocol, module_name):
        """Check for known CVE versions using proper semver comparison."""
        # CVE-2017-12635 (auth bypass) - versions <1.7.2 and <2.1.1
        # CVE-2017-12636 (RCE) - same affected versions

        parsed = self._parse_version(version)
        if parsed is None:
            self.log(module_name, "SUSPECTED",
                     f"Could not parse version '{version}' for CVE check")
            return

        fixed_2x = (2, 1, 1)

        if parsed < fixed_2x:
            self.log(module_name, "RCE_POSSIBLE",
                     f"Version {version} is below 2.1.1 and may be vulnerable to CVE-2017-12635/12636 (remote exec)")
            self.print_exploit_steps([
                f"If unauthenticated: curl {protocol}://{target}:{port}/_all_dbs",
                f"Read documents: curl {protocol}://{target}:{port}/<db>/_all_docs",
                f"CVE-2017-12635 auth bypass: create admin via _users DB",
                f"CVE-2017-12636 RCE: malicious query server via _design docs",
                "Mitigation: Upgrade to CouchDB 2.1.1+ or 1.7.2+",
            ])

    @staticmethod
    def _parse_version(version_str):
        """Parse a version string like '2.1.0' into a comparable tuple of ints."""
        parts = []
        for chunk in version_str.strip().split("."):
            digits = ""
            for ch in chunk:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            if not digits:
                return None
            parts.append(int(digits))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)