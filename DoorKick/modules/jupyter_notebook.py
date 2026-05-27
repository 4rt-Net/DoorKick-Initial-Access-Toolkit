#!/usr/bin/env python3
"""
Jupyter Notebook Security Checker
"""
import sys
import os
import urllib.request
import urllib.error
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class JupyterNotebookModule(BaseModule):
    """Jupyter Notebook Security Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Jupyter Notebook"
        self.port = 8888

    def run(self):
        """Check for exposed Jupyter Notebook without auth"""
        module_name = "Jupyter Notebook"
        target = self.get_target()

        print(f"\n[*] Testing {target} for Jupyter Notebook...")

        ports = [8888, 8889, 8890, 8000, 8080]
        for port in ports:
            if not self.check_port(port, timeout=2):
                continue
            self.check_jupyter(target, port, module_name)

    def check_jupyter(self, target, port, module_name):
        """Check Jupyter endpoint and validate API access."""
        base = f"http://{target}:{port}"
        try:
            req = urllib.request.Request(f"{base}/", method="GET")
            response = urllib.request.urlopen(req, timeout=5)
            content = response.read().decode("utf-8", errors="ignore").lower()

            if "jupyter" not in content and "notebook" not in content and "jupyterlab" not in content:
                return

            self.log(module_name, "POTENTIAL", f"Jupyter UI detected at {base}/")

            if "login" in content or "password" in content or "token" in content:
                self.report_validation(module_name, "Jupyter web access", False, "login or token gate detected on UI")
            else:
                self.log(module_name, "SUSPECTED", "Jupyter UI appears reachable without immediate auth challenge")

            self.validate_api_access(base, module_name)

        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.report_validation(module_name, "Jupyter web access", False, f"HTTP {e.code} unauthorized")
        except Exception as e:
            self.log(module_name, "ERROR", f"Jupyter probe failed: {str(e)}")

    def validate_api_access(self, base, module_name):
        """Validate whether sensitive API endpoints are accessible without auth."""
        checks = [
            ("/api/contents", "contents listing"),
            ("/api/sessions", "session listing"),
            ("/api/kernels", "kernel listing"),
        ]

        for path, label in checks:
            url = f"{base}{path}"
            try:
                req = urllib.request.Request(url, method="GET")
                resp = urllib.request.urlopen(req, timeout=4)
                body = resp.read().decode("utf-8", errors="ignore")

                if resp.getcode() != 200:
                    continue

                parsed = json.loads(body)
                if isinstance(parsed, (list, dict)):
                    self.report_validation(module_name, f"Unauthenticated {label}", True, f"{path} returned structured JSON")
                    self.log(module_name, "RCE_POSSIBLE", "Unauthenticated API access can enable notebook abuse")
                    return

            except urllib.error.HTTPError as e:
                if e.code in [401, 403]:
                    self.report_validation(module_name, f"Unauthenticated {label}", False, f"blocked with HTTP {e.code}")
                continue
            except json.JSONDecodeError:
                self.log(module_name, "SUSPECTED", f"{path} returned 200 but non-JSON content")
            except Exception as e:
                self.log(module_name, "ERROR", f"Jupyter API check failed for {path}: {str(e)}")

        self.log(module_name, "SUSPECTED", "Jupyter detected but unauthenticated API validation was inconclusive")