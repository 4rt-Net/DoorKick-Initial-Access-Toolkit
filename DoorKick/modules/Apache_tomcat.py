#!/usr/bin/env python3
"""
Apache Tomcat Security Checker
"""
import sys
import os
import urllib.request
import urllib.error
import base64

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class TomcatModule(BaseModule):

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Apache Tomcat"
        self.port = 8080

    def run(self):
        """Check for Tomcat security issues with active credential validation."""
        module_name = "Apache Tomcat"
        target = self.get_target()

        print(f"\n[*] Testing {target} for Apache Tomcat...")

        ports = [8080, 8081, 8088, 8090, 8888, 8181, 8443]
        for port in ports:
            if not self.check_port(port, timeout=2):
                continue
            self.check_tomcat(target, port, module_name)

    def check_tomcat(self, target, port, module_name):
        """Identify Tomcat and validate manager auth behavior."""
        base = f"http://{target}:{port}"
        status, content = self.get_text(f"{base}/")
        if status != 200 or not content:
            return

        lowered = content.lower()
        if "tomcat" not in lowered and "apache tomcat" not in lowered:
            return

        self.log(module_name, "POTENTIAL", f"Tomcat identified at {base}/")

        manager_url = f"{base}/manager/text/serverinfo"
        manager_status, _ = self.get_text(manager_url)
        if manager_status in [401, 403]:
            self.report_validation(module_name, "Tomcat manager unauthenticated access", False, f"blocked with HTTP {manager_status}")
            self.test_tomcat_defaults(target, port, module_name)
            return

        if manager_status == 200:
            self.report_validation(module_name, "Tomcat manager unauthenticated access", True, "manager text endpoint reachable without credentials")
            self.log(module_name, "RCE_POSSIBLE", "Unauthenticated manager access may allow deployment abuse")
            return

        self.log(module_name, "SUSPECTED", "Tomcat detected but manager endpoint validation was inconclusive")

    def test_tomcat_defaults(self, target, port, module_name):
        """Validate default credentials against manager text API."""
        credentials = [
            ("admin", "admin"),
            ("tomcat", "tomcat"),
            ("manager", "manager"),
            ("role1", "tomcat"),
            ("admin", ""),
        ]

        url = f"http://{target}:{port}/manager/text/serverinfo"
        for username, password in credentials:
            status, body = self.get_text(url, username=username, password=password)
            if status != 200:
                continue

            if body and "Tomcat Version" in body:
                shown_password = password if password else "(blank)"
                self.report_validation(module_name, "Tomcat default credentials", True, f"{username}/{shown_password} authenticated to manager API")
                self.log(module_name, "RCE_POSSIBLE", "Valid manager credentials can enable WAR deployment")
                return

        self.report_validation(module_name, "Tomcat default credentials", False, "tested default credentials were rejected")

    def get_text(self, url, username=None, password=None):
        """HTTP GET helper returning status and decoded body."""
        try:
            headers = {}
            if username is not None and password is not None:
                token = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {token}"

            req = urllib.request.Request(url, method="GET", headers=headers)
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.getcode(), resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode("utf-8", errors="ignore")
            except Exception:
                return e.code, ""
        except Exception:
            return None, ""