#!/usr/bin/env python3
import sys
import os
import ssl
import json
import urllib.request
import urllib.error

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class KubernetesAPIModule(BaseModule):
    """Kubernetes API Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Kubernetes API"
        self.port = 6443

    def run(self):
        """Validate whether Kubernetes API allows unauthenticated data access."""
        module_name = "Kubernetes API"
        target = self.get_target()

        print(f"\n[*] Testing {target} for Kubernetes API...")

        endpoints = [
            (6443, True),
            (443, True),
            (8443, True),
            (8080, False),
            (10255, False),
        ]

        for port, https in endpoints:
            if not self.check_port(port, timeout=2):
                continue
            self.check_k8s_api_endpoint(target, port, https, module_name)

    def check_k8s_api_endpoint(self, target, port, https, module_name):
        """Probe and validate Kubernetes API exposure."""
        protocol = "https" if https else "http"
        base = f"{protocol}://{target}:{port}"

        context = None
        if https:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.log(module_name, "INFO", f"Using insecure TLS validation for probe on {base}")

        version_data = self.fetch_json(f"{base}/version", context)
        if not version_data:
            return

        if "gitVersion" not in version_data and "major" not in version_data:
            return

        self.log(module_name, "POTENTIAL", f"Kubernetes API identified at {base}")
        if version_data.get("gitVersion"):
            self.log(module_name, "INFO", f"Kubernetes version: {version_data.get('gitVersion')}")

        namespace_result = self.fetch_json(f"{base}/api/v1/namespaces", context, include_status=True)
        if namespace_result[0] == 200 and isinstance(namespace_result[1], dict):
            count = len(namespace_result[1].get("items", []))
            self.report_validation(module_name, "Unauthenticated namespace listing", True, f"read {count} namespaces")
            self.log(module_name, "RCE_POSSIBLE", "Cluster metadata exposed without authentication")

            pods_result = self.fetch_json(f"{base}/api/v1/pods", context, include_status=True)
            if pods_result[0] == 200 and isinstance(pods_result[1], dict):
                pod_count = len(pods_result[1].get("items", []))
                self.report_validation(module_name, "Unauthenticated pod listing", True, f"read {pod_count} pods")
            return

        if namespace_result[0] in [401, 403]:
            self.report_validation(module_name, "Unauthenticated namespace listing", False, f"blocked with HTTP {namespace_result[0]}")
            return

        self.log(module_name, "SUSPECTED", f"Kubernetes API discovered at {base}, but auth validation was inconclusive")

    def fetch_json(self, url, context=None, include_status=False):
        """Fetch JSON from URL and optionally include status code."""
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("Accept", "application/json")
            resp = urllib.request.urlopen(req, timeout=4, context=context)
            body = resp.read().decode("utf-8", errors="ignore")
            parsed = json.loads(body)
            if include_status:
                return resp.getcode(), parsed
            return parsed
        except urllib.error.HTTPError as e:
            if include_status:
                return e.code, None
            return None
        except Exception:
            if include_status:
                return None, None
            return None