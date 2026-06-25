#!/usr/bin/env python3
import sys
import os
import json
import urllib.request
import urllib.error

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class ElasticsearchRCEModule(BaseModule):

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Elasticsearch RCE"
        self.port = 9200

    def run(self):
        """Validate unauthenticated Elasticsearch access and script execution risk."""
        module_name = "Elasticsearch RCE"
        target = self.get_target()

        print(f"\n[*] Testing {target} for Elasticsearch...")

        ports = [9200, 9300]
        for port in ports:
            if not self.check_port(port, timeout=2):
                continue
            self.validate_elasticsearch(target, port, module_name)

    def validate_elasticsearch(self, target, port, module_name):
        """Run active validation steps against Elasticsearch endpoints."""
        base = f"http://{target}:{port}"

        root_status, root_body = self.http_json(f"{base}/")
        if root_status != 200 or not isinstance(root_body, dict):
            return

        if "cluster_name" not in root_body and "version" not in root_body:
            return

        self.log(module_name, "POTENTIAL", f"Elasticsearch endpoint identified at {base}")

        version = ""
        if isinstance(root_body.get("version"), dict):
            version = root_body.get("version", {}).get("number", "")
        if version:
            self.log(module_name, "INFO", f"Elasticsearch version: {version}")

        health_status, health_body = self.http_json(f"{base}/_cluster/health")
        if health_status == 200 and isinstance(health_body, dict) and "cluster_name" in health_body:
            self.report_validation(module_name, "Unauthenticated cluster health read", True, "_cluster/health returned cluster metadata")
        elif health_status in [401, 403]:
            self.report_validation(module_name, "Unauthenticated cluster health read", False, f"blocked with HTTP {health_status}")
            return
        else:
            self.log(module_name, "SUSPECTED", "Elasticsearch detected but health endpoint validation was inconclusive")

        self.validate_script_capability(base, module_name, version)

    def validate_script_capability(self, base, module_name, version):
        """validate dynamic script execution using arithmetic."""
        payload = {
            "size": 1,
            "query": {"match_all": {}},
            "script_fields": {
                "doorkick_validation": {
                    "script": {
                        "lang": "painless",
                        "source": "1+1"
                    }
                }
            }
        }

        status, body = self.http_json(f"{base}/_search", method="POST", data=payload)
        if status == 200 and isinstance(body, dict):
            hits = body.get("hits", {}).get("hits", [])
            if hits:
                fields = hits[0].get("fields", {})
                values = fields.get("doorkick_validation", [])
                if values and values[0] == 2:
                    self.report_validation(module_name, "Unauthenticated script execution", True, "script_fields arithmetic executed successfully")
                    self.log(module_name, "RCE_POSSIBLE", "Dynamic script execution is enabled for unauthenticated requests")
                    return

            self.log(module_name, "SUSPECTED", "_search succeeded but script execution marker was not returned")
            return

        if status in [400, 404]:
            if version.startswith("1.3.") or version.startswith("1.4."):
                self.log(module_name, "SUSPECTED", "Version is in known vulnerable range but script validation was blocked/inconclusive")
            else:
                self.report_validation(module_name, "Unauthenticated script execution", False, "script execution path not available")
            return

        if status in [401, 403]:
            self.report_validation(module_name, "Unauthenticated script execution", False, f"blocked with HTTP {status}")
            return

        self.log(module_name, "SUSPECTED", "Unable to confirm script execution state")

    def http_json(self, url, method="GET", data=None):
        """Send HTTP request and parse JSON."""
        try:
            payload = None
            headers = {"Accept": "application/json"}
            if data is not None:
                payload = json.dumps(data).encode("utf-8")
                headers["Content-Type"] = "application/json"

            req = urllib.request.Request(url, data=payload, method=method, headers=headers)
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read().decode("utf-8", errors="ignore")
            try:
                return resp.getcode(), json.loads(body)
            except json.JSONDecodeError:
                return resp.getcode(), None
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
                return e.code, json.loads(body)
            except Exception:
                return e.code, None
        except Exception:
            return None, None