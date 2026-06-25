#!/usr/bin/env python3
"""
Hadoop YARN RCE Checker
Tests for unauthenticated YARN ResourceManager REST API access,
validates application enumeration and submission capability.
"""
import sys
import os
import json
import urllib.request
import urllib.error

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class HadoopYARNModule(BaseModule):

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Hadoop YARN RCE"
        self.port = 8088

    def run(self):
        """Check for Hadoop YARN ResourceManager unauthenticated access."""
        module_name = "Hadoop YARN RCE"
        target = self.get_target()

        print(f"\n[*] Testing {target} for Hadoop YARN...")

        # YARN ResourceManager (8088), NodeManager HTTP (8042)
        ports = [8088, 8042]

        for port in ports:
            if not self.check_port(port, timeout=2):
                continue

            if port == 8088:
                self.check_yarn_resourcemanager(target, module_name)
            elif port == 8042:
                self.check_yarn_nodemanager(target, module_name)

    def check_yarn_resourcemanager(self, target, module_name):
        """Check YARN ResourceManager REST API for unauthenticated access."""
        base = f"http://{target}:8088/ws/v1/cluster"

        # 1. Verify it's actually YARN
        info_url = f"{base}/info"
        try:
            req = urllib.request.Request(info_url, method="GET")
            req.add_header("Accept", "application/json")
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode("utf-8", errors="ignore"))

            if "clusterInfo" not in data:
                self.log(module_name, "ERROR",
                         f"Response from {info_url} does not contain clusterInfo")
                return

            cluster = data["clusterInfo"]
            rm_version = cluster.get("rmVersion", "unknown")
            hadoop_version = cluster.get("hadoopVersion", "unknown")
            self.log(module_name, "POTENTIAL",
                     f"YARN ResourceManager accessible (RM: {rm_version}, Hadoop: {hadoop_version})")

        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.report_validation(module_name,
                                       "YARN ResourceManager unauthenticated access",
                                       False, f"blocked with HTTP {e.code}")
                return
            self.log(module_name, "ERROR",
                     f"YARN cluster info request failed: HTTP {e.code}")
            return
        except Exception as e:
            self.log(module_name, "ERROR",
                     f"YARN ResourceManager check failed: {str(e)}")
            return

        # 2. Enumerate running applications (proves unauthenticated read access)
        apps_url = f"{base}/apps?states=RUNNING"
        try:
            req = urllib.request.Request(apps_url, method="GET")
            req.add_header("Accept", "application/json")
            response = urllib.request.urlopen(req, timeout=5)
            apps_data = json.loads(response.read().decode("utf-8", errors="ignore"))

            app_list = apps_data.get("apps", {}).get("app", [])
            app_count = len(app_list) if isinstance(app_list, list) else 0

            self.report_validation(
                module_name,
                "YARN application enumeration",
                True,
                f"unauthenticated access to running app list ({app_count} apps)",
            )

            if app_count > 0:
                for app in app_list[:5]:
                    app_name = app.get("name", "unknown")
                    app_user = app.get("user", "unknown")
                    app_state = app.get("state", "unknown")
                    self.log(module_name, "INFO",
                             f"  App: {app_name} (user: {app_user}, state: {app_state})")

        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.report_validation(module_name,
                                       "YARN application enumeration",
                                       False, f"blocked with HTTP {e.code}")
                return
            self.log(module_name, "SUSPECTED",
                     f"Application enumeration failed: HTTP {e.code}")

        # 3. Test New Application API
        #    YARN accepts new application creation via the REST API.
        #    A successful response returns an application-id that can then
        #    be used for submission. This proves the write/RCE path exists.
        self.test_new_application_api(target, base, module_name)

    def test_new_application_api(self, target, base, module_name):
        """Test if the New Application API is accessible without auth.

        POST /ws/v1/cluster/apps/new-app returns a new application ID.
        This is step 1 of the YARN application submission process and
        proves that unauthenticated RCE is possible.
        """
        new_app_url = f"{base}/apps/new-app"

        try:
            req = urllib.request.Request(new_app_url, method="POST")
            req.add_header("Accept", "application/json")
            response = urllib.request.urlopen(req, timeout=5)

            if response.getcode() in (200, 202):
                body = json.loads(response.read().decode("utf-8", errors="ignore"))
                app_id = body.get("application-id", "unknown")

                self.report_validation(
                    module_name,
                    "YARN application submission (new-app)",
                    True,
                    f"new-app API returned application-id: {app_id}",
                )
                self.log(module_name, "RCE_POSSIBLE",
                         "Unauthenticated new-app access enables full RCE via malicious container launch")

                # Try to kill the test application to clean up
                if app_id != "unknown":
                    try:
                        kill_url = f"{base}/apps/{app_id}/state"
                        kill_data = json.dumps({"state": "KILLED"}).encode("utf-8")
                        kill_req = urllib.request.Request(
                            kill_url, data=kill_data, method="PUT")
                        kill_req.add_header("Content-Type", "application/json")
                        urllib.request.urlopen(kill_req, timeout=5)
                        self.log(module_name, "INFO",
                                 f"Cleaned up test application {app_id}")
                    except Exception:
                        self.log(module_name, "INFO",
                                 f"Could not clean up test app {app_id} (may need manual cleanup)")

                return

        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.report_validation(
                    module_name,
                    "YARN application submission (new-app)",
                    False,
                    f"blocked with HTTP {e.code}",
                )
                return
            self.log(module_name, "SUSPECTED",
                     f"new-app API returned HTTP {e.code}")

        except Exception as e:
            self.log(module_name, "ERROR",
                     f"new-app API test failed: {str(e)}")

    def check_yarn_nodemanager(self, target, module_name):
        """Check YARN NodeManager HTTP interface for info leakage."""
        try:
            url = f"http://{target}:8042/node"
            req = urllib.request.Request(url, method="GET")
            req.add_header("Accept", "application/json")
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode("utf-8", errors="ignore"))

            if "nodeInfo" in data:
                node = data["nodeInfo"]
                self.log(module_name, "POTENTIAL",
                         f"YARN NodeManager accessible (host: {node.get('HostName', 'unknown')}, "
                         f"containers: {node.get('usedContainers', '?')}/{node.get('totalContainers', '?')})")
                self.log(module_name, "INFO",
                         "NodeManager access enables container log and environment variable leakage")
            else:
                self.log(module_name, "SUSPECTED",
                         f"NodeManager responded on 8042 but nodeInfo not found")

        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.report_validation(module_name,
                                       "YARN NodeManager access",
                                       False, f"blocked with HTTP {e.code}")
            else:
                self.log(module_name, "ERROR",
                         f"NodeManager returned HTTP {e.code}")
        except Exception as e:
            self.log(module_name, "ERROR",
                     f"NodeManager check failed: {str(e)}")