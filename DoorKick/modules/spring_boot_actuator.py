#!/usr/bin/env python3
"""
Spring Boot Actuator Exposure Checker
Tests for unauthenticated access to Spring Boot Actuator endpoints.
"""
import sys
import os
import json
import urllib.request
import urllib.error
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class SpringBootActuatorModule(BaseModule):
    """Spring Boot Actuator Exposure Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Spring Boot Actuator"
        self.port = 8080

    def run(self):
        """Check for exposed Spring Boot Actuator endpoints without auth."""
        module_name = "Spring Boot Actuator"
        target = self.get_target()

        print(f"\n[*] Testing {target} for Spring Boot Actuator...")

        ports = [8080, 8081, 8443, 9090, 8000, 8888, 80]
        for port in ports:
            if not self.check_port(port, timeout=2):
                continue
            self.check_spring_boot(target, port, module_name)

    def check_spring_boot(self, target, port, module_name):
        """Detect Spring Boot and validate actuator endpoint exposure."""
        base = f"http://{target}:{port}"

        # Step 1: Identify if this is a Spring Boot application
        if not self._is_spring_boot(base, module_name):
            return

        # Step 2: Probe actuator endpoints
        actuator_base = self._find_actuator_base(base, module_name)
        if not actuator_base:
            self.log(module_name, "SUSPECTED",
                     "Spring Boot detected but actuator base path not found")
            return

        self._check_actuator_endpoints(actuator_base, module_name)

    def _is_spring_boot(self, base, module_name):
        """Check if the service is a Spring Boot application."""
        indicators = ["/actuator", "/"]

        for path in indicators:
            try:
                req = urllib.request.Request(f"{base}{path}", method="GET")
                resp = urllib.request.urlopen(req, timeout=4)
                content = resp.read().decode("utf-8", errors="ignore").lower()
                headers = dict(resp.headers)

                # Check response content and headers for Spring Boot indicators
                spring_indicators = [
                    "whitelabel error page",
                    "spring boot",
                    "actuator",
                    "springframework",
                ]

                for indicator in spring_indicators:
                    if indicator in content:
                        self.log(module_name, "POTENTIAL",
                                 f"Spring Boot detected at {base} (indicator: {indicator})")
                        return True

                # Check X-Application-Context header (common in Spring Boot)
                app_ctx = headers.get("X-Application-Context", "")
                if app_ctx:
                    self.log(module_name, "POTENTIAL",
                             f"Spring Boot detected (X-Application-Context: {app_ctx})")
                    return True

            except urllib.error.HTTPError as e:
                # 401/403 on /actuator still means actuator exists
                if e.code in [401, 403] and path == "/actuator":
                    self.log(module_name, "POTENTIAL",
                             f"Spring Boot Actuator at {base}/actuator (auth required)")
                    self.report_validation(
                        module_name,
                        "Actuator unauthenticated access",
                        False,
                        f"/actuator blocked with HTTP {e.code}",
                    )
                    return True
            except Exception:
                continue

        return False

    def _find_actuator_base(self, base, module_name):
        """Find the actuator base path (can be customized via management.endpoints.web.base-path)."""
        common_paths = [
            "/actuator",
            "/management",
            "/manage",
            "/admin",
            "/internal",
        ]

        for path in common_paths:
            try:
                url = f"{base}{path}"
                req = urllib.request.Request(url, method="GET")
                req.add_header("Accept", "application/json")
                resp = urllib.request.urlopen(req, timeout=4)
                body = resp.read().decode("utf-8", errors="ignore")

                # Actuator index typically returns a JSON map of endpoint links
                try:
                    data = json.loads(body)
                    if isinstance(data, dict) and ("_links" in data or "endpoints" in data):
                        self.log(module_name, "INFO",
                                 f"Actuator base found at: {url}")
                        return url
                except json.JSONDecodeError:
                    pass

                # Some versions return HTML or HAL+JSON
                if "actuator" in body.lower() or "health" in body.lower():
                    self.log(module_name, "INFO",
                             f"Possible actuator base at: {url}")
                    return url

            except urllib.error.HTTPError as e:
                # 401/403 means the path exists but requires auth
                if e.code in [401, 403]:
                    self.log(module_name, "SUSPECTED",
                             f"Path {path} exists but requires auth")
                    # Still try it - some endpoints under it might be open
                    return f"{base}{path}"
            except Exception:
                continue

        return None

    def _check_actuator_endpoints(self, actuator_base, module_name):
        """Check individual actuator endpoints for unauthenticated access."""
        # Ordered by severity
        endpoints = [
            ("/env", "environment variables (may contain passwords, DB creds, API keys)",
             "RCE_POSSIBLE"),
            ("/heapdump", "JVM heap dump (contains all application state, credentials in memory)",
             "RCE_POSSIBLE"),
            ("/configprops", "configuration properties (passwords, secrets)",
             "RCE_POSSIBLE"),
            ("/mappings", "all URL endpoint mappings (for attack surface mapping)",
             "INFO"),
            ("/beans", "all Spring beans (reveals internal architecture)",
             "INFO"),
            ("/metrics", "application metrics (performance data, custom business metrics)",
             "INFO"),
            ("/trace", "recent HTTP request traces (may contain auth tokens, cookies)",
             "RCE_POSSIBLE"),
            ("/logfile", "application log file (may contain credentials, errors, stack traces)",
             "INFO"),
            ("/health", "health check (reveals component status, DB connections, service URLs)",
             "INFO"),
            ("/info", "application info (build version, git info)",
             "INFO"),
        ]

        # First get the actuator index to find available endpoints
        available_endpoints = self._get_actuator_index(actuator_base, module_name)

        for path, description, severity in endpoints:
            url = f"{actuator_base}{path}"

            # Skip if we know it's not exposed from the index
            if available_endpoints is not None:
                endpoint_name = path.lstrip("/")
                if endpoint_name not in available_endpoints:
                    continue

            self._probe_endpoint(url, path, description, severity, module_name)

    def _get_actuator_index(self, actuator_base, module_name):
        """Fetch the actuator index to discover available endpoints."""
        try:
            req = urllib.request.Request(actuator_base, method="GET")
            req.add_header("Accept", "application/json")
            resp = urllib.request.urlopen(req, timeout=4)
            body = resp.read().decode("utf-8", errors="ignore")

            data = json.loads(body)
            endpoints = set()

            # Spring Boot 2.x format: {"_links": {"env": {"href": "..."}, ...}}
            if "_links" in data:
                for key in data["_links"]:
                    endpoints.add(key)

            # Spring Boot 3.x / custom format: {"endpoints": {"env": {...}, ...}}
            elif "endpoints" in data:
                for key in data["endpoints"]:
                    endpoints.add(key)

            if endpoints:
                self.log(module_name, "INFO",
                         f"Discovered {len(endpoints)} actuator endpoints: "
                         f"{', '.join(sorted(endpoints))}")

            return endpoints

        except Exception:
            # If we can't get the index, try all endpoints anyway
            return None

    def _probe_endpoint(self, url, path, description, severity, module_name):
        """Probe a single actuator endpoint."""
        try:
            req = urllib.request.Request(url, method="GET")
            resp = urllib.request.urlopen(req, timeout=4)

            if resp.getcode() == 200:
                content_type = resp.headers.get("Content-Type", "")

                # heapdump returns binary
                if "heapdump" in path and "application/octet-stream" in content_type:
                    self.report_validation(
                        module_name,
                        f"Unauthenticated /heapdump",
                        True,
                        f"JVM heap dump downloadable ({len(resp.read())} bytes)",
                    )
                    self.log(module_name, "RCE_POSSIBLE",
                             "Heap dump contains credentials, session tokens, "
                             "and application secrets from memory - "
                             "parse with Eclipse MAT or jhat")
                    return

                body = resp.read().decode("utf-8", errors="ignore")

                self.report_validation(
                    module_name,
                    f"Unauthenticated {path}",
                    True,
                    f"exposes {description}",
                )

                if severity == "RCE_POSSIBLE":
                    self.log(module_name, "RCE_POSSIBLE",
                             f"/{path} exposure may contain credentials or secrets")

                # For /env, try to extract some key names (not values)
                if path == "/env" and len(body) > 100:
                    try:
                        env_data = json.loads(body)
                        if isinstance(env_data, dict):
                            # Look for property sources
                            prop_sources = list(env_data.get("propertySources", []))
                            source_names = []
                            for ps in prop_sources[:5]:
                                name = ps.get("name", "")
                                if name:
                                    source_names.append(name.split("/")[-1])
                            if source_names:
                                self.log(module_name, "INFO",
                                         f"Env property sources: {', '.join(source_names)}")
                    except Exception:
                        pass

                return

        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.report_validation(
                    module_name,
                    f"Unauthenticated {path}",
                    False,
                    f"blocked with HTTP {e.code}",
                )
        except Exception as e:
            self.log(module_name, "ERROR",
                     f"Actuator {path} check failed: {str(e)[:80]}")