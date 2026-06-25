#!/usr/bin/env python3
"""
Network Service Exposure Checker
Checks for commonly exposed services that provide initial access vectors.
Replaces the unreliable GRE/VXLAN module with practical service checks.
"""
import sys
import os
import socket
import json
import urllib.request
import urllib.error
import ssl
import subprocess
import shutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class NetworkExposureModule(BaseModule):
    """Network Service Exposure Checker - replaces GRE/VXLAN module."""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Network Exposure"
        self.port = None

    def run(self):
        """Check for commonly exposed network services."""
        module_name = "Network Exposure"
        target = self.get_target()

        print(f"\n[*] Testing {target} for exposed network services...")

        # RabbitMQ Management
        self._check_rabbitmq(target, module_name)

        # Kibana
        self._check_kibana(target, module_name)

        # Grafana
        self._check_grafana(target, module_name)

        # PHPMyAdmin
        self._check_phpmyadmin(target, module_name)

        # VNC
        self._check_vnc(target, module_name)

        # SMB Signing
        self._check_smb_signing(target, module_name)

    def _check_rabbitmq(self, target, module_name):
        """Check for RabbitMQ Management Console with default credentials."""
        port = 15672
        if not self.check_port(port, timeout=2):
            return

        base = f"http://{target}:{port}"
        try:
            req = urllib.request.Request(f"{base}/api/overview", method="GET")
            resp = urllib.request.urlopen(req, timeout=4)

            if resp.getcode() == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if "rabbitmq_version" in data:
                    version = data.get("rabbitmq_version", "unknown")
                    self.log(module_name, "POTENTIAL",
                             f"RabbitMQ Management API accessible (version: {version})")

                    # Try default guest:guest
                    try:
                        from base64 import b64encode
                        token = b64encode(b"guest:guest").decode()
                        auth_req = urllib.request.Request(
                            f"{base}/api/whoami",
                            method="GET",
                            headers={"Authorization": f"Basic {token}"})
                        auth_resp = urllib.request.urlopen(auth_req, timeout=4)

                        if auth_resp.getcode() == 200:
                            user_data = json.loads(
                                auth_resp.read().decode("utf-8", errors="ignore"))
                            user_name = user_data.get("name", "guest")
                            user_tags = user_data.get("tags", "")
                            self.report_validation(
                                module_name,
                                "RabbitMQ default credentials",
                                True,
                                f"guest:guest authenticated (user: {user_name}, tags: {user_tags})",
                            )
                            self.log(module_name, "RCE_POSSIBLE",
                                     "RabbitMQ admin access enables queue manipulation, "
                                     "message injection, and virtual host control")

                    except urllib.error.HTTPError as e:
                        if e.code in [401, 403]:
                            self.report_validation(
                                module_name,
                                "RabbitMQ default credentials",
                                False,
                                f"guest:guest rejected (HTTP {e.code})",
                            )

        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.log(module_name, "PROTECTED", "RabbitMQ Management requires authentication")
        except Exception as e:
            self.log(module_name, "ERROR", f"RabbitMQ check failed: {str(e)}")

    def _check_kibana(self, target, module_name):
        """Check for Kibana dashboard exposure."""
        for port in [5601, 5602]:
            if not self.check_port(port, timeout=2):
                continue

            base = f"http://{target}:{port}"
            try:
                req = urllib.request.Request(f"{base}/api/status", method="GET")
                resp = urllib.request.urlopen(req, timeout=4)

                if resp.getcode() == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    version = data.get("version", {}).get("number", "unknown")
                    self.log(module_name, "POTENTIAL",
                             f"Kibana accessible at {base} (version: {version})")

                    # Check if we can access data
                    try:
                        dash_req = urllib.request.Request(
                            f"{base}/api/saved_objects/_find?type=dashboard",
                            method="GET")
                        dash_resp = urllib.request.urlopen(dash_req, timeout=4)
                        if dash_resp.getcode() == 200:
                            self.report_validation(
                                module_name,
                                "Kibana unauthenticated access",
                                True,
                                "dashboard and saved object listing accessible",
                            )
                            self.log(module_name, "INFO",
                                     "Kibana access reveals index patterns, dashboards, "
                                     "and potentially allows data export")
                    except urllib.error.HTTPError as e:
                        if e.code in [401, 403]:
                            self.report_validation(
                                module_name,
                                "Kibana unauthenticated access",
                                False,
                                f"saved objects blocked (HTTP {e.code})",
                            )

            except urllib.error.HTTPError as e:
                if e.code in [401, 403]:
                    self.log(module_name, "PROTECTED",
                             f"Kibana on {port} requires authentication")
            except Exception as e:
                self.log(module_name, "ERROR",
                         f"Kibana check on port {port} failed: {str(e)[:80]}")

    def _check_grafana(self, target, module_name):
        """Check for Grafana dashboard with default credentials."""
        port = 3000
        if not self.check_port(port, timeout=2):
            return

        base = f"http://{target}:{port}"
        try:
            req = urllib.request.Request(f"{base}/api/health", method="GET")
            resp = urllib.request.urlopen(req, timeout=4)

            if resp.getcode() == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if data.get("commit") or data.get("database"):
                    self.log(module_name, "POTENTIAL",
                             f"Grafana accessible at {base}")

                    # Try default admin:admin
                    from base64 import b64encode
                    token = b64encode(b"admin:admin").decode()
                    try:
                        auth_req = urllib.request.Request(
                            f"{base}/api/org",
                            method="GET",
                            headers={"Authorization": f"Basic {token}"})
                        auth_resp = urllib.request.urlopen(auth_req, timeout=4)

                        if auth_resp.getcode() == 200:
                            org_data = json.loads(
                                auth_resp.read().decode("utf-8", errors="ignore"))
                            org_name = org_data.get("name", "unknown")
                            self.report_validation(
                                module_name,
                                "Grafana default credentials",
                                True,
                                f"admin:admin authenticated (org: {org_name})",
                            )
                            self.log(module_name, "RCE_POSSIBLE",
                                     "Grafana admin access enables dashboard creation, "
                                     "data source query (SQL), and plugin upload")
                    except urllib.error.HTTPError as e:
                        if e.code in [401, 403]:
                            self.report_validation(
                                module_name,
                                "Grafana default credentials",
                                False,
                                "admin:admin rejected",
                            )

        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.log(module_name, "PROTECTED",
                         "Grafana requires authentication")
        except Exception as e:
            self.log(module_name, "ERROR", f"Grafana check failed: {str(e)}")

    def _check_phpmyadmin(self, target, module_name):
        """Check for PHPMyAdmin exposure with default credentials."""
        ports = [8081, 8888, 80, 443, 8080]
        paths = ["/phpmyadmin/", "/pma/", "/phpMyAdmin/", "/db/", "/mysql/"]

        for port in ports:
            if not self.check_port(port, timeout=2):
                continue

            protocol = "https" if port == 443 else "http"
            base = f"{protocol}://{target}:{port}"
            context = None
            if protocol == "https":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            for path in paths:
                url = f"{base}{path}"
                try:
                    req = urllib.request.Request(url, method="GET")
                    resp = urllib.request.urlopen(req, timeout=4, context=context)
                    content = resp.read().decode("utf-8", errors="ignore").lower()

                    if "phpmyadmin" in content or "pma" in content:
                        self.log(module_name, "POTENTIAL",
                                 f"PHPMyAdmin detected at {url}")

                        # Test default credentials via the login form
                        # PHPMyAdmin uses session-based auth; we test the
                        # token-protected login endpoint
                        try:
                            # Get the login page for a CSRF token
                            get_resp = urllib.request.urlopen(
                                urllib.request.Request(url, method="GET"),
                                timeout=4, context=context)
                            page = get_resp.read().decode("utf-8", errors="ignore")

                            # Extract the token
                            import re
                            token_match = re.search(
                                r'name="token"\s+value="([^"]+)"', page)
                            if token_match:
                                token = token_match.group(1)
                                credentials = [
                                    ("root", ""),
                                    ("root", "root"),
                                    ("root", "password"),
                                    ("admin", "admin"),
                                    ("phpmyadmin", "phpmyadmin"),
                                ]

                                for user, pwd in credentials:
                                    display_pw = "(blank)" if pwd == "" else pwd
                                    post_data = urllib.parse.urlencode({
                                        "pma_username": user,
                                        "pma_password": pwd,
                                        "token": token,
                                    }).encode("utf-8")

                                    post_req = urllib.request.Request(
                                        url, data=post_data, method="POST")
                                    post_resp = urllib.request.urlopen(
                                        post_req, timeout=4, context=context)
                                    post_content = post_resp.read().decode(
                                        "utf-8", errors="ignore").lower()

                                    # If we don't see "login" or "password" fields,
                                    # login may have succeeded
                                    if ("login" not in post_content[:2000]
                                            and "password" not in post_content[:2000]
                                            and "error" not in post_content[:2000]):
                                        self.report_validation(
                                            module_name,
                                            "PHPMyAdmin default credentials",
                                            True,
                                            f"{user}/{display_pw} authenticated",
                                        )
                                        self.log(module_name, "RCE_POSSIBLE",
                                                 "PHPMyAdmin access enables SQL execution, "
                                                 "file read/write, and database manipulation")
                                        return

                                self.report_validation(
                                    module_name,
                                    "PHPMyAdmin default credentials",
                                    False,
                                    "tested default credentials were rejected",
                                )
                        except Exception as e:
                            self.log(module_name, "ERROR",
                                     f"PHPMyAdmin cred test failed: {str(e)[:80]}")
                        return

                except urllib.error.HTTPError:
                    continue
                except Exception:
                    continue

    def _check_vnc(self, target, module_name):
        """Check for VNC servers without authentication."""
        for port in [5900, 5901, 5902, 5903]:
            if not self.check_port(port, timeout=2):
                continue

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))

                # RFB protocol version handshake
                data = sock.recv(12)
                if not data or len(data) < 12:
                    sock.close()
                    continue

                decoded = data.decode("utf-8", errors="ignore")
                if not decoded.startswith("RFB "):
                    sock.close()
                    continue

                version = decoded.strip()
                self.log(module_name, "INFO",
                         f"VNC detected on port {port}: {version}")

                # Send our version
                sock.sendall(b"RFB 003.008\n")

                # Read security type(s)
                security_data = sock.recv(4)
                if not security_data or len(security_data) < 4:
                    sock.close()
                    continue

                num_types = security_data[3]
                if num_types == 0:
                    # Connection failed
                    sock.close()
                    continue

                if num_types > 1:
                    # Read the type list
                    type_list = sock.recv(num_types)
                    # Always choose the first type
                    if type_list:
                        security_type = type_list[0]
                    else:
                        sock.close()
                        continue
                else:
                    security_type = security_data[3]

                # Security type 1 = None (no authentication!)
                if security_type == 1:
                    self.report_validation(
                        module_name,
                        f"VNC no-auth (port {port})",
                        True,
                        "VNC server has NO authentication",
                    )
                    self.log(module_name, "RCE_POSSIBLE",
                             "Unauthenticated VNC provides full desktop access")
                elif security_type == 2:
                    self.log(module_name, "INFO",
                             f"VNC on port {port} uses VNC authentication")
                elif security_type == 19:
                    self.log(module_name, "INFO",
                             f"VNC on port {port} uses TLS authentication")
                else:
                    self.log(module_name, "INFO",
                             f"VNC on port {port} uses security type {security_type}")

                sock.close()

            except Exception as e:
                self.log(module_name, "ERROR",
                         f"VNC check on port {port} failed: {str(e)[:80]}")

    def _check_smb_signing(self, target, module_name):
        """Check if SMB signing is enforced (prerequisite for NTLM relay)."""
        port = 445
        if not self.check_port(port, timeout=2):
            return

        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            self.log(module_name, "INFO",
                     "impacket not available for SMB signing check")
            return

        try:
            smb = SMBConnection(target, target, smbport=port, timeout=5)
            smb.login("", "")

            if smb.isSigningRequired():
                self.report_validation(
                    module_name,
                    "SMB signing enforcement",
                    True,
                    "SMB signing is REQUIRED - NTLM relay attacks are prevented",
                )
            else:
                self.report_validation(
                    module_name,
                    "SMB signing enforcement",
                    False,
                    "SMB signing is NOT required - NTLM relay attacks are possible",
                )
                self.log(module_name, "RCE_POSSIBLE",
                         "Unenforced SMB signing enables NTLM relay via tools "
                         "like impacket's ntlmrelayx, potentially granting domain admin")

            smb.logoff()

        except Exception as e:
            err = str(e).lower()
            if "access denied" in err or "logon failure" in err:
                # Even if null session fails, we can sometimes still check
                # signing status from the negotiate response
                self.log(module_name, "SUSPECTED",
                         "Null session failed; SMB signing status unknown")
            else:
                self.log(module_name, "ERROR",
                         f"SMB signing check failed: {str(e)[:80]}")


# Need urllib.parse for PHPMyAdmin
import urllib.parse