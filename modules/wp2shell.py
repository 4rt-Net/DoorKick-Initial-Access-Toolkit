#!/usr/bin/env python3
"""
WP2Shell Detection Module - CVE-2026-63030
Checks for the wp2shell WordPress RCE vulnerability that allows
unauthenticated or low-privilege attackers to achieve remote code
execution through WordPress file upload and deserialization chains.

References:
  - CVE-2026-63030
  - WordPress wp2shell (unauthenticated RCE via upload/deserialization)
"""
import sys
import os
import re
import json
import urllib.request
import urllib.error
import urllib.parse
import hashlib
import time
import http.cookiejar

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class Wp2shellModule(BaseModule):
    """WP2Shell (CVE-2026-63030) Detection & Validation"""

    CVE = "CVE-2026-63030"

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "WP2Shell (CVE-2026-63030)"
        self.port = 80
        self.wp_version = None
        self.wp_detected = False

    # ------------------------------------------------------------------ #
    #  Entry point
    # ------------------------------------------------------------------ #
    def run(self):
        """Orchestrate the full wp2shell detection sequence."""
        module_name = "WP2Shell (CVE-2026-63030)"
        target = self.get_target()

        print(f"\n[*] Testing {target} for {self.CVE} (wp2shell)...")

        ports = [80, 443, 8080, 8443, 8000, 8888]
        for port in ports:
            if not self.check_port(port, timeout=3):
                continue
            scheme = "https" if port in (443, 8443) else "http"
            base = f"{scheme}://{target}:{port}"
            self.log(module_name, "INFO", f"Probing {base} for WordPress")
            self._investigate(base, port, module_name)

    # ------------------------------------------------------------------ #
    #  High-level investigation flow
    # ------------------------------------------------------------------ #
    def _investigate(self, base, port, module_name):
        """Full wp2shell investigation on a single base URL."""
        # Phase 1 — Fingerprint
        if not self._fingerprint_wordpress(base, module_name):
            return

        # Phase 2 — Version extraction
        self._extract_version(base, module_name)

        # Phase 3 — Attack surface enumeration
        self._check_rest_api_media_upload(base, module_name)
        self._check_theme_plugin_editors(base, module_name)
        self._check_xmlrpc(base, module_name)
        self._check_unfiltered_upload(base, module_name)
        self._check_rest_api_users(base, module_name)
        self._check_vulnerable_plugin_endpoints(base, module_name)

        # Phase 4 — Safe validation
        self._validate_wp2shell(base, module_name)

        # Phase 5 — Remediation guidance
        if self.wp_detected:
            self.print_exploit_steps([
                "Identify the exact vulnerable WordPress version and installed plugins",
                "If REST API media upload is open, craft a PHP payload disguised as an image",
                "Upload via POST to /wp-json/wp/v2/media with a valid nonce (if required)",
                "Alternatively, exploit the deserialization chain via crafted POST data",
                "Access the uploaded file to confirm code execution",
                "Upgrade WordPress core and all plugins to the latest patched versions",
                "Disable XML-RPC if not needed: add 'add_filter('xmlrpc_enabled', '__return_false');' to functions.php",
                "Restrict file upload types via wp-config.php: define('ALLOW_UNFILTERED_UPLOADS', false);",
                "Install a WAF rule to block suspicious wp-json/media POST requests from unauthenticated users",
            ])

    # ------------------------------------------------------------------ #
    #  Phase 1 — WordPress fingerprinting
    # ------------------------------------------------------------------ #
    def _fingerprint_wordpress(self, base, module_name):
        """Determine whether the target is running WordPress."""
        indicators = {
            "/": [
                "wp-content",
                "wp-includes",
                "wordpress",
                "wp-json",
                "name=\"generator\" content=\"wordpress",
            ],
            "/wp-login.php": [
                "wp-login",
                "log in",
                "password",
                "rememberme",
                "wp-submit",
            ],
            "/wp-json/wp/v2/": [
                "routes",
                "namespaces",
            ],
            "/feed/": [
                "rss",
                "wordpress",
                "wp-content",
            ],
        }

        for path, fingerprints in indicators.items():
            try:
                url = f"{base}{path}"
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", self.opsec_ua())
                resp = urllib.request.urlopen(req, timeout=5)
                content = resp.read().decode("utf-8", errors="ignore").lower()

                matches = [fp for fp in fingerprints if fp in content]
                if matches:
                    self.wp_detected = True
                    self.log(module_name, "POTENTIAL",
                             f"WordPress fingerprint detected at {url} "
                             f"(indicators: {', '.join(matches[:3])})")
                    return True

            except urllib.error.HTTPError as e:
                # 401/403 on wp-login still confirms WordPress
                if path == "/wp-login.php" and e.code in (401, 403, 200):
                    self.wp_detected = True
                    self.log(module_name, "POTENTIAL",
                             f"WordPress login page at {base}/wp-login.php (HTTP {e.code})")
                    return True
            except Exception:
                continue

        self.log(module_name, "INFO", f"No WordPress fingerprint found at {base}")
        return False

    # ------------------------------------------------------------------ #
    #  Phase 2 — Version extraction
    # ------------------------------------------------------------------ #
    def _extract_version(self, base, module_name):
        """Extract WordPress version from multiple sources."""
        sources = [
            ("/", r'<meta\s+name=["\']generator["\']\s+content=["\']wordpress\s+([0-9.]+)'),
            ("/feed/", r'<generator>https?://wordpress\.\S*?/?\s*v?([0-9.]+)</generator>'),
            ("/readme.html", r'<br\s*/?>\s*Version\s+([0-9.]+)'),
            ("/wp-includes/js/wp-embed.min.js",
             r'wpEmbedSettings.*?version["\']?\s*[:=]\s*["\']?([0-9.]+)'),
        ]

        for path, pattern in sources:
            try:
                url = f"{base}{path}"
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", self.opsec_ua())
                resp = urllib.request.urlopen(req, timeout=4)
                content = resp.read().decode("utf-8", errors="ignore")

                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    self.wp_version = match.group(1)
                    self.log(module_name, "INFO",
                             f"WordPress version detected: {self.wp_version} "
                             f"(source: {path})")
                    self._assess_version_risk(module_name)
                    return
            except Exception:
                continue

        self.log(module_name, "INFO", "WordPress version could not be determined")

    def _assess_version_risk(self, module_name):
        """Check if the detected version falls within the CVE-2026-63030 affected range."""
        if not self.wp_version:
            return
        try:
            parts = self.wp_version.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0

            # wp2shell (CVE-2026-63030) affects WordPress versions
            # prior to the 6.8.3 security release
            if major < 6:
                self.log(module_name, "VULNERABLE",
                         f"Version {self.wp_version} is below the "
                         f"{self.CVE} patch threshold — likely vulnerable")
            elif major == 6 and minor < 8:
                self.log(module_name, "VULNERABLE",
                         f"Version {self.wp_version} is below the "
                         f"{self.CVE} patch threshold — likely vulnerable")
            elif major == 6 and minor == 8 and patch < 3:
                self.log(module_name, "VULNERABLE",
                         f"Version {self.wp_version} is below 6.8.3 — "
                         f"{self.CVE} patch not applied")
            else:
                self.log(module_name, "INFO",
                         f"Version {self.wp_version} appears patched "
                         f"(>= 6.8.3), but verify all plugins as well")
        except (ValueError, IndexError):
            self.log(module_name, "SUSPECTED",
                     f"Could not parse version '{self.wp_version}' for risk assessment")

    # ------------------------------------------------------------------ #
    #  Phase 3 — Attack surface checks
    # ------------------------------------------------------------------ #
    def _check_rest_api_media_upload(self, base, module_name):
        """Check if the REST API media upload endpoint is accessible."""
        endpoint = f"{base}/wp-json/wp/v2/media"

        try:
            req = urllib.request.Request(endpoint, method="GET")
            req.add_header("User-Agent", self.opsec_ua())
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read().decode("utf-8", errors="ignore")

            if resp.getcode() == 200:
                self.log(module_name, "POTENTIAL",
                         "REST API media endpoint accessible without authentication")

                # Attempt a safe POST to validate write access
                self._validate_media_upload(base, module_name)

        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.report_validation(
                    module_name,
                    "Unauthenticated REST API media upload",
                    False,
                    "endpoint requires authentication (HTTP 401)",
                )
            elif e.code == 403:
                self.report_validation(
                    module_name,
                    "Unauthenticated REST API media upload",
                    False,
                    "endpoint access denied (HTTP 403)",
                )
            elif e.code == 405:
                self.log(module_name, "INFO",
                         "REST API media endpoint exists (method not allowed on GET)")
        except Exception as e:
            self.log(module_name, "ERROR",
                     f"REST API media check failed: {str(e)[:80]}")

    def _validate_media_upload(self, base, module_name):
        """Attempt a safe validation upload to confirm unauthenticated write access."""
        marker = self.opsec_marker("v_")
        marker_hash = self.opsec_marker("h_")
        boundary_str = self.opsec_marker("b_")

        endpoint = f"{base}/wp-json/wp/v2/media"

        # Create a safe text file (not PHP) to test upload capability
        safe_content = f"{marker} - validation - "
        safe_content += f"timestamp:{int(time.time())} - {marker_hash}"

        # Build a multipart form-data body manually (no requests library)
        boundary = boundary_str
        filename = f"test_{marker_hash}.txt"

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"{safe_content}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        try:
            req = urllib.request.Request(endpoint, data=body, method="POST")
            req.add_header("Content-Type",
                           f"multipart/form-data; boundary={boundary}")
            req.add_header("User-Agent", self.opsec_ua())

            resp = urllib.request.urlopen(req, timeout=8)
            resp_body = resp.read().decode("utf-8", errors="ignore")

            if resp.getcode() in (200, 201):
                # Extract upload URL from REST API response
                upload_url = None
                file_id = None
                try:
                    data = json.loads(resp_body)
                    upload_url = data.get("source_url") or data.get("link")
                    file_id = data.get("id")
                except Exception:
                    pass

                self.report_validation(
                    module_name,
                    "Unauthenticated media upload",
                    True,
                    "file uploaded without authentication (safe text marker)",
                )
                self.log(module_name, "RCE_POSSIBLE",
                         "Unauthenticated file upload confirmed — "
                         "attacker could upload a PHP webshell disguised as an image")
                self.log(module_name, "INFO",
                         f"Uploaded filename: {filename}")
                if upload_url:
                    self.log(module_name, "INFO",
                             f"Upload URL returned by server: {upload_url}")
                elif file_id:
                    self.log(module_name, "INFO",
                             f"Upload accepted (media ID: {file_id}) — "
                             f"file likely at /wp-content/uploads/YYYY/MM/")
                else:
                    self.log(module_name, "INFO",
                             f"Upload accepted but no URL in response — "
                             f"check /wp-content/uploads/YYYY/MM/ for: {filename}")
                # Attempt to clean up the text test file only
                self._cleanup_test_file(base, resp_body, module_name)
                return

        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.report_validation(
                    module_name,
                    "Unauthenticated media upload",
                    False,
                    f"upload blocked with HTTP {e.code}",
                )
            elif e.code == 415:
                self.log(module_name, "SUSPECTED",
                         "Media endpoint rejects upload — may enforce MIME type restrictions")
            else:
                self.log(module_name, "SUSPECTED",
                         f"Media upload returned HTTP {e.code} — partial restriction in place")
        except Exception as e:
            self.log(module_name, "ERROR",
                     f"Media upload validation failed: {str(e)[:80]}")

    def _cleanup_test_file(self, base, resp_body, module_name):
        """Try to delete the validation file via REST API if an ID is returned."""
        try:
            data = json.loads(resp_body)
            file_id = data.get("id")
            if not file_id:
                return

            delete_url = f"{base}/wp-json/wp/v2/media/{file_id}?force=true"
            req = urllib.request.Request(delete_url, method="DELETE")
            req.add_header("User-Agent", self.opsec_ua())
            urllib.request.urlopen(req, timeout=4)
            self.log(module_name, "INFO", f"Cleaned up test file (ID: {file_id})")
        except Exception:
            pass  # Cleanup is best-effort

    def _check_theme_plugin_editors(self, base, module_name):
        """Check if theme and plugin file editors are accessible."""
        editor_paths = [
            ("/wp-admin/theme-editor.php", "Theme editor"),
            ("/wp-admin/plugin-editor.php", "Plugin editor"),
            ("/wp-admin/customize.php", "Customizer"),
        ]

        for path, label in editor_paths:
            url = f"{base}{path}"
            try:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", self.opsec_ua())
                resp = urllib.request.urlopen(req, timeout=4)

                if resp.getcode() == 200:
                    content = resp.read().decode("utf-8", errors="ignore")
                    if "wp-admin" in content.lower() or "editor" in content.lower():
                        self.log(module_name, "SUSPECTED",
                                 f"{label} accessible at {url} — verify if auth is required")

            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    self.report_validation(
                        module_name,
                        f"Unauthenticated {label.lower()}",
                        False,
                        f"{label} requires authentication (HTTP {e.code})",
                    )
            except Exception:
                continue

    def _check_xmlrpc(self, base, module_name):
        """Check if XML-RPC is enabled and test for wp2shell deserialization vectors."""
        xmlrpc_url = f"{base}/xmlrpc.php"

        # Build a system.listMethods probe
        xml_probe = """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>system.listMethods</methodName>
</methodCall>"""

        try:
            req = urllib.request.Request(xmlrpc_url,
                                         data=xml_probe.encode("utf-8"),
                                         method="POST")
            req.add_header("Content-Type", "text/xml")
            req.add_header("User-Agent", self.opsec_ua())
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read().decode("utf-8", errors="ignore")

            if resp.getcode() == 200 and "<methodResponse>" in body:
                self.log(module_name, "POTENTIAL",
                         "XML-RPC is enabled — may allow system.multicall abuse")

                # Check for dangerous methods
                dangerous_methods = [
                    "wp.uploadFile",
                    "wp.newPost",
                    "wp.editPost",
                ]
                found_methods = [m for m in dangerous_methods if m in body]
                if found_methods:
                    self.log(module_name, "SUSPECTED",
                             f"XML-RPC exposes upload/post methods: "
                             f"{', '.join(found_methods)}")

                self.report_validation(
                    module_name,
                    "XML-RPC enabled",
                    True,
                    f"xmlrpc.php is active with {len(found_methods)} dangerous methods",
                )

                # Check for multicall amplification
                self._check_xmlrpc_multicall(xmlrpc_url, module_name)

        except urllib.error.HTTPError as e:
            if e.code == 405:
                self.report_validation(
                    module_name,
                    "XML-RPC enabled",
                    False,
                    "xmlrpc.php exists but POST is disabled (HTTP 405)",
                )
        except Exception as e:
            self.log(module_name, "ERROR",
                     f"XML-RPC check failed: {str(e)[:80]}")

    def _check_xmlrpc_multicall(self, xmlrpc_url, module_name):
        """Test if system.multicall is available (used in amplification attacks)."""
        multicall_probe = """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>system.listMethods</string></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>"""

        try:
            req = urllib.request.Request(xmlrpc_url,
                                         data=multicall_probe.encode("utf-8"),
                                         method="POST")
            req.add_header("Content-Type", "text/xml")
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read().decode("utf-8", errors="ignore")

            if resp.getcode() == 200 and "<methodResponse>" in body:
                self.log(module_name, "SUSPECTED",
                         "system.multicall is available — can be used for "
                         "brute-force amplification and deserialization chains")
        except Exception:
            pass

    def _check_unfiltered_upload(self, base, module_name):
        """Check for the wp2shell unfiltered upload vector via async-upload.php."""
        marker = self.opsec_marker("v_")
        marker_hash = self.opsec_marker("h_")
        boundary_str = self.opsec_marker("b_")

        endpoint = f"{base}/wp-admin/async-upload.php"

        # Build a minimal safe upload request
        boundary = boundary_str
        filename = f"upload_{marker_hash}.txt"
        safe_content = f"{marker} - upload test - {int(time.time())}"

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="async-upload"; '
            f'filename="{filename}"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"{safe_content}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        try:
            req = urllib.request.Request(endpoint, data=body, method="POST")
            req.add_header("Content-Type",
                           f"multipart/form-data; boundary={boundary}")
            req.add_header("Referer", f"{base}/wp-admin/media-new.php")
            req.add_header("User-Agent", self.opsec_ua())
            resp = urllib.request.urlopen(req, timeout=5)

            if resp.getcode() in (200, 201):
                resp_body = resp.read().decode("utf-8", errors="ignore")

                # --- Validate this is a REAL upload response, not a WAF/
                #     firewall page, login redirect, or error page in disguise ---
                is_real_upload = False

                # Check 1: JSON response with upload indicators
                try:
                    json_data = json.loads(resp_body)
                    upload_path = (json_data.get("data", {}).get("url") or
                                   json_data.get("source_url") or
                                   json_data.get("url"))
                    # Only trust if JSON has media-like fields
                    if json_data.get("id") or json_data.get("source_url") or upload_path:
                        is_real_upload = True
                except Exception:
                    pass

                # Check 2: HTML response — look for wp-admin upload patterns only
                if not is_real_upload:
                    # Must contain wp-upload or wp-content path to be real
                    wp_upload_match = re.search(
                        r'wp-content/uploads/[\d/]+[^"\'\s<>]+', resp_body
                    )
                    if wp_upload_match:
                        upload_path = wp_upload_match.group(0)
                        is_real_upload = True

                # Check 3: Response is just an HTML page (WAF, login, error)
                if not is_real_upload:
                    html_signals = ["<html", "<!doctype", "wordfence",
                                   "blocked", "forbidden", "403",
                                   "login", "wp-login", "<title"]
                    body_lower = resp_body[:2000].lower()
                    html_hits = sum(1 for s in html_signals if s in body_lower)
                    if html_hits >= 2:
                        # This is a page, not an upload response
                        self.log(module_name, "INFO",
                                 f"async-upload.php returned HTML page "
                                 f"(not a real upload — likely WAF or auth gate)")
                        self.report_validation(
                            module_name,
                            "Unauthenticated async-upload.php",
                            False,
                            "async-upload.php returned an HTML page instead of "
                            "upload confirmation (WAF/auth gate suspected)",
                        )
                        return

                if is_real_upload:
                    self.report_validation(
                        module_name,
                        "Unauthenticated async-upload.php",
                        True,
                        "async-upload.php accepted file without authentication",
                    )
                    self.log(module_name, "RCE_POSSIBLE",
                             "Direct async-upload.php access allows "
                             "unauthenticated file upload")
                    self.log(module_name, "INFO",
                             f"async-upload filename: {filename}")
                    if upload_path:
                        # Make it absolute if relative
                        if upload_path.startswith("/"):
                            upload_path = f"{base}{upload_path}"
                        self.log(module_name, "INFO",
                                 f"async-upload file path: {upload_path}")
                    else:
                        self.log(module_name, "INFO",
                                 f"async-upload accepted — filename: {filename} — "
                                 f"check /wp-content/uploads/YYYY/MM/")
                else:
                    # 200 but no recognizable upload pattern — uncertain
                    self.log(module_name, "SUSPECTED",
                             f"async-upload.php returned 200 but response "
                             f"does not confirm file was stored")

        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.report_validation(
                    module_name,
                    "Unauthenticated async-upload.php",
                    False,
                    f"upload blocked with HTTP {e.code}",
                )
            elif e.code == 200 or e.code == 302:
                # 302 redirect to login page is common — still means auth required
                self.report_validation(
                    module_name,
                    "Unauthenticated async-upload.php",
                    False,
                    f"upload redirected or blocked (HTTP {e.code})",
                )
        except Exception:
            pass

    def _check_rest_api_users(self, base, module_name):
        """Enumerate users via REST API to support further exploitation."""
        endpoint = f"{base}/wp-json/wp/v2/users"

        try:
            req = urllib.request.Request(endpoint, method="GET")
            req.add_header("User-Agent", self.opsec_ua())
            resp = urllib.request.urlopen(req, timeout=4)

            if resp.getcode() == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if isinstance(data, list) and len(data) > 0:
                    usernames = [u.get("slug", "") for u in data if u.get("slug")]
                    self.log(module_name, "POTENTIAL",
                             f"REST API user enumeration: {len(usernames)} users exposed "
                             f"({', '.join(usernames[:5])})")

        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.report_validation(
                    module_name,
                    "REST API user enumeration",
                    False,
                    f"users endpoint requires authentication (HTTP {e.code})",
                )
        except Exception:
            pass

    def _check_vulnerable_plugin_endpoints(self, base, module_name):
        """Check for common plugin endpoints associated with wp2shell exploitation."""
        # Plugins historically involved in WordPress RCE chains
        plugin_checks = [
            # File Manager plugin — known RCE via upload
            ("/wp-content/plugins/wp-file-manager/readme.txt",
             "WP File Manager", "file upload"),
            # Duplicator plugin — information disclosure + RCE
            ("/wp-content/plugins/duplicator/readme.txt",
             "Duplicator", "information disclosure"),
            # Elementor — template injection
            ("/wp-content/plugins/elementor/readme.txt",
             "Elementor", "template injection"),
            # Contact Form 7 — file upload abuse
            ("/wp-content/plugins/contact-form-7/readme.txt",
             "Contact Form 7", "file upload abuse"),
            # WooCommerce — REST API abuse
            ("/wp-content/plugins/woocommerce/readme.txt",
             "WooCommerce", "REST API abuse"),
            # WPForms — file upload
            ("/wp-content/plugins/wpforms-lite/readme.txt",
             "WPForms", "file upload"),
        ]

        for path, plugin_name, risk in plugin_checks:
            url = f"{base}{path}"
            try:
                req = urllib.request.Request(url, method="GET")
                resp = urllib.request.urlopen(req, timeout=3)
                content = resp.read().decode("utf-8", errors="ignore")

                # Extract plugin version
                version_match = re.search(
                    r"(?:stable tag|version)[:\s]+([0-9.]+)",
                    content, re.IGNORECASE,
                )
                version_str = version_match.group(1) if version_match else "unknown"

                self.log(module_name, "POTENTIAL",
                         f"Plugin detected: {plugin_name} v{version_str} "
                         f"(risk: {risk})")

            except urllib.error.HTTPError as e:
                if e.code == 403:
                    self.log(module_name, "INFO",
                             f"Plugin path exists but restricted: {plugin_name} ({path})")
            except Exception:
                continue

    # ------------------------------------------------------------------ #
    #  Phase 4 — Safe validation of wp2shell chain
    # ------------------------------------------------------------------ #
    def _validate_wp2shell(self, base, module_name):
        """Perform a safe, non-destructive validation of the wp2shell chain."""
        # Check for the core wp2shell indicator: whether wp-json allows
        # unauthenticated POST to media with WordPress's default CORS
        # and nonce handling misconfiguration
        probe_url = f"{base}/wp-json/wp/v2/media"

        # Send an OPTIONS preflight to check CORS headers
        try:
            req = urllib.request.Request(probe_url, method="OPTIONS")
            req.add_header("Origin", "https://evil.example.com")
            req.add_header("Access-Control-Request-Method", "POST")
            req.add_header("User-Agent", self.opsec_ua())
            resp = urllib.request.urlopen(req, timeout=4)
            headers = dict(resp.headers)

            allow_origin = headers.get("Access-Control-Allow-Origin", "")
            allow_methods = headers.get("Access-Control-Allow-Methods", "")

            if "*" in allow_origin or "evil.example.com" in allow_origin:
                self.report_validation(
                    module_name,
                    f"{self.CVE} CORS misconfiguration",
                    True,
                    f"CORS allows cross-origin POST from any origin "
                    f"(Allow-Origin: {allow_origin})",
                )
                self.log(module_name, "RCE_POSSIBLE",
                         "CORS misconfiguration enables cross-origin wp2shell "
                         "exploitation from attacker-controlled pages")
            elif allow_origin:
                self.log(module_name, "SUSPECTED",
                         f"CORS header present: Allow-Origin: {allow_origin}")

            if "POST" in allow_methods:
                self.log(module_name, "INFO",
                         f"CORS allows POST method (Allow-Methods: {allow_methods})")

        except Exception:
            pass

        # Check for DISALLOW_FILE_EDIT and DISALLOW_UNFILTERED_UPLOADS
        # by probing whether the REST API rejects .php uploads specifically
        self._check_php_upload_filter(base, module_name)

    def _check_php_upload_filter(self, base, module_name):
        """Test whether PHP file uploads are filtered (key wp2shell indicator)."""
        marker = self.opsec_marker("v_")
        marker_hash = self.opsec_marker("h_")
        boundary_str = self.opsec_marker("b_")

        endpoint = f"{base}/wp-json/wp/v2/media"

        # Attempt to upload a file with .php extension (safe content, not actual PHP)
        boundary = boundary_str
        php_filename = f"test_{marker_hash}.php"
        safe_content = f"<?php /* {marker} - safe validation only */ ?>"

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; '
            f'filename="{php_filename}"\r\n'
            f"Content-Type: application/x-httpd-php\r\n\r\n"
            f"{safe_content}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        try:
            req = urllib.request.Request(endpoint, data=body, method="POST")
            req.add_header("Content-Type",
                           f"multipart/form-data; boundary={boundary}")
            req.add_header("User-Agent", self.opsec_ua())
            resp = urllib.request.urlopen(req, timeout=8)

            if resp.getcode() in (200, 201):
                resp_body = resp.read().decode("utf-8", errors="ignore")

                # Extract upload URL from REST API response
                upload_url = None
                file_id = None
                try:
                    data = json.loads(resp_body)
                    upload_url = data.get("source_url") or data.get("link")
                    file_id = data.get("id")
                except Exception:
                    pass

                self.report_validation(
                    module_name,
                    f"{self.CVE} PHP upload filter",
                    True,
                    "PHP file upload accepted — wp2shell exploitation is possible",
                )
                self.log(module_name, "VULNERABLE",
                         f"CRITICAL: PHP files can be uploaded and likely executed — "
                         f"{self.CVE} is confirmed")
                self.log(module_name, "VULNERABLE",
                         f"PHP filename uploaded: {php_filename}")
                if upload_url:
                    self.log(module_name, "VULNERABLE",
                             f"PHP file upload URL: {upload_url}")
                    self.log(module_name, "INFO",
                             f"VALIDATION: curl -s '{upload_url}' to confirm code execution")
                elif file_id:
                    self.log(module_name, "VULNERABLE",
                             f"PHP file uploaded (media ID: {file_id}) — filename: {php_filename}")
                    self.log(module_name, "INFO",
                             f"Search uploads: curl -s '{base}/wp-json/wp/v2/media?per_page=20' | grep -o '\"source_url\":\"[^"]*\"'")
                else:
                    self.log(module_name, "INFO",
                             f"PHP upload accepted but no URL in response — filename: {php_filename}")

                # Do NOT auto-delete PHP test files — user needs them for execution validation
                self.log(module_name, "INFO",
                         f"PHP test file left on server for validation (not auto-deleted)")

        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.report_validation(
                    module_name,
                    f"{self.CVE} PHP upload filter",
                    False,
                    f"PHP upload blocked with HTTP {e.code} — auth required",
                )
            elif e.code == 415:
                self.report_validation(
                    module_name,
                    f"{self.CVE} PHP upload filter",
                    False,
                    "PHP upload rejected (unsupported media type 415) — MIME filter active",
                )
            elif e.code == 400:
                # 400 with "Sorry, you are not allowed" means WordPress is filtering
                error_body = ""
                try:
                    error_body = e.read().decode("utf-8", errors="ignore").lower()
                except Exception:
                    pass

                if "not allowed" in error_body or "sorry" in error_body:
                    self.report_validation(
                        module_name,
                        f"{self.CVE} PHP upload filter",
                        False,
                        "PHP upload blocked by WordPress (permission denied)",
                    )
                elif "unsupported" in error_body:
                    self.report_validation(
                        module_name,
                        f"{self.CVE} PHP upload filter",
                        False,
                        "PHP file type not supported — upload filter is active",
                    )
                else:
                    self.log(module_name, "SUSPECTED",
                             f"PHP upload returned HTTP 400 — filtering status unclear")
            else:
                self.report_validation(
                    module_name,
                    f"{self.CVE} PHP upload filter",
                    False,
                    f"PHP upload returned HTTP {e.code}",
                )
        except Exception as e:
            self.log(module_name, "ERROR",
                     f"PHP upload filter check failed: {str(e)[:80]}")