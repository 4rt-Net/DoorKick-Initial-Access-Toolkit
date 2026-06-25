#!/usr/bin/env python3
"""
FTP Anonymous & Default Credentials Checker
"""
import sys
import os
import socket

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class FTPAuthModule(BaseModule):
    """FTP Anonymous Access & Default Credentials Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "FTP Default Creds"
        self.port = 21

    def run(self):
        """Validate FTP anonymous access and default credentials."""
        module_name = "FTP Default Creds"
        target = self.get_target()

        print(f"\n[*] Testing {target}:21 for FTP...")

        if not self.check_port(21, timeout=3):
            self.log(module_name, "ERROR", "Port 21 closed")
            return

        self.check_ftp_service(target, module_name)

    def check_ftp_service(self, target, module_name):
        """Connect to FTP and test authentication methods."""
        try:
            from ftplib import FTP
        except ImportError:
            self.log(module_name, "ERROR", "ftplib not available (standard library should have it)")
            return

        # First grab the banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 21))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()

            if banner and banner.startswith("220"):
                self.log(module_name, "INFO", f"FTP banner: {banner[:80]}")
        except Exception as e:
            self.log(module_name, "ERROR", f"FTP banner grab failed: {str(e)}")
            return

        credentials = [
            ("anonymous", "", "anonymous"),
            ("anonymous", "anonymous@", "anonymous"),
            ("anonymous", "test@test.com", "anonymous"),
            ("ftp", "ftp", "ftp:ftp"),
            ("admin", "admin", "admin:admin"),
            ("root", "root", "root:root"),
            ("admin", "password", "admin:password"),
            ("root", "", "root:(blank)"),
            ("test", "test", "test:test"),
            ("user", "user", "user:user"),
            ("backup", "backup", "backup:backup"),
        ]

        found = False
        for username, password, display in credentials:
            ftp = None
            try:
                ftp = FTP()
                ftp.connect(target, 21, timeout=5)

                resp_code = ftp.login(username, password)

                if "230" in str(resp_code):
                    self.report_validation(
                        module_name,
                        "FTP authentication",
                        True,
                        f"{display} - login successful",
                    )

                    # Try to enumerate accessible files
                    try:
                        pwd = ftp.pwd()
                        self.log(module_name, "INFO", f"Working directory: {pwd}")
                    except Exception:
                        pass

                    try:
                        files = ftp.nlst()
                        if files:
                            self.log(module_name, "INFO",
                                     f"Visible files/dirs: {', '.join(files[:10])}")
                    except Exception:
                        pass

                    # Check write permissions
                    try:
                        test_filename = f"doorkick_test_{os.getpid()}"
                        from io import BytesIO
                        ftp.storbinary(f"STOR {test_filename}", BytesIO(b"doorkick_test"))
                        self.log(module_name, "RCE_POSSIBLE",
                                 "Write access confirmed - can upload files (potentially webshells)")
                        try:
                            ftp.delete(test_filename)
                        except Exception:
                            self.log(module_name, "INFO",
                                     f"Could not delete test file {test_filename}")
                    except Exception:
                        self.log(module_name, "INFO", "Read-only access (upload denied)")

                    found = True
                    ftp.quit()
                    break

                elif "530" in str(resp_code):
                    continue
                else:
                    self.log(module_name, "SUSPECTED",
                             f"Unexpected FTP response for {display}: {resp_code}")

            except Exception as e:
                err = str(e).lower()
                if "530" in err or "login incorrect" in err or "authentication failed" in err:
                    continue
                self.log(module_name, "ERROR",
                         f"FTP test error for {display}: {str(e)[:80]}")
                continue
            finally:
                try:
                    if ftp:
                        ftp.quit()
                except Exception:
                    pass

        if not found:
            self.report_validation(
                module_name,
                "FTP default/anonymous credentials",
                False,
                "all tested credentials were rejected",
            )