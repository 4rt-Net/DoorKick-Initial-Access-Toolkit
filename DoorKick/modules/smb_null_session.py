#!/usr/bin/env python3
"""
SMB Null Session & Guest Access Checker
Tests for unauthenticated (null) session and guest access to Windows shares.
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class SMBNullSessionModule(BaseModule):
    """SMB Null Session & Guest Access Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "SMB Null Session"
        self.port = 445

    def run(self):
        """Validate SMB null session and guest access using impacket."""
        module_name = "SMB Null Session"
        target = self.get_target()

        print(f"\n[*] Testing {target}:445 for SMB...")

        ports = [445, 139]
        smb_port = None

        for port in ports:
            if self.check_port(port, timeout=3):
                smb_port = port
                break

        if not smb_port:
            self.log(module_name, "ERROR", "SMB ports 139/445 closed")
            return

        self.log(module_name, "POTENTIAL", f"SMB port {smb_port} open")

        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            self.log(module_name, "ERROR",
                     "impacket not installed; cannot perform SMB validation")
            self.log(module_name, "INFO", "Install dependency: pip install impacket")
            return

        self.test_null_session(target, smb_port, module_name)

    def test_null_session(self, target, port, module_name):
        """Attempt a null session (empty username/password) and enumerate shares."""
        from impacket.smbconnection import SMBConnection

        smb = None
        try:
            smb = SMBConnection(target, target, smbport=port, timeout=5)

            # Null session - empty credentials
            smb.login("", "")

            self.report_validation(
                module_name,
                "SMB null session",
                True,
                "server accepted null session (no credentials)",
            )

            # Enumerate shares
            try:
                shares = smb.listShares()
                share_names = []
                readable_shares = []

                for share in shares:
                    share_name = share.get("share", share.get("shi1_netname", ""))
                    if share_name:
                        share_names.append(share_name.strip("\x00"))

                if share_names:
                    self.log(module_name, "INFO",
                             f"Visible shares: {', '.join(share_names[:15])}")

                    # Test which shares are readable
                    for sname in share_names:
                        # Skip IPC$ and print shares
                        if sname.upper() in ("IPC$", "PRINT$"):
                            continue
                        try:
                            tid = smb.connectTree(sname)
                            # Try to list files in the share root
                            files = smb.listPath(sname, "*")
                            readable_shares.append(sname)
                            file_count = len(files) if files else 0
                            self.log(module_name, "INFO",
                                     f"  Share '{sname}' readable ({file_count} items visible)")
                        except Exception:
                            pass

                    if readable_shares:
                        self.log(module_name, "RCE_POSSIBLE",
                                 f"Readable shares accessible: {', '.join(readable_shares)} - "
                                 "may contain sensitive files, credentials, or allow file upload")
                else:
                    self.log(module_name, "INFO",
                             "Null session accepted but no shares enumerated")

            except Exception as e:
                self.log(module_name, "SUSPECTED",
                         f"Null session connected but share enumeration failed: {str(e)[:80]}")

            smb.logoff()

        except Exception as e:
            err = str(e).lower()
            if "access denied" in err or "logon failure" in err or "status_access_denied" in err:
                self.report_validation(
                    module_name,
                    "SMB null session",
                    False,
                    "null session rejected by authentication controls",
                )
                # Still try guest access
                self.test_guest_access(target, port, module_name)
            elif "timeout" in err or "timed out" in err:
                self.log(module_name, "ERROR", "SMB connection timed out")
            else:
                self.log(module_name, "ERROR",
                         f"SMB null session test failed: {str(e)[:100]}")

    def test_guest_access(self, target, port, module_name):
        """Attempt SMB login with 'guest' credentials."""
        from impacket.smbconnection import SMBConnection

        smb = None
        try:
            smb = SMBConnection(target, target, smbport=port, timeout=5)
            smb.login("guest", "")

            self.report_validation(
                module_name,
                "SMB guest access",
                True,
                "guest account accepted without password",
            )

            try:
                shares = smb.listShares()
                share_names = []
                for share in shares:
                    name = share.get("share", share.get("shi1_netname", ""))
                    if name:
                        share_names.append(name.strip("\x00"))
                if share_names:
                    self.log(module_name, "INFO",
                             f"Guest-visible shares: {', '.join(share_names[:10])}")
            except Exception:
                pass

            self.log(module_name, "RCE_POSSIBLE",
                     "Guest access may allow share enumeration and data exfiltration")
            smb.logoff()

        except Exception as e:
            err = str(e).lower()
            if "access denied" in err or "logon failure" in err:
                self.report_validation(
                    module_name,
                    "SMB guest access",
                    False,
                    "guest account login rejected",
                )
            else:
                self.log(module_name, "ERROR",
                         f"Guest access test failed: {str(e)[:80]}")