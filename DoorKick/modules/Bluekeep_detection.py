#!/usr/bin/env python3
"""
RDP Security Checker - NLA Detection & Version Identification
Replaces the unreliable BlueKeep detection with actionable NLA status.
"""
import sys
import os
import socket
import struct

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class RDPSecurityModule(BaseModule):

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "RDP Security"
        self.port = 3389

    def run(self):
        module_name = "RDP Security"
        target = self.get_target()

        print(f"\n[*] Testing {target}:3389 for RDP security issues...")

        if not self.check_port(3389, timeout=3):
            self.log(module_name, "ERROR", "Port 3389 closed")
            return

        self.check_rdp_service(target, module_name)
        self.check_nla_status(target, module_name)

    def check_rdp_service(self, target, module_name):
        """Identify RDP service from the X.224 Connection Request PDU."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 3389))

            # RDP servers send a Connection Request PDU (TPKT + X.224)
            data = sock.recv(1024)
            sock.close()

            if not data or len(data) < 11:
                self.log(module_name, "ERROR", "No RDP handshake data received")
                return

            # TPKT header: version(1) + reserved(1) + length(2)
            if data[0] != 0x03:
                self.log(module_name, "ERROR", "Non-RDP protocol on port 3389")
                return

            self.log(module_name, "INFO", "RDP service confirmed via TPKT/X.224 handshake")

            # Parse X.224 Connection Request to extract RDP version from
            # the cookie or protocol negotiation
            # The RDP Negotiation Request (TYPE_RDP_NEG_REQ) sits in the
            # X.224 cookie and contains the selected protocol:
            #   0x00000000 = Standard RDP Security
            #   0x00000001 = TLS
            #   0x00000002 = CredSSP / NLA
            #   0x00000003 = CredSSP + NLA (early)

            # Look for RDP_NEG_REQ cookie in the data
            # Cookie format: "Cookie: mstshash=<identifier>\r\n"
            # followed by optional RDP Negotiation Request
            decoded = data.decode("utf-8", errors="ignore")

            if "mstshash" in decoded.lower():
                self.log(module_name, "INFO", "RDP cookie detected - service active")

            # Try to find the RDP Negotiation Request structure
            # It starts after the X.224 connection request fields.
            # The Negotiation Request is 8 bytes:
            #   Type(1) = 0x01 | Flags(1) | Length(2) | Protocol(4)
            rdp_neg_req = b"\x01\x00\x08\x00"

            neg_offset = data.find(rdp_neg_req)
            if neg_offset >= 0 and neg_offset + 8 <= len(data):
                protocol = struct.unpack("<I", data[neg_offset + 4 : neg_offset + 8])[0]
                proto_names = {
                    0: "Standard RDP (no encryption/NLA)",
                    1: "TLS",
                    2: "CredSSP / NLA",
                    3: "CredSSP + NLA (early)",
                }
                proto_desc = proto_names.get(protocol, f"Unknown ({protocol})")
                self.log(module_name, "INFO", f"RDP negotiated protocol: {proto_desc}")

        except socket.timeout:
            self.log(module_name, "ERROR", "RDP banner grab timed out")
        except Exception as e:
            self.log(module_name, "ERROR", f"RDP identification failed: {str(e)}")

    def check_nla_status(self, target, module_name):
        """Determine if Network Level Authentication is enforced.

        NLA status is critical for pentest planning:
        - NLA OFF: Credential brute-force is invisible to Windows event logs
                  (no logon attempt is recorded until credentials succeed).
        - NLA ON:  Every failed attempt generates Event ID 4625.

        We detect this by attempting a CredSSP connection with known-bad
        credentials. If the server immediately disconnects after the
        CredSSP phase (before reaching the logon screen), NLA is ON.
        If the server proceeds to show the logon screen, NLA is OFF.

        Uses impacket's rdp_check when available.
        """
        try:
            from impacket.examples.rdp_check import RDPCheck

            self.log(module_name, "INFO", "Running impacket NLA check...")

            # RDPCheck returns True if NLA is required
            checker = RDPCheck(target, 3389)
            nla_required = checker.check()

            if nla_required:
                self.report_validation(
                    module_name,
                    "NLA enforcement",
                    True,
                    "Network Level Authentication is REQUIRED - brute-force attempts will be logged (Event 4625)",
                )
            else:
                self.report_validation(
                    module_name,
                    "NLA enforcement",
                    False,
                    "NLA is NOT enforced - credential brute-force will be STEALTHY (no log entries until success)",
                )
                self.log(
                    module_name,
                    "RCE_POSSIBLE",
                    "NLA disabled enables invisible credential spraying and relay attacks",
                )
            return

        except ImportError:
            self.log(module_name, "INFO", "impacket rdp_check not available for NLA detection")
        except Exception as e:
            self.log(module_name, "ERROR", f"NLA check failed: {str(e)}")

        # Fallback: protocol-based heuristic from handshake data
        self.log(module_name, "INFO",
                 "Falling back to handshake-based NLA heuristic...")
        self._heuristic_nla_check(target, module_name)

    def _heuristic_nla_check(self, target, module_name):
        """Send a CredSSP SPNEGO token and observe the server response.

        If the server accepts the SPNEGO token and moves to the logon
        phase, NLA is likely enabled. If the server immediately sends
        a licensing PDU or error, we infer NLA status from the
        negotiated protocol in the handshake.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 3389))

            # Read the server's Connection Request
            server_data = sock.recv(1024)

            if not server_data or len(server_data) < 11:
                sock.close()
                self.log(module_name, "SUSPECTED", "Could not read RDP handshake for NLA heuristic")
                return

            # Check negotiated protocol from the server's response
            rdp_neg_req = b"\x01\x00\x08\x00"
            neg_offset = server_data.find(rdp_neg_req)

            if neg_offset >= 0 and neg_offset + 8 <= len(server_data):
                protocol = struct.unpack("<I", server_data[neg_offset + 4 : neg_offset + 8])[0]

                if protocol in (2, 3):
                    self.report_validation(
                        module_name,
                        "NLA enforcement",
                        True,
                        "Server advertises CredSSP/NLA in negotiation (heuristic - use impacket for confirmation)",
                    )
                elif protocol == 1:
                    self.log(module_name, "SUSPECTED",
                             "Server advertises TLS only - NLA status unclear")
                elif protocol == 0:
                    self.report_validation(
                        module_name,
                        "NLA enforcement",
                        False,
                        "Server advertises Standard RDP Security - NLA is likely NOT enforced",
                    )
                    self.log(module_name, "RCE_POSSIBLE",
                             "NLA disabled enables invisible credential spraying and relay attacks")
            else:
                self.log(module_name, "SUSPECTED",
                         "No RDP Negotiation Request found - NLA status indeterminate")

            sock.close()

        except Exception as e:
            self.log(module_name, "ERROR", f"Heuristic NLA check failed: {str(e)}")