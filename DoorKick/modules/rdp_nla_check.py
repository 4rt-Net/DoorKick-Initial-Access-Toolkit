#!/usr/bin/env python3
"""
RDP NLA (Network Level Authentication) Checker
Dedicated module that focuses purely on NLA enforcement status.
This is critical pre-attack intelligence for pentesters.
"""
import sys
import os
import socket
import struct

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class RDPNLACheckModule(BaseModule):
    """RDP NLA Enforcement Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "RDP NLA Check"
        self.port = 3389

    def run(self):
        """Check if RDP has Network Level Authentication enabled."""
        module_name = "RDP NLA Check"
        target = self.get_target()

        print(f"\n[*] Testing {target}:3389 for RDP NLA status...")

        if not self.check_port(3389, timeout=3):
            self.log(module_name, "ERROR", "Port 3389 closed")
            return

        # Try impacket first (most reliable)
        try:
            from impacket.examples.rdp_check import RDPCheck

            self.log(module_name, "INFO", "Running impacket NLA detection...")

            checker = RDPCheck(target, 3389)
            nla_required = checker.check()

            if nla_required:
                self.report_validation(
                    module_name,
                    "NLA enforcement",
                    True,
                    "Network Level Authentication is REQUIRED - "
                    "brute-force generates Event 4625 on every attempt",
                )
            else:
                self.report_validation(
                    module_name,
                    "NLA enforcement",
                    False,
                    "NLA is NOT enforced - credential brute-force is STEALTHY "
                    "(no server-side log entries until valid credentials are sent)",
                )
                self.log(
                    module_name,
                    "RCE_POSSIBLE",
                    "NLA disabled enables invisible credential spraying, "
                    "password guessing, and NTLM relay attacks",
                )
            return

        except ImportError:
            self.log(module_name, "INFO",
                     "impacket rdp_check not available, using protocol heuristic")
        except Exception as e:
            self.log(module_name, "ERROR",
                     f"impacket NLA check failed: {str(e)}")

        # Fallback: protocol-based heuristic
        self._heuristic_nla_check(target, module_name)

    def _heuristic_nla_check(self, target, module_name):
        """Parse the RDP Negotiation Request from the server handshake.

        The server's X.224 Connection Confirm PDU contains an RDP
        Negotiation Response that advertises the required security
        protocol:
          0x00000000 = Standard RDP Security (no NLA)
          0x00000001 = TLS
          0x00000002 = CredSSP / NLA
          0x00000003 = CredSSP + NLA (early user auth)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 3389))

            # Read server's X.224 Connection Request
            server_data = sock.recv(1024)

            if not server_data or len(server_data) < 11:
                sock.close()
                self.log(module_name, "SUSPECTED",
                         "Could not read RDP handshake for NLA heuristic")
                return

            # The server's Connection Request may contain an RDP
            # Negotiation Request cookie: Type(1)=0x01, Flags(1)=0x00,
            # Length(2)=0x0008, Protocol(4)
            neg_marker = b"\x01\x00\x08\x00"
            neg_offset = server_data.find(neg_marker)

            if neg_offset < 0 or neg_offset + 8 > len(server_data):
                sock.close()
                self.log(module_name, "SUSPECTED",
                         "No RDP Negotiation Request found in handshake")
                return

            protocol = struct.unpack("<I",
                                     server_data[neg_offset + 4 : neg_offset + 8])[0]

            sock.close()

            proto_map = {
                0: "Standard RDP Security (no NLA)",
                1: "TLS (NLA status depends on server config)",
                2: "CredSSP / NLA",
                3: "CredSSP + NLA (early)",
            }
            proto_desc = proto_map.get(protocol, f"Unknown ({protocol})")
            self.log(module_name, "INFO",
                     f"Server advertises: {proto_desc}")

            if protocol in (2, 3):
                self.report_validation(
                    module_name,
                    "NLA enforcement (heuristic)",
                    True,
                    f"Server advertises CredSSP/NLA (protocol={protocol})",
                )
            elif protocol == 0:
                self.report_validation(
                    module_name,
                    "NLA enforcement (heuristic)",
                    False,
                    "Server advertises Standard RDP - NLA likely not enforced",
                )
                self.log(module_name, "RCE_POSSIBLE",
                         "NLA disabled enables invisible credential spraying")
            elif protocol == 1:
                self.log(module_name, "SUSPECTED",
                         "Server advertises TLS only - NLA status unclear "
                         "(use impacket rdp_check for confirmation)")

        except Exception as e:
            self.log(module_name, "ERROR",
                     f"Heuristic NLA check failed: {str(e)}")