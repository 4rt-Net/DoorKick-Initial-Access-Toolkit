#!/usr/bin/env python3
import sys
import os
import socket

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class RedisUnauthModule(BaseModule):
    """Redis Unauthenticated Access Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Redis Unauth RCE"
        self.port = 6379

    def run(self):
        """Validate whether Redis allows unauthenticated command execution."""
        module_name = "Redis Unauth RCE"
        target = self.get_target()

        print(f"\n[*] Testing {target}:6379 for Redis...")

        if not self.check_port(6379, timeout=3):
            self.log(module_name, "ERROR", "Port 6379 closed")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((target, 6379))

            ping_response = self.redis_command(sock, "PING")
            if "NOAUTH" in ping_response.upper():
                self.report_validation(module_name, "Redis authentication", False, "server requires authentication")
                sock.close()
                return

            if "PONG" not in ping_response.upper() and "ERR" in ping_response.upper():
                self.log(module_name, "ERROR", f"Unexpected Redis reply to PING: {ping_response.strip()}")
                sock.close()
                return

            self.log(module_name, "POTENTIAL", "Redis service responded to command channel")

            info_response = self.redis_command(sock, "INFO", "server")
            if "redis_version" in info_response.lower():
                self.report_validation(module_name, "Unauthenticated INFO", True, "server metadata exposed without AUTH")
            else:
                self.report_validation(module_name, "Unauthenticated INFO", False, "INFO command blocked or filtered")

            config_response = self.redis_command(sock, "CONFIG", "GET", "dir")
            if "ERR" in config_response.upper() or "NOAUTH" in config_response.upper():
                self.report_validation(module_name, "Filesystem write vector", False, "CONFIG command blocked by controls")
            elif "/" in config_response:
                self.report_validation(module_name, "Filesystem write vector", True, "CONFIG GET dir succeeded without AUTH")
                self.log(module_name, "RCE_POSSIBLE", "Unauthenticated CONFIG access can enable file-write abuse")
            else:
                self.log(module_name, "SUSPECTED", "Redis unauthenticated access detected, but write vector validation was inconclusive")

            sock.close()

        except socket.timeout:
            self.log(module_name, "ERROR", "Connection timeout during Redis validation")
        except ConnectionRefusedError:
            self.log(module_name, "ERROR", "Connection refused on port 6379")
        except (socket.error, OSError) as e:
            self.log(module_name, "ERROR", f"Redis socket error: {str(e)}")

    def redis_command(self, sock, *parts):
        """Send a Redis RESP command and return a decoded response chunk."""
        payload = f"*{len(parts)}\r\n".encode()
        for part in parts:
            encoded = str(part).encode()
            payload += f"${len(encoded)}\r\n".encode() + encoded + b"\r\n"

        sock.sendall(payload)
        data = sock.recv(8192)
        return data.decode("utf-8", errors="ignore")