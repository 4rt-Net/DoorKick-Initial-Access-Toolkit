#!/usr/bin/env python3
"""
Cassandra No Auth Checker
"""
import sys
import os
import socket
import struct

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class CassandraNoAuthModule(BaseModule):

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Cassandra No Auth"
        self.port = 9042

    def run(self):
        """Validate whether Cassandra allows unauthenticated CQL access."""
        module_name = "Cassandra No Auth"
        target = self.get_target()

        print(f"\n[*] Testing {target}:9042 for Cassandra...")

        if not self.check_port(9042, timeout=3):
            self.log(module_name, "ERROR", "Port 9042 closed")
            return

        try:
            from cassandra.cluster import Cluster
            from cassandra import Unauthorized
            from cassandra.auth import NoAuthProvider
        except ImportError:
            self.log(module_name, "INFO", "cassandra-driver not installed; using protocol fallback validation")
            self.manual_cassandra_check(target, module_name)
            return

        cluster = None
        try:
            cluster = Cluster([target], port=9042, connect_timeout=5, auth_provider=NoAuthProvider())
            session = cluster.connect()
            self.log(module_name, "POTENTIAL", "Cassandra accepted no-auth connection attempt")

            rows = session.execute("SELECT keyspace_name FROM system_schema.keyspaces")
            keyspaces = [row.keyspace_name for row in rows]
            self.report_validation(module_name, "Unauthenticated keyspace listing", True, "system_schema.keyspaces query succeeded")
            if keyspaces:
                self.log(module_name, "INFO", f"Keyspaces visible without auth: {', '.join(keyspaces[:10])}")

        except Unauthorized:
            self.report_validation(module_name, "Unauthenticated keyspace listing", False, "authentication is required")
        except Exception as e:
            message = str(e).lower()
            if "authentication" in message or "unauthorized" in message:
                self.report_validation(module_name, "Unauthenticated keyspace listing", False, "authentication is required")
            else:
                self.log(module_name, "ERROR", f"Cassandra validation failed: {str(e)}")
                self.manual_cassandra_check(target, module_name)
        finally:
            if cluster:
                cluster.shutdown()

    def manual_cassandra_check(self, target, module_name):
        """Fallback protocol-level check for READY vs AUTHENTICATE."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 9042))

            # STARTUP message with CQL_VERSION:3.0.0
            body = b"\x00\x01" + b"\x00\x0bCQL_VERSION" + b"\x00\x053.0.0"
            header = struct.pack(">BBBBI", 0x04, 0x00, 0x00, 0x01, len(body))
            sock.sendall(header + body)

            response_header = sock.recv(9)
            if len(response_header) < 9:
                self.log(module_name, "SUSPECTED", "Cassandra protocol response too short for validation")
                sock.close()
                return

            opcode = response_header[4]

            if opcode == 0x02:  # READY
                self.report_validation(module_name, "Unauthenticated startup", True, "server returned READY without AUTHENTICATE")
            elif opcode == 0x03:  # AUTHENTICATE
                self.report_validation(module_name, "Unauthenticated startup", False, "server requested authentication challenge")
            elif opcode == 0x00:  # ERROR
                self.log(module_name, "SUSPECTED", "Cassandra returned protocol error; auth state inconclusive")
            else:
                self.log(module_name, "SUSPECTED", f"Unexpected Cassandra opcode {opcode}; validation inconclusive")

            sock.close()

        except Exception as e:
            self.log(module_name, "ERROR", f"Manual Cassandra validation failed: {str(e)}")