#!/usr/bin/env python3
"""
MySQL Default Credentials Checker
Tests for unauthenticated access and common default credentials.
"""
import sys
import os
import socket

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class MySQLDefaultCredsModule(BaseModule):
    """MySQL Default Credentials Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "MySQL Default Creds"
        self.port = 3306

    def run(self):
        """Validate MySQL default credentials and unauthenticated access."""
        module_name = "MySQL Default Creds"
        target = self.get_target()

        print(f"\n[*] Testing {target}:3306 for MySQL...")

        if not self.check_port(3306, timeout=3):
            self.log(module_name, "ERROR", "Port 3306 closed")
            return

        # Grab MySQL version from handshake
        version = self.get_mysql_version(target, module_name)
        if version:
            self.log(module_name, "INFO", f"MySQL version: {version}")

        # Try authentication
        self.test_credentials(target, module_name)

    def get_mysql_version(self, target, module_name):
        """Parse MySQL version from the server greeting packet."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, 3306))

            # Read greeting packet
            data = sock.recv(1024)

            if not data or len(data) < 5:
                sock.close()
                return None

            # MySQL greeting: packet_header(4) + protocol_version(1) + ...
            protocol = data[4]
            if protocol != 10:
                sock.close()
                return None

            # Version string is null-terminated, starts at offset 5
            version_end = data.index(b"\x00", 5)
            version = data[5:version_end].decode("utf-8", errors="ignore")

            sock.close()
            return version

        except Exception:
            return None

    def test_credentials(self, target, module_name):
        """Test MySQL authentication with common default credentials."""
        credentials = [
            ("root", ""),
            ("root", "root"),
            ("root", "mysql"),
            ("root", "password"),
            ("root", "toor"),
            ("root", "admin"),
            ("root", "123456"),
            ("root", "test"),
            ("root", "mysql_root"),
            ("admin", "admin"),
            ("mysql", "mysql"),
            ("debian-sys-maint", ""),
            ("phpmyadmin", "phpmyadmin"),
            ("test", "test"),
            ("backup", "backup"),
        ]

        try:
            import pymysql
            use_pymysql = True
        except ImportError:
            use_pymysql = False
            self.log(module_name, "INFO", "pymysql not installed; trying mysql.connector fallback")

        if not use_pymysql:
            try:
                import mysql.connector
            except ImportError:
                self.log(module_name, "ERROR",
                         "Neither pymysql nor mysql.connector installed; cannot validate MySQL auth")
                self.log(module_name, "INFO",
                         "Install dependency: pip install pymysql")
                return

        for username, password in credentials:
            display_pw = "(blank)" if password == "" else password
            conn = None
            try:
                if use_pymysql:
                    conn = pymysql.connect(
                        host=target,
                        port=3306,
                        user=username,
                        password=password,
                        connect_timeout=5,
                    )
                else:
                    conn = mysql.connector.connect(
                        host=target,
                        port=3306,
                        user=username,
                        password=password,
                        connection_timeout=5,
                    )

                # Validate with a real query
                cursor = conn.cursor()
                cursor.execute("SELECT CURRENT_USER()")
                row = cursor.fetchone()
                current_user = str(row[0]) if row else "unknown"
                cursor.close()

                self.report_validation(
                    module_name,
                    "MySQL default credential",
                    True,
                    f"{username}/{display_pw} authenticated (connected as: {current_user})",
                )

                # Enumerate databases
                try:
                    cursor = conn.cursor()
                    cursor.execute("SHOW DATABASES")
                    dbs = [r[0] for r in cursor.fetchall()]
                    cursor.close()

                    if dbs:
                        safe_dbs = [d for d in dbs if d not in (
                            "information_schema", "performance_schema", "sys")]
                        if safe_dbs:
                            self.log(module_name, "INFO",
                                     f"User databases: {', '.join(safe_dbs[:10])}")
                except Exception:
                    pass

                # Check FILE privilege (enables read/write files on the host)
                try:
                    cursor = conn.cursor()
                    cursor.execute("SHOW GRANTS")
                    grants = cursor.fetchall()
                    cursor.close()

                    for grant in grants:
                        grant_str = str(grant[0]).lower()
                        if "file" in grant_str or "all privileges" in grant_str:
                            self.log(module_name, "RCE_POSSIBLE",
                                     "FILE privilege detected - can read/write host files (e.g., /etc/passwd, SSH keys)")
                            break
                except Exception:
                    pass

                conn.close()
                return

            except Exception as e:
                err = str(e).lower()
                if "access denied" in err or "authentication" in err:
                    continue
                if "timeout" in err or "timed out" in err:
                    self.log(module_name, "ERROR", "MySQL connection timed out")
                    return
                self.log(module_name, "ERROR",
                         f"MySQL auth error for {username}/{display_pw}: {str(e)[:80]}")
                continue
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

        self.report_validation(
            module_name,
            "MySQL default credentials",
            False,
            "all tested credentials were rejected",
        )