#!/usr/bin/env python3
"""
MSSQL Default SA Checker - Real TDS authentication via impacket
"""
import sys
import os
import socket

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class MSSQLDefaultModule(BaseModule):
    """MSSQL Default SA Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "MSSQL Default SA"
        self.port = 1433

    def run(self):
        """Check for MSSQL default/blank SA passwords using impacket TDS."""
        module_name = "MSSQL Default SA"
        target = self.get_target()

        print(f"\n[*] Testing {target}:1433 for MSSQL default credentials...")

        if not self.check_port(1433, timeout=3):
            self.log(module_name, "ERROR", "Port 1433 closed")
            return

        try:
            from impacket.tds import TDSClient
        except ImportError:
            self.log(module_name, "ERROR",
                     "impacket not installed; cannot perform TDS authentication")
            self.log(module_name, "INFO", "Install dependency: pip install impacket")
            return

        passwords = [
            "",            # Blank
            "sa",          # Same as username
            "password",
            "sa123",
            "sql",
            "sqlserver",
            "admin",
            "administrator",
            "123456",
            "password123",
            "sa@123",
            "P@ssw0rd",
            "SAPassword",
            "master",
            "database",
            "MSSQL",
            "mssql",
        ]

        self.log(module_name, "POTENTIAL", "MSSQL port open, testing credentials...")

        for password in passwords:
            display_pw = "(blank)" if password == "" else password
            tds = None
            try:
                tds = TDSClient(
                    target,
                    port=1433,
                    username="sa",
                    password=password,
                    timeout=5,
                )
                tds.connect()

                # Validate with a real SQL query
                rows = tds.sql_query("SELECT @@VERSION")
                if rows and len(rows) > 0:
                    version_info = str(rows[0])[:120]
                    self.report_validation(
                        module_name,
                        "MSSQL SA default credential",
                        True,
                        f"sa/{display_pw} authenticated; version: {version_info}",
                    )
                    self.log(module_name, "RCE_POSSIBLE",
                             "SA access enables xp_cmdshell RCE and full database control")
                    tds.disconnect()
                    return

                tds.disconnect()

            except Exception as e:
                err_msg = str(e).lower()
                if "login failed" in err_msg or "authentication" in err_msg:
                    # Expected - move to next password
                    pass
                elif "timeout" in err_msg or "timed out" in err_msg:
                    self.log(module_name, "ERROR", "MSSQL connection timed out")
                    return
                else:
                    # Unexpected error - log and continue
                    self.log(module_name, "ERROR",
                             f"MSSQL auth error with sa/{display_pw}: {str(e)[:80]}")
                    continue
            finally:
                try:
                    if tds:
                        tds.disconnect()
                except Exception:
                    pass

        self.report_validation(
            module_name,
            "MSSQL SA default credential",
            False,
            "all tested SA passwords were rejected",
        )