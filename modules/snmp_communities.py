#!/usr/bin/env python3
"""
SNMP Communities Checker
"""
import sys
import os
import subprocess
import shutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class SNMPCommunitiesModule(BaseModule):
    """SNMP Communities Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "SNMP Communities"
        self.port = 161

    def run(self):
        """Validate default SNMP community exposure with live OID reads."""
        module_name = "SNMP Communities"
        target = self.get_target()

        print(f"\n[*] Testing {target}:161 for SNMP...")

        communities = [
            "public", "private", "community", "snmp", "manager",
            "admin", "default", "read", "monitor", "ro", "rw",
            "cisco", "ibm", "hp", "dell"
        ]

        if self.try_with_pysnmp(target, communities, module_name):
            return

        self.try_with_net_snmp(target, communities, module_name)

    def try_with_pysnmp(self, target, communities, module_name):
        """Preferred SNMP validation path with pysnmp."""
        try:
            from pysnmp.hlapi import (
                getCmd,
                CommunityData,
                UdpTransportTarget,
                ContextData,
                ObjectType,
                ObjectIdentity,
            )
        except ImportError:
            self.log(module_name, "INFO", "pysnmp not available, falling back to system tools")
            return False

        found = False
        for community in communities:
            try:
                result = next(
                    getCmd(
                        CommunityData(community),
                        UdpTransportTarget((target, 161), timeout=2, retries=0),
                        ContextData(),
                        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
                    )
                )
                err_indication, err_status, _, var_binds = result
                if err_indication or err_status:
                    continue

                found = True
                self.report_validation(module_name, "SNMP read community", True, f"community '{community}' can read sysDescr")
                for var_bind in var_binds:
                    self.log(module_name, "INFO", f"{var_bind[0]} = {var_bind[1]}")
                return True

            except Exception:
                continue

        if not found:
            self.report_validation(module_name, "SNMP default communities", False, "no tested community provided valid read access")
        return found

    def try_with_net_snmp(self, target, communities, module_name):
        """Fallback path using snmpget/snmpset utilities."""
        snmpget_bin = shutil.which("snmpget")
        if not snmpget_bin:
            self.log(module_name, "ERROR", "Neither pysnmp nor snmpget is available for SNMP validation")
            return

        oid = "1.3.6.1.2.1.1.1.0"
        for community in communities:
            try:
                result = subprocess.run(
                    [snmpget_bin, "-v2c", "-c", community, "-t", "2", "-r", "0", target, oid],
                    capture_output=True,
                    timeout=5,
                )
                output = result.stdout.decode("utf-8", errors="ignore")
                if result.returncode == 0 and output and "Timeout" not in output:
                    self.report_validation(module_name, "SNMP read community", True, f"community '{community}' can read sysDescr")
                    self.log(module_name, "INFO", output.strip())
                    return
            except Exception:
                continue

        self.report_validation(module_name, "SNMP default communities", False, "no tested community provided valid read access")