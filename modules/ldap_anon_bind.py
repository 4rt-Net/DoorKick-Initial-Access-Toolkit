#!/usr/bin/env python3
"""
LDAP Anonymous Bind Checker
Tests for unauthenticated LDAP access to Active Directory / directory services.
"""
import sys
import os
import socket

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class LDAPAnonBindModule(BaseModule):
    """LDAP Anonymous Bind Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "LDAP Anonymous Bind"
        self.port = 389

    def run(self):
        """Validate LDAP anonymous bind and directory enumeration."""
        module_name = "LDAP Anonymous Bind"
        target = self.get_target()

        print(f"\n[*] Testing {target} for LDAP...")

        ports = [
            (389, False, "LDAP"),
            (636, True, "LDAPS"),
            (3268, False, "Global Catalog"),
            (3269, True, "Global Catalog SSL"),
        ]

        for port, use_ssl, label in ports:
            if not self.check_port(port, timeout=2):
                continue
            self.check_ldap(target, port, use_ssl, label, module_name)

    def check_ldap(self, target, port, use_ssl, label, module_name):
        """Test LDAP anonymous bind and enumerate directory info."""
        try:
            from ldap3 import Server, Connection, ALL, SUBTREE
            from ldap3.core.exceptions import LDAPException
        except ImportError:
            self.log(module_name, "ERROR",
                     "ldap3 not installed; cannot validate LDAP access")
            self.log(module_name, "INFO",
                     "Install dependency: pip install ldap3")
            return

        try:
            server = Server(
                target,
                port=port,
                use_ssl=use_ssl,
                get_info=ALL,
                connect_timeout=5,
            )

            # Anonymous bind
            conn = Connection(
                server,
                user=None,
                password=None,
                auto_bind=True,
                receive_timeout=5,
            )

            if not conn.bound:
                self.report_validation(
                    module_name,
                    f"{label} anonymous bind",
                    False,
                    "anonymous bind rejected",
                )
                return

            self.report_validation(
                module_name,
                f"{label} anonymous bind",
                True,
                "anonymous bind succeeded - directory is readable without credentials",
            )

            # Enumerate naming contexts (root DSE)
            if server.info.naming_contexts:
                self.log(module_name, "INFO",
                         f"Naming contexts: {', '.join(server.info.naming_contexts[:5])}")

            # Try to read the default naming context
            base_dn = None
            if server.info.naming_contexts:
                base_dn = server.info.naming_contexts[0]

            if base_dn:
                self._enumerate_users(conn, base_dn, module_name, label)
                self._enumerate_groups(conn, base_dn, module_name, label)
                self._check_password_policy(conn, base_dn, module_name, label)

            conn.unbind()

        except LDAPException as e:
            err = str(e).lower()
            if "unwilling" in err or "insufficient" in err or "auth" in err:
                self.report_validation(
                    module_name,
                    f"{label} anonymous bind",
                    False,
                    f"server refused anonymous access: {str(e)[:80]}",
                )
            else:
                self.log(module_name, "ERROR",
                         f"LDAP {label} error: {str(e)[:100]}")
        except Exception as e:
            self.log(module_name, "ERROR",
                     f"LDAP {label} check failed: {str(e)[:100]}")

    def _enumerate_users(self, conn, base_dn, module_name, label):
        """Enumerate user accounts via anonymous LDAP."""
        try:
            # Search for user accounts
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=user)",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "description", "userPrincipalName",
                            "mail", "title", "department"],
                size_limit=20,
            )

            if conn.entries:
                user_count = len(conn.entries)
                self.log(module_name, "INFO",
                         f"{label}: Found {user_count} user objects (showing up to 10)")

                for entry in conn.entries[:10]:
                    attrs = entry.entry_attributes
                    name = str(entry.sAMAccountName) if "sAMAccountName" in attrs else "unknown"
                    desc = str(entry.description) if "description" in attrs else ""
                    email = str(entry.userPrincipalName) if "userPrincipalName" in attrs else ""
                    mail = str(entry.mail) if "mail" in attrs else ""

                    display = name
                    if email and email != "None":
                        display += f" ({email})"
                    elif mail and mail != "None":
                        display += f" ({mail})"
                    if desc and desc != "None" and len(desc) > 2:
                        display += f" - {desc[:60]}"

                    self.log(module_name, "INFO", f"  User: {display}")

                self.log(module_name, "RCE_POSSIBLE",
                         f"User enumeration via anonymous {label} reveals account names "
                         "for password spraying and social engineering")

        except Exception as e:
            self.log(module_name, "SUSPECTED",
                     f"User enumeration failed: {str(e)[:80]}")

    def _enumerate_groups(self, conn, base_dn, module_name, label):
        """Enumerate privileged groups."""
        try:
            privileged_groups = [
                "(cn=Domain Admins)",
                "(cn=Enterprise Admins)",
                "(cn=Administrators)",
                "(cn=Schema Admins)",
            ]

            for group_filter in privileged_groups:
                conn.search(
                    search_base=base_dn,
                    search_filter=f"(&(objectClass=group){group_filter})",
                    search_scope=SUBTREE,
                    attributes=["member", "description"],
                    size_limit=1,
                )

                if conn.entries:
                    group_name = group_filter.split("=")[1].rstrip(")")
                    member_count = 0
                    for entry in conn.entries:
                        if "member" in entry.entry_attributes:
                            members = entry.member.values if hasattr(entry.member, 'values') else []
                            member_count = len(members)

                    self.log(module_name, "INFO",
                             f"Group '{group_name}' has {member_count} members (via anonymous read)")

        except Exception:
            pass

    def _check_password_policy(self, conn, base_dn, module_name, label):
        """Check for password policy information leakage."""
        try:
            # Try to read the default domain password policy
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=domainDNS)",
                search_scope=SUBTREE,
                attributes=["minPwdLength", "pwdHistoryLength", "maxPwdAge",
                            "minPwdAge", "lockoutThreshold", "lockoutDuration"],
                size_limit=1,
            )

            if conn.entries:
                policy_attrs = []
                for entry in conn.entries:
                    for attr in ["minPwdLength", "pwdHistoryLength", "lockoutThreshold"]:
                        if attr in entry.entry_attributes:
                            val = getattr(entry, attr)
                            policy_attrs.append(f"{attr}={val}")

                if policy_attrs:
                    self.log(module_name, "INFO",
                             f"Password policy exposed: {', '.join(policy_attrs)}")
                    self.log(module_name, "RCE_POSSIBLE",
                             "Password policy disclosure enables targeted password attacks")

        except Exception:
            pass