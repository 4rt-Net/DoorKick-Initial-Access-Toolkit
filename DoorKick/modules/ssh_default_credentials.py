#!/usr/bin/env python3
"""
SSH Default Credentials Checker
"""
import sys
import os
import socket
import shutil
import subprocess

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class SSHDefaultCredsModule(BaseModule):
    """SSH Default Credentials Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "SSH Default Credentials"
        self.port = 22

    def run(self):
        """Validate weak/default SSH credentials with command execution proof."""
        module_name = "SSH Default Credentials"
        target = self.get_target()

        print(f"\n[*] Testing {target}:22 for default SSH credentials...")

        if not self.check_port(22, timeout=3):
            self.log(module_name, "ERROR", "Port 22 closed")
            return

        try:
            import paramiko
            self.test_with_paramiko(target, module_name)
            return
        except ImportError:
            self.log(module_name, "INFO", "paramiko not installed; trying sshpass fallback")

        self.test_with_sshpass(target, module_name)

    def test_with_paramiko(self, target, module_name):
        """Test credentials using Paramiko and confirm shell command execution."""
        import paramiko

        credentials = [
            ("root", ""), ("root", "root"), ("root", "toor"), ("root", "password"),
            ("admin", "admin"), ("admin", "password"), ("admin", ""),
            ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("debian", "debian"),
            ("tomcat", "tomcat"), ("cisco", "cisco"), ("Administrator", "password"),
        ]

        auth_failures = 0
        for username, password in credentials:
            ssh = None
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    target,
                    port=22,
                    username=username,
                    password=password,
                    timeout=4,
                    banner_timeout=4,
                    auth_timeout=4,
                    allow_agent=False,
                    look_for_keys=False,
                )

                marker = "DOORKICK_SSH_VALIDATION"
                stdin, stdout, stderr = ssh.exec_command(f"echo {marker}")
                output = stdout.read().decode("utf-8", errors="ignore")

                shown_password = password if password else "(blank)"
                if marker in output:
                    self.report_validation(module_name, "SSH default credential login", True, f"{username}/{shown_password} authenticated and executed command")
                    self.log(module_name, "RCE_POSSIBLE", "Validated shell command execution over SSH")
                    ssh.close()
                    return

                self.log(module_name, "SUSPECTED", f"{username}/{shown_password} authenticated but marker command output was inconclusive")
                ssh.close()
                return

            except paramiko.AuthenticationException:
                auth_failures += 1
                continue
            except (socket.timeout, TimeoutError):
                self.log(module_name, "ERROR", "SSH validation timed out")
                return
            except Exception as e:
                self.log(module_name, "ERROR", f"SSH validation error: {str(e)}")
                return
            finally:
                if ssh:
                    ssh.close()

        if auth_failures == len(credentials):
            self.report_validation(module_name, "SSH default credential login", False, "all tested credentials were rejected")

    def test_with_sshpass(self, target, module_name):
        """Fallback validation using sshpass when Paramiko is unavailable."""
        sshpass_bin = shutil.which("sshpass")
        ssh_bin = shutil.which("ssh")

        if not sshpass_bin or not ssh_bin:
            self.log(module_name, "ERROR", "Cannot validate SSH creds: install paramiko or sshpass+ssh")
            return

        credentials = [
            ("root", "root"),
            ("admin", "admin"),
            ("ubuntu", "ubuntu"),
            ("pi", "raspberry"),
        ]

        marker = "DOORKICK_SSH_VALIDATION"
        for username, password in credentials:
            try:
                cmd = [
                    sshpass_bin,
                    "-p",
                    password,
                    ssh_bin,
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "ConnectTimeout=4",
                    f"{username}@{target}",
                    f"echo {marker}",
                ]
                result = subprocess.run(cmd, capture_output=True, timeout=8)
                out = result.stdout.decode("utf-8", errors="ignore")

                if result.returncode == 0 and marker in out:
                    self.report_validation(module_name, "SSH default credential login", True, f"{username}/{password} authenticated and executed command")
                    self.log(module_name, "RCE_POSSIBLE", "Validated shell command execution over SSH")
                    return
            except subprocess.TimeoutExpired:
                self.log(module_name, "ERROR", "sshpass validation timed out")
                return
            except Exception as e:
                self.log(module_name, "ERROR", f"sshpass validation failed: {str(e)}")
                return

        self.report_validation(module_name, "SSH default credential login", False, "all tested credentials were rejected")