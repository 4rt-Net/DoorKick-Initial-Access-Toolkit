#!/usr/bin/env python3
"""
Docker Daemon Socket Checker
"""
import sys
import os
import json
import urllib.request
import urllib.error

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class DockerSocketModule(BaseModule):

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "Docker Daemon"
        self.port = 2375

    def run(self):
        """Check for exposed Docker daemon socket (2375)"""
        module_name = "Docker Daemon"
        target = self.get_target()

        print(f"\n[*] Testing {target}:2375 for Docker API...")

        if not self.check_port(2375, timeout=3):
            self.log(module_name, "ERROR", "Port 2375 closed")
            return

        try:
            url = f"http://{target}:2375/version"
            req = urllib.request.Request(url, method="GET")
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode())

            if "Version" in data:
                self.log(module_name, "VULNERABLE", "Docker daemon API exposed without TLS")
                self.log(module_name, "INFO", f"Docker version: {data.get('Version', 'unknown')}")
                self.get_docker_info(target, module_name)
            else:
                self.log(module_name, "POTENTIAL", "Docker API responded unexpectedly")

        except urllib.error.HTTPError as e:
            self.log(module_name, "ERROR", f"Docker API HTTP error: {e.code}")
        except Exception as e:
            self.log(module_name, "ERROR", f"Failed to query Docker API: {str(e)}")

    def get_docker_info(self, target, module_name):
        """Collect additional Docker API information."""
        endpoints = [
            ("/info", "daemon info"),
            ("/containers/json", "container list"),
            ("/images/json", "image list"),
        ]

        for endpoint, label in endpoints:
            try:
                url = f"http://{target}:2375{endpoint}"
                req = urllib.request.Request(url, method="GET")
                response = urllib.request.urlopen(req, timeout=5)

                if response.getcode() != 200:
                    continue

                content = response.read().decode("utf-8", errors="ignore")

                if endpoint == "/containers/json":
                    containers = json.loads(content)
                    self.log(module_name, "INFO", f"Accessible containers endpoint ({len(containers)} containers)")
                elif endpoint == "/images/json":
                    images = json.loads(content)
                    self.log(module_name, "INFO", f"Accessible images endpoint ({len(images)} images)")
                else:
                    info = json.loads(content)
                    host = info.get("Name", "unknown")
                    self.log(module_name, "INFO", f"Accessible {label}; host: {host}")

            except Exception:
                continue