#!/usr/bin/env python3
"""
Base module class for all DoorKick modules
"""
import sys
import os
import socket
import urllib.request
from abc import ABC, abstractmethod

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import *
from utils.opsec import (
    random_hostname,
    random_user_agent,
    jitter as _jitter,
    random_marker as _random_marker,
    hostname_spoof,
)


class BaseModule(ABC):
    
    def __init__(self, frontdoor):
        self.frontdoor = frontdoor
        self.name = self.__class__.__name__
        self.target = frontdoor.target
        self.port = None
        
    @abstractmethod
    def run(self):
        pass
    
    def log(self, *args):
        if len(args) == 2:
            module_name = self.name
            status, details = args
        elif len(args) == 3:
            module_name, status, details = args
        else:
            raise ValueError("log() expects 2 or 3 arguments")

        self.frontdoor.log_result(module_name, status, details)

    def get_target(self):
        """Return current target for module compatibility"""
        target = self.frontdoor.get_target()
        self.target = target
        return target
    
    def check_port(self, port, timeout=2):
        try:
            target = self.get_target()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def report_validation(self, module_name, check_name, validated, reason):
        status = "CONFIRMED" if validated else "MITIGATED"
        self.log(module_name, status, f"{check_name}: {reason}")
    
    def print_exploit_steps(self, steps):
        print(f"\n{Y}{BRIGHT}[→] Exploitation Steps:{RESET}")
        for i, step in enumerate(steps, 1):
            print(f"   {C}{i}.{RESET} {step}")
        print()

    # ------------------------------------------------------------------ #
    #  OPSEC helpers — available to every module via inheritance
    # ------------------------------------------------------------------ #
    def opsec_hostname(self):
        """Return a randomised, plausible hostname."""
        return random_hostname()

    def opsec_ua(self):
        """Return a randomised, realistic browser User-Agent."""
        return random_user_agent()

    def opsec_jitter(self, min_s=0.3, max_s=1.5):
        """Sleep for a random interval to mimic human cadence."""
        _jitter(min_s, max_s)

    def opsec_marker(self, prefix=""):
        """Return a non-identifying validation marker (no tool strings)."""
        return _random_marker(prefix)

    def spoofed_connection(self, hostname=None):
        """Context manager that overrides socket.gethostname() for the block.

        Use when connecting to MySQL, MSSQL, SMB, or any protocol that
        broadcasts the client hostname in its handshake.

        Usage::

            with self.spoofed_connection():
                conn = pymysql.connect(host=target, ...)
        """
        return hostname_spoof(hostname)

    def stealth_request(self, url, data=None, method="GET", headers=None,
                        timeout=None, **kwargs):
        """Build a urllib Request with OPSEC User-Agent auto-injected.

        Modules should use this instead of ``urllib.request.Request()``
        for all outbound HTTP traffic.  A randomised browser UA is added
        unless the caller explicitly sets one in *headers*.
        """
        if headers is None:
            headers = {}
        if "User-Agent" not in headers:
            headers["User-Agent"] = self.opsec_ua()
        return urllib.request.Request(url, data=data, method=method,
                                      headers=headers, **kwargs)

    def stealth_headers(self, extra=None):
        """Return a dict with a randomised User-Agent, merged with *extra*."""
        h = {"User-Agent": self.opsec_ua()}
        if extra:
            h.update(extra)
        return h