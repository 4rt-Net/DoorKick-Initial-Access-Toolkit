#!/usr/bin/env python3
"""
Base module class for all DoorKick modules
"""
import sys
import os
import socket
from abc import ABC, abstractmethod

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import *

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
