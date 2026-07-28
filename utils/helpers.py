#!/usr/bin/env python3
"""
Helper functions for DoorKick
"""
import socket
import struct
import ipaddress
from .colors import *

def is_ip(address):
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(address)
        return True
    except:
        return False

def is_domain(address):
    """Basic domain check"""
    return '.' in address and not address.replace('.', '').isdigit()

def validate_target(target):
    """Validate target format"""
    if is_ip(target) or is_domain(target):
        return True
    return False

def port_scan(target, ports, timeout=1):
    """Simple port scanner"""
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def print_table(headers, rows):
    """Print a formatted table"""
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Print header
    header_line = "  "
    for i, header in enumerate(headers):
        header_line += f"{header:<{col_widths[i]}}  "
    print(C + header_line + RESET)
    
    # Print separator
    sep = "  " + "-" * (sum(col_widths) + (len(headers)-1)*2)
    print(sep)
    
    # Print rows
    for row in rows:
        line = "  "
        for i, cell in enumerate(row):
            line += f"{str(cell):<{col_widths[i]}}  "
        print(line)