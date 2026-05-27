import sys
import os
import socket
import time
import struct

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *
class GREVXLANModule(BaseModule):
    
    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "GRE/VXLAN Tunnel"
        self.port = None
    


    def run(self):
        """Check for exposed GRE/VXLAN tunnels"""
        module_name = "Tunnel Discovery"
        target = self.get_target()
        
        print(f"\n[*] Testing {target} for GRE/VXLAN tunnels...")
        
        # Note: GRE uses IP protocol 47
        # Note: VXLAN uses UDP 4789
        
        try:
            self.test_gre_tunnel(target)
            
            self.test_vxlan_tunnel(target)
            
        except Exception as e:
            self.log(module_name, "ERROR", f"Unexpected error: {str(e)}")
    
    def test_gre_tunnel(self, target):
        """Test for exposed GRE tunnel"""
        module_name = "GRE Tunnel"
        
        try:
            # Create raw socket for GRE
            # Note: This requires root privileges
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE)
            sock.settimeout(3)
            
            # Note: GRE probe packet
            # GRE header (4 bytes) + inner IP header (20 bytes) + ICMP (8 bytes)
            
            # GRE header
            gre_flags = 0x0000
            gre_protocol = 0x0800 #(ipv4)
            
            # Inner IP header
            inner_ip = struct.pack('!BBHHHBBH4s4s',
                0x45,           # Version 4, IHL 5
                0x00,           # DSCP
                40,             # Total length (20 IP + 8 ICMP + 12)
                0x0000,         # Identification
                0x0000,         # Flags/fragment
                64,             # TTL
                socket.IPPROTO_ICMP,  # Protocol
                0,              # Checksum (0 - will adjust if needed)
                socket.inet_aton('192.168.1.100'),  # Source (spoofed)
                socket.inet_aton(target)  # Destination
            )
            
            # ICMP Echo Request
            icmp = struct.pack('!BBHHH',
                8,  # Type
                0,  # Code
                0,  # Checksum (0 for now)
                1,  # Identifier
                1   # Sequence
            )
            
            # Combine
            packet = struct.pack('!HH', gre_flags, gre_protocol) + inner_ip + icmp
            
            # Try multiple potential peer IPs (common internal ranges)
            internal_peers = [
                '10.0.0.1', '10.0.0.2', '10.0.1.1', '10.0.1.2',
                '192.168.1.1', '192.168.1.2', '192.168.0.1', '192.168.0.2',
                '172.16.0.1', '172.16.0.2', '172.16.1.1', '172.16.1.2'
            ]
            
            sock.settimeout(2)
            
            for peer in internal_peers[:4]:  # Limit for demo
                try:
                    # Send GRE packet
                    sock.sendto(packet, (target, 0))
                    
                    # Listen for response (ICMP Echo Reply)
                    response = sock.recv(1024)
                    
                    if response:
                        self.log("GRE Tunnel", "VULNERABLE", 
                                      f"Possible tunnel to internal peer {peer}")
                        return
                        
                except socket.timeout:
                    continue
                    
            self.log("GRE Tunnel", "NOT VULNERABLE", 
                          "No GRE tunnel detected")
            
        except PermissionError:
            self.log("GRE Tunnel", "ERROR", 
                          "Root privileges required for raw sockets")
        except Exception as e:
            self.log("GRE Tunnel", "ERROR", str(e))
    
    def test_vxlan_tunnel(self, target):
        """Test for exposed VXLAN tunnel"""
        module_name = "VXLAN Tunnel"
        
        try:
            # Create UDP socket for VXLAN (port 4789)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            
            # VXLAN header
            vxlan_flags = 0x08000000  # Flags with VNI present
            vxlan_vni = 0x000001       # VNI 1
            
            # Inner Ethernet frame
            eth_dst = b'\xff\xff\xff\xff\xff\xff'  # Broadcast
            eth_src = b'\x00\x11\x22\x33\x44\x55'  # Spoofed MAC
            eth_type = 0x0806  # ARP
            
            # ARP Request
            arp = struct.pack('!HHBBHHH4s4s4s4s',
                1,      # Hardware type: Ethernet
                0x0800, # Protocol type: IPv4
                6,      # Hardware size
                4,      # Protocol size
                1,      # Opcode: Request
                0x0000, # Sender MAC (will be overwritten)
                0x0000, # Sender IP (will be overwritten)
                b'\x00\x00\x00\x00\x00\x00',  # Target MAC
                socket.inet_aton('192.168.1.1')  # Target IP
            )
            
            # Build packet
            vxlan_header = struct.pack('!I', vxlan_flags) + struct.pack('!I', vxlan_vni)[1:4] + b'\x00'
            inner_frame = eth_dst + eth_src + struct.pack('!H', eth_type) + arp
            packet = vxlan_header + inner_frame
            
            # Send to target
            sock.sendto(packet, (target, 4789))
            
            # Listen for broadcast traffic
            try:
                response, addr = sock.recvfrom(2048)
                if response:
                    self.log(module_name, "VULNERABLE", 
                                  "VXLAN endpoint responded - possible FDB poisoning")
                    
                    # Parse response for network mapping
                    self.log(module_name, "INFO", 
                                  "Captured broadcast traffic - network may be mapped")
            except socket.timeout:
                self.log(module_name, "NOT VULNERABLE", 
                              "No response to VXLAN probe")
                
        except Exception as e:
            self.log(module_name, "ERROR", str(e))