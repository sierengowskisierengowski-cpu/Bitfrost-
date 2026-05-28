#!/usr/bin/env python3
"""
Bifrost eBPF Rules Manager v0.1.0

Allows Heimdall to update kernel-level block rules
in real-time. When Heimdall decides to block something,
it writes to the BPF maps and the kernel denies it
on the next syscall - microsecond response time.
"""

import logging
import socket
import struct

log = logging.getLogger("heimdall.bpf_rules")

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False


class BPFRulesManager:
    """
    Manages eBPF maps for kernel-level blocking.
    Used by Heimdall to add/remove block rules dynamically.
    """
    
    def __init__(self, bpf_program=None):
        self.bpf = bpf_program
        self.enabled = bpf_program is not None and BCC_AVAILABLE
        
        if not self.enabled:
            log.warning("eBPF rules manager disabled (BPF program not loaded)")
    
    def block_path(self, path: str) -> bool:
        """
        Add a file path to the kernel block list.
        Future attempts to open this path will be denied.
        """
        if not self.enabled:
            return False
        
        try:
            # Convert path to bytes (max 256 chars)
            path_bytes = path.encode('utf-8')[:256]
            
            # Update BPF map: path -> 1 (block)
            self.bpf["blocked_paths"][path_bytes] = 1
            
            log.info(f"✅ Added to kernel block list: {path}")
            return True
            
        except Exception as e:
            log.error(f"Failed to block path {path}: {e}")
            return False
    
    def unblock_path(self, path: str) -> bool:
        """Remove a path from the kernel block list."""
        if not self.enabled:
            return False
        
        try:
            path_bytes = path.encode('utf-8')[:256]
            
            # Remove from BPF map
            del self.bpf["blocked_paths"][path_bytes]
            
            log.info(f"🔓 Removed from kernel block list: {path}")
            return True
            
        except Exception as e:
            log.error(f"Failed to unblock path {path}: {e}")
            return False
    
    def block_ip(self, ip_str: str) -> bool:
        """
        Add an IP address to the kernel block list.
        Future connection attempts to this IP will be denied.
        """
        if not self.enabled:
            return False
        
        try:
            # Convert IP string to 32-bit integer
            ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
            
            # Update BPF map: ip -> 1 (block)
            self.bpf["blocked_ips"][ip_int] = 1
            
            log.info(f"✅ Added to kernel IP block list: {ip_str}")
            return True
            
        except Exception as e:
            log.error(f"Failed to block IP {ip_str}: {e}")
            return False
    
    def unblock_ip(self, ip_str: str) -> bool:
        """Remove an IP from the kernel block list."""
        if not self.enabled:
            return False
        
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
            del self.bpf["blocked_ips"][ip_int]
            
            log.info(f"🔓 Removed from kernel IP block list: {ip_str}")
            return True
            
        except Exception as e:
            log.error(f"Failed to unblock IP {ip_str}: {e}")
            return False
    
    def block_pid(self, pid: int) -> bool:
        """
        Add a PID to the kernel kill list.
        This process will be denied on next syscall.
        """
        if not self.enabled:
            return False
        
        # Safety check: never block init or kernel threads
        if pid <= 2:
            log.error(f"SAFETY BLOCK: Refusing to block PID {pid}")
            return False
        
        try:
            self.bpf["blocked_pids"][pid] = 1
            log.info(f"✅ Added to kernel PID block list: {pid}")
            return True
            
        except Exception as e:
            log.error(f"Failed to block PID {pid}: {e}")
            return False
    
    def unblock_pid(self, pid: int) -> bool:
        """Remove a PID from the kill list."""
        if not self.enabled:
            return False
        
        try:
            del self.bpf["blocked_pids"][pid]
            log.info(f"🔓 Removed from kernel PID block list: {pid}")
            return True
            
        except Exception as e:
            log.error(f"Failed to unblock PID {pid}: {e}")
            return False
    
    def get_blocked_paths(self) -> list:
        """Returns list of currently blocked paths."""
        if not self.enabled:
            return []
        
        try:
            return [
                path.decode('utf-8', errors='ignore')
                for path in self.bpf["blocked_paths"].keys()
            ]
        except Exception:
            return []
    
    def get_blocked_ips(self) -> list:
        """Returns list of currently blocked IPs."""
        if not self.enabled:
            return []
        
        try:
            return [
                socket.inet_ntoa(struct.pack("!I", ip))
                for ip in self.bpf["blocked_ips"].keys()
            ]
        except Exception:
            return []
    
    def get_blocked_pids(self) -> list:
        """Returns list of currently blocked PIDs."""
        if not self.enabled:
            return []
        
        try:
            return list(self.bpf["blocked_pids"].keys())
        except Exception:
            return []
    
    def clear_all_rules(self):
        """Clear all kernel block rules (emergency reset)."""
        if not self.enabled:
            return
        
        try:
            self.bpf["blocked_paths"].clear()
            self.bpf["blocked_ips"].clear()
            self.bpf["blocked_pids"].clear()
            log.info("🧹 Cleared all kernel block rules")
        except Exception as e:
            log.error(f"Failed to clear rules: {e}")
