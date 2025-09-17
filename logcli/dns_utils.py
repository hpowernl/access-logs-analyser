"""DNS utilities for reverse DNS lookups."""

import subprocess
import socket
from typing import Dict, Optional
from functools import lru_cache


class DNSLookup:
    """Handles DNS lookups with caching."""
    
    def __init__(self):
        self._cache: Dict[str, str] = {}
    
    @lru_cache(maxsize=1000)
    def reverse_dns_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup for an IP address.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Hostname or original IP if lookup fails
        """
        if not ip or ip == 'Unknown':
            return ip
            
        try:
            # First try Python's socket library (faster)
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            try:
                # Fallback to dig command if available
                result = subprocess.run(
                    ['dig', '-x', ip, '+short'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0 and result.stdout.strip():
                    hostname = result.stdout.strip().rstrip('.')
                    return hostname if hostname else ip
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
        
        return ip
    
    def bulk_reverse_dns_lookup(self, ips: list) -> Dict[str, str]:
        """Perform reverse DNS lookup for multiple IPs.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dictionary mapping IP to hostname
        """
        results = {}
        for ip in ips:
            results[ip] = self.reverse_dns_lookup(ip)
        return results


# Global instance for use across the application
dns_lookup = DNSLookup()
