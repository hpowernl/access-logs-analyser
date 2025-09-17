"""JSON log parsing and normalization module."""

import json
import ipaddress
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from user_agents import parse as parse_user_agent

from .config import BOT_SIGNATURES


class LogParser:
    """Parses and normalizes JSON log entries."""
    
    def __init__(self):
        self.bot_signatures = {sig.lower() for sig in BOT_SIGNATURES}
    
    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single JSON log line and normalize fields."""
        try:
            raw_log = json.loads(line.strip())
            return self.normalize_log(raw_log)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            # Skip invalid log lines
            return None
    
    def normalize_log(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize log entry fields for Nginx JSON format."""
        normalized = {}
        
        # Time parsing - Nginx uses 'time' field
        time_str = raw_log.get('time', '')
        normalized['timestamp'] = self._parse_timestamp(time_str)
        
        # IP address - Nginx uses 'remote_addr'
        ip_str = raw_log.get('remote_addr', '')
        normalized['ip'] = self._parse_ip(ip_str)
        
        # User agent parsing
        ua_str = raw_log.get('user_agent', '')
        normalized['user_agent'] = ua_str
        normalized['parsed_ua'] = self._parse_user_agent(ua_str)
        normalized['is_bot'] = self._is_bot(ua_str)
        
        # HTTP details - parse from 'request' field (e.g., "POST /graphql HTTP/1.1")
        request_str = raw_log.get('request', '')
        method, path = self._parse_request_string(request_str)
        normalized['method'] = method
        normalized['path'] = path
        
        normalized['status'] = int(raw_log.get('status', 0))
        normalized['referer'] = raw_log.get('referer', '')
        
        # Response details - Nginx specific fields
        normalized['response_time'] = float(raw_log.get('request_time', 0))
        normalized['bytes_sent'] = int(raw_log.get('body_bytes_sent', 0))
        
        # Geographic info - Nginx provides country
        normalized['country'] = raw_log.get('country', '')
        
        # Additional Nginx-specific fields
        normalized['host'] = raw_log.get('host', '')
        normalized['server_name'] = raw_log.get('server_name', '')
        normalized['handler'] = raw_log.get('handler', '')
        normalized['port'] = raw_log.get('port', '')
        normalized['ssl_protocol'] = raw_log.get('ssl_protocol', '')
        normalized['ssl_cipher'] = raw_log.get('ssl_cipher', '')
        normalized['remote_user'] = raw_log.get('remote_user', '')
        
        # Original raw log for reference
        normalized['raw'] = raw_log
        
        return normalized
    
    def _parse_request_string(self, request_str: str) -> Tuple[str, str]:
        """Parse HTTP request string like 'POST /graphql HTTP/1.1'."""
        if not request_str:
            return 'GET', '/'
            
        parts = request_str.split(' ')
        if len(parts) >= 2:
            method = parts[0]
            path = parts[1]
            return method, path
        
        return 'GET', '/'
    
    def _parse_timestamp(self, time_str: str) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        if not time_str:
            return datetime.now()
            
        # Common timestamp formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',  # ISO format with microseconds
            '%Y-%m-%dT%H:%M:%SZ',     # ISO format
            '%Y-%m-%d %H:%M:%S',      # Standard format
            '%d/%b/%Y:%H:%M:%S %z',   # Apache/Nginx format
            '%Y-%m-%dT%H:%M:%S%z',    # ISO with timezone
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(time_str, fmt)
            except ValueError:
                continue
                
        # Try parsing as Unix timestamp
        try:
            return datetime.fromtimestamp(float(time_str))
        except (ValueError, TypeError):
            pass
            
        return datetime.now()
    
    def _parse_ip(self, ip_str: str) -> Optional[ipaddress.IPv4Address]:
        """Parse IP address."""
        if not ip_str or ip_str == '-':
            return None
            
        try:
            # Handle X-Forwarded-For format (take first IP)
            if ',' in ip_str:
                ip_str = ip_str.split(',')[0].strip()
            
            return ipaddress.ip_address(ip_str)
        except ValueError:
            return None
    
    def _parse_user_agent(self, ua_str: str) -> Dict[str, str]:
        """Parse user agent string."""
        if not ua_str or ua_str == '-':
            return {'browser': 'Unknown', 'os': 'Unknown', 'device': 'Unknown'}
        
        try:
            parsed = parse_user_agent(ua_str)
            return {
                'browser': f"{parsed.browser.family} {parsed.browser.version_string}",
                'os': f"{parsed.os.family} {parsed.os.version_string}",
                'device': parsed.device.family if parsed.device.family != 'Other' else 'Desktop'
            }
        except Exception:
            return {'browser': 'Unknown', 'os': 'Unknown', 'device': 'Unknown'}
    
    def _is_bot(self, ua_str: str) -> bool:
        """Detect if user agent is a bot."""
        if not ua_str:
            return False
            
        ua_lower = ua_str.lower()
        return any(bot_sig in ua_lower for bot_sig in self.bot_signatures)
    
    def get_status_category(self, status: int) -> str:
        """Categorize HTTP status code."""
        if 200 <= status < 300:
            return 'success'
        elif 300 <= status < 400:
            return 'redirect'
        elif 400 <= status < 500:
            return 'client_error'
        elif 500 <= status < 600:
            return 'server_error'
        else:
            return 'other'
