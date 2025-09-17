"""Filtering logic for log entries."""

import re
import ipaddress
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Tuple
from .config import DEFAULT_FILTERS


class LogFilter:
    """Filters log entries based on various criteria."""
    
    def __init__(self):
        self.filters = DEFAULT_FILTERS.copy()
        self._compiled_path_patterns = []
        self._ip_networks = []
        self._update_compiled_patterns()
    
    def update_filters(self, **kwargs) -> None:
        """Update filter settings."""
        self.filters.update(kwargs)
        self._update_compiled_patterns()
    
    def _update_compiled_patterns(self) -> None:
        """Compile regex patterns and IP networks for performance."""
        # Compile path patterns
        self._compiled_path_patterns = []
        for pattern in self.filters.get('paths', []):
            try:
                self._compiled_path_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                # Skip invalid regex patterns
                pass
        
        # Parse IP networks
        self._ip_networks = []
        for ip_range in self.filters.get('ip_ranges', []):
            try:
                self._ip_networks.append(ipaddress.ip_network(ip_range, strict=False))
            except ValueError:
                # Skip invalid IP ranges
                pass
    
    def should_include(self, log_entry: Dict[str, Any]) -> bool:
        """Check if a log entry should be included based on current filters."""
        
        # Country filter
        if self.filters.get('countries'):
            country = log_entry.get('country', '').upper()
            if country not in [c.upper() for c in self.filters['countries']]:
                return False
        
        # Status code filter
        if self.filters.get('status_codes'):
            status = log_entry.get('status', 0)
            if status not in self.filters['status_codes']:
                return False
        
        # Bot filter
        if self.filters.get('exclude_bots', False):
            if log_entry.get('is_bot', False):
                return False
        
        # IP range filter
        if self._ip_networks:
            ip = log_entry.get('ip')
            if ip and not any(ip in network for network in self._ip_networks):
                return False
        
        # Time range filter
        time_range = self.filters.get('time_range')
        if time_range:
            timestamp = log_entry.get('timestamp')
            if timestamp:
                start_time, end_time = time_range
                
                # Handle timezone-aware vs naive datetime comparison
                if timestamp.tzinfo is not None and start_time and start_time.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=None)
                elif timestamp.tzinfo is None and start_time and start_time.tzinfo is not None:
                    start_time = start_time.replace(tzinfo=None)
                if timestamp.tzinfo is not None and end_time and end_time.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=None)
                elif timestamp.tzinfo is None and end_time and end_time.tzinfo is not None:
                    end_time = end_time.replace(tzinfo=None)
                
                # Apply time range filter
                if start_time and end_time:
                    if not (start_time <= timestamp <= end_time):
                        return False
                elif start_time:
                    if timestamp < start_time:
                        return False
                elif end_time:
                    if timestamp > end_time:
                        return False
        
        # HTTP method filter
        if self.filters.get('methods'):
            method = log_entry.get('method', '').upper()
            if method not in [m.upper() for m in self.filters['methods']]:
                return False
        
        # Path pattern filter
        if self._compiled_path_patterns:
            path = log_entry.get('path', '')
            if not any(pattern.search(path) for pattern in self._compiled_path_patterns):
                return False
        
        return True
    
    def get_active_filters(self) -> Dict[str, Any]:
        """Get currently active filters (non-empty ones)."""
        active = {}
        for key, value in self.filters.items():
            if value:  # Non-empty list, non-None, non-False
                active[key] = value
        return active
    
    def clear_filters(self) -> None:
        """Clear all filters."""
        self.filters = DEFAULT_FILTERS.copy()
        self._update_compiled_patterns()
    
    def add_country_filter(self, countries: List[str]) -> None:
        """Add countries to filter."""
        current = set(self.filters.get('countries', []))
        current.update(countries)
        self.filters['countries'] = list(current)
    
    def remove_country_filter(self, countries: List[str]) -> None:
        """Remove countries from filter."""
        current = set(self.filters.get('countries', []))
        current.difference_update(countries)
        self.filters['countries'] = list(current)
    
    def add_status_filter(self, status_codes: List[int]) -> None:
        """Add status codes to filter."""
        current = set(self.filters.get('status_codes', []))
        current.update(status_codes)
        self.filters['status_codes'] = list(current)
    
    def remove_status_filter(self, status_codes: List[int]) -> None:
        """Remove status codes from filter."""
        current = set(self.filters.get('status_codes', []))
        current.difference_update(status_codes)
        self.filters['status_codes'] = list(current)
    
    def toggle_bot_filter(self) -> None:
        """Toggle bot exclusion filter."""
        self.filters['exclude_bots'] = not self.filters.get('exclude_bots', False)
    
    def set_time_range(self, start_time: Optional[datetime], end_time: Optional[datetime]) -> None:
        """Set time range filter."""
        if start_time and end_time:
            self.filters['time_range'] = (start_time, end_time)
        else:
            self.filters['time_range'] = None
    
    def add_ip_range(self, ip_range: str) -> None:
        """Add IP range to filter."""
        current = self.filters.get('ip_ranges', [])
        if ip_range not in current:
            current.append(ip_range)
            self.filters['ip_ranges'] = current
            self._update_compiled_patterns()
    
    def remove_ip_range(self, ip_range: str) -> None:
        """Remove IP range from filter."""
        current = self.filters.get('ip_ranges', [])
        if ip_range in current:
            current.remove(ip_range)
            self.filters['ip_ranges'] = current
            self._update_compiled_patterns()
    
    def add_path_pattern(self, pattern: str) -> None:
        """Add path pattern to filter."""
        current = self.filters.get('paths', [])
        if pattern not in current:
            current.append(pattern)
            self.filters['paths'] = current
            self._update_compiled_patterns()
    
    def remove_path_pattern(self, pattern: str) -> None:
        """Remove path pattern from filter."""
        current = self.filters.get('paths', [])
        if pattern in current:
            current.remove(pattern)
            self.filters['paths'] = current
            self._update_compiled_patterns()


class FilterPresets:
    """Predefined filter presets for common use cases."""
    
    @staticmethod
    def errors_only() -> Dict[str, Any]:
        """Filter to show only error responses (4xx, 5xx)."""
        return {
            'status_codes': list(range(400, 600)),
            'countries': [],
            'exclude_bots': False,
            'ip_ranges': [],
            'time_range': None,
            'methods': [],
            'paths': []
        }
    
    @staticmethod
    def success_only() -> Dict[str, Any]:
        """Filter to show only successful responses (2xx)."""
        return {
            'status_codes': list(range(200, 300)),
            'countries': [],
            'exclude_bots': False,
            'ip_ranges': [],
            'time_range': None,
            'methods': [],
            'paths': []
        }
    
    @staticmethod
    def no_bots() -> Dict[str, Any]:
        """Filter to exclude all bot traffic."""
        return {
            'status_codes': [],
            'countries': [],
            'exclude_bots': True,
            'ip_ranges': [],
            'time_range': None,
            'methods': [],
            'paths': []
        }
    
    @staticmethod
    def api_only() -> Dict[str, Any]:
        """Filter to show only API endpoints."""
        return {
            'status_codes': [],
            'countries': [],
            'exclude_bots': False,
            'ip_ranges': [],
            'time_range': None,
            'methods': [],
            'paths': [r'^/api/.*']
        }
    
    @staticmethod
    def high_response_time(threshold: float = 1.0) -> Dict[str, Any]:
        """Filter for requests with high response times."""
        # Note: This would need to be implemented in the aggregator
        # as it requires access to response_time values
        return DEFAULT_FILTERS.copy()
    
    @staticmethod
    def recent_activity(hours: int = 1) -> Dict[str, Any]:
        """Filter for recent activity within specified hours."""
        from datetime import datetime, timedelta
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        return {
            'status_codes': [],
            'countries': [],
            'exclude_bots': False,
            'ip_ranges': [],
            'time_range': (start_time, end_time),
            'methods': [],
            'paths': []
        }


def create_filter_from_preset(preset_name: str, **kwargs) -> LogFilter:
    """Create a LogFilter instance from a preset."""
    log_filter = LogFilter()
    
    preset_methods = {
        'errors_only': FilterPresets.errors_only,
        'success_only': FilterPresets.success_only,
        'no_bots': FilterPresets.no_bots,
        'api_only': FilterPresets.api_only,
        'recent_activity': FilterPresets.recent_activity,
    }
    
    if preset_name in preset_methods:
        if preset_name == 'recent_activity' and 'hours' in kwargs:
            filters = preset_methods[preset_name](kwargs['hours'])
        else:
            filters = preset_methods[preset_name]()
        
        log_filter.update_filters(**filters)
    
    return log_filter
