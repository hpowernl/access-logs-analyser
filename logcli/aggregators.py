"""Data aggregation and statistics module."""

import statistics
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional, Deque
from .config import TIMELINE_SETTINGS


class TimelineAggregator:
    """Manages timeline data with sliding windows."""
    
    def __init__(self, granularity: str = 'minute', window_size: int = 60):
        self.granularity = granularity
        self.window_size = window_size
        self.timeline = defaultdict(lambda: deque(maxlen=window_size))
        self.response_times = defaultdict(list)
        self.bytes_sent = defaultdict(list)
        
    def add_entry(self, log_entry: Dict[str, Any]) -> None:
        """Add a log entry to the timeline."""
        timestamp = log_entry.get('timestamp')
        if not timestamp:
            return
            
        time_key = self._get_time_key(timestamp)
        
        # Add to hit counter
        self.timeline[time_key].append(1)
        
        # Track response times
        response_time = log_entry.get('response_time', 0)
        if response_time > 0:
            self.response_times[time_key].append(response_time)
            
        # Track bytes sent
        bytes_sent = log_entry.get('bytes_sent', 0) or log_entry.get('body_bytes_sent', 0)
        if bytes_sent > 0:
            self.bytes_sent[time_key].append(bytes_sent)
    
    def _get_time_key(self, timestamp: datetime) -> datetime:
        """Get the time key based on granularity."""
        if self.granularity == 'minute':
            return timestamp.replace(second=0, microsecond=0)
        elif self.granularity == 'hour':
            return timestamp.replace(minute=0, second=0, microsecond=0)
        elif self.granularity == 'day':
            return timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            return timestamp.replace(second=0, microsecond=0)
    
    def get_hits_timeline(self) -> Dict[datetime, int]:
        """Get hits per time unit."""
        return {time_key: sum(hits) for time_key, hits in self.timeline.items()}
    
    def get_response_time_stats(self) -> Dict[datetime, Dict[str, float]]:
        """Get response time statistics per time unit."""
        stats = {}
        for time_key, times in self.response_times.items():
            if times:
                stats[time_key] = {
                    'avg': statistics.mean(times),
                    'max': max(times),
                    'min': min(times),
                    'median': statistics.median(times),
                    'p95': statistics.quantiles(times, n=20)[18] if len(times) > 1 else times[0],
                    'p99': statistics.quantiles(times, n=100)[98] if len(times) > 1 else times[0]
                }
        return stats
    
    def get_bandwidth_timeline(self) -> Dict[datetime, int]:
        """Get total bytes sent per time unit."""
        return {time_key: sum(bytes_list) for time_key, bytes_list in self.bytes_sent.items()}
    
    def clear_old_data(self, cutoff_time: datetime) -> None:
        """Remove data older than cutoff time."""
        keys_to_remove = [k for k in self.timeline.keys() if k < cutoff_time]
        for key in keys_to_remove:
            del self.timeline[key]
            if key in self.response_times:
                del self.response_times[key]
            if key in self.bytes_sent:
                del self.bytes_sent[key]


class StatisticsAggregator:
    """Aggregates various statistics from log entries."""
    
    def __init__(self):
        # Basic counters
        self.hits_per_country = Counter()
        self.hits_per_status = Counter()
        self.hits_per_ip = Counter()
        self.hits_per_user_agent = Counter()
        self.hits_per_browser = Counter()
        self.hits_per_os = Counter()
        self.hits_per_device = Counter()
        self.hits_per_method = Counter()
        self.hits_per_path = Counter()
        self.hits_per_referer = Counter()
        
        # Bot vs human traffic
        self.bot_traffic = Counter()  # bot vs human
        self.bot_types = Counter()    # specific bot types
        
        # Status code categories
        self.status_categories = Counter()
        
        # Response time tracking
        self.response_times = []
        self.slow_requests = []  # requests > threshold
        
        # Bandwidth tracking
        self.total_bytes = 0
        self.bytes_per_status = Counter()
        
        # Unique visitors (based on IP)
        self.unique_ips = set()
        
        # Error tracking
        self.error_details = defaultdict(list)
        
        # Timeline aggregator
        self.timeline = TimelineAggregator()
        
        # Total request count
        self.total_requests = 0
        
        # Time range tracking
        self.earliest_timestamp = None
        self.latest_timestamp = None
        
    def add_entry(self, log_entry: Dict[str, Any]) -> None:
        """Add a log entry to all aggregators."""
        self.total_requests += 1
        
        # Track time range
        timestamp = log_entry.get('timestamp')
        if timestamp:
            if self.earliest_timestamp is None or timestamp < self.earliest_timestamp:
                self.earliest_timestamp = timestamp
            if self.latest_timestamp is None or timestamp > self.latest_timestamp:
                self.latest_timestamp = timestamp
        
        # Basic aggregations
        self.hits_per_country[log_entry.get('country', 'Unknown')] += 1
        self.hits_per_status[log_entry.get('status', 0)] += 1
        self.hits_per_ip[str(log_entry.get('ip', 'Unknown'))] += 1
        self.hits_per_method[log_entry.get('method', 'Unknown')] += 1
        self.hits_per_path[log_entry.get('path', 'Unknown')] += 1
        self.hits_per_referer[log_entry.get('referer', 'Unknown')] += 1
        
        # User agent aggregations
        user_agent = log_entry.get('user_agent', 'Unknown')
        self.hits_per_user_agent[user_agent] += 1
        
        parsed_ua = log_entry.get('parsed_ua', {})
        self.hits_per_browser[parsed_ua.get('browser', 'Unknown')] += 1
        self.hits_per_os[parsed_ua.get('os', 'Unknown')] += 1
        self.hits_per_device[parsed_ua.get('device', 'Unknown')] += 1
        
        # Bot tracking
        is_bot = log_entry.get('is_bot', False)
        self.bot_traffic['Bot' if is_bot else 'Human'] += 1
        
        if is_bot:
            # Extract bot type from user agent
            ua_lower = (user_agent or "").lower()
            if 'googlebot' in ua_lower:
                self.bot_types['Googlebot'] += 1
            elif 'bingbot' in ua_lower:
                self.bot_types['Bingbot'] += 1
            elif 'crawler' in ua_lower or 'spider' in ua_lower:
                self.bot_types['Crawler/Spider'] += 1
            else:
                self.bot_types['Other Bot'] += 1
        
        # Status code categories
        status = log_entry.get('status', 0)
        if 200 <= status < 300:
            self.status_categories['Success'] += 1
        elif 300 <= status < 400:
            self.status_categories['Redirect'] += 1
        elif 400 <= status < 500:
            self.status_categories['Client Error'] += 1
        elif 500 <= status < 600:
            self.status_categories['Server Error'] += 1
        else:
            self.status_categories['Other'] += 1
        
        # Response time tracking
        response_time = log_entry.get('response_time', 0)
        if response_time > 0:
            self.response_times.append(response_time)
            if response_time > 1.0:  # Slow request threshold
                self.slow_requests.append({
                    'timestamp': log_entry.get('timestamp'),
                    'path': log_entry.get('path'),
                    'response_time': response_time,
                    'ip': str(log_entry.get('ip', ''))
                })
        
        # Bandwidth tracking
        bytes_sent = log_entry.get('bytes_sent', 0) or log_entry.get('body_bytes_sent', 0)
        if bytes_sent > 0:
            self.total_bytes += bytes_sent
            self.bytes_per_status[status] += bytes_sent
        
        # Unique visitors
        ip = log_entry.get('ip') or log_entry.get('remote_addr')
        if ip:
            self.unique_ips.add(str(ip))
        
        # Error tracking
        if status >= 400:
            self.error_details[status].append({
                'timestamp': log_entry.get('timestamp'),
                'path': log_entry.get('path'),
                'ip': str(log_entry.get('ip', '')),
                'user_agent': user_agent
            })
        
        # Add to timeline
        self.timeline.add_entry(log_entry)
    
    def get_top_n(self, counter: Counter, n: int = 10) -> List[Tuple[str, int]]:
        """Get top N items from a counter."""
        return counter.most_common(n)
    
    def get_response_time_stats(self) -> Dict[str, float]:
        """Get response time statistics."""
        if not self.response_times:
            return {}
            
        return {
            'avg': statistics.mean(self.response_times),
            'max': max(self.response_times),
            'min': min(self.response_times),
            'median': statistics.median(self.response_times),
            'p95': statistics.quantiles(self.response_times, n=20)[18] if len(self.response_times) > 1 else self.response_times[0],
            'p99': statistics.quantiles(self.response_times, n=100)[98] if len(self.response_times) > 1 else self.response_times[0]
        }
    
    def get_error_rate(self) -> float:
        """Calculate overall error rate (4xx + 5xx)."""
        if self.total_requests == 0:
            return 0.0
            
        errors = sum(count for status, count in self.hits_per_status.items() if status >= 400)
        return (errors / self.total_requests) * 100
    
    def get_bandwidth_stats(self) -> Dict[str, Any]:
        """Get bandwidth statistics."""
        if self.total_requests == 0:
            return {}
            
        return {
            'total_bytes': self.total_bytes,
            'avg_bytes_per_request': self.total_bytes / self.total_requests,
            'total_mb': self.total_bytes / (1024 * 1024),
            'total_gb': self.total_bytes / (1024 * 1024 * 1024)
        }
    
    def get_time_range_stats(self) -> Dict[str, Any]:
        """Get time range statistics."""
        if not self.earliest_timestamp or not self.latest_timestamp:
            return {}
        
        time_span = self.latest_timestamp - self.earliest_timestamp
        time_span_seconds = time_span.total_seconds()
        
        return {
            'earliest_timestamp': self.earliest_timestamp,
            'latest_timestamp': self.latest_timestamp,
            'time_span': time_span,
            'time_span_seconds': time_span_seconds,
            'time_span_hours': time_span_seconds / 3600,
            'time_span_days': time_span_seconds / 86400,
            'requests_per_hour': (self.total_requests / (time_span_seconds / 3600)) if time_span_seconds > 0 else 0,
            'requests_per_minute': (self.total_requests / (time_span_seconds / 60)) if time_span_seconds > 0 else 0,
        }
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics."""
        return {
            'total_requests': self.total_requests,
            'unique_visitors': len(self.unique_ips),
            'error_rate': self.get_error_rate(),
            'bot_percentage': (self.bot_traffic.get('Bot', 0) / max(self.total_requests, 1)) * 100,
            'response_time_stats': self.get_response_time_stats(),
            'bandwidth_stats': self.get_bandwidth_stats(),
            'slow_requests_count': len(self.slow_requests),
            'time_range_stats': self.get_time_range_stats()
        }
    
    def reset(self) -> None:
        """Reset all counters and data."""
        self.__init__()


class RealTimeAggregator:
    """Real-time aggregator that maintains sliding windows and live statistics."""
    
    def __init__(self, window_minutes: int = 10):
        self.window_minutes = window_minutes
        self.stats = StatisticsAggregator()
        self.recent_entries: Deque[Tuple[datetime, Dict[str, Any]]] = deque()
        
    def add_entry(self, log_entry: Dict[str, Any]) -> None:
        """Add entry and maintain sliding window."""
        timestamp = log_entry.get('timestamp', datetime.now())
        
        # Add to recent entries
        self.recent_entries.append((timestamp, log_entry))
        
        # Clean old entries
        cutoff_time = datetime.now() - timedelta(minutes=self.window_minutes)
        while self.recent_entries and self.recent_entries[0][0] < cutoff_time:
            self.recent_entries.popleft()
        
        # Rebuild statistics from recent entries
        self.stats.reset()
        for _, entry in self.recent_entries:
            self.stats.add_entry(entry)
    
    def get_current_stats(self) -> StatisticsAggregator:
        """Get current statistics for the sliding window."""
        return self.stats
    
    def get_requests_per_minute(self) -> float:
        """Get current requests per minute rate."""
        if not self.recent_entries:
            return 0.0
            
        time_span = (self.recent_entries[-1][0] - self.recent_entries[0][0]).total_seconds() / 60
        if time_span == 0:
            return len(self.recent_entries)
            
        return len(self.recent_entries) / time_span
