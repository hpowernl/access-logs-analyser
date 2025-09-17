"""Performance analysis module for analyzing response times, bandwidth, and optimization opportunities."""

import statistics
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path

from .parser import LogParser
from .log_reader import LogTailer


class PerformanceAnalyzer:
    """Analyzes logs for performance metrics and optimization opportunities."""
    
    def __init__(self):
        self.parser = LogParser()
        
        # Response time tracking
        self.response_times = []
        self.endpoint_response_times = defaultdict(list)
        self.handler_response_times = defaultdict(list)
        self.slow_requests = []
        
        # Bandwidth tracking
        self.total_bytes = 0
        self.bytes_per_endpoint = defaultdict(int)
        self.bytes_per_hour = defaultdict(int)
        self.bytes_per_status = defaultdict(int)
        
        # Request tracking
        self.total_requests = 0
        self.requests_per_endpoint = Counter()
        self.requests_per_hour = defaultdict(int)
        self.requests_per_handler = Counter()
        
        # Cache analysis
        self.cache_hits = defaultdict(int)
        self.cache_misses = defaultdict(int)
        self.cached_response_times = defaultdict(list)
        self.uncached_response_times = defaultdict(list)
        
        # Status code performance
        self.status_response_times = defaultdict(list)
        
        # Geographic performance
        self.country_response_times = defaultdict(list)
        
        # Time-based analysis
        self.hourly_stats = defaultdict(lambda: {
            'requests': 0,
            'response_times': [],
            'bytes': 0,
            'errors': 0
        })
        
    def analyze_file(self, file_path: str, handler_filter: Optional[str] = None):
        """Analyze a single log file for performance metrics."""
        file_path = Path(file_path)
        
        with LogTailer(str(file_path), follow=False) as tailer:
            for line in tailer.tail():
                if not line.strip():
                    continue
                    
                log_entry = self.parser.parse_log_line(line)
                if not log_entry:
                    continue
                
                # Apply handler filter if specified
                if handler_filter and log_entry.get('handler') != handler_filter:
                    continue
                    
                self._analyze_entry(log_entry)
    
    def _analyze_entry(self, log_entry: Dict[str, Any]):
        """Analyze a single log entry for performance metrics."""
        timestamp = log_entry.get('timestamp', datetime.now())
        response_time = log_entry.get('response_time', 0)
        bytes_sent = log_entry.get('bytes_sent', 0)
        status = log_entry.get('status', 0)
        path = log_entry.get('path', '/')
        handler = log_entry.get('handler', 'unknown')
        country = log_entry.get('country', 'unknown')
        method = log_entry.get('method', 'GET')
        
        # Basic tracking
        self.total_requests += 1
        self.total_bytes += bytes_sent
        
        # Response time analysis
        if response_time > 0:
            self.response_times.append(response_time)
            endpoint = f"{method} {path}"
            self.endpoint_response_times[endpoint].append(response_time)
            self.handler_response_times[handler].append(response_time)
            self.status_response_times[status].append(response_time)
            self.country_response_times[country].append(response_time)
            
            # Track slow requests (>2 seconds)
            if response_time > 2.0:
                self.slow_requests.append({
                    'timestamp': timestamp,
                    'path': path,
                    'method': method,
                    'response_time': response_time,
                    'bytes_sent': bytes_sent,
                    'status': status,
                    'handler': handler,
                    'country': country
                })
        
        # Endpoint tracking
        endpoint = f"{method} {path}"
        self.requests_per_endpoint[endpoint] += 1
        self.bytes_per_endpoint[endpoint] += bytes_sent
        self.requests_per_handler[handler] += 1
        
        # Time-based analysis
        hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
        self.requests_per_hour[hour_key] += 1
        self.bytes_per_hour[hour_key] += bytes_sent
        self.hourly_stats[hour_key]['requests'] += 1
        self.hourly_stats[hour_key]['bytes'] += bytes_sent
        if response_time > 0:
            self.hourly_stats[hour_key]['response_times'].append(response_time)
        if status >= 400:
            self.hourly_stats[hour_key]['errors'] += 1
        
        # Cache analysis (based on handler)
        self._analyze_cache_performance(handler, response_time, status)
        
        # Status code performance
        self.bytes_per_status[status] += bytes_sent
    
    def _analyze_cache_performance(self, handler: str, response_time: float, status: int):
        """Analyze cache performance based on handler and response characteristics."""
        if handler == 'varnish':
            # Varnish typically serves cached content
            # Fast response times (< 0.1s) usually indicate cache hits
            if response_time < 0.1 and status == 200:
                self.cache_hits[handler] += 1
                self.cached_response_times[handler].append(response_time)
            else:
                self.cache_misses[handler] += 1
                self.uncached_response_times[handler].append(response_time)
        elif handler == 'phpfpm':
            # PHP-FPM serves dynamic content (cache misses)
            self.cache_misses[handler] += 1
            self.uncached_response_times[handler].append(response_time)
        else:
            # Unknown handler, classify based on response time
            if response_time < 0.05:
                self.cache_hits[handler] += 1
                self.cached_response_times[handler].append(response_time)
            else:
                self.cache_misses[handler] += 1
                self.uncached_response_times[handler].append(response_time)
    
    def get_response_time_stats(self) -> Dict[str, float]:
        """Get comprehensive response time statistics."""
        if not self.response_times:
            return {}
        
        sorted_times = sorted(self.response_times)
        
        return {
            'avg': statistics.mean(self.response_times),
            'median': statistics.median(self.response_times),
            'min': min(self.response_times),
            'max': max(self.response_times),
            'p50': statistics.median(self.response_times),
            'p75': statistics.quantiles(self.response_times, n=4)[2] if len(self.response_times) > 3 else sorted_times[-1],
            'p90': statistics.quantiles(self.response_times, n=10)[8] if len(self.response_times) > 9 else sorted_times[-1],
            'p95': statistics.quantiles(self.response_times, n=20)[18] if len(self.response_times) > 19 else sorted_times[-1],
            'p99': statistics.quantiles(self.response_times, n=100)[98] if len(self.response_times) > 99 else sorted_times[-1],
            'std_dev': statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0
        }
    
    def get_slowest_endpoints(self, limit: int = 10) -> List[Tuple[str, float]]:
        """Get the slowest endpoints by average response time."""
        endpoint_avg_times = []
        
        for endpoint, times in self.endpoint_response_times.items():
            if len(times) >= 5:  # Only consider endpoints with significant traffic
                avg_time = statistics.mean(times)
                endpoint_avg_times.append((endpoint, avg_time))
        
        return sorted(endpoint_avg_times, key=lambda x: x[1], reverse=True)[:limit]
    
    def get_bandwidth_stats(self) -> Dict[str, Any]:
        """Get bandwidth usage statistics."""
        if self.total_requests == 0:
            return {}
        
        # Calculate peak hour
        peak_hour = max(self.bytes_per_hour.items(), key=lambda x: x[1]) if self.bytes_per_hour else (None, 0)
        
        return {
            'total_bytes': self.total_bytes,
            'total_mb': self.total_bytes / (1024 * 1024),
            'total_gb': self.total_bytes / (1024 * 1024 * 1024),
            'avg_per_request': self.total_bytes / self.total_requests,
            'peak_hour': peak_hour[0].strftime('%Y-%m-%d %H:00') if peak_hour[0] else 'N/A',
            'peak_hour_gb': peak_hour[1] / (1024 * 1024 * 1024) if peak_hour[1] else 0,
            'requests_per_gb': self.total_requests / max(self.total_bytes / (1024 * 1024 * 1024), 0.001)
        }
    
    def get_cache_stats(self, handler: str) -> Dict[str, Any]:
        """Get cache performance statistics for a specific handler."""
        hits = self.cache_hits.get(handler, 0)
        misses = self.cache_misses.get(handler, 0)
        total = hits + misses
        
        if total == 0:
            return {
                'hit_ratio': 0,
                'hits': 0,
                'misses': 0,
                'total': 0,
                'cached_avg': 0,
                'uncached_avg': 0
            }
        
        cached_times = self.cached_response_times.get(handler, [])
        uncached_times = self.uncached_response_times.get(handler, [])
        
        return {
            'hit_ratio': (hits / total) * 100,
            'hits': hits,
            'misses': misses,
            'total': total,
            'cached_avg': statistics.mean(cached_times) if cached_times else 0,
            'uncached_avg': statistics.mean(uncached_times) if uncached_times else 0,
            'cache_speedup': (
                statistics.mean(uncached_times) / max(statistics.mean(cached_times), 0.001)
                if cached_times and uncached_times else 1
            )
        }
    
    def get_handler_performance(self) -> Dict[str, Dict[str, Any]]:
        """Get performance statistics by handler."""
        handler_stats = {}
        
        for handler, times in self.handler_response_times.items():
            if times:
                handler_stats[handler] = {
                    'requests': self.requests_per_handler[handler],
                    'avg_response_time': statistics.mean(times),
                    'median_response_time': statistics.median(times),
                    'p95_response_time': (
                        statistics.quantiles(times, n=20)[18] 
                        if len(times) > 19 else max(times)
                    ),
                    'slow_requests': len([t for t in times if t > 2.0]),
                    'cache_stats': self.get_cache_stats(handler)
                }
        
        return handler_stats
    
    def get_peak_hours_analysis(self) -> List[Dict[str, Any]]:
        """Analyze peak traffic hours and their performance impact."""
        hourly_analysis = []
        
        for hour, stats in self.hourly_stats.items():
            if stats['requests'] > 0:
                error_rate = (stats['errors'] / stats['requests']) * 100
                avg_response_time = (
                    statistics.mean(stats['response_times']) 
                    if stats['response_times'] else 0
                )
                
                hourly_analysis.append({
                    'hour': hour.strftime('%Y-%m-%d %H:00'),
                    'requests': stats['requests'],
                    'avg_response_time': avg_response_time,
                    'total_gb': stats['bytes'] / (1024 * 1024 * 1024),
                    'error_rate': error_rate,
                    'requests_per_minute': stats['requests'] / 60
                })
        
        # Sort by request count to identify peak hours
        return sorted(hourly_analysis, key=lambda x: x['requests'], reverse=True)
    
    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        # Check for slow endpoints
        slow_endpoints = self.get_slowest_endpoints(5)
        if slow_endpoints:
            recommendations.append({
                'category': 'Slow Endpoints',
                'priority': 'High',
                'issue': f'Found {len(slow_endpoints)} slow endpoints',
                'recommendation': 'Optimize database queries, add caching, or implement pagination',
                'endpoints': [f"{ep} ({time:.3f}s)" for ep, time in slow_endpoints[:3]]
            })
        
        # Check cache performance
        overall_cache_stats = {}
        for handler in self.cache_hits.keys():
            stats = self.get_cache_stats(handler)
            if stats['total'] > 100:  # Only consider handlers with significant traffic
                overall_cache_stats[handler] = stats
        
        low_cache_handlers = [
            handler for handler, stats in overall_cache_stats.items()
            if stats['hit_ratio'] < 60
        ]
        
        if low_cache_handlers:
            recommendations.append({
                'category': 'Cache Optimization',
                'priority': 'Medium',
                'issue': f'Low cache hit ratio for handlers: {", ".join(low_cache_handlers)}',
                'recommendation': 'Review cache configuration, increase cache TTL, or implement better cache warming',
                'details': {handler: f"{stats['hit_ratio']:.1f}% hit ratio" 
                          for handler, stats in overall_cache_stats.items() 
                          if handler in low_cache_handlers}
            })
        
        # Check for high error rates during peak hours
        peak_hours = self.get_peak_hours_analysis()[:5]
        high_error_hours = [hour for hour in peak_hours if hour['error_rate'] > 10]
        
        if high_error_hours:
            recommendations.append({
                'category': 'Error Rate',
                'priority': 'High',
                'issue': f'High error rates during {len(high_error_hours)} peak hours',
                'recommendation': 'Investigate capacity issues, implement rate limiting, or scale resources',
                'hours': [f"{hour['hour']}: {hour['error_rate']:.1f}% errors" 
                         for hour in high_error_hours[:3]]
            })
        
        # Check bandwidth usage
        bandwidth_stats = self.get_bandwidth_stats()
        if bandwidth_stats.get('avg_per_request', 0) > 1024 * 1024:  # > 1MB per request
            recommendations.append({
                'category': 'Bandwidth Optimization',
                'priority': 'Medium',
                'issue': f'High average response size: {bandwidth_stats["avg_per_request"]/1024:.1f} KB',
                'recommendation': 'Enable gzip compression, optimize images, or implement content CDN',
                'current_usage': f"{bandwidth_stats['total_gb']:.2f} GB total"
            })
        
        # Check response time distribution
        rt_stats = self.get_response_time_stats()
        if rt_stats.get('p95', 0) > 5.0:  # 95th percentile > 5 seconds
            recommendations.append({
                'category': 'Response Time',
                'priority': 'High',
                'issue': f'95th percentile response time: {rt_stats["p95"]:.2f}s',
                'recommendation': 'Profile slow requests, optimize database queries, or add horizontal scaling',
                'stats': f"Avg: {rt_stats['avg']:.2f}s, Max: {rt_stats['max']:.2f}s"
            })
        
        return recommendations
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        rt_stats = self.get_response_time_stats()
        bandwidth_stats = self.get_bandwidth_stats()
        
        return {
            'total_requests': self.total_requests,
            'response_time_stats': rt_stats,
            'bandwidth_stats': bandwidth_stats,
            'slow_requests': len(self.slow_requests),
            'handlers_analyzed': len(self.handler_response_times),
            'endpoints_analyzed': len(self.endpoint_response_times),
            'peak_rps': max(
                [stats['requests'] / 3600 for stats in self.hourly_stats.values()],
                default=0
            ),
            'optimization_opportunities': len(self.get_optimization_recommendations())
        }
    
    def export_performance_report(self, output_file: str):
        """Export detailed performance report to JSON."""
        import json
        
        # Get top endpoints by various metrics
        top_endpoints_by_requests = self.requests_per_endpoint.most_common(20)
        top_endpoints_by_bytes = sorted(
            self.bytes_per_endpoint.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:20]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': self.get_performance_summary(),
            'response_time_stats': self.get_response_time_stats(),
            'bandwidth_stats': self.get_bandwidth_stats(),
            'handler_performance': self.get_handler_performance(),
            'peak_hours': self.get_peak_hours_analysis()[:24],  # Top 24 hours
            'slowest_endpoints': self.get_slowest_endpoints(20),
            'top_endpoints_by_requests': top_endpoints_by_requests,
            'top_endpoints_by_bytes': top_endpoints_by_bytes,
            'slow_requests': [
                {
                    'timestamp': req['timestamp'].isoformat() if req['timestamp'] else None,
                    'path': req['path'],
                    'method': req['method'],
                    'response_time': req['response_time'],
                    'bytes_sent': req['bytes_sent'],
                    'status': req['status'],
                    'handler': req['handler']
                } for req in sorted(self.slow_requests, key=lambda x: x['response_time'], reverse=True)[:100]
            ],
            'optimization_recommendations': self.get_optimization_recommendations()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
