"""Timeline analysis module for attack patterns and traffic trends over time."""

import json
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
import statistics
from rich.console import Console

console = Console()


class TimelineAnalyzer:
    """Analyzes traffic patterns and attack timelines over time."""
    
    def __init__(self, granularity: str = 'minute', window_size: int = 1440):  # 24 hours in minutes
        """Initialize timeline analyzer."""
        self.granularity = granularity
        self.window_size = window_size
        
        # Time-based data structures
        self.timeline_data = defaultdict(lambda: {
            'requests': 0,
            'unique_ips': set(),
            'errors': 0,
            'attacks': 0,
            'response_times': [],
            'bandwidth_bytes': 0,
            'bot_requests': 0,
            'status_codes': Counter(),
            'attack_types': Counter(),
            'top_ips': Counter(),
            'top_paths': Counter(),
            'countries': Counter()
        })
        
        # Attack timeline tracking
        self.attack_timeline = defaultdict(lambda: {
            'sql_injection': 0,
            'xss_attempts': 0,
            'directory_traversal': 0,
            'brute_force': 0,
            'scanning': 0,
            'suspicious_bots': 0
        })
        
        # Traffic pattern analysis
        self.traffic_patterns = {
            'hourly_distribution': defaultdict(int),
            'daily_peaks': [],
            'anomalies': [],
            'trends': {}
        }
        
        # Security incident tracking
        self.security_incidents = []
        self.incident_threshold = 10  # attacks per minute to constitute an incident
        
        # Performance timeline
        self.performance_timeline = defaultdict(lambda: {
            'avg_response_time': 0,
            'p95_response_time': 0,
            'slowest_endpoints': Counter(),
            'error_rate': 0
        })
        
        # Initialize attack patterns
        self._init_attack_patterns()
    
    def _init_attack_patterns(self):
        """Initialize attack detection patterns."""
        self.attack_patterns = {
            'sql_injection': [
                r'union.*select', r'or.*1=1', r'drop.*table', r'insert.*into',
                r'update.*set', r'delete.*from', r'exec.*xp_', r'sp_executesql',
                r'information_schema', r'sysobjects', r'@@version'
            ],
            'xss_attempts': [
                r'<script', r'javascript:', r'onerror=', r'onload=', r'alert\(',
                r'document\.cookie', r'eval\(', r'fromcharcode', r'<iframe'
            ],
            'directory_traversal': [
                r'\.\./', r'\.\.\\', r'/etc/passwd', r'/proc/self/environ',
                r'boot\.ini', r'win\.ini', r'system32'
            ],
            'command_injection': [
                r';\s*cat', r';\s*ls', r';\s*id', r';\s*pwd', r';\s*whoami',
                r'\|.*cat', r'\|.*ls', r'`.*`', r'\$\(.*\)'
            ],
            'scanning': [
                r'admin', r'wp-admin', r'phpmyadmin', r'config', r'backup',
                r'\.env', r'\.git', r'\.svn', r'test', r'debug'
            ]
        }
    
    def _get_time_key(self, timestamp: datetime) -> datetime:
        """Get time key based on granularity."""
        if self.granularity == 'minute':
            return timestamp.replace(second=0, microsecond=0)
        elif self.granularity == 'hour':
            return timestamp.replace(minute=0, second=0, microsecond=0)
        elif self.granularity == '5min':
            minute = (timestamp.minute // 5) * 5
            return timestamp.replace(minute=minute, second=0, microsecond=0)
        elif self.granularity == '15min':
            minute = (timestamp.minute // 15) * 15
            return timestamp.replace(minute=minute, second=0, microsecond=0)
        else:
            return timestamp.replace(second=0, microsecond=0)
    
    def analyze_entry(self, log_entry: Dict[str, Any]) -> None:
        """Analyze a single log entry for timeline patterns."""
        timestamp = log_entry.get('timestamp')
        if not timestamp:
            return
        
        time_key = self._get_time_key(timestamp)
        data = self.timeline_data[time_key]
        
        # Basic metrics
        data['requests'] += 1
        ip = log_entry.get('remote_addr', '')
        if ip:
            data['unique_ips'].add(ip)
            data['top_ips'][ip] += 1
        
        # Status code tracking
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        data['status_codes'][status] += 1
        if status >= 400:
            data['errors'] += 1
        
        # Response time tracking
        response_time = log_entry.get('request_time', 0)
        if isinstance(response_time, str):
            try:
                response_time = float(response_time)
            except:
                response_time = 0
        
        if response_time > 0:
            data['response_times'].append(response_time)
        
        # Bandwidth tracking
        bytes_sent = log_entry.get('body_bytes_sent', 0)
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = int(bytes_sent)
            except:
                bytes_sent = 0
        data['bandwidth_bytes'] += bytes_sent
        
        # Bot detection
        if log_entry.get('is_bot', False):
            data['bot_requests'] += 1
        
        # Path tracking
        path = log_entry.get('path', '')
        if path:
            data['top_paths'][path] += 1
        
        # Country tracking
        country = log_entry.get('country', 'Unknown')
        if country and country != '-':
            data['countries'][country] += 1
        
        # Attack detection and timeline tracking
        self._detect_attacks(log_entry, time_key, data)
        
        # Update hourly distribution for pattern analysis
        self.traffic_patterns['hourly_distribution'][timestamp.hour] += 1
    
    def _detect_attacks(self, log_entry: Dict[str, Any], time_key: datetime, data: Dict[str, Any]) -> None:
        """Detect and track attacks in timeline."""
        path = log_entry.get('path', '').lower()
        user_agent = log_entry.get('user_agent', '').lower()
        query_string = log_entry.get('query_string', '').lower()
        referer = log_entry.get('referer', '').lower()
        
        # Combine all text fields for pattern matching
        combined_text = f"{path} {user_agent} {query_string} {referer}"
        
        attack_detected = False
        
        # Check for SQL injection
        import re
        for pattern in self.attack_patterns['sql_injection']:
            if re.search(pattern, combined_text, re.IGNORECASE):
                self.attack_timeline[time_key]['sql_injection'] += 1
                data['attack_types']['sql_injection'] += 1
                data['attacks'] += 1
                attack_detected = True
                break
        
        # Check for XSS
        for pattern in self.attack_patterns['xss_attempts']:
            if re.search(pattern, combined_text, re.IGNORECASE):
                self.attack_timeline[time_key]['xss_attempts'] += 1
                data['attack_types']['xss_attempts'] += 1
                data['attacks'] += 1
                attack_detected = True
                break
        
        # Check for directory traversal
        for pattern in self.attack_patterns['directory_traversal']:
            if re.search(pattern, combined_text, re.IGNORECASE):
                self.attack_timeline[time_key]['directory_traversal'] += 1
                data['attack_types']['directory_traversal'] += 1
                data['attacks'] += 1
                attack_detected = True
                break
        
        # Check for command injection
        for pattern in self.attack_patterns['command_injection']:
            if re.search(pattern, combined_text, re.IGNORECASE):
                self.attack_timeline[time_key]['command_injection'] += 1
                data['attack_types']['command_injection'] += 1
                data['attacks'] += 1
                attack_detected = True
                break
        
        # Check for scanning behavior
        for pattern in self.attack_patterns['scanning']:
            if re.search(pattern, combined_text, re.IGNORECASE):
                self.attack_timeline[time_key]['scanning'] += 1
                data['attack_types']['scanning'] += 1
                data['attacks'] += 1
                attack_detected = True
                break
        
        # Check for brute force (multiple failed logins from same IP)
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        if status in [401, 403] and any(auth in path for auth in ['/login', '/auth', '/admin']):
            self.attack_timeline[time_key]['brute_force'] += 1
            data['attack_types']['brute_force'] += 1
            data['attacks'] += 1
            attack_detected = True
        
        # Check for suspicious bots
        if 'bot' in user_agent and any(bad in user_agent for bad in ['hack', 'exploit', 'scan', 'attack']):
            self.attack_timeline[time_key]['suspicious_bots'] += 1
            data['attack_types']['suspicious_bots'] += 1
            data['attacks'] += 1
            attack_detected = True
        
        # Record security incident if attack threshold exceeded
        if data['attacks'] >= self.incident_threshold:
            self._record_security_incident(time_key, log_entry, data)
    
    def _record_security_incident(self, time_key: datetime, log_entry: Dict[str, Any], data: Dict[str, Any]) -> None:
        """Record a security incident."""
        incident = {
            'timestamp': time_key,
            'attack_count': data['attacks'],
            'attack_types': dict(data['attack_types']),
            'top_attacking_ips': dict(data['top_ips'].most_common(5)),
            'severity': self._calculate_incident_severity(data),
            'affected_paths': dict(data['top_paths'].most_common(5)),
            'countries_involved': dict(data['countries'].most_common(5))
        }
        
        # Avoid duplicate incidents for the same time period
        if not any(inc['timestamp'] == time_key for inc in self.security_incidents):
            self.security_incidents.append(incident)
    
    def _calculate_incident_severity(self, data: Dict[str, Any]) -> str:
        """Calculate incident severity based on attack patterns."""
        attack_count = data['attacks']
        unique_ips = len(data['unique_ips'])
        attack_types = len(data['attack_types'])
        
        # Severity scoring
        severity_score = 0
        severity_score += min(attack_count / 10, 10)  # Attack volume
        severity_score += min(unique_ips / 5, 5)     # IP diversity
        severity_score += attack_types * 2           # Attack variety
        
        if severity_score >= 15:
            return 'Critical'
        elif severity_score >= 10:
            return 'High'
        elif severity_score >= 5:
            return 'Medium'
        else:
            return 'Low'
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect traffic anomalies using statistical analysis."""
        anomalies = []
        
        # Get request counts for each time period
        request_counts = [data['requests'] for data in self.timeline_data.values()]
        
        if len(request_counts) < 10:  # Need sufficient data
            return anomalies
        
        # Calculate statistical thresholds
        mean_requests = statistics.mean(request_counts)
        std_dev = statistics.stdev(request_counts) if len(request_counts) > 1 else 0
        
        # Z-score threshold for anomaly detection
        z_threshold = 2.5
        
        for time_key, data in self.timeline_data.items():
            requests = data['requests']
            
            # Skip if not enough activity
            if requests < 5:
                continue
            
            # Calculate z-score
            if std_dev > 0:
                z_score = abs(requests - mean_requests) / std_dev
                
                if z_score > z_threshold:
                    anomaly_type = 'traffic_spike' if requests > mean_requests else 'traffic_drop'
                    
                    anomalies.append({
                        'timestamp': time_key,
                        'type': anomaly_type,
                        'severity': 'High' if z_score > 3.5 else 'Medium',
                        'z_score': z_score,
                        'requests': requests,
                        'expected_requests': mean_requests,
                        'unique_ips': len(data['unique_ips']),
                        'error_rate': (data['errors'] / requests) * 100 if requests > 0 else 0,
                        'attack_count': data['attacks'],
                        'top_countries': dict(data['countries'].most_common(3))
                    })
        
        # Sort by severity and z-score
        anomalies.sort(key=lambda x: (x['severity'] == 'High', x['z_score']), reverse=True)
        return anomalies
    
    def get_timeline_summary(self) -> Dict[str, Any]:
        """Get comprehensive timeline analysis summary."""
        if not self.timeline_data:
            return {'error': 'No timeline data available'}
        
        # Calculate overall statistics
        total_requests = sum(data['requests'] for data in self.timeline_data.values())
        total_attacks = sum(data['attacks'] for data in self.timeline_data.values())
        total_errors = sum(data['errors'] for data in self.timeline_data.values())
        
        # Time range analysis
        time_keys = sorted(self.timeline_data.keys())
        time_range = {
            'start': time_keys[0] if time_keys else None,
            'end': time_keys[-1] if time_keys else None,
            'duration_hours': (time_keys[-1] - time_keys[0]).total_seconds() / 3600 if len(time_keys) > 1 else 0
        }
        
        # Peak analysis
        peak_requests = max((data['requests'] for data in self.timeline_data.values()), default=0)
        peak_attacks = max((data['attacks'] for data in self.timeline_data.values()), default=0)
        
        peak_request_time = None
        peak_attack_time = None
        
        for time_key, data in self.timeline_data.items():
            if data['requests'] == peak_requests:
                peak_request_time = time_key
            if data['attacks'] == peak_attacks:
                peak_attack_time = time_key
        
        # Attack type distribution over time
        attack_type_timeline = defaultdict(int)
        for attacks in self.attack_timeline.values():
            for attack_type, count in attacks.items():
                attack_type_timeline[attack_type] += count
        
        # Detect anomalies
        anomalies = self.detect_anomalies()
        
        return {
            'time_range': time_range,
            'total_requests': total_requests,
            'total_attacks': total_attacks,
            'total_errors': total_errors,
            'attack_rate': (total_attacks / total_requests * 100) if total_requests > 0 else 0,
            'error_rate': (total_errors / total_requests * 100) if total_requests > 0 else 0,
            'peak_analysis': {
                'peak_requests': peak_requests,
                'peak_request_time': peak_request_time,
                'peak_attacks': peak_attacks,
                'peak_attack_time': peak_attack_time
            },
            'attack_distribution': dict(attack_type_timeline),
            'security_incidents': len(self.security_incidents),
            'anomalies_detected': len(anomalies),
            'hourly_pattern': dict(self.traffic_patterns['hourly_distribution']),
            'timeline_data_points': len(self.timeline_data)
        }
    
    def get_attack_timeline(self) -> Dict[datetime, Dict[str, Any]]:
        """Get detailed attack timeline data."""
        attack_timeline = {}
        
        for time_key in sorted(self.timeline_data.keys()):
            data = self.timeline_data[time_key]
            attacks = self.attack_timeline[time_key]
            
            if data['attacks'] > 0:  # Only include periods with attacks
                attack_timeline[time_key] = {
                    'total_attacks': data['attacks'],
                    'attack_types': dict(attacks),
                    'unique_attacking_ips': len([ip for ip, count in data['top_ips'].items() if count > 5]),
                    'error_rate': (data['errors'] / data['requests'] * 100) if data['requests'] > 0 else 0,
                    'top_attacking_ips': dict(data['top_ips'].most_common(5)),
                    'targeted_paths': dict(data['top_paths'].most_common(5)),
                    'countries_involved': dict(data['countries'].most_common(3))
                }
        
        return attack_timeline
    
    def get_traffic_patterns(self) -> Dict[str, Any]:
        """Get traffic pattern analysis."""
        patterns = {}
        
        # Hourly distribution analysis
        hourly_dist = self.traffic_patterns['hourly_distribution']
        if hourly_dist:
            peak_hour = max(hourly_dist.items(), key=lambda x: x[1])
            quiet_hour = min(hourly_dist.items(), key=lambda x: x[1])
            
            patterns['hourly_analysis'] = {
                'peak_hour': {'hour': peak_hour[0], 'requests': peak_hour[1]},
                'quiet_hour': {'hour': quiet_hour[0], 'requests': quiet_hour[1]},
                'distribution': dict(hourly_dist)
            }
        
        # Request volume trends
        if self.timeline_data:
            sorted_times = sorted(self.timeline_data.keys())
            request_trend = [self.timeline_data[t]['requests'] for t in sorted_times]
            
            if len(request_trend) > 1:
                # Simple trend analysis
                first_half = request_trend[:len(request_trend)//2]
                second_half = request_trend[len(request_trend)//2:]
                
                first_avg = sum(first_half) / len(first_half)
                second_avg = sum(second_half) / len(second_half)
                
                trend_direction = 'increasing' if second_avg > first_avg else 'decreasing' if second_avg < first_avg else 'stable'
                trend_magnitude = abs(second_avg - first_avg) / first_avg * 100 if first_avg > 0 else 0
                
                patterns['trend_analysis'] = {
                    'direction': trend_direction,
                    'magnitude_percent': trend_magnitude,
                    'first_half_avg': first_avg,
                    'second_half_avg': second_avg
                }
        
        return patterns
    
    def export_timeline_report(self, output_file: str) -> None:
        """Export comprehensive timeline analysis report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_timeline_summary(),
            'attack_timeline': {
                time_key.isoformat(): data 
                for time_key, data in self.get_attack_timeline().items()
            },
            'traffic_patterns': self.get_traffic_patterns(),
            'security_incidents': [
                {
                    **incident,
                    'timestamp': incident['timestamp'].isoformat()
                }
                for incident in self.security_incidents
            ],
            'anomalies': [
                {
                    **anomaly,
                    'timestamp': anomaly['timestamp'].isoformat()
                }
                for anomaly in self.detect_anomalies()
            ],
            'recommendations': self._get_timeline_recommendations()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def _get_timeline_recommendations(self) -> List[Dict[str, Any]]:
        """Generate timeline-based security recommendations."""
        recommendations = []
        summary = self.get_timeline_summary()
        
        # High attack rate recommendation
        if summary['attack_rate'] > 5:  # More than 5% of requests are attacks
            recommendations.append({
                'priority': 'High',
                'category': 'Attack Rate',
                'issue': f'High attack rate detected: {summary["attack_rate"]:.1f}%',
                'recommendation': 'Implement enhanced security monitoring and consider rate limiting',
                'details': f'{summary["total_attacks"]} attacks out of {summary["total_requests"]} requests'
            })
        
        # Security incidents recommendation
        if len(self.security_incidents) > 0:
            critical_incidents = [i for i in self.security_incidents if i['severity'] == 'Critical']
            if critical_incidents:
                recommendations.append({
                    'priority': 'Critical',
                    'category': 'Security Incidents',
                    'issue': f'{len(critical_incidents)} critical security incidents detected',
                    'recommendation': 'Immediate investigation and response required',
                    'incidents': len(self.security_incidents),
                    'details': 'Critical security incidents require immediate attention'
                })
        
        # Anomaly detection recommendation
        anomalies = self.detect_anomalies()
        high_severity_anomalies = [a for a in anomalies if a['severity'] == 'High']
        if high_severity_anomalies:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Traffic Anomalies',
                'issue': f'{len(high_severity_anomalies)} high-severity traffic anomalies',
                'recommendation': 'Investigate unusual traffic patterns for potential issues',
                'details': 'Unusual traffic spikes or drops may indicate problems or attacks'
            })
        
        return recommendations
