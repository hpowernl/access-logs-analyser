"""Anomaly detection module using statistical and machine learning approaches."""

import json
import math
from collections import defaultdict, deque, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Tuple, Optional
import statistics
from rich.console import Console

console = Console()


class AnomalyDetector:
    """Detects traffic anomalies using statistical analysis and pattern recognition."""
    
    def __init__(self, window_size: int = 60, sensitivity: float = 2.5):
        """Initialize anomaly detector."""
        self.window_size = window_size  # Minutes of data to keep in memory
        self.sensitivity = sensitivity   # Z-score threshold for anomaly detection
        
        # Time-series data for anomaly detection
        self.time_series_data = defaultdict(lambda: deque(maxlen=window_size))
        self.baseline_metrics = {}
        
        # Traffic pattern tracking
        self.traffic_patterns = {
            'requests_per_minute': deque(maxlen=window_size),
            'unique_ips_per_minute': deque(maxlen=window_size),
            'error_rate_per_minute': deque(maxlen=window_size),
            'response_time_per_minute': deque(maxlen=window_size),
            'bandwidth_per_minute': deque(maxlen=window_size)
        }
        
        # Anomaly tracking
        self.detected_anomalies = []
        self.anomaly_types = {
            'traffic_spike': 0,
            'traffic_drop': 0,
            'error_spike': 0,
            'response_time_spike': 0,
            'unusual_ip_activity': 0,
            'bandwidth_anomaly': 0,
            'geographic_anomaly': 0,
            'user_agent_anomaly': 0,
            'attack_pattern_anomaly': 0
        }
        
        # Behavioral baselines
        self.behavioral_baselines = {
            'hourly_patterns': defaultdict(list),
            'daily_patterns': defaultdict(list),
            'ip_behavior': defaultdict(lambda: {
                'request_intervals': [],
                'paths_accessed': set(),
                'user_agents': set(),
                'countries': set()
            }),
            'path_popularity': Counter(),
            'user_agent_popularity': Counter()
        }
        
        # Current minute aggregation
        self.current_minute_data = {
            'timestamp': None,
            'requests': 0,
            'unique_ips': set(),
            'errors': 0,
            'response_times': [],
            'bandwidth': 0,
            'countries': Counter(),
            'user_agents': Counter(),
            'paths': Counter(),
            'ips': Counter()
        }
        
        # Pattern learning
        self.learned_patterns = {
            'normal_request_patterns': set(),
            'normal_ip_behaviors': set(),
            'normal_user_agents': set(),
            'suspicious_patterns': set()
        }
    
    def analyze_entry(self, log_entry: Dict[str, Any]) -> None:
        """Analyze a single log entry for anomalies."""
        timestamp = log_entry.get('timestamp')
        if not timestamp:
            return
        
        # Get minute-level timestamp
        minute_timestamp = timestamp.replace(second=0, microsecond=0)
        
        # Initialize or update current minute data
        if self.current_minute_data['timestamp'] != minute_timestamp:
            # Process completed minute if we have data
            if self.current_minute_data['timestamp'] is not None:
                self._process_completed_minute()
            
            # Initialize new minute
            self._initialize_minute(minute_timestamp)
        
        # Aggregate data for current minute
        self._aggregate_entry_data(log_entry)
        
        # Real-time anomaly detection for critical issues
        self._detect_realtime_anomalies(log_entry)
        
        # Update behavioral baselines
        self._update_behavioral_baselines(log_entry, timestamp)
    
    def _initialize_minute(self, timestamp: datetime) -> None:
        """Initialize data collection for a new minute."""
        self.current_minute_data = {
            'timestamp': timestamp,
            'requests': 0,
            'unique_ips': set(),
            'errors': 0,
            'response_times': [],
            'bandwidth': 0,
            'countries': Counter(),
            'user_agents': Counter(),
            'paths': Counter(),
            'ips': Counter()
        }
    
    def _aggregate_entry_data(self, log_entry: Dict[str, Any]) -> None:
        """Aggregate log entry data for current minute."""
        data = self.current_minute_data
        
        # Basic metrics
        data['requests'] += 1
        
        # IP tracking
        ip = log_entry.get('remote_addr', '')
        if ip:
            data['unique_ips'].add(ip)
            data['ips'][ip] += 1
        
        # Error tracking
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
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
        data['bandwidth'] += bytes_sent
        
        # Pattern tracking
        country = log_entry.get('country', '')
        if country and country != '-':
            data['countries'][country] += 1
        
        user_agent = log_entry.get('user_agent', '')
        if user_agent:
            data['user_agents'][user_agent] += 1
        
        path = log_entry.get('path', '')
        if path:
            data['paths'][path] += 1
    
    def _process_completed_minute(self) -> None:
        """Process completed minute data and detect anomalies."""
        data = self.current_minute_data
        
        # Calculate minute-level metrics
        requests = data['requests']
        unique_ips = len(data['unique_ips'])
        error_rate = (data['errors'] / requests * 100) if requests > 0 else 0
        avg_response_time = statistics.mean(data['response_times']) if data['response_times'] else 0
        bandwidth_mb = data['bandwidth'] / (1024 * 1024)
        
        # Add to time series
        self.traffic_patterns['requests_per_minute'].append(requests)
        self.traffic_patterns['unique_ips_per_minute'].append(unique_ips)
        self.traffic_patterns['error_rate_per_minute'].append(error_rate)
        self.traffic_patterns['response_time_per_minute'].append(avg_response_time)
        self.traffic_patterns['bandwidth_per_minute'].append(bandwidth_mb)
        
        # Detect statistical anomalies
        self._detect_statistical_anomalies(data)
        
        # Detect behavioral anomalies
        self._detect_behavioral_anomalies(data)
        
        # Update baselines
        self._update_baselines()
    
    def _detect_realtime_anomalies(self, log_entry: Dict[str, Any]) -> None:
        """Detect immediate anomalies that require real-time alerting."""
        # Detect potential DDoS attacks (high request rate from single IP)
        ip = log_entry.get('remote_addr', '')
        if ip:
            ip_requests_this_minute = self.current_minute_data['ips'][ip]
            if ip_requests_this_minute > 100:  # More than 100 requests per minute from single IP
                self._record_anomaly('ddos_attack', {
                    'type': 'High Request Rate',
                    'ip': ip,
                    'requests_per_minute': ip_requests_this_minute,
                    'severity': 'Critical',
                    'timestamp': log_entry.get('timestamp')
                })
        
        # Detect critical response times
        response_time = log_entry.get('request_time', 0)
        if isinstance(response_time, str):
            try:
                response_time = float(response_time)
            except:
                response_time = 0
        
        if response_time > 30:  # Response time > 30 seconds
            self._record_anomaly('critical_response_time', {
                'type': 'Critical Response Time',
                'response_time': response_time,
                'path': log_entry.get('path', ''),
                'ip': ip,
                'severity': 'High',
                'timestamp': log_entry.get('timestamp')
            })
    
    def _detect_statistical_anomalies(self, minute_data: Dict[str, Any]) -> None:
        """Detect statistical anomalies using z-score analysis."""
        if len(self.traffic_patterns['requests_per_minute']) < 10:
            return  # Need more data for statistical analysis
        
        # Traffic volume anomalies
        requests = minute_data['requests']
        if len(self.traffic_patterns['requests_per_minute']) > 1:
            z_score = self._calculate_z_score(requests, self.traffic_patterns['requests_per_minute'])
            if abs(z_score) > self.sensitivity:
                anomaly_type = 'traffic_spike' if z_score > 0 else 'traffic_drop'
                self.anomaly_types[anomaly_type] += 1
                
                self._record_anomaly(anomaly_type, {
                    'type': 'Traffic Volume Anomaly',
                    'z_score': z_score,
                    'actual_requests': requests,
                    'expected_requests': statistics.mean(self.traffic_patterns['requests_per_minute']),
                    'severity': 'High' if abs(z_score) > 3 else 'Medium',
                    'timestamp': minute_data['timestamp']
                })
        
        # Error rate anomalies
        error_rate = (minute_data['errors'] / minute_data['requests'] * 100) if minute_data['requests'] > 0 else 0
        if len(self.traffic_patterns['error_rate_per_minute']) > 1:
            z_score = self._calculate_z_score(error_rate, self.traffic_patterns['error_rate_per_minute'])
            if z_score > self.sensitivity:  # Only alert on error rate increases
                self.anomaly_types['error_spike'] += 1
                
                self._record_anomaly('error_spike', {
                    'type': 'Error Rate Spike',
                    'z_score': z_score,
                    'actual_error_rate': error_rate,
                    'expected_error_rate': statistics.mean(self.traffic_patterns['error_rate_per_minute']),
                    'error_count': minute_data['errors'],
                    'severity': 'High' if z_score > 3 else 'Medium',
                    'timestamp': minute_data['timestamp']
                })
        
        # Response time anomalies
        avg_response_time = statistics.mean(minute_data['response_times']) if minute_data['response_times'] else 0
        if avg_response_time > 0 and len(self.traffic_patterns['response_time_per_minute']) > 1:
            z_score = self._calculate_z_score(avg_response_time, self.traffic_patterns['response_time_per_minute'])
            if z_score > self.sensitivity:
                self.anomaly_types['response_time_spike'] += 1
                
                self._record_anomaly('response_time_spike', {
                    'type': 'Response Time Spike',
                    'z_score': z_score,
                    'actual_response_time': avg_response_time,
                    'expected_response_time': statistics.mean(self.traffic_patterns['response_time_per_minute']),
                    'severity': 'High' if z_score > 3 else 'Medium',
                    'timestamp': minute_data['timestamp']
                })
        
        # Unique IP anomalies
        unique_ips = len(minute_data['unique_ips'])
        if len(self.traffic_patterns['unique_ips_per_minute']) > 1:
            z_score = self._calculate_z_score(unique_ips, self.traffic_patterns['unique_ips_per_minute'])
            if abs(z_score) > self.sensitivity:
                self.anomaly_types['unusual_ip_activity'] += 1
                
                self._record_anomaly('unusual_ip_activity', {
                    'type': 'Unusual IP Activity',
                    'z_score': z_score,
                    'actual_unique_ips': unique_ips,
                    'expected_unique_ips': statistics.mean(self.traffic_patterns['unique_ips_per_minute']),
                    'severity': 'Medium',
                    'timestamp': minute_data['timestamp']
                })
    
    def _detect_behavioral_anomalies(self, minute_data: Dict[str, Any]) -> None:
        """Detect behavioral anomalies based on learned patterns."""
        # Geographic anomalies
        self._detect_geographic_anomalies(minute_data)
        
        # User agent anomalies
        self._detect_user_agent_anomalies(minute_data)
        
        # Path access anomalies
        self._detect_path_anomalies(minute_data)
        
        # IP behavior anomalies
        self._detect_ip_behavior_anomalies(minute_data)
    
    def _detect_geographic_anomalies(self, minute_data: Dict[str, Any]) -> None:
        """Detect unusual geographic patterns."""
        countries = minute_data['countries']
        if not countries:
            return
        
        # Check for sudden appearance of new countries with high traffic
        for country, count in countries.items():
            if count > 50:  # High traffic from a country
                # Check if this country is unusual for this time
                historical_avg = self._get_historical_country_average(country)
                if historical_avg == 0 or count > historical_avg * 5:  # 5x normal traffic
                    self.anomaly_types['geographic_anomaly'] += 1
                    
                    self._record_anomaly('geographic_anomaly', {
                        'type': 'Geographic Traffic Anomaly',
                        'country': country,
                        'requests': count,
                        'expected_requests': historical_avg,
                        'severity': 'Medium',
                        'timestamp': minute_data['timestamp']
                    })
    
    def _detect_user_agent_anomalies(self, minute_data: Dict[str, Any]) -> None:
        """Detect unusual user agent patterns."""
        user_agents = minute_data['user_agents']
        
        for user_agent, count in user_agents.items():
            if count > 20:  # High usage of specific user agent
                # Check for suspicious patterns
                ua_lower = user_agent.lower()
                suspicious_patterns = [
                    'hack', 'exploit', 'scan', 'attack', 'inject', 'bot',
                    'crawler', 'spider', 'scraper'
                ]
                
                if any(pattern in ua_lower for pattern in suspicious_patterns):
                    # Check if this is unusual volume for this user agent
                    historical_avg = self.behavioral_baselines['user_agent_popularity'].get(user_agent, 0) / max(len(self.traffic_patterns['requests_per_minute']), 1)
                    
                    if count > historical_avg * 3:  # 3x normal usage
                        self.anomaly_types['user_agent_anomaly'] += 1
                        
                        self._record_anomaly('user_agent_anomaly', {
                            'type': 'Suspicious User Agent Activity',
                            'user_agent': user_agent[:100],  # Truncate for readability
                            'requests': count,
                            'expected_requests': historical_avg,
                            'severity': 'High',
                            'timestamp': minute_data['timestamp']
                        })
    
    def _detect_path_anomalies(self, minute_data: Dict[str, Any]) -> None:
        """Detect unusual path access patterns."""
        paths = minute_data['paths']
        
        for path, count in paths.items():
            if count > 30:  # High access to specific path
                # Check for attack patterns in path
                path_lower = path.lower()
                attack_patterns = [
                    'admin', 'wp-admin', 'phpmyadmin', 'config', '.env',
                    'backup', 'sql', 'union', 'select', 'script', 'alert'
                ]
                
                if any(pattern in path_lower for pattern in attack_patterns):
                    self.anomaly_types['attack_pattern_anomaly'] += 1
                    
                    self._record_anomaly('attack_pattern_anomaly', {
                        'type': 'Attack Pattern in Path',
                        'path': path,
                        'requests': count,
                        'severity': 'High',
                        'timestamp': minute_data['timestamp']
                    })
    
    def _detect_ip_behavior_anomalies(self, minute_data: Dict[str, Any]) -> None:
        """Detect unusual IP behavior patterns."""
        for ip, count in minute_data['ips'].items():
            if count > 50:  # High request rate from single IP
                # Analyze IP behavior pattern
                ip_behavior = self.behavioral_baselines['ip_behavior'][ip]
                
                # Check for scanning behavior (accessing many different paths)
                paths_accessed = len(set(path for path in minute_data['paths'].keys() 
                                       if minute_data['ips'][ip] > 0))  # Simplified check
                
                if paths_accessed > 20:  # Accessing many different paths
                    self._record_anomaly('scanning_behavior', {
                        'type': 'Scanning Behavior Detected',
                        'ip': ip,
                        'requests': count,
                        'paths_accessed': paths_accessed,
                        'severity': 'High',
                        'timestamp': minute_data['timestamp']
                    })
    
    def _calculate_z_score(self, value: float, data_series: deque) -> float:
        """Calculate z-score for anomaly detection."""
        if len(data_series) < 2:
            return 0
        
        mean = statistics.mean(data_series)
        try:
            stdev = statistics.stdev(data_series)
            if stdev == 0:
                return 0
            return (value - mean) / stdev
        except:
            return 0
    
    def _get_historical_country_average(self, country: str) -> float:
        """Get historical average requests for a country."""
        # Simplified implementation - in production, this would use historical data
        return 10.0  # Default baseline
    
    def _record_anomaly(self, anomaly_type: str, details: Dict[str, Any]) -> None:
        """Record an anomaly detection."""
        anomaly = {
            'type': anomaly_type,
            'details': details,
            'detected_at': datetime.now(),
            'confidence': self._calculate_confidence(details)
        }
        
        self.detected_anomalies.append(anomaly)
        
        # Keep only recent anomalies to prevent memory issues
        if len(self.detected_anomalies) > 1000:
            self.detected_anomalies = self.detected_anomalies[-500:]
    
    def _calculate_confidence(self, details: Dict[str, Any]) -> float:
        """Calculate confidence score for anomaly detection."""
        # Simple confidence calculation based on z-score and severity
        z_score = abs(details.get('z_score', 0))
        severity = details.get('severity', 'Low')
        
        base_confidence = min(z_score / 5.0, 1.0)  # Normalize z-score to 0-1
        
        if severity == 'Critical':
            return min(base_confidence * 1.5, 1.0)
        elif severity == 'High':
            return min(base_confidence * 1.2, 1.0)
        else:
            return base_confidence
    
    def _update_behavioral_baselines(self, log_entry: Dict[str, Any], timestamp: datetime) -> None:
        """Update behavioral baselines for learning."""
        hour = timestamp.hour
        day = timestamp.weekday()
        
        # Update hourly patterns
        self.behavioral_baselines['hourly_patterns'][hour].append(1)  # Simple request count
        
        # Update daily patterns
        self.behavioral_baselines['daily_patterns'][day].append(1)
        
        # Update path popularity
        path = log_entry.get('path', '')
        if path:
            self.behavioral_baselines['path_popularity'][path] += 1
        
        # Update user agent popularity
        user_agent = log_entry.get('user_agent', '')
        if user_agent:
            self.behavioral_baselines['user_agent_popularity'][user_agent] += 1
    
    def _update_baselines(self) -> None:
        """Update statistical baselines for anomaly detection."""
        # Update baseline metrics every 10 minutes
        if len(self.traffic_patterns['requests_per_minute']) % 10 == 0:
            self.baseline_metrics = {
                'avg_requests_per_minute': statistics.mean(self.traffic_patterns['requests_per_minute']),
                'avg_unique_ips_per_minute': statistics.mean(self.traffic_patterns['unique_ips_per_minute']),
                'avg_error_rate_per_minute': statistics.mean(self.traffic_patterns['error_rate_per_minute']),
                'avg_response_time_per_minute': statistics.mean(self.traffic_patterns['response_time_per_minute']),
                'avg_bandwidth_per_minute': statistics.mean(self.traffic_patterns['bandwidth_per_minute'])
            }
    
    def get_anomaly_summary(self) -> Dict[str, Any]:
        """Get comprehensive anomaly detection summary."""
        total_anomalies = len(self.detected_anomalies)
        recent_anomalies = [a for a in self.detected_anomalies 
                          if (datetime.now() - a['detected_at']).total_seconds() < 3600]  # Last hour
        
        # Categorize anomalies by severity
        critical_anomalies = [a for a in recent_anomalies if a['details'].get('severity') == 'Critical']
        high_anomalies = [a for a in recent_anomalies if a['details'].get('severity') == 'High']
        medium_anomalies = [a for a in recent_anomalies if a['details'].get('severity') == 'Medium']
        
        # Get top anomaly types
        anomaly_type_counts = Counter(a['type'] for a in recent_anomalies)
        
        return {
            'total_anomalies': total_anomalies,
            'recent_anomalies': len(recent_anomalies),
            'critical_anomalies': len(critical_anomalies),
            'high_severity_anomalies': len(high_anomalies),
            'medium_severity_anomalies': len(medium_anomalies),
            'anomaly_types': dict(self.anomaly_types),
            'top_anomaly_types': dict(anomaly_type_counts.most_common(5)),
            'baseline_metrics': self.baseline_metrics,
            'detection_sensitivity': self.sensitivity,
            'data_window_minutes': self.window_size
        }
    
    def get_recent_anomalies(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get recent anomalies within specified time window."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [
            {
                **anomaly,
                'detected_at': anomaly['detected_at'].isoformat()
            }
            for anomaly in self.detected_anomalies
            if anomaly['detected_at'] >= cutoff_time
        ]
    
    def get_anomaly_recommendations(self) -> List[Dict[str, Any]]:
        """Generate recommendations based on detected anomalies."""
        recommendations = []
        recent_anomalies = self.get_recent_anomalies(hours=24)
        
        # DDoS protection recommendation
        ddos_attacks = [a for a in recent_anomalies if a['type'] == 'ddos_attack']
        if len(ddos_attacks) > 5:
            recommendations.append({
                'priority': 'Critical',
                'category': 'DDoS Protection',
                'issue': f'{len(ddos_attacks)} potential DDoS attacks detected',
                'recommendation': 'Implement rate limiting and DDoS protection measures',
                'details': 'Multiple high-request-rate incidents from individual IPs detected'
            })
        
        # Performance optimization recommendation
        response_time_spikes = [a for a in recent_anomalies if a['type'] == 'response_time_spike']
        if len(response_time_spikes) > 10:
            recommendations.append({
                'priority': 'High',
                'category': 'Performance Optimization',
                'issue': f'{len(response_time_spikes)} response time anomalies detected',
                'recommendation': 'Investigate performance bottlenecks and optimize slow endpoints',
                'details': 'Multiple response time spikes may indicate performance issues'
            })
        
        # Security monitoring recommendation
        attack_patterns = [a for a in recent_anomalies if a['type'] == 'attack_pattern_anomaly']
        if len(attack_patterns) > 3:
            recommendations.append({
                'priority': 'High',
                'category': 'Security Monitoring',
                'issue': f'{len(attack_patterns)} attack patterns detected',
                'recommendation': 'Enhance security monitoring and implement WAF rules',
                'details': 'Attack patterns in URLs suggest active security threats'
            })
        
        return recommendations
    
    def export_anomaly_report(self, output_file: str) -> None:
        """Export comprehensive anomaly detection report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_anomaly_summary(),
            'recent_anomalies': self.get_recent_anomalies(hours=24),
            'anomaly_timeline': self._get_anomaly_timeline(),
            'recommendations': self.get_anomaly_recommendations(),
            'configuration': {
                'sensitivity_threshold': self.sensitivity,
                'window_size_minutes': self.window_size,
                'detection_methods': ['statistical', 'behavioral', 'pattern-based']
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def _get_anomaly_timeline(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get anomaly timeline for the last 24 hours."""
        timeline = defaultdict(list)
        recent_anomalies = self.get_recent_anomalies(hours=24)
        
        for anomaly in recent_anomalies:
            hour = anomaly['detected_at'][:13]  # Group by hour
            timeline[hour].append({
                'type': anomaly['type'],
                'severity': anomaly['details'].get('severity', 'Unknown'),
                'confidence': anomaly['confidence']
            })
        
        return dict(timeline)
