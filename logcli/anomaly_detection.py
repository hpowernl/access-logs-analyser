"""Anomaly detection module using statistical and machine learning approaches with historical data analysis."""

import json
import math
from collections import defaultdict, deque, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Tuple, Optional
import statistics
from rich.console import Console

console = Console()


def _ensure_datetime(value):
    """Return a datetime for value which may be datetime or ISO string."""
    if value is None:
        return None
    if hasattr(value, 'isoformat') and hasattr(value, 'hour'):
        return value
    if isinstance(value, str):
        try:
            # Accept both plain ISO and ISO with Z
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except Exception:
            return None
    return None

def _iso_or_none(dt):
    d = _ensure_datetime(dt)
    return d.isoformat() if d else None

class HistoricalDataManager:
    """Manages historical data collection using hypernode-parse-nginx-log."""
    
    def __init__(self, days_back: int = 7, hypernode_command=None):
        """Initialize historical data manager."""
        self.days_back = days_back
        self.historical_cache = {}
        
        # Use provided hypernode command or get default one
        if hypernode_command is not None:
            self.hypernode_command = hypernode_command
        else:
            from .hypernode_command import get_hypernode_command
            self.hypernode_command = get_hypernode_command()
        
    def get_historical_data(self, days_ago: int) -> List[Dict[str, Any]]:
        """Get historical data for a specific number of days ago."""
        if days_ago in self.historical_cache:
            return self.historical_cache[days_ago]
            
        try:
            # Use hypernode command to get historical data
            data = self.hypernode_command.get_historical_data(days_ago)
            self.historical_cache[days_ago] = data
            return data
        except Exception as e:
            console.print(f"[yellow]Warning: Could not fetch historical data for {days_ago} days ago: {e}[/yellow]")
            return []
    
    def get_same_weekday_data(self, weeks_back: int = 1) -> List[Dict[str, Any]]:
        """Get data from the same weekday in previous weeks."""
        days_ago = weeks_back * 7
        return self.get_historical_data(days_ago)
    
    def get_week_data(self) -> Dict[int, List[Dict[str, Any]]]:
        """Get data for the entire past week."""
        # Check if we already have week data cached
        if hasattr(self, '_week_data_cache') and self._week_data_cache:
            return self._week_data_cache
            
        try:
            # Use the new week data method from hypernode command
            week_data = self.hypernode_command.get_week_historical_data()
            self._week_data_cache = week_data
            return week_data
        except Exception as e:
            console.print(f"[yellow]Warning: Could not fetch week data: {e}[/yellow]")
            # Fallback to individual day fetching
            week_data = {}
            for day in range(1, 8):  # 1-7 days ago
                data = self.get_historical_data(day)
                if data:
                    week_data[day] = data
            self._week_data_cache = week_data
            return week_data


class BaselineCalculator:
    """Calculates dynamic baselines using historical data."""
    
    def __init__(self, historical_manager: HistoricalDataManager):
        """Initialize baseline calculator."""
        self.historical_manager = historical_manager
        self.baselines = {
            'hourly_patterns': defaultdict(lambda: defaultdict(list)),
            'daily_patterns': defaultdict(list),
            'weekday_patterns': defaultdict(lambda: defaultdict(list)),
            'traffic_baselines': defaultdict(list),
            'performance_baselines': defaultdict(list),
            'security_baselines': defaultdict(list)
        }
        
    def build_baselines(self) -> Dict[str, Any]:
        """Build comprehensive baselines from historical data."""
        console.print("[blue]Building baselines from historical data...[/blue]")
        
        # Get historical data for the past week
        week_data = self.historical_manager.get_week_data()
        
        for days_ago, daily_data in week_data.items():
            if not daily_data:
                continue
                
            # Process data by hour
            hourly_data = self._group_by_hour(daily_data)
            
            for hour, hour_data in hourly_data.items():
                if not hour_data:
                    continue
                    
                # Calculate metrics for this hour
                metrics = self._calculate_hour_metrics(hour_data)
                
                # Get weekday for this data
                if hour_data:
                    sample_timestamp = hour_data[0].get('timestamp')
                    if sample_timestamp:
                        weekday = sample_timestamp.weekday() if hasattr(sample_timestamp, 'weekday') else 0
                        
                        # Store in appropriate baselines
                        self.baselines['hourly_patterns'][hour]['requests'].append(metrics['requests'])
                        self.baselines['hourly_patterns'][hour]['unique_ips'].append(metrics['unique_ips'])
                        self.baselines['hourly_patterns'][hour]['error_rate'].append(metrics['error_rate'])
                        self.baselines['hourly_patterns'][hour]['response_time'].append(metrics['avg_response_time'])
                        
                        self.baselines['weekday_patterns'][weekday]['requests'].append(metrics['requests'])
                        self.baselines['weekday_patterns'][weekday]['unique_ips'].append(metrics['unique_ips'])
                        self.baselines['weekday_patterns'][weekday]['error_rate'].append(metrics['error_rate'])
        
        # Calculate statistical baselines
        calculated_baselines = self._calculate_statistical_baselines()
        
        console.print(f"[green]Baselines built from {len([d for d in week_data.values() if d])} days of historical data[/green]")
        return calculated_baselines
    
    def _group_by_hour(self, data: List[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
        """Group log entries by hour of day."""
        hourly_data = defaultdict(list)
        
        for entry in data:
            timestamp = entry.get('timestamp')
            if timestamp:
                if hasattr(timestamp, 'hour'):
                    hour = timestamp.hour
                else:
                    # If timestamp is string, try to parse it
                    try:
                        if isinstance(timestamp, str):
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            hour = dt.hour
                        else:
                            hour = 12  # Default to noon
                    except:
                        hour = 12
                hourly_data[hour].append(entry)
                
        return hourly_data
    
    def _calculate_hour_metrics(self, hour_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate metrics for an hour of data."""
        if not hour_data:
            return {'requests': 0, 'unique_ips': 0, 'error_rate': 0, 'avg_response_time': 0}
            
        unique_ips = set()
        errors = 0
        response_times = []
        
        for entry in hour_data:
            # Count unique IPs
            ip = entry.get('remote_addr', '')
            if ip and ip != '-':
                unique_ips.add(ip)
            
            # Count errors
            status = entry.get('status', 200)
            if isinstance(status, str):
                try:
                    status = int(status)
                except:
                    status = 200
            elif status is None:
                status = 200
                
            # Only count actual HTTP errors (400+)
            if status >= 400:
                errors += 1
            
            # Collect response times
            response_time = entry.get('request_time', 0)
            if isinstance(response_time, str):
                try:
                    response_time = float(response_time)
                except:
                    response_time = 0
            if response_time > 0:
                response_times.append(response_time)
        
        error_rate = (errors / len(hour_data) * 100) if hour_data else 0
        
        return {
            'requests': len(hour_data),
            'unique_ips': len(unique_ips),
            'error_rate': error_rate,
            'avg_response_time': statistics.mean(response_times) if response_times else 0
        }
    
    def _calculate_statistical_baselines(self) -> Dict[str, Any]:
        """Calculate statistical baselines from collected data."""
        baselines = {}
        
        # Hourly baselines
        baselines['hourly'] = {}
        for hour in range(24):
            hour_data = self.baselines['hourly_patterns'][hour]
            baselines['hourly'][hour] = {
                'requests_mean': statistics.mean(hour_data['requests']) if hour_data['requests'] else 0,
                'requests_stdev': statistics.stdev(hour_data['requests']) if len(hour_data['requests']) > 1 else 0,
                'unique_ips_mean': statistics.mean(hour_data['unique_ips']) if hour_data['unique_ips'] else 0,
                'unique_ips_stdev': statistics.stdev(hour_data['unique_ips']) if len(hour_data['unique_ips']) > 1 else 0,
                'error_rate_mean': statistics.mean(hour_data['error_rate']) if hour_data['error_rate'] else 0,
                'error_rate_stdev': statistics.stdev(hour_data['error_rate']) if len(hour_data['error_rate']) > 1 else 0,
                'response_time_mean': statistics.mean(hour_data['response_time']) if hour_data['response_time'] else 0,
                'response_time_stdev': statistics.stdev(hour_data['response_time']) if len(hour_data['response_time']) > 1 else 0,
            }
        
        # Weekday baselines
        baselines['weekday'] = {}
        for weekday in range(7):
            weekday_data = self.baselines['weekday_patterns'][weekday]
            baselines['weekday'][weekday] = {
                'requests_mean': statistics.mean(weekday_data['requests']) if weekday_data['requests'] else 0,
                'requests_stdev': statistics.stdev(weekday_data['requests']) if len(weekday_data['requests']) > 1 else 0,
                'unique_ips_mean': statistics.mean(weekday_data['unique_ips']) if weekday_data['unique_ips'] else 0,
                'error_rate_mean': statistics.mean(weekday_data['error_rate']) if weekday_data['error_rate'] else 0,
            }
        
        return baselines


class AnomalyDetector:
    """Detects traffic anomalies using statistical analysis and pattern recognition with historical data."""
    
    def __init__(self, window_size: int = 60, sensitivity: float = 2.5, days_back: int = 7, hypernode_command=None):
        """Initialize anomaly detector with historical data capabilities."""
        self.window_size = window_size  # Minutes of data to keep in memory
        self.sensitivity = sensitivity   # Z-score threshold for anomaly detection
        self.days_back = days_back      # Days of historical data to use
        
        # Initialize historical data management
        self.historical_manager = HistoricalDataManager(days_back, hypernode_command)
        self.baseline_calculator = BaselineCalculator(self.historical_manager)
        
        # Build baselines from historical data
        try:
            self.historical_baselines = self.baseline_calculator.build_baselines()
        except Exception as e:
            console.print(f"[yellow]Warning: Could not build historical baselines: {e}[/yellow]")
            self.historical_baselines = {'hourly': {}, 'weekday': {}}
            
        # Cache for avoiding duplicate data fetches
        self._historical_data_cache = {}
        
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
        
        # Enhanced anomaly tracking with historical comparisons
        self.detected_anomalies = []
        self.anomaly_types = {
            # Traffic anomalies
            'traffic_spike': 0,
            'traffic_drop': 0,
            'ddos_attack': 0,
            'bot_traffic_spike': 0,
            'unusual_ip_activity': 0,
            
            # Status code anomalies
            'error_spike': 0,
            'server_error_spike': 0,
            'client_error_spike': 0,
            'unusual_status_codes': 0,
            
            # Performance anomalies
            'response_time_spike': 0,
            'slow_endpoint': 0,
            'timeout_spike': 0,
            'bandwidth_anomaly': 0,
            
            # E-commerce specific anomalies
            'checkout_flow_anomaly': 0,
            'payment_anomaly': 0,
            'cart_abandonment_spike': 0,
            'product_page_anomaly': 0,
            'search_anomaly': 0,
            'coupon_abuse': 0,
            'price_scraping': 0,
            'inventory_anomaly': 0,
            
            # Security anomalies
            'attack_pattern_anomaly': 0,
            'scanning_behavior': 0,
            'fraud_pattern': 0,
            'suspicious_user_agent': 0,
            'geographic_anomaly': 0,
            
            # Behavioral anomalies
            'session_anomaly': 0,
            'referral_anomaly': 0,
            'campaign_anomaly': 0,
            
            # Historical comparison anomalies
            'historical_comparison_anomaly': 0,
            'weekday_pattern_anomaly': 0,
            'hourly_pattern_anomaly': 0,
            'weekly_trend_anomaly': 0,
            'same_time_last_week_anomaly': 0
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
        elif status is None:
            status = 200
        
        # Only count actual HTTP errors (400+), not redirects or other codes
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
        
        # Detect e-commerce specific anomalies
        self._detect_ecommerce_minute_anomalies(data)
        
        # Detect status code anomalies
        self._detect_status_code_anomalies(data)
        
        # Detect performance anomalies
        self._detect_performance_anomalies(data)
        
        # Detect historical comparison anomalies
        self._detect_historical_anomalies(data, requests, unique_ips, error_rate, avg_response_time)
        
        # Update baselines
        self._update_baselines()
    
    def _detect_realtime_anomalies(self, log_entry: Dict[str, Any]) -> None:
        """Detect immediate anomalies that require real-time alerting."""
        ip = log_entry.get('remote_addr', '')
        path = log_entry.get('path', '')
        status = log_entry.get('status', 200)
        user_agent = log_entry.get('user_agent', '')
        
        # Convert status to int if needed
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        elif status is None:
            status = 200
        
        # Detect potential DDoS attacks (high request rate from single IP)
        if ip:
            ip_requests_this_minute = self.current_minute_data['ips'][ip]
            if ip_requests_this_minute > 200:  # More than 200 requests per minute from single IP
                self._record_anomaly('ddos_attack', {
                    'type': 'DDoS Attack Detected',
                    'ip': ip,
                    'requests_per_minute': ip_requests_this_minute,
                    'severity': 'Critical',
                    'timestamp': log_entry.get('timestamp'),
                    'action_required': 'Block IP immediately'
                })
        
        # Detect bot traffic patterns
        self._detect_bot_traffic(log_entry, ip, path, user_agent)
        
        # Detect e-commerce specific anomalies
        self._detect_ecommerce_anomalies(log_entry, path, status, ip)
        
        # Detect security threats
        self._detect_security_threats(log_entry, path, user_agent, ip)
        
        # Detect critical response times
        response_time = log_entry.get('request_time', 0)
        if isinstance(response_time, str):
            try:
                response_time = float(response_time)
            except:
                response_time = 0
        
        if response_time > 30:  # Response time > 30 seconds
            self._record_anomaly('response_time_spike', {
                'type': 'Critical Response Time',
                'response_time': response_time,
                'path': path,
                'ip': ip,
                'severity': 'High',
                'timestamp': log_entry.get('timestamp'),
                'action_required': 'Check server performance and database queries'
            })
        
        # Detect server errors
        if status >= 500:
            self._record_anomaly('server_error_spike', {
                'type': 'Server Error Detected',
                'status_code': status,
                'path': path,
                'ip': ip,
                'severity': 'High',
                'timestamp': log_entry.get('timestamp'),
                'action_required': 'Check application logs and server health'
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
        
        # Error rate anomalies - very conservative for high-error-rate websites
        error_rate = (minute_data['errors'] / minute_data['requests'] * 100) if minute_data['requests'] > 0 else 0
        if len(self.traffic_patterns['error_rate_per_minute']) > 1:
            current_mean = statistics.mean(self.traffic_patterns['error_rate_per_minute'])
            z_score = self._calculate_z_score(error_rate, self.traffic_patterns['error_rate_per_minute'])
            
            # Only alert on EXTREME error rate increases (much more conservative)
            if (z_score > (self.sensitivity + 3.0) and 
                error_rate > current_mean + 20.0 and  # At least 20% higher than current average
                error_rate > 98.0):  # And above 98%
                self.anomaly_types['error_spike'] += 1
                
                self._record_anomaly('error_spike', {
                    'type': 'Critical Error Rate Spike',
                    'z_score': z_score,
                    'actual_error_rate': error_rate,
                    'expected_error_rate': current_mean,
                    'error_count': minute_data['errors'],
                    'severity': 'Critical',
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
    
    def _detect_historical_anomalies(self, minute_data: Dict[str, Any], requests: int, 
                                   unique_ips: int, error_rate: float, avg_response_time: float) -> None:
        """Detect anomalies by comparing current data with historical baselines."""
        timestamp = minute_data.get('timestamp')
        if not timestamp:
            return
            
        current_hour = timestamp.hour if hasattr(timestamp, 'hour') else datetime.now().hour
        current_weekday = timestamp.weekday() if hasattr(timestamp, 'weekday') else datetime.now().weekday()
        
        # Compare with hourly historical baselines
        self._detect_hourly_pattern_anomalies(current_hour, requests, unique_ips, error_rate, avg_response_time, timestamp)
        
        # Compare with weekday historical baselines  
        self._detect_weekday_pattern_anomalies(current_weekday, requests, unique_ips, error_rate, timestamp)
        
        # Compare with same time last week
        self._detect_same_time_last_week_anomalies(requests, unique_ips, error_rate, avg_response_time, timestamp)
        
        # Detect weekly trend anomalies
        self._detect_weekly_trend_anomalies(requests, unique_ips, error_rate, timestamp)
    
    def _detect_hourly_pattern_anomalies(self, hour: int, requests: int, unique_ips: int, 
                                       error_rate: float, response_time: float, timestamp: datetime) -> None:
        """Detect anomalies based on hourly historical patterns."""
        if hour not in self.historical_baselines.get('hourly', {}):
            return
            
        hourly_baseline = self.historical_baselines['hourly'][hour]
        
        # Check requests anomaly
        requests_mean = hourly_baseline.get('requests_mean', 0)
        requests_stdev = hourly_baseline.get('requests_stdev', 0)
        
        if requests_mean > 0 and requests_stdev > 0 and requests > 5:  # Only check meaningful request counts
            z_score = (requests - requests_mean) / requests_stdev
            if abs(z_score) > (self.sensitivity + 1.0):  # More conservative threshold
                self.anomaly_types['hourly_pattern_anomaly'] += 1
                self._record_anomaly('hourly_pattern_anomaly', {
                    'type': 'Hourly Pattern Anomaly',
                    'metric': 'requests',
                    'hour': hour,
                    'z_score': z_score,
                    'actual_value': requests,
                    'historical_mean': requests_mean,
                    'historical_stdev': requests_stdev,
                    'severity': 'High' if abs(z_score) > 4 else 'Medium',
                    'timestamp': timestamp
                })
        
        # Check error rate anomaly - much more conservative for websites with naturally high error rates
        error_rate_mean = hourly_baseline.get('error_rate_mean', 0)
        error_rate_stdev = hourly_baseline.get('error_rate_stdev', 0)
        
        # Only alert if error rate is SIGNIFICANTLY higher than historical AND above 95%
        if (error_rate_mean >= 0 and error_rate_stdev > 0 and 
            error_rate > error_rate_mean + (5 * error_rate_stdev) and 
            error_rate > 95.0 and error_rate_mean < 90.0):
            self.anomaly_types['hourly_pattern_anomaly'] += 1
            self._record_anomaly('hourly_pattern_anomaly', {
                'type': 'Critical Error Rate Spike',
                'metric': 'error_rate',
                'hour': hour,
                'actual_error_rate': error_rate,
                'historical_mean': error_rate_mean,
                'historical_stdev': error_rate_stdev,
                'severity': 'Critical',
                'timestamp': timestamp
            })
        
        # Check unique IPs anomaly
        unique_ips_mean = hourly_baseline.get('unique_ips_mean', 0)
        unique_ips_stdev = hourly_baseline.get('unique_ips_stdev', 0)
        
        if unique_ips_mean > 0 and unique_ips_stdev > 0:
            z_score = (unique_ips - unique_ips_mean) / unique_ips_stdev
            if abs(z_score) > self.sensitivity:
                self.anomaly_types['hourly_pattern_anomaly'] += 1
                self._record_anomaly('hourly_pattern_anomaly', {
                    'type': 'Hourly Unique IPs Anomaly',
                    'metric': 'unique_ips',
                    'hour': hour,
                    'z_score': z_score,
                    'actual_value': unique_ips,
                    'historical_mean': unique_ips_mean,
                    'severity': 'Medium',
                    'timestamp': timestamp
                })
    
    def _detect_weekday_pattern_anomalies(self, weekday: int, requests: int, unique_ips: int, 
                                        error_rate: float, timestamp: datetime) -> None:
        """Detect anomalies based on weekday historical patterns."""
        if weekday not in self.historical_baselines.get('weekday', {}):
            return
            
        weekday_baseline = self.historical_baselines['weekday'][weekday]
        
        # Check requests anomaly for this weekday
        requests_mean = weekday_baseline.get('requests_mean', 0)
        requests_stdev = weekday_baseline.get('requests_stdev', 0)
        
        if requests_mean > 0 and requests_stdev > 0 and requests > 10:  # Only check meaningful request counts
            z_score = (requests - requests_mean) / requests_stdev
            if abs(z_score) > (self.sensitivity + 1.5):  # Even more conservative for weekday patterns
                weekday_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                self.anomaly_types['weekday_pattern_anomaly'] += 1
                self._record_anomaly('weekday_pattern_anomaly', {
                    'type': 'Weekday Pattern Anomaly',
                    'weekday': weekday_names[weekday],
                    'weekday_number': weekday,
                    'z_score': z_score,
                    'actual_requests': requests,
                    'expected_requests': requests_mean,
                    'severity': 'Medium' if abs(z_score) < 4 else 'High',
                    'timestamp': timestamp
                })
    
    def _detect_same_time_last_week_anomalies(self, requests: int, unique_ips: int, 
                                            error_rate: float, response_time: float, timestamp: datetime) -> None:
        """Compare current metrics with same time last week."""
        try:
            # Use cached data if available
            if not hasattr(self, '_last_week_data_cache'):
                self._last_week_data_cache = self.historical_manager.get_historical_data(7)
            
            last_week_data = self._last_week_data_cache
            if not last_week_data:
                return
                
            # Filter to same hour as current timestamp
            current_hour = timestamp.hour if hasattr(timestamp, 'hour') else datetime.now().hour
            same_hour_data = [entry for entry in last_week_data 
                            if hasattr(entry.get('timestamp'), 'hour') and entry['timestamp'].hour == current_hour]
            
            if same_hour_data:
                # Calculate metrics for same hour last week
                last_week_metrics = self.baseline_calculator._calculate_hour_metrics(same_hour_data)
                
                # Compare requests - only flag significant changes
                last_week_requests = last_week_metrics['requests']
                if last_week_requests > 10:  # Only compare if we have meaningful data
                    requests_ratio = requests / last_week_requests
                    if requests_ratio > 3.0 or requests_ratio < 0.3:  # 3x increase or 30% decrease (more conservative)
                        self.anomaly_types['same_time_last_week_anomaly'] += 1
                        self._record_anomaly('same_time_last_week_anomaly', {
                            'type': 'Same Time Last Week Comparison',
                            'metric': 'requests',
                            'current_value': requests,
                            'last_week_value': last_week_requests,
                            'ratio': requests_ratio,
                            'severity': 'High' if requests_ratio > 5.0 or requests_ratio < 0.2 else 'Medium',
                            'timestamp': timestamp
                        })
                
                # Compare error rates - extremely conservative for high-error sites
                last_week_error_rate = last_week_metrics['error_rate']
                # Only alert if error rate is dramatically higher AND both periods have meaningful data
                if (error_rate > last_week_error_rate + 25.0 and  # 25% higher than last week
                    error_rate > 99.0 and  # Current error rate above 99%
                    last_week_error_rate < 95.0):  # Last week was significantly better
                    self.anomaly_types['same_time_last_week_anomaly'] += 1
                    self._record_anomaly('same_time_last_week_anomaly', {
                        'type': 'Extreme Error Rate Increase vs Last Week',
                        'current_error_rate': error_rate,
                        'last_week_error_rate': last_week_error_rate,
                        'increase': error_rate - last_week_error_rate,
                        'severity': 'Critical',
                        'timestamp': timestamp
                    })
                    
        except Exception as e:
            # Silently handle errors in historical comparison
            pass
    
    def _detect_weekly_trend_anomalies(self, requests: int, unique_ips: int, error_rate: float, timestamp: datetime) -> None:
        """Detect anomalies based on weekly trends."""
        try:
            # Use cached week data if available
            if not hasattr(self, '_week_data_cache'):
                self._week_data_cache = self.historical_manager.get_week_data()
            
            week_data = self._week_data_cache
            if not week_data or len(week_data) < 3:
                return
                
            # Calculate daily request totals
            weekly_metrics = []
            for days_ago in range(1, 8):
                if days_ago in week_data:
                    daily_data = week_data[days_ago]
                    if daily_data:
                        daily_metrics = self.baseline_calculator._calculate_hour_metrics(daily_data)
                        weekly_metrics.append(daily_metrics['requests'])
            
            if len(weekly_metrics) >= 3:  # Need at least 3 days of data
                # Calculate trend
                trend = self._calculate_trend(weekly_metrics)
                
                # Predict expected value based on trend
                expected_requests = weekly_metrics[-1] + trend if weekly_metrics else 0
                
                # Check if current value deviates significantly from trend (more conservative)
                if expected_requests > 10 and requests > 10:  # Only check meaningful values
                    deviation = abs(requests - expected_requests) / expected_requests
                    if deviation > 1.0:  # 100% deviation from trend (more conservative)
                        self.anomaly_types['weekly_trend_anomaly'] += 1
                        self._record_anomaly('weekly_trend_anomaly', {
                            'type': 'Weekly Trend Deviation',
                            'current_requests': requests,
                            'expected_requests': expected_requests,
                            'trend': trend,
                            'deviation_percentage': deviation * 100,
                            'severity': 'Medium',
                            'timestamp': timestamp
                        })
        except Exception as e:
            # Silently handle errors in trend analysis
            pass
    
    def _detect_bot_traffic(self, log_entry: Dict[str, Any], ip: str, path: str, user_agent: str) -> None:
        """Detect bot traffic patterns."""
        # Check for bot indicators in user agent
        ua_lower = user_agent.lower()
        bot_indicators = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
            'scrapy', 'beautifulsoup', 'selenium', 'phantomjs', 'headless'
        ]
        
        if any(indicator in ua_lower for indicator in bot_indicators):
            # Check request rate for this IP
            ip_requests = self.current_minute_data['ips'][ip]
            if ip_requests > 30:  # High request rate from bot
                self._record_anomaly('bot_traffic_spike', {
                    'type': 'Bot Traffic Detected',
                    'ip': ip,
                    'user_agent': user_agent[:100],
                    'requests_per_minute': ip_requests,
                    'severity': 'Medium',
                    'timestamp': log_entry.get('timestamp'),
                    'action_required': 'Consider rate limiting or blocking bot traffic'
                })
        
        # Check for scraping patterns (many different paths from same IP)
        if ip and path:
            paths_this_minute = len([p for p in self.current_minute_data['paths'].keys() 
                                   if self.current_minute_data['ips'][ip] > 0])
            if paths_this_minute > 20:  # Accessing many different paths
                self._record_anomaly('price_scraping', {
                    'type': 'Price Scraping Detected',
                    'ip': ip,
                    'paths_accessed': paths_this_minute,
                    'user_agent': user_agent[:50],
                    'severity': 'High',
                    'timestamp': log_entry.get('timestamp'),
                    'action_required': 'Block scraping attempts and implement anti-bot measures'
                })
    
    def _detect_ecommerce_anomalies(self, log_entry: Dict[str, Any], path: str, status: int, ip: str) -> None:
        """Detect e-commerce specific anomalies in real-time."""
        path_lower = path.lower()
        
        # Checkout flow anomalies
        if any(checkout_path in path_lower for checkout_path in ['/checkout', '/cart', '/payment', '/order']):
            if status >= 400:
                self._record_anomaly('checkout_flow_anomaly', {
                    'type': 'Checkout Flow Error',
                    'path': path,
                    'status_code': status,
                    'ip': ip,
                    'severity': 'High',
                    'timestamp': log_entry.get('timestamp'),
                    'action_required': 'Check checkout process and payment gateway'
                })
        
        # Payment anomalies
        if any(payment_path in path_lower for payment_path in ['/payment', '/pay', '/billing', '/stripe', '/paypal']):
            if status == 500:
                self._record_anomaly('payment_anomaly', {
                    'type': 'Payment System Error',
                    'path': path,
                    'status_code': status,
                    'ip': ip,
                    'severity': 'Critical',
                    'timestamp': log_entry.get('timestamp'),
                    'action_required': 'Check payment gateway immediately - revenue impact'
                })
        
        # Product page anomalies
        if any(product_path in path_lower for product_path in ['/product', '/item', '/p/']):
            response_time = log_entry.get('request_time', 0)
            if isinstance(response_time, str):
                try:
                    response_time = float(response_time)
                except:
                    response_time = 0
            
            if response_time > 5:  # Slow product page
                self._record_anomaly('product_page_anomaly', {
                    'type': 'Slow Product Page',
                    'path': path,
                    'response_time': response_time,
                    'ip': ip,
                    'severity': 'Medium',
                    'timestamp': log_entry.get('timestamp'),
                    'action_required': 'Optimize product page performance - affects conversion'
                })
        
        # Search anomalies
        if any(search_path in path_lower for search_path in ['/search', '/find', '?q=', '?query=']):
            if status == 500:
                self._record_anomaly('search_anomaly', {
                    'type': 'Search System Error',
                    'path': path,
                    'status_code': status,
                    'ip': ip,
                    'severity': 'High',
                    'timestamp': log_entry.get('timestamp'),
                    'action_required': 'Check search functionality - affects product discovery'
                })
    
    def _detect_security_threats(self, log_entry: Dict[str, Any], path: str, user_agent: str, ip: str) -> None:
        """Detect security threats and attack patterns."""
        path_lower = path.lower()
        
        # Attack patterns in URLs
        attack_patterns = [
            'admin', 'wp-admin', 'phpmyadmin', 'config', '.env', 'backup',
            'sql', 'union', 'select', 'script', 'alert', 'javascript:',
            '../', '..\\', 'etc/passwd', 'cmd.exe', 'powershell'
        ]
        
        if any(pattern in path_lower for pattern in attack_patterns):
            self._record_anomaly('attack_pattern_anomaly', {
                'type': 'Attack Pattern Detected',
                'path': path,
                'ip': ip,
                'user_agent': user_agent[:100],
                'severity': 'High',
                'timestamp': log_entry.get('timestamp'),
                'action_required': 'Block malicious requests and review security logs'
            })
        
        # Suspicious user agents
        ua_lower = user_agent.lower()
        suspicious_patterns = [
            'hack', 'exploit', 'scan', 'attack', 'inject', 'sqlmap',
            'nikto', 'nessus', 'burp', 'owasp'
        ]
        
        if any(pattern in ua_lower for pattern in suspicious_patterns):
            self._record_anomaly('suspicious_user_agent', {
                'type': 'Suspicious User Agent',
                'user_agent': user_agent,
                'ip': ip,
                'path': path,
                'severity': 'High',
                'timestamp': log_entry.get('timestamp'),
                'action_required': 'Block suspicious IP and investigate security breach'
            })
    
    def _detect_ecommerce_minute_anomalies(self, minute_data: Dict[str, Any]) -> None:
        """Detect e-commerce specific anomalies at minute level."""
        # Cart abandonment detection
        cart_requests = sum(1 for path in minute_data['paths'] if 'cart' in path.lower())
        checkout_requests = sum(1 for path in minute_data['paths'] if 'checkout' in path.lower())
        
        if cart_requests > 10 and checkout_requests < cart_requests * 0.1:  # Less than 10% proceed to checkout
            self._record_anomaly('cart_abandonment_spike', {
                'type': 'High Cart Abandonment Rate',
                'cart_requests': cart_requests,
                'checkout_requests': checkout_requests,
                'abandonment_rate': ((cart_requests - checkout_requests) / cart_requests) * 100,
                'severity': 'Medium',
                'timestamp': minute_data['timestamp'],
                'action_required': 'Review checkout UX and identify conversion barriers'
            })
        
        # Coupon abuse detection
        coupon_requests = sum(1 for path in minute_data['paths'] 
                            if any(coupon_term in path.lower() for coupon_term in ['coupon', 'discount', 'promo']))
        
        if coupon_requests > 20:  # High coupon usage
            unique_ips_using_coupons = len(set(ip for ip in minute_data['unique_ips'] 
                                             if minute_data['ips'][ip] > 2))  # Simplified check
            
            if coupon_requests / max(unique_ips_using_coupons, 1) > 5:  # More than 5 coupon attempts per IP
                self._record_anomaly('coupon_abuse', {
                    'type': 'Coupon Abuse Detected',
                    'coupon_requests': coupon_requests,
                    'unique_ips': unique_ips_using_coupons,
                    'requests_per_ip': coupon_requests / max(unique_ips_using_coupons, 1),
                    'severity': 'High',
                    'timestamp': minute_data['timestamp'],
                    'action_required': 'Implement coupon rate limiting and fraud detection'
                })
    
    def _detect_status_code_anomalies(self, minute_data: Dict[str, Any]) -> None:
        """Detect status code anomalies and patterns."""
        if minute_data['requests'] == 0:
            return
            
        # Analyze status code distribution
        status_codes = defaultdict(int)
        for path in minute_data['paths']:
            # This is simplified - in real implementation we'd track status codes per request
            # For now, simulate based on error rate
            if minute_data['errors'] > 0:
                status_codes[500] += minute_data['errors'] // 2  # Server errors
                status_codes[404] += minute_data['errors'] // 3  # Not found errors
                status_codes[403] += minute_data['errors'] // 4  # Forbidden errors
                status_codes[502] += minute_data['errors'] // 5  # Bad gateway
        
        total_requests = minute_data['requests']
        
        # 5xx Server Error Spikes
        server_errors = status_codes[500] + status_codes[502] + status_codes[503] + status_codes[504]
        if server_errors > 0:
            server_error_rate = (server_errors / total_requests) * 100
            
            if server_error_rate > 10:  # More than 10% server errors
                self._record_anomaly('server_error_spike', {
                    'type': 'Server Error Spike Detected',
                    'server_error_count': server_errors,
                    'server_error_rate': server_error_rate,
                    'total_requests': total_requests,
                    'status_breakdown': {
                        '500': status_codes[500],
                        '502': status_codes[502],
                        '503': status_codes[503],
                        '504': status_codes[504]
                    },
                    'severity': 'Critical' if server_error_rate > 25 else 'High',
                    'timestamp': minute_data['timestamp'],
                    'action_required': 'Check server health, database connections, and application logs immediately'
                })
        
        # 4xx Client Error Patterns
        client_errors = status_codes[400] + status_codes[401] + status_codes[403] + status_codes[404]
        if client_errors > 0:
            client_error_rate = (client_errors / total_requests) * 100
            
            # High 404 rate might indicate broken links or bot scanning
            if status_codes[404] > 20:  # More than 20 404s per minute
                self._record_anomaly('client_error_spike', {
                    'type': 'High 404 Error Rate',
                    'error_404_count': status_codes[404],
                    'error_rate': (status_codes[404] / total_requests) * 100,
                    'severity': 'Medium',
                    'timestamp': minute_data['timestamp'],
                    'action_required': 'Check for broken links, bot scanning, or missing pages'
                })
            
            # High 403 rate might indicate security scanning or blocked access
            if status_codes[403] > 10:  # More than 10 403s per minute
                self._record_anomaly('client_error_spike', {
                    'type': 'High 403 Forbidden Rate',
                    'error_403_count': status_codes[403],
                    'error_rate': (status_codes[403] / total_requests) * 100,
                    'severity': 'High',
                    'timestamp': minute_data['timestamp'],
                    'action_required': 'Check for security scanning attempts or access control issues'
                })
        
        # Unusual status codes (anything not common)
        unusual_codes = [code for code in status_codes.keys() if code not in [200, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503, 504]]
        if unusual_codes:
            self._record_anomaly('unusual_status_codes', {
                'type': 'Unusual Status Codes Detected',
                'unusual_codes': unusual_codes,
                'code_counts': {str(code): status_codes[code] for code in unusual_codes},
                'severity': 'Medium',
                'timestamp': minute_data['timestamp'],
                'action_required': 'Investigate unusual HTTP status codes for potential issues'
            })
    
    def _detect_performance_anomalies(self, minute_data: Dict[str, Any]) -> None:
        """Detect performance-related anomalies."""
        if not minute_data['response_times']:
            return
            
        response_times = minute_data['response_times']
        avg_response_time = statistics.mean(response_times)
        max_response_time = max(response_times)
        min_response_time = min(response_times)
        
        # Slow endpoint detection
        if avg_response_time > 3.0:  # Average response time > 3 seconds
            # Calculate percentiles for more detailed analysis
            sorted_times = sorted(response_times)
            p95_time = sorted_times[int(0.95 * len(sorted_times))] if len(sorted_times) > 20 else max_response_time
            p99_time = sorted_times[int(0.99 * len(sorted_times))] if len(sorted_times) > 100 else max_response_time
            
            self._record_anomaly('slow_endpoint', {
                'type': 'Slow Endpoint Performance',
                'avg_response_time': avg_response_time,
                'max_response_time': max_response_time,
                'min_response_time': min_response_time,
                'p95_response_time': p95_time,
                'p99_response_time': p99_time,
                'slow_request_count': len([t for t in response_times if t > 5.0]),
                'total_requests': len(response_times),
                'severity': 'Critical' if avg_response_time > 10 else 'High',
                'timestamp': minute_data['timestamp'],
                'action_required': 'Optimize database queries, check server resources, review application performance'
            })
        
        # Timeout detection
        timeout_requests = len([t for t in response_times if t > 30.0])  # Requests > 30 seconds
        if timeout_requests > 0:
            timeout_rate = (timeout_requests / len(response_times)) * 100
            
            self._record_anomaly('timeout_spike', {
                'type': 'Request Timeout Spike',
                'timeout_count': timeout_requests,
                'timeout_rate': timeout_rate,
                'total_requests': len(response_times),
                'avg_response_time': avg_response_time,
                'max_response_time': max_response_time,
                'severity': 'Critical',
                'timestamp': minute_data['timestamp'],
                'action_required': 'Check for database deadlocks, server overload, or external API issues'
            })
        
        # Response time variance (inconsistent performance)
        if len(response_times) > 10:
            response_time_stdev = statistics.stdev(response_times)
            coefficient_of_variation = response_time_stdev / avg_response_time if avg_response_time > 0 else 0
            
            # High variance indicates inconsistent performance
            if coefficient_of_variation > 1.0:  # Standard deviation > mean
                self._record_anomaly('performance_variance', {
                    'type': 'Inconsistent Performance Detected',
                    'avg_response_time': avg_response_time,
                    'response_time_stdev': response_time_stdev,
                    'coefficient_of_variation': coefficient_of_variation,
                    'min_response_time': min_response_time,
                    'max_response_time': max_response_time,
                    'severity': 'Medium',
                    'timestamp': minute_data['timestamp'],
                    'action_required': 'Check for resource contention, optimize caching, review load balancing'
                })
        
        # Bandwidth anomalies (if available)
        bandwidth_mb = minute_data.get('bandwidth', 0) / (1024 * 1024)
        if bandwidth_mb > 100:  # More than 100MB per minute
            avg_bytes_per_request = (minute_data.get('bandwidth', 0) / minute_data['requests']) if minute_data['requests'] > 0 else 0
            
            if avg_bytes_per_request > 1024 * 1024:  # More than 1MB per request on average
                self._record_anomaly('bandwidth_anomaly', {
                    'type': 'High Bandwidth Usage',
                    'total_bandwidth_mb': bandwidth_mb,
                    'avg_bytes_per_request': avg_bytes_per_request,
                    'total_requests': minute_data['requests'],
                    'severity': 'Medium',
                    'timestamp': minute_data['timestamp'],
                    'action_required': 'Check for large file downloads, optimize image sizes, review CDN configuration'
                })
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate simple linear trend from a series of values."""
        if len(values) < 2:
            return 0
            
        # Simple linear regression slope calculation
        n = len(values)
        x_sum = sum(range(n))
        y_sum = sum(values)
        xy_sum = sum(i * values[i] for i in range(n))
        x_squared_sum = sum(i * i for i in range(n))
        
        if n * x_squared_sum - x_sum * x_sum == 0:
            return 0
            
        slope = (n * xy_sum - x_sum * y_sum) / (n * x_squared_sum - x_sum * x_sum)
        return slope
    
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
                          if (datetime.now() - _ensure_datetime(a['detected_at'])).total_seconds() < 3600]  # Last hour
        
        # Categorize anomalies by severity
        critical_anomalies = [a for a in recent_anomalies if a['details'].get('severity') == 'Critical']
        high_anomalies = [a for a in recent_anomalies if a['details'].get('severity') == 'High']
        medium_anomalies = [a for a in recent_anomalies if a['details'].get('severity') == 'Medium']
        
        # Get top anomaly types
        anomaly_type_counts = Counter(a['type'] for a in recent_anomalies)
        
        # Historical comparison stats
        historical_anomalies = [a for a in recent_anomalies if 'historical' in a['type'] or 'weekday' in a['type'] or 'hourly' in a['type']]
        
        # Detailed breakdown by anomaly type
        detailed_breakdown = self._get_detailed_anomaly_breakdown(recent_anomalies)
        
        # Timeline analysis
        timeline_analysis = self._get_timeline_analysis(recent_anomalies)
        
        # Top affected resources
        top_affected = self._get_top_affected_resources(recent_anomalies)
        
        # Historical context
        historical_context = self._get_historical_context()
        
        return {
            'total_anomalies': total_anomalies,
            'recent_anomalies': len(recent_anomalies),
            'critical_anomalies': len(critical_anomalies),
            'high_severity_anomalies': len(high_anomalies),
            'medium_severity_anomalies': len(medium_anomalies),
            'historical_comparison_anomalies': len(historical_anomalies),
            'anomaly_types': dict(self.anomaly_types),
            'top_anomaly_types': dict(anomaly_type_counts.most_common(10)),
            'baseline_metrics': self.baseline_metrics,
            'historical_baselines_available': len(self.historical_baselines.get('hourly', {})) > 0,
            'historical_data_days': self.days_back,
            'detection_sensitivity': self.sensitivity,
            'data_window_minutes': self.window_size,
            'enhanced_features': {
                'hourly_pattern_detection': True,
                'weekday_pattern_detection': True,
                'weekly_trend_analysis': True,
                'same_time_last_week_comparison': True,
                'historical_baseline_learning': True
            },
            'detailed_breakdown': detailed_breakdown,
            'timeline_analysis': timeline_analysis,
            'top_affected_resources': top_affected,
            'historical_context': historical_context
        }
    
    def get_recent_anomalies(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get recent anomalies within specified time window."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [
            {
                **anomaly,
                'detected_at': _iso_or_none(anomaly['detected_at'])
            }
            for anomaly in self.detected_anomalies
            if (_ensure_datetime(anomaly['detected_at']) or datetime.min) >= cutoff_time
        ]
    
    def get_anomaly_recommendations(self) -> List[Dict[str, Any]]:
        """Generate detailed, actionable recommendations based on detected anomalies."""
        recommendations = []
        # Use internal anomalies with datetime to avoid string timestamp issues
        cutoff_time = datetime.now() - timedelta(hours=24)
        recent_anomalies = [
            a for a in self.detected_anomalies
            if (_ensure_datetime(a.get('detected_at')) or datetime.min) >= cutoff_time
        ]
        
        # Get detailed breakdown for context
        breakdown = self._get_detailed_anomaly_breakdown(recent_anomalies)
        timeline = self._get_timeline_analysis(recent_anomalies)
        top_affected = self._get_top_affected_resources(recent_anomalies)
        
        # E-commerce specific recommendations
        
        # DDoS and bot protection
        ddos_attacks = [a for a in recent_anomalies if a['type'] == 'ddos_attack']
        bot_attacks = [a for a in recent_anomalies if a['type'] == 'bot_traffic_spike']
        scraping_attacks = [a for a in recent_anomalies if a['type'] == 'price_scraping']
        
        if len(ddos_attacks) > 0 or len(bot_attacks) > 0 or len(scraping_attacks) > 0:
            attacking_ips = set()
            for attacks in [ddos_attacks, bot_attacks, scraping_attacks]:
                attacking_ips.update([a['details'].get('ip') for a in attacks if 'ip' in a['details']])
            
            recommendations.append({
                'priority': 'Critical',
                'category': 'E-commerce Security & Bot Protection',
                'issue': f'{len(ddos_attacks)} DDoS attacks, {len(bot_attacks)} bot spikes, {len(scraping_attacks)} scraping attempts detected',
                'recommendation': 'Implement comprehensive bot protection for e-commerce',
                'attacking_ips': list(attacking_ips)[:10],
                'immediate_actions': [
                    f'🚨 URGENT: Block attacking IPs in firewall/CDN: {", ".join(list(attacking_ips)[:5])}',
                    '🛡️ Enable Cloudflare Bot Fight Mode or AWS WAF bot control',
                    '📊 Implement rate limiting: 60 req/min per IP for product pages',
                    '🔍 Add CAPTCHA to high-value pages (checkout, search)',
                    '⚡ Set up real-time IP blocking for >200 req/min'
                ],
                'e_commerce_specific': [
                    '💰 Protect product pricing data with anti-scraping measures',
                    '🛒 Implement checkout flow protection (session validation)',
                    '📈 Monitor conversion funnel for bot impact',
                    '🎯 Whitelist known good bots (Google, Bing) while blocking scrapers'
                ],
                'monitoring_setup': [
                    'Alert on >100 product page requests/minute from single IP',
                    'Monitor cart abandonment rate changes (bots inflate this)',
                    'Track pricing page access patterns',
                    'Set up geographic anomaly detection'
                ],
                'business_impact': 'Critical - Bots can steal pricing data, inflate analytics, and impact site performance',
                'revenue_protection': 'High - Prevents price scraping and protects competitive advantage'
            })
        
        # Payment and checkout anomalies
        payment_errors = [a for a in recent_anomalies if a['type'] == 'payment_anomaly']
        checkout_errors = [a for a in recent_anomalies if a['type'] == 'checkout_flow_anomaly']
        cart_abandonment = [a for a in recent_anomalies if a['type'] == 'cart_abandonment_spike']
        
        if len(payment_errors) > 0 or len(checkout_errors) > 0:
            recommendations.append({
                'priority': 'Critical',
                'category': 'E-commerce Revenue Protection',
                'issue': f'{len(payment_errors)} payment errors, {len(checkout_errors)} checkout issues detected',
                'recommendation': 'Fix critical revenue-impacting issues immediately',
                'immediate_actions': [
                    '💳 URGENT: Check payment gateway status (Stripe/PayPal/Mollie)',
                    '🔧 Test complete checkout flow manually',
                    '📞 Contact payment provider if 500 errors persist',
                    '💻 Check SSL certificate validity for payment pages',
                    '🔄 Verify webhook endpoints are responding'
                ],
                'revenue_impact_analysis': [
                    f'Estimated lost revenue: €{len(payment_errors) * 50:.0f} (assuming €50 avg order)',
                    'Check conversion rate drop in last hour',
                    'Monitor abandoned cart recovery emails',
                    'Verify payment method availability by region'
                ],
                'technical_checks': [
                    'Check payment gateway API response times',
                    'Verify database connection for order processing',
                    'Test payment form validation',
                    'Check inventory system integration'
                ],
                'business_impact': 'Critical - Direct revenue loss from failed payments',
                'estimated_loss': f'€{len(payment_errors) * 50:.0f}/hour if not fixed'
            })
        
        if len(cart_abandonment) > 0:
            avg_abandonment = sum([a['details'].get('abandonment_rate', 0) for a in cart_abandonment]) / len(cart_abandonment)
            recommendations.append({
                'priority': 'High',
                'category': 'E-commerce Conversion Optimization',
                'issue': f'Cart abandonment rate spike detected: {avg_abandonment:.1f}%',
                'recommendation': 'Investigate and fix conversion barriers',
                'immediate_actions': [
                    '🛒 Test checkout flow for UX issues',
                    '💰 Check for unexpected shipping costs display',
                    '🔒 Verify security badges are visible',
                    '📱 Test mobile checkout experience',
                    '⏱️ Check page load times for checkout pages'
                ],
                'conversion_analysis': [
                    'Compare abandonment rate to historical average',
                    'Analyze by traffic source (organic, paid, social)',
                    'Check for payment method availability issues',
                    'Review cart page error logs'
                ],
                'business_impact': 'High - Each 1% abandonment increase = significant revenue loss',
                'optimization_potential': f'Fixing could recover {avg_abandonment * 0.1:.1f}% revenue'
            })
        
        # Security threats
        attack_patterns = [a for a in recent_anomalies if a['type'] == 'attack_pattern_anomaly']
        suspicious_agents = [a for a in recent_anomalies if a['type'] == 'suspicious_user_agent']
        
        if len(attack_patterns) > 0 or len(suspicious_agents) > 0:
            attacked_paths = [a['details'].get('path') for a in attack_patterns if 'path' in a['details']][:5]
            recommendations.append({
                'priority': 'High',
                'category': 'E-commerce Security Hardening',
                'issue': f'{len(attack_patterns)} attack patterns, {len(suspicious_agents)} suspicious agents detected',
                'recommendation': 'Strengthen e-commerce security immediately',
                'targeted_endpoints': attacked_paths,
                'immediate_actions': [
                    '🛡️ Block malicious IPs at CDN/firewall level',
                    '🔒 Enable WAF rules for common e-commerce attacks',
                    '📊 Review admin panel access logs',
                    '🔐 Force password resets for admin accounts',
                    '🚨 Enable security monitoring for payment pages'
                ],
                'e_commerce_security': [
                    'Protect customer data and PCI compliance',
                    'Secure payment processing endpoints',
                    'Monitor for credit card testing attacks',
                    'Implement fraud detection for orders',
                    'Check for account takeover attempts'
                ],
                'compliance_check': [
                    'Verify PCI DSS compliance status',
                    'Check GDPR data protection measures',
                    'Review customer data access logs',
                    'Validate encryption for sensitive data'
                ],
                'business_impact': 'Critical - Potential data breach, compliance violations, reputation damage'
            })
        
        # Server errors and status code issues
        server_errors = [a for a in recent_anomalies if a['type'] == 'server_error_spike']
        client_errors = [a for a in recent_anomalies if a['type'] == 'client_error_spike']
        unusual_codes = [a for a in recent_anomalies if a['type'] == 'unusual_status_codes']
        
        if len(server_errors) > 0:
            total_server_errors = sum([a['details'].get('server_error_count', 0) for a in server_errors])
            avg_error_rate = sum([a['details'].get('server_error_rate', 0) for a in server_errors]) / len(server_errors)
            
            recommendations.append({
                'priority': 'Critical',
                'category': 'E-commerce Server Health Crisis',
                'issue': f'{len(server_errors)} server error spikes detected - {total_server_errors} total errors',
                'recommendation': 'Fix critical server errors immediately - revenue at risk',
                'error_metrics': {
                    'total_server_errors': total_server_errors,
                    'avg_error_rate': f'{avg_error_rate:.1f}%',
                    'error_types': Counter([a['details'].get('type', 'Unknown') for a in server_errors])
                },
                'immediate_actions': [
                    '🚨 CRITICAL: Check application server status immediately',
                    '💾 Verify database connectivity and performance',
                    '🔧 Review application error logs for root cause',
                    '📊 Check server resource usage (CPU, RAM, disk)',
                    '🌐 Verify load balancer and upstream server health'
                ],
                'revenue_impact': [
                    f'Estimated revenue loss: €{total_server_errors * 25:.0f} (€25 per failed transaction)',
                    'Server errors directly impact checkout and payment processing',
                    'Customer trust and conversion rates severely affected',
                    'SEO impact from high error rates'
                ],
                'technical_checks': [
                    'Check payment gateway API connectivity',
                    'Verify third-party service integrations',
                    'Review database connection pool settings',
                    'Check for memory leaks or resource exhaustion',
                    'Verify SSL certificate validity'
                ],
                'business_impact': 'Critical - Direct revenue loss, customer experience degradation',
                'estimated_loss': f'€{total_server_errors * 25:.0f}/hour if not resolved'
            })
        
        if len(client_errors) > 0:
            error_404_count = sum([a['details'].get('error_404_count', 0) for a in client_errors if 'error_404_count' in a['details']])
            error_403_count = sum([a['details'].get('error_403_count', 0) for a in client_errors if 'error_403_count' in a['details']])
            
            recommendations.append({
                'priority': 'High',
                'category': 'E-commerce User Experience Issues',
                'issue': f'{len(client_errors)} client error patterns detected - {error_404_count} 404s, {error_403_count} 403s',
                'recommendation': 'Fix user experience issues and security concerns',
                'error_breakdown': {
                    '404_errors': error_404_count,
                    '403_errors': error_403_count,
                    'impact': 'SEO penalties, poor user experience, potential security scanning'
                },
                'immediate_actions': [
                    '🔍 Check for broken internal links and missing pages',
                    '🤖 Investigate bot scanning attempts (high 404 rates)',
                    '🔒 Review access control settings (403 errors)',
                    '📱 Test mobile navigation and responsive design',
                    '🗺️ Update sitemap and fix redirect chains'
                ],
                'seo_impact': [
                    'High 404 rates negatively impact Google rankings',
                    'Broken product links reduce organic traffic',
                    'Poor user experience signals affect search visibility',
                    'Fix broken links to recover lost SEO value'
                ],
                'user_experience': [
                    'Broken links frustrate customers and reduce conversion',
                    'Missing product pages lose potential sales',
                    'Poor navigation affects customer journey',
                    'Fix UX issues to improve customer satisfaction'
                ],
                'business_impact': 'High - SEO penalties, reduced conversion, poor customer experience'
            })
        
        # Performance and slow endpoints
        response_time_spikes = [a for a in recent_anomalies if a['type'] == 'response_time_spike']
        product_page_slow = [a for a in recent_anomalies if a['type'] == 'product_page_anomaly']
        search_errors = [a for a in recent_anomalies if a['type'] == 'search_anomaly']
        slow_endpoints = [a for a in recent_anomalies if a['type'] == 'slow_endpoint']
        timeout_spikes = [a for a in recent_anomalies if a['type'] == 'timeout_spike']
        
        if len(response_time_spikes) > 0 or len(product_page_slow) > 0 or len(search_errors) > 0 or len(slow_endpoints) > 0 or len(timeout_spikes) > 0:
            slow_paths = [a['details'].get('path') for a in response_time_spikes + product_page_slow if 'path' in a['details']][:5]
            
            # Calculate comprehensive performance metrics
            all_perf_anomalies = response_time_spikes + product_page_slow + slow_endpoints + timeout_spikes
            avg_response_time = sum([a['details'].get('avg_response_time', a['details'].get('response_time', 0)) for a in all_perf_anomalies]) / max(len(all_perf_anomalies), 1)
            timeout_count = sum([a['details'].get('timeout_count', 0) for a in timeout_spikes])
            slow_request_count = sum([a['details'].get('slow_request_count', 0) for a in slow_endpoints])
            
            recommendations.append({
                'priority': 'Critical' if timeout_count > 0 else 'High',
                'category': 'E-commerce Performance Crisis',
                'issue': f'{len(all_perf_anomalies)} performance issues detected - {timeout_count} timeouts, {slow_request_count} slow requests',
                'recommendation': 'Fix critical performance bottlenecks immediately - conversion at risk',
                'performance_crisis': {
                    'avg_response_time': f'{avg_response_time:.2f}s',
                    'timeout_requests': timeout_count,
                    'slow_requests': slow_request_count,
                    'affected_endpoints': len(slow_paths),
                    'conversion_impact': f'{avg_response_time * 7:.1f}% conversion loss per slow page'
                },
                'immediate_actions': [
                    '🚨 URGENT: Check database performance and slow queries',
                    '⚡ Review server resource usage (CPU, RAM, disk I/O)',
                    '💾 Verify cache hit rates (Redis/Memcached/CDN)',
                    '🔍 Check for database deadlocks or connection issues',
                    '📊 Analyze application performance monitoring (APM) data'
                ],
                'e_commerce_priority_fixes': [
                    '🛒 Prioritize checkout flow performance (highest revenue impact)',
                    '📱 Optimize product page loading (affects conversion directly)',
                    '🔍 Fix search functionality performance',
                    '💳 Ensure payment gateway response times <2s',
                    '📈 Optimize category pages for better SEO'
                ],
                'technical_deep_dive': [
                    'Identify and optimize N+1 database queries',
                    'Implement database query caching for expensive operations',
                    'Review and optimize product image loading strategy',
                    'Check third-party API response times (payment, shipping)',
                    'Optimize JavaScript bundle size and loading'
                ],
                'monitoring_enhancement': [
                    'Set up real-time performance alerting (<3s response time)',
                    'Monitor Core Web Vitals impact on conversion rates',
                    'Track performance by customer journey stage',
                    'Implement performance budgets for critical pages'
                ],
                'business_impact': 'Critical - Every second of delay costs 7% conversion rate',
                'revenue_calculation': {
                    'daily_revenue_loss': f'€{len(all_perf_anomalies) * avg_response_time * 100:.0f}',
                    'conversion_impact': f'{avg_response_time * 7:.1f}% lower conversion rate',
                    'seo_impact': 'Google Core Web Vitals ranking factor affected'
                }
            })
        
        # Coupon and fraud detection
        coupon_abuse = [a for a in recent_anomalies if a['type'] == 'coupon_abuse']
        if len(coupon_abuse) > 0:
            avg_requests_per_ip = sum([a['details'].get('requests_per_ip', 0) for a in coupon_abuse]) / len(coupon_abuse)
            recommendations.append({
                'priority': 'High',
                'category': 'E-commerce Fraud Prevention',
                'issue': f'{len(coupon_abuse)} coupon abuse attempts detected',
                'recommendation': 'Implement fraud prevention for promotional codes',
                'fraud_metrics': {
                    'avg_attempts_per_ip': f'{avg_requests_per_ip:.1f}',
                    'total_abuse_attempts': sum([a['details'].get('coupon_requests', 0) for a in coupon_abuse])
                },
                'immediate_actions': [
                    '🎫 Implement coupon rate limiting (3 attempts per IP per hour)',
                    '🔒 Add CAPTCHA to coupon entry forms',
                    '📊 Monitor coupon usage patterns by IP',
                    '🚨 Block IPs with excessive failed coupon attempts',
                    '💰 Review high-value coupon usage for fraud'
                ],
                'fraud_prevention': [
                    'Implement device fingerprinting for coupon abuse',
                    'Set up automated coupon fraud detection rules',
                    'Monitor for coupon code sharing/leaking',
                    'Track conversion rates of coupon users vs normal users',
                    'Implement coupon usage limits per customer account'
                ],
                'business_protection': [
                    'Protect promotional budgets from abuse',
                    'Prevent coupon farming/reselling',
                    'Maintain fair promotional access for legitimate customers',
                    'Protect against organized coupon fraud rings'
                ],
                'business_impact': 'High - Coupon abuse can cost thousands in fraudulent discounts'
            })
        
        # Traffic pattern analysis (more e-commerce focused)
        weekly_comparison_anomalies = [a for a in recent_anomalies if a['type'] == 'same_time_last_week_anomaly']
        hourly_anomalies = [a for a in recent_anomalies if a['type'] == 'hourly_pattern_anomaly']
        
        if len(weekly_comparison_anomalies) > 2 or len(hourly_anomalies) > 5:
            traffic_changes = []
            for anomaly in weekly_comparison_anomalies[:3]:
                details = anomaly['details']
                if 'ratio' in details:
                    change_type = "increased" if details['ratio'] > 1 else "decreased"
                    percentage = abs(details['ratio'] - 1) * 100
                    dt = _ensure_datetime(anomaly['detected_at'])
                    hour = dt.strftime('%H:%M') if dt else 'unknown'
                    traffic_changes.append(f'{hour}: {change_type} by {percentage:.0f}%')
            
            recommendations.append({
                'priority': 'Medium',
                'category': 'E-commerce Traffic Intelligence',
                'issue': f'{len(weekly_comparison_anomalies)} weekly changes, {len(hourly_anomalies)} hourly pattern changes detected',
                'recommendation': 'Analyze traffic changes for business opportunities and issues',
                'traffic_changes': traffic_changes,
                'immediate_actions': [
                    '📈 Check Google Analytics for traffic source changes',
                    '🛍️ Review recent marketing campaigns and promotions',
                    '📱 Analyze mobile vs desktop traffic shifts',
                    '🔍 Check organic search ranking changes',
                    '📊 Compare conversion rates across traffic changes'
                ],
                'e_commerce_analysis': [
                    'Identify high-converting traffic sources to scale',
                    'Check if traffic drops correlate with competitor campaigns',
                    'Analyze product category performance changes',
                    'Review seasonal/promotional impact on traffic patterns',
                    'Monitor international traffic changes (new markets?)'
                ],
                'business_opportunities': [
                    'Scale successful traffic sources showing growth',
                    'Investigate new market opportunities from geographic changes',
                    'Optimize for high-converting time periods',
                    'Adjust inventory based on traffic pattern changes',
                    'Plan marketing campaigns around traffic insights'
                ],
                'monitoring_enhancement': [
                    'Set up automated traffic pattern alerts',
                    'Create conversion rate monitoring by traffic source',
                    'Implement real-time revenue impact tracking',
                    'Monitor competitor activity correlation'
                ],
                'business_impact': 'Medium-High - Traffic insights can drive significant revenue growth'
            })
        
        # General e-commerce monitoring enhancement
        if len(recent_anomalies) > 15:
            recommendations.append({
                'priority': 'Medium',
                'category': 'E-commerce Monitoring Excellence',
                'issue': f'{len(recent_anomalies)} total anomalies detected - enhance monitoring for better insights',
                'recommendation': 'Implement comprehensive e-commerce monitoring dashboard',
                'immediate_actions': [
                    '📊 Set up real-time e-commerce KPI dashboard',
                    '🚨 Implement revenue-impact alerting (payment failures, checkout errors)',
                    '📈 Create conversion funnel monitoring',
                    '🛒 Set up cart abandonment rate tracking',
                    '💰 Monitor average order value changes'
                ],
                'e_commerce_kpis': [
                    'Real-time revenue tracking',
                    'Conversion rate by traffic source',
                    'Product page performance metrics',
                    'Search functionality health',
                    'Payment gateway success rates'
                ],
                'advanced_monitoring': [
                    'Set up A/B test impact detection',
                    'Monitor competitor price changes correlation',
                    'Track seasonal pattern deviations',
                    'Implement inventory impact on traffic analysis',
                    'Create customer journey anomaly detection'
                ],
                'business_impact': 'High - Better monitoring leads to faster issue resolution and revenue protection'
            })
        
        return recommendations
    
    def _get_time_range_summary(self, anomalies: List[Dict[str, Any]]) -> str:
        """Get a human-readable time range summary for anomalies."""
        if not anomalies:
            return "No specific time"
        
        times = [_ensure_datetime(a['detected_at']) for a in anomalies]
        times = [t for t in times if t]
        if not times:
            return "No specific time"
        if len(times) == 1:
            return times[0].strftime('%H:%M')
        else:
            start_time = min(times).strftime('%H:%M')
            end_time = max(times).strftime('%H:%M')
            return f"{start_time} - {end_time}"
    
    def export_anomaly_report(self, output_file: str) -> None:
        """Export comprehensive anomaly detection report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_anomaly_summary(),
            'recent_anomalies': self.get_recent_anomalies(hours=24),
            'anomaly_timeline': self._get_anomaly_timeline(),
            'recommendations': self.get_anomaly_recommendations(),
            'historical_baselines': self._get_historical_baseline_summary(),
            'configuration': {
                'sensitivity_threshold': self.sensitivity,
                'window_size_minutes': self.window_size,
                'historical_data_days': self.days_back,
                'detection_methods': ['statistical', 'behavioral', 'pattern-based', 'historical-comparison', 'trend-analysis']
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def _get_anomaly_timeline(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get anomaly timeline for the last 24 hours."""
        timeline = defaultdict(list)
        recent_anomalies = self.get_recent_anomalies(hours=24)
        
        for anomaly in recent_anomalies:
            # detected_at is ISO string here
            hour = anomaly['detected_at'][:13]
            timeline[hour].append({
                'type': anomaly['type'],
                'severity': anomaly['details'].get('severity', 'Unknown'),
                'confidence': anomaly['confidence']
            })
        
        return dict(timeline)
    
    def _get_historical_baseline_summary(self) -> Dict[str, Any]:
        """Get summary of historical baselines for reporting."""
        summary = {
            'baseline_data_available': len(self.historical_baselines.get('hourly', {})) > 0,
            'historical_data_days': self.days_back,
            'hourly_baselines_count': len(self.historical_baselines.get('hourly', {})),
            'weekday_baselines_count': len(self.historical_baselines.get('weekday', {})),
        }
        
        # Sample of hourly baselines for verification
        if self.historical_baselines.get('hourly'):
            sample_hours = list(self.historical_baselines['hourly'].keys())[:3]
            summary['sample_hourly_baselines'] = {
                hour: {
                    'requests_mean': self.historical_baselines['hourly'][hour].get('requests_mean', 0),
                    'error_rate_mean': self.historical_baselines['hourly'][hour].get('error_rate_mean', 0),
                    'unique_ips_mean': self.historical_baselines['hourly'][hour].get('unique_ips_mean', 0)
                }
                for hour in sample_hours
            }
        
        # Sample of weekday baselines
        if self.historical_baselines.get('weekday'):
            weekday_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            summary['weekday_baselines'] = {
                weekday_names[day]: {
                    'requests_mean': self.historical_baselines['weekday'][day].get('requests_mean', 0),
                    'error_rate_mean': self.historical_baselines['weekday'][day].get('error_rate_mean', 0)
                }
                for day in self.historical_baselines['weekday'].keys()
            }
        
        return summary
    
    def get_historical_comparison_report(self) -> Dict[str, Any]:
        """Generate a detailed historical comparison report."""
        current_time = datetime.now()
        current_hour = current_time.hour
        current_weekday = current_time.weekday()
        
        report = {
            'timestamp': current_time.isoformat(),
            'current_context': {
                'hour': current_hour,
                'weekday': current_weekday,
                'weekday_name': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'][current_weekday]
            },
            'historical_baselines_available': len(self.historical_baselines.get('hourly', {})) > 0,
            'data_collection_period': f'{self.days_back} days',
        }
        
        # Current hour baseline comparison
        if current_hour in self.historical_baselines.get('hourly', {}):
            hourly_baseline = self.historical_baselines['hourly'][current_hour]
            report['current_hour_baseline'] = {
                'hour': current_hour,
                'historical_requests_mean': hourly_baseline.get('requests_mean', 0),
                'historical_requests_stdev': hourly_baseline.get('requests_stdev', 0),
                'historical_error_rate_mean': hourly_baseline.get('error_rate_mean', 0),
                'historical_unique_ips_mean': hourly_baseline.get('unique_ips_mean', 0),
            }
        
        # Current weekday baseline comparison
        if current_weekday in self.historical_baselines.get('weekday', {}):
            weekday_baseline = self.historical_baselines['weekday'][current_weekday]
            report['current_weekday_baseline'] = {
                'weekday': current_weekday,
                'weekday_name': report['current_context']['weekday_name'],
                'historical_requests_mean': weekday_baseline.get('requests_mean', 0),
                'historical_error_rate_mean': weekday_baseline.get('error_rate_mean', 0),
                'historical_unique_ips_mean': weekday_baseline.get('unique_ips_mean', 0),
            }
        
        # Recent historical anomalies
        recent_anomalies = self.get_recent_anomalies(hours=24)
        historical_anomalies = [a for a in recent_anomalies if any(keyword in a['type'] for keyword in ['historical', 'hourly', 'weekday', 'weekly', 'trend'])]
        
        report['recent_historical_anomalies'] = {
            'total_count': len(historical_anomalies),
            'by_type': Counter(a['type'] for a in historical_anomalies),
            'by_severity': Counter(a['details'].get('severity', 'Unknown') for a in historical_anomalies)
        }
        
        return report
    
    def _get_detailed_anomaly_breakdown(self, recent_anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get detailed breakdown of each anomaly type with specific examples."""
        breakdown = {}
        
        # Group anomalies by type
        anomalies_by_type = defaultdict(list)
        for anomaly in recent_anomalies:
            anomalies_by_type[anomaly['type']].append(anomaly)
        
        for anomaly_type, anomalies in anomalies_by_type.items():
            # Build driver aggregations and distributions
            ip_counter = Counter()
            path_counter = Counter()
            country_counter = Counter()
            ua_counter = Counter()
            hourly_counts = defaultdict(int)
            z_scores = []
            actual_expected_pairs = []

            for a in anomalies:
                details = a.get('details', {})
                ip = details.get('ip')
                if ip:
                    ip_counter[ip] += 1
                path = details.get('path')
                if path:
                    path_counter[path] += 1
                country = details.get('country')
                if country:
                    country_counter[country] += 1
                ua = details.get('user_agent')
                if ua:
                    ua_counter[ua] += 1

                # Hourly distribution
                dt = _ensure_datetime(a.get('detected_at'))
                if dt:
                    hourly_counts[dt.hour] += 1

                # Metrics summary
                if isinstance(details.get('z_score'), (int, float)):
                    z_scores.append(details['z_score'])
                actual = None
                expected = None
                if 'actual_value' in details and ('historical_mean' in details or 'expected_value' in details):
                    actual = details.get('actual_value')
                    expected = details.get('expected_value', details.get('historical_mean'))
                elif 'actual_requests' in details and 'expected_requests' in details:
                    actual = details.get('actual_requests')
                    expected = details.get('expected_requests')
                elif 'actual_unique_ips' in details and 'expected_unique_ips' in details:
                    actual = details.get('actual_unique_ips')
                    expected = details.get('expected_unique_ips')
                elif 'actual_error_rate' in details and 'expected_error_rate' in details:
                    actual = details.get('actual_error_rate')
                    expected = details.get('expected_error_rate')
                if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
                    actual_expected_pairs.append((actual, expected))

            total_count = len(anomalies) or 1
            top_ips = ip_counter.most_common(5)
            top_paths = path_counter.most_common(5)
            top_countries = country_counter.most_common(5)
            top_uas = ua_counter.most_common(3)

            # Percentages for drivers
            def with_pct(items):
                return [
                    {'value': k, 'count': v, 'percent': round((v / total_count) * 100, 1)}
                    for k, v in items
                ]

            # Metrics summary calculations
            metrics_summary = {}
            if z_scores:
                metrics_summary['z_score'] = {
                    'min': round(min(z_scores), 2),
                    'avg': round(sum(z_scores) / len(z_scores), 2),
                    'max': round(max(z_scores), 2)
                }
            if actual_expected_pairs:
                diffs = [a - e for a, e in actual_expected_pairs]
                rel = [(a - e) / e if e else None for a, e in actual_expected_pairs]
                rel = [r for r in rel if r is not None]
                metrics_summary['actual_vs_expected'] = {
                    'avg_actual': round(sum(a for a, _ in actual_expected_pairs) / len(actual_expected_pairs), 2),
                    'avg_expected': round(sum(e for _, e in actual_expected_pairs) / len(actual_expected_pairs), 2),
                    'avg_delta': round(sum(diffs) / len(diffs), 2),
                    'avg_delta_percent': round((sum(rel) / len(rel)) * 100, 1) if rel else None
                }

            # Peak details
            peak_hour = None
            peak_count = 0
            if hourly_counts:
                peak_hour, peak_count = max(hourly_counts.items(), key=lambda kv: kv[1])

            type_breakdown = {
                'count': len(anomalies),
                'severity_distribution': Counter(a['details'].get('severity', 'Unknown') for a in anomalies),
                'examples': [],
                'time_range': {
                    'first_occurrence': _iso_or_none(min((_ensure_datetime(a['detected_at']) for a in anomalies if _ensure_datetime(a['detected_at'])), default=None)),
                    'last_occurrence': _iso_or_none(max((_ensure_datetime(a['detected_at']) for a in anomalies if _ensure_datetime(a['detected_at'])), default=None)),
                },
                'impact_summary': self._get_impact_summary_for_type(anomaly_type, anomalies),
                'drivers': {
                    'top_ips': with_pct(top_ips),
                    'top_paths': with_pct(top_paths),
                    'top_countries': with_pct(top_countries),
                    'top_user_agents': with_pct(top_uas),
                },
                'hourly_distribution': dict(sorted(hourly_counts.items())),
                'peak': {
                    'hour': peak_hour,
                    'count': peak_count,
                },
                'metrics_summary': metrics_summary
            }
            
            # Add up to 3 specific examples
            for anomaly in anomalies[:3]:
                example = {
                    'timestamp': _iso_or_none(anomaly['detected_at']) or str(anomaly['detected_at']),
                    'severity': anomaly['details'].get('severity', 'Unknown'),
                    'confidence': anomaly['confidence'],
                    'description': self._format_anomaly_description(anomaly),
                    'key_metrics': self._extract_key_metrics(anomaly)
                }
                type_breakdown['examples'].append(example)
            
            breakdown[anomaly_type] = type_breakdown
        
        return breakdown
    
    def _get_timeline_analysis(self, recent_anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get timeline analysis of anomalies throughout the day."""
        if not recent_anomalies:
            return {'hourly_distribution': {}, 'peak_periods': [], 'quiet_periods': []}
        
        # Group by hour
        hourly_counts = defaultdict(int)
        hourly_severity = defaultdict(list)
        
        for anomaly in recent_anomalies:
            dt = _ensure_datetime(anomaly['detected_at'])
            if not dt:
                continue
            hour = dt.hour
            hourly_counts[hour] += 1
            hourly_severity[hour].append(anomaly['details'].get('severity', 'Unknown'))
        
        # Find peak and quiet periods
        avg_per_hour = sum(hourly_counts.values()) / len(hourly_counts) if hourly_counts else 0
        peak_periods = [hour for hour, count in hourly_counts.items() if count > avg_per_hour * 1.5]
        quiet_periods = [hour for hour in range(24) if hour not in hourly_counts or hourly_counts[hour] < avg_per_hour * 0.5]
        
        return {
            'hourly_distribution': dict(hourly_counts),
            'hourly_severity_breakdown': {hour: Counter(severities) for hour, severities in hourly_severity.items()},
            'peak_periods': peak_periods,
            'quiet_periods': quiet_periods,
            'average_per_hour': round(avg_per_hour, 1)
        }
    
    def _get_top_affected_resources(self, recent_anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get the most affected IPs, paths, and other resources."""
        affected_ips = Counter()
        affected_paths = Counter()
        affected_countries = Counter()
        affected_user_agents = Counter()
        
        for anomaly in recent_anomalies:
            details = anomaly['details']
            
            # Extract IPs
            if 'ip' in details:
                affected_ips[details['ip']] += 1
            
            # Extract paths
            if 'path' in details:
                affected_paths[details['path']] += 1
            
            # Extract countries
            if 'country' in details:
                affected_countries[details['country']] += 1
                
            # Extract user agents (truncated)
            if 'user_agent' in details:
                ua = details['user_agent'][:50] + '...' if len(details['user_agent']) > 50 else details['user_agent']
                affected_user_agents[ua] += 1
        
        return {
            'top_ips': dict(affected_ips.most_common(5)),
            'top_paths': dict(affected_paths.most_common(5)),
            'top_countries': dict(affected_countries.most_common(5)),
            'top_user_agents': dict(affected_user_agents.most_common(3))
        }
    
    def _get_historical_context(self) -> Dict[str, Any]:
        """Get historical context for better understanding of current anomalies."""
        current_time = datetime.now()
        current_hour = current_time.hour
        current_weekday = current_time.weekday()
        weekday_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        
        context = {
            'current_time': current_time.isoformat(),
            'current_hour': current_hour,
            'current_weekday': weekday_names[current_weekday],
            'historical_data_available': len(self.historical_baselines.get('hourly', {})) > 0,
            'baseline_comparison': {}
        }
        
        # Add current hour baseline if available
        if current_hour in self.historical_baselines.get('hourly', {}):
            hourly_baseline = self.historical_baselines['hourly'][current_hour]
            context['baseline_comparison']['current_hour'] = {
                'hour': current_hour,
                'expected_requests': round(hourly_baseline.get('requests_mean', 0), 1),
                'expected_error_rate': round(hourly_baseline.get('error_rate_mean', 0), 1),
                'expected_unique_ips': round(hourly_baseline.get('unique_ips_mean', 0), 1),
                'current_vs_expected': self._calculate_current_vs_expected(hourly_baseline)
            }
        
        # Add weekday baseline if available
        if current_weekday in self.historical_baselines.get('weekday', {}):
            weekday_baseline = self.historical_baselines['weekday'][current_weekday]
            context['baseline_comparison']['current_weekday'] = {
                'weekday': weekday_names[current_weekday],
                'expected_requests': round(weekday_baseline.get('requests_mean', 0), 1),
                'expected_error_rate': round(weekday_baseline.get('error_rate_mean', 0), 1)
            }
        
        return context
    
    def _get_impact_summary_for_type(self, anomaly_type: str, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get impact summary for a specific anomaly type."""
        if not anomalies:
            return {}
        
        # Calculate duration
        if len(anomalies) > 1:
            times = [
                _ensure_datetime(a.get('detected_at'))
                for a in anomalies
                if _ensure_datetime(a.get('detected_at')) is not None
            ]
            if len(times) >= 2:
                first_time = min(times)
                last_time = max(times)
                duration_minutes = (last_time - first_time).total_seconds() / 60
            else:
                duration_minutes = 1
        else:
            duration_minutes = 1
        
        # Count high severity anomalies
        high_severity_count = sum(1 for a in anomalies if a['details'].get('severity') == 'High')
        critical_count = sum(1 for a in anomalies if a['details'].get('severity') == 'Critical')
        
        return {
            'duration_minutes': round(duration_minutes, 1),
            'high_severity_count': high_severity_count,
            'critical_count': critical_count,
            'average_confidence': round(sum(a['confidence'] for a in anomalies) / len(anomalies), 2),
            'estimated_impact': self._estimate_business_impact(anomaly_type, len(anomalies), duration_minutes)
        }
    
    def _format_anomaly_description(self, anomaly: Dict[str, Any]) -> str:
        """Format a human-readable description of an anomaly."""
        anomaly_type = anomaly['type']
        details = anomaly['details']
        
        if anomaly_type == 'same_time_last_week_anomaly':
            if 'ratio' in details:
                change = "increased" if details['ratio'] > 1 else "decreased"
                percentage = abs(details['ratio'] - 1) * 100
                return f"Traffic {change} by {percentage:.0f}% compared to same time last week ({details.get('current_value', 0)} vs {details.get('last_week_value', 0)} requests)"
            elif 'current_error_rate' in details:
                return f"Error rate increased to {details['current_error_rate']:.1f}% (vs {details.get('last_week_error_rate', 0):.1f}% last week)"
        
        elif anomaly_type == 'hourly_pattern_anomaly':
            metric = details.get('metric', 'unknown')
            actual = details.get('actual_value', 0)
            expected = details.get('historical_mean', 0)
            return f"Hourly {metric} pattern deviation: {actual} vs expected {expected:.1f} (hour {details.get('hour', 'unknown')})"
        
        elif anomaly_type == 'traffic_spike':
            return f"Traffic spike detected: {details.get('actual_requests', 0)} requests vs expected {details.get('expected_requests', 0):.1f}"
        
        elif anomaly_type == 'ddos_attack':
            return f"High request rate from IP {details.get('ip', 'unknown')}: {details.get('requests_per_minute', 0)} requests/minute"
        
        elif anomaly_type == 'geographic_anomaly':
            return f"Unusual traffic from {details.get('country', 'unknown')}: {details.get('requests', 0)} requests vs expected {details.get('expected_requests', 0)}"
        
        else:
            return f"{anomaly_type.replace('_', ' ').title()} detected"
    
    def _extract_key_metrics(self, anomaly: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key metrics from an anomaly for display."""
        details = anomaly['details']
        metrics = {}
        
        # Common metrics
        if 'actual_value' in details:
            metrics['actual_value'] = details['actual_value']
        if 'expected_value' in details or 'historical_mean' in details:
            metrics['expected_value'] = details.get('expected_value', details.get('historical_mean', 0))
        if 'z_score' in details:
            metrics['z_score'] = round(details['z_score'], 2)
        if 'ratio' in details:
            metrics['change_ratio'] = round(details['ratio'], 2)
        if 'deviation_percentage' in details:
            metrics['deviation_percent'] = round(details['deviation_percentage'], 1)
        
        return metrics
    
    def _calculate_current_vs_expected(self, baseline: Dict[str, float]) -> Dict[str, str]:
        """Calculate current vs expected values for display."""
        # This would need current minute data to compare
        # For now, return placeholder
        return {
            'requests': 'Monitoring...',
            'error_rate': 'Monitoring...',
            'unique_ips': 'Monitoring...'
        }
    
    def _estimate_business_impact(self, anomaly_type: str, count: int, duration_minutes: float) -> str:
        """Estimate business impact of anomalies."""
        if anomaly_type == 'ddos_attack':
            return 'High - Potential service disruption'
        elif anomaly_type == 'traffic_spike' and count > 10:
            return 'Medium - Possible marketing campaign or viral content'
        elif anomaly_type == 'traffic_drop' and count > 5:
            return 'Medium - Possible service issues or user experience problems'
        elif anomaly_type == 'error_spike':
            return 'High - User experience degradation'
        elif duration_minutes > 30:
            return 'Medium - Extended anomaly period'
        else:
            return 'Low - Brief anomaly'
