"""API endpoint analysis module for REST, GraphQL, and API pattern insights."""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Tuple, Optional
from urllib.parse import urlparse, parse_qs
import statistics
from rich.console import Console

console = Console()


class APIAnalyzer:
    """Analyzes API endpoints, patterns, and performance."""
    
    def __init__(self):
        """Initialize API analyzer."""
        # API endpoint tracking
        self.api_endpoints = defaultdict(lambda: {
            'total_requests': 0,
            'unique_ips': set(),
            'methods': Counter(),
            'status_codes': Counter(),
            'response_times': [],
            'bandwidth_bytes': 0,
            'error_count': 0,
            'user_agents': Counter(),
            'countries': Counter(),
            'hourly_distribution': defaultdict(int),
            'query_parameters': Counter(),
            'api_versions': Counter(),
            'content_types': Counter()
        })
        
        # API pattern analysis
        self.api_patterns = {
            'rest_endpoints': Counter(),
            'graphql_queries': Counter(),
            'api_versions': Counter(),
            'authentication_methods': Counter(),
            'rate_limited_endpoints': Counter(),
            'deprecated_endpoints': Counter()
        }
        
        # Performance metrics
        self.performance_metrics = {
            'slowest_endpoints': Counter(),
            'highest_error_rate': Counter(),
            'most_bandwidth_intensive': Counter(),
            'most_popular': Counter()
        }
        
        # Security analysis
        self.security_issues = {
            'unauthenticated_access': Counter(),
            'excessive_requests': Counter(),
            'suspicious_queries': Counter(),
            'potential_abuse': Counter()
        }
        
        # Platform detections and metrics
        self.platforms = {
            'wordpress': {
                'detected': False,
                'signals': Counter(),
                'endpoints': Counter(),
                'plugins': Counter(),
                'woocommerce': {'detected': False, 'signals': Counter(), 'endpoints': Counter()}
            },
            'magento2': {
                'detected': False,
                'signals': Counter(),
                'endpoints': Counter()
            },
            'prestashop': {
                'detected': False,
                'signals': Counter(),
                'endpoints': Counter()
            },
            'shopware': {
                'detected': False,
                'signals': Counter(),
                'endpoints': Counter()
            }
        }

        # GraphQL specific analysis
        self.graphql_analysis = {
            'query_types': Counter(),
            'mutation_types': Counter(),
            'subscription_types': Counter(),
            'query_complexity': [],
            'introspection_queries': 0,
            'nested_queries': Counter()
        }
        
        # Initialize API detection patterns
        self._init_api_patterns()
    
    def _init_api_patterns(self):
        """Initialize API detection patterns."""
        self.api_detection_patterns = {
            'rest_api': [
                r'/api/v?\d+/', r'/api/', r'/rest/', r'/service/',
                r'/endpoints?/', r'/resources?/'
            ],
            'graphql': [
                r'/graphql', r'/graph', r'/gql', r'/query'
            ],
            'webhook': [
                r'/webhook', r'/hook', r'/callback', r'/notify'
            ],
            'auth_api': [
                r'/auth/', r'/oauth/', r'/login', r'/token', r'/signin'
            ],
            'admin_api': [
                r'/admin/api', r'/management/', r'/control/'
            ]
        }

        # Platform-specific patterns
        self.platform_detection_patterns = {
            'wordpress': [
                r'/wp-json/', r'/wp-admin/', r'/wp-content/', r'/wp-includes/',
                r'wp-.*\.php', r'/xmlrpc\.php', r'/wp-login\.php',
                r'/\?rest_route=', r'X-WP-Total', r'X-WP-Nonce'
            ],
            'woocommerce': [
                r'/wp-json/wc/\w+', r'/\?wc-ajax=', r'woocommerce_session_',
                r'woocommerce_.*', r'wc-api='
            ],
            'magento2': [
                r'/rest/(V\d+/)?', r'/graphql', r'/static/(version\d+/)?',
                r'/index\.php', r'/customer/section/load', r'X-Magento-Cache',
                r'/V1/'
            ],
            'prestashop': [
                r'/api/\w+\?ws_key=', r'/modules/', r'PrestaShop-[\d\.]+',
                r'/index\.php\?controller=', r'ps-.*'
            ],
            'shopware': [
                r'/api', r'/store-api', r'/sales-channel-api', r'shopware-[\d\.]+',
                r'/admin/api'
            ]
        }
        
        # Common API versioning patterns
        self.version_patterns = [
            r'/v(\d+)/',           # /v1/, /v2/
            r'/api/v(\d+)/',       # /api/v1/
            r'version=(\d+)',      # ?version=1
            r'v=(\d+)',            # ?v=1
            r'/(\d+\.\d+)/'        # /1.0/, /2.1/
        ]
        
        # GraphQL operation patterns
        self.graphql_patterns = {
            'query': r'query\s+(\w+)',
            'mutation': r'mutation\s+(\w+)',
            'subscription': r'subscription\s+(\w+)',
            'fragment': r'fragment\s+(\w+)',
            'introspection': r'__schema|__type|__typename'
        }
    
    def analyze_entry(self, log_entry: Dict[str, Any]) -> None:
        """Analyze a single log entry for API patterns."""
        path = log_entry.get('path', '')
        method = log_entry.get('method', 'GET')
        
        if not self._is_api_request(path):
            return
        
        # Normalize API endpoint
        api_endpoint = self._normalize_api_endpoint(path)
        endpoint_data = self.api_endpoints[api_endpoint]
        
        # Basic metrics
        endpoint_data['total_requests'] += 1
        endpoint_data['methods'][method] += 1
        
        # IP tracking
        ip = log_entry.get('remote_addr', '')
        if ip:
            endpoint_data['unique_ips'].add(ip)
        
        # Status code analysis
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        endpoint_data['status_codes'][status] += 1
        if status >= 400:
            endpoint_data['error_count'] += 1
        
        # Performance tracking
        response_time = log_entry.get('request_time', 0)
        if isinstance(response_time, str):
            try:
                response_time = float(response_time)
            except:
                response_time = 0
        
        if response_time > 0:
            endpoint_data['response_times'].append(response_time)
            if response_time > 5:  # Slow API calls
                self.performance_metrics['slowest_endpoints'][api_endpoint] += 1
        
        # Bandwidth tracking
        bytes_sent = log_entry.get('body_bytes_sent', 0)
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = int(bytes_sent)
            except:
                bytes_sent = 0
        endpoint_data['bandwidth_bytes'] += bytes_sent
        
        if bytes_sent > 1024 * 1024:  # > 1MB responses
            self.performance_metrics['most_bandwidth_intensive'][api_endpoint] += 1
        
        # User agent analysis
        user_agent = log_entry.get('user_agent', '')
        if user_agent:
            endpoint_data['user_agents'][user_agent] += 1
        
        # Geographic analysis
        country = log_entry.get('country', '')
        if country and country != '-':
            endpoint_data['countries'][country] += 1
        
        # Temporal analysis
        timestamp = log_entry.get('timestamp')
        if timestamp:
            endpoint_data['hourly_distribution'][timestamp.hour] += 1
        
        # API-specific analysis
        self._analyze_api_specifics(path, method, log_entry, api_endpoint)
        
        # Security analysis
        self._analyze_api_security(path, method, log_entry, api_endpoint, ip)

        # Platform detection and analysis
        self._detect_and_analyze_platforms(log_entry, api_endpoint)

    def _detect_and_analyze_platforms(self, log_entry: Dict[str, Any], api_endpoint: str) -> None:
        """Detect platform signals and track platform-specific metrics."""
        path = log_entry.get('path', '') or ''
        request_line = log_entry.get('request', '') or ''
        user_agent = (log_entry.get('user_agent') or '').lower()
        referer = (log_entry.get('referer') or '').lower()
        cookies = (log_entry.get('http_cookie') or log_entry.get('cookie') or '')
        headers = log_entry.get('headers') or {}

        text_blob = ' '.join([
            path.lower(), request_line.lower(), user_agent, referer,
            cookies.lower(), ' '.join(f"{k}:{v}" for k, v in headers.items()).lower()
        ])

        def match_any(patterns: list) -> list:
            matches = []
            for patt in patterns:
                try:
                    if re.search(patt, text_blob):
                        matches.append(patt)
                except Exception:
                    continue
            return matches

        # WordPress
        wp_matches = match_any(self.platform_detection_patterns['wordpress'])
        if wp_matches:
            wp = self.platforms['wordpress']
            wp['detected'] = True
            for m in wp_matches:
                wp['signals'][m] += 1
            wp['endpoints'][api_endpoint] += 1

            # Detect plugins from paths like /wp-content/plugins/<plugin>/
            try:
                plugin_match = re.findall(r'/wp-content/plugins/([\w\-]+)/', path, flags=re.IGNORECASE)
                for plugin in plugin_match:
                    wp['plugins'][plugin.lower()] += 1
            except Exception:
                pass

            # WooCommerce (as WordPress plugin)
            wc_matches = match_any(self.platform_detection_patterns['woocommerce'])
            if wc_matches:
                wc = wp['woocommerce']
                wc['detected'] = True
                for m in wc_matches:
                    wc['signals'][m] += 1
                wc['endpoints'][api_endpoint] += 1

            # Platform-specific security heuristics
            if '/xmlrpc.php' in path.lower():
                self.security_issues['potential_abuse'][f'wordpress:xmlrpc'] += 1
            if '/wp-admin' in path.lower() and 'authorization' not in ' '.join(headers.keys()).lower():
                self.security_issues['unauthenticated_access'][f'wordpress:wp-admin'] += 1

        # Magento 2
        m2_matches = match_any(self.platform_detection_patterns['magento2'])
        if m2_matches:
            m2 = self.platforms['magento2']
            m2['detected'] = True
            for m in m2_matches:
                m2['signals'][m] += 1
            m2['endpoints'][api_endpoint] += 1

            # Security heuristics
            if '/customer/section/load' in path.lower() and ('*/*' in (headers.get('Accept', '') or '')):
                self.security_issues['potential_abuse'][f'magento2:section-load'] += 1
            if 'x-magento-cache' in text_blob:
                self.security_issues['potential_abuse'][f'magento2:cache-exposed'] += 1

        # PrestaShop
        ps_matches = match_any(self.platform_detection_patterns['prestashop'])
        if ps_matches:
            ps = self.platforms['prestashop']
            ps['detected'] = True
            for m in ps_matches:
                ps['signals'][m] += 1
            ps['endpoints'][api_endpoint] += 1

            # Security heuristics
            if 'ws_key=' in request_line.lower():
                self.security_issues['potential_abuse'][f'prestashop:ws-key-exposed'] += 1

        # Shopware
        sw_matches = match_any(self.platform_detection_patterns['shopware'])
        if sw_matches:
            sw = self.platforms['shopware']
            sw['detected'] = True
            for m in sw_matches:
                sw['signals'][m] += 1
            sw['endpoints'][api_endpoint] += 1

            # Security heuristics
            if '/store-api' in path.lower() and log_entry.get('status') == 401:
                self.security_issues['unauthenticated_access'][f'shopware:store-api'] += 1
    
    def _is_api_request(self, path: str) -> bool:
        """Determine if a request is an API call."""
        path_lower = path.lower()
        
        # Check for API patterns
        for pattern_type, patterns in self.api_detection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, path_lower):
                    return True
        
        # Check for common API indicators
        api_indicators = [
            '.json', '.xml', '.api', 'application/json',
            '/search/', '/data/', '/fetch/', '/get/', '/post/',
            '/put/', '/delete/', '/update/', '/create/'
        ]
        
        return any(indicator in path_lower for indicator in api_indicators)
    
    def _normalize_api_endpoint(self, path: str) -> str:
        """Normalize API endpoint for grouping similar requests."""
        # Remove query parameters
        if '?' in path:
            path = path.split('?')[0]
        
        # Replace IDs and UUIDs with placeholders
        path = re.sub(r'/\d+(?:/|$)', '/{id}/', path)
        path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/|$)', '/{uuid}/', path)
        path = re.sub(r'/[a-zA-Z0-9]{20,}(?:/|$)', '/{token}/', path)
        
        # Normalize trailing slashes
        if path.endswith('/') and len(path) > 1:
            path = path[:-1]
        
        return path
    
    def _analyze_api_specifics(self, path: str, method: str, log_entry: Dict[str, Any], api_endpoint: str) -> None:
        """Analyze API-specific patterns."""
        # Version detection
        for pattern in self.version_patterns:
            match = re.search(pattern, path)
            if match:
                version = match.group(1)
                self.api_patterns['api_versions'][version] += 1
                self.api_endpoints[api_endpoint]['api_versions'][version] += 1
                break
        
        # REST API pattern analysis
        if re.search(r'/api/', path, re.IGNORECASE):
            self.api_patterns['rest_endpoints'][api_endpoint] += 1
            
            # Analyze REST methods
            if method in ['POST', 'PUT', 'PATCH']:
                self.api_patterns['rest_endpoints'][f"{method}_{api_endpoint}"] += 1
        
        # GraphQL analysis
        if re.search(r'/graphql|/graph|/gql', path, re.IGNORECASE):
            self._analyze_graphql_request(log_entry, api_endpoint)
        
        # Authentication analysis
        if re.search(r'/auth|/login|/token|/oauth', path, re.IGNORECASE):
            self.api_patterns['authentication_methods'][api_endpoint] += 1
        
        # Rate limiting detection
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        if status == 429:  # Too Many Requests
            self.api_patterns['rate_limited_endpoints'][api_endpoint] += 1
        
        # Query parameter analysis
        if '?' in log_entry.get('request', ''):
            try:
                query_string = log_entry.get('request', '').split('?', 1)[1].split(' ')[0]
                parsed_query = parse_qs(query_string)
                for param in parsed_query.keys():
                    self.api_endpoints[api_endpoint]['query_parameters'][param] += 1
            except:
                pass
    
    def _analyze_graphql_request(self, log_entry: Dict[str, Any], api_endpoint: str) -> None:
        """Analyze GraphQL-specific patterns."""
        # This would typically require request body analysis
        # For now, we'll analyze based on available data
        
        user_agent = log_entry.get('user_agent', '').lower()
        referer = log_entry.get('referer', '').lower()
        
        # Check for GraphQL client indicators
        if any(client in user_agent for client in ['apollo', 'relay', 'graphiql', 'altair']):
            self.graphql_analysis['query_types']['client_query'] += 1
        
        # Check for introspection patterns in referer or user agent
        if any(pattern in f"{user_agent} {referer}" for pattern in ['__schema', '__type', 'introspection']):
            self.graphql_analysis['introspection_queries'] += 1
        
        # Estimate query complexity based on response size
        bytes_sent = log_entry.get('body_bytes_sent', 0)
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = int(bytes_sent)
            except:
                bytes_sent = 0
        
        if bytes_sent > 0:
            # Simple complexity estimation based on response size
            complexity = min(bytes_sent / 1000, 100)  # Cap at 100
            self.graphql_analysis['query_complexity'].append(complexity)
    
    def _analyze_api_security(self, path: str, method: str, log_entry: Dict[str, Any], api_endpoint: str, ip: str) -> None:
        """Analyze API security patterns."""
        # Check for unauthenticated access to sensitive endpoints
        if any(sensitive in path.lower() for sensitive in ['/admin', '/management', '/control', '/config']):
            # Simple heuristic: no authorization header mentioned in logs
            self.security_issues['unauthenticated_access'][api_endpoint] += 1
        
        # Check for excessive requests from single IP
        if ip:
            ip_request_count = sum(1 for endpoint_data in self.api_endpoints.values() 
                                 if ip in endpoint_data['unique_ips'])
            if ip_request_count > 100:  # Threshold for excessive requests
                self.security_issues['excessive_requests'][ip] += 1
        
        # Check for suspicious query patterns
        if '?' in path:
            query_string = path.split('?', 1)[1].lower()
            suspicious_patterns = ['script', 'alert', 'union', 'select', 'drop', 'delete', 'update']
            if any(pattern in query_string for pattern in suspicious_patterns):
                self.security_issues['suspicious_queries'][api_endpoint] += 1
        
        # Check for potential API abuse (high error rates)
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        if status >= 400:
            endpoint_data = self.api_endpoints[api_endpoint]
            error_rate = endpoint_data['error_count'] / max(endpoint_data['total_requests'], 1)
            if error_rate > 0.5:  # More than 50% errors
                self.security_issues['potential_abuse'][api_endpoint] += 1
    
    def get_api_summary(self) -> Dict[str, Any]:
        """Get comprehensive API analysis summary."""
        total_api_requests = sum(data['total_requests'] for data in self.api_endpoints.values())
        total_endpoints = len(self.api_endpoints)
        
        # Calculate overall statistics
        all_response_times = []
        total_errors = 0
        total_bandwidth = 0
        
        for endpoint_data in self.api_endpoints.values():
            all_response_times.extend(endpoint_data['response_times'])
            total_errors += endpoint_data['error_count']
            total_bandwidth += endpoint_data['bandwidth_bytes']
        
        # Performance statistics
        performance_stats = {}
        if all_response_times:
            performance_stats = {
                'avg_response_time': statistics.mean(all_response_times),
                'median_response_time': statistics.median(all_response_times),
                'p95_response_time': statistics.quantiles(all_response_times, n=20)[18] if len(all_response_times) > 1 else all_response_times[0],
                'p99_response_time': statistics.quantiles(all_response_times, n=100)[98] if len(all_response_times) > 1 else all_response_times[0],
                'max_response_time': max(all_response_times),
                'min_response_time': min(all_response_times)
            }
        
        # Top endpoints by various metrics
        top_endpoints = {
            'most_popular': dict(Counter({
                endpoint: data['total_requests'] 
                for endpoint, data in self.api_endpoints.items()
            }).most_common(10)),
            'slowest': dict(self.performance_metrics['slowest_endpoints'].most_common(10)),
            'highest_error_rate': self._get_highest_error_rate_endpoints(),
            'most_bandwidth': dict(self.performance_metrics['most_bandwidth_intensive'].most_common(10))
        }
        
        return {
            'total_api_requests': total_api_requests,
            'total_endpoints': total_endpoints,
            'error_rate': (total_errors / total_api_requests * 100) if total_api_requests > 0 else 0,
            'total_bandwidth_mb': total_bandwidth / (1024 * 1024),
            'performance_stats': performance_stats,
            'top_endpoints': top_endpoints,
            'api_patterns': dict(self.api_patterns['api_versions'].most_common()),
            'security_issues': {
                'unauthenticated_access': len(self.security_issues['unauthenticated_access']),
                'excessive_requests': len(self.security_issues['excessive_requests']),
                'suspicious_queries': len(self.security_issues['suspicious_queries']),
                'potential_abuse': len(self.security_issues['potential_abuse'])
            },
            'graphql_analysis': self._get_graphql_summary(),
            'platforms': self._get_platform_summary()
        }

    def _get_platform_summary(self) -> Dict[str, Any]:
        """Summarize detected platforms and key signals."""
        summary = {}
        for name, data in self.platforms.items():
            if not data['detected'] and sum(data['signals'].values()) == 0:
                continue
            entry = {
                'detected': data['detected'],
                'top_endpoints': dict(data['endpoints'].most_common(5)),
                'top_signals': dict(data['signals'].most_common(5))
            }
            if name == 'wordpress':
                entry['top_plugins'] = dict(data['plugins'].most_common(5))
                entry['woocommerce'] = {
                    'detected': data['woocommerce']['detected'],
                    'top_endpoints': dict(data['woocommerce']['endpoints'].most_common(5)),
                    'top_signals': dict(data['woocommerce']['signals'].most_common(5))
                }
            summary[name] = entry
        return summary
    
    def _get_highest_error_rate_endpoints(self) -> Dict[str, float]:
        """Get endpoints with highest error rates."""
        error_rates = {}
        for endpoint, data in self.api_endpoints.items():
            if data['total_requests'] >= 10:  # Minimum threshold
                error_rate = (data['error_count'] / data['total_requests']) * 100
                if error_rate > 5:  # Only include endpoints with >5% error rate
                    error_rates[endpoint] = error_rate
        
        return dict(sorted(error_rates.items(), key=lambda x: x[1], reverse=True)[:10])
    
    def _get_graphql_summary(self) -> Dict[str, Any]:
        """Get GraphQL-specific analysis summary."""
        if not any(self.graphql_analysis.values()):
            return {'active': False}
        
        avg_complexity = 0
        if self.graphql_analysis['query_complexity']:
            avg_complexity = statistics.mean(self.graphql_analysis['query_complexity'])
        
        return {
            'active': True,
            'query_types': dict(self.graphql_analysis['query_types']),
            'mutation_types': dict(self.graphql_analysis['mutation_types']),
            'introspection_queries': self.graphql_analysis['introspection_queries'],
            'avg_query_complexity': avg_complexity,
            'total_queries': sum(self.graphql_analysis['query_types'].values())
        }
    
    def get_endpoint_details(self, endpoint: str) -> Dict[str, Any]:
        """Get detailed analysis for a specific endpoint."""
        if endpoint not in self.api_endpoints:
            return {'error': 'Endpoint not found'}
        
        data = self.api_endpoints[endpoint]
        
        # Calculate statistics
        error_rate = (data['error_count'] / data['total_requests'] * 100) if data['total_requests'] > 0 else 0
        
        performance_stats = {}
        if data['response_times']:
            performance_stats = {
                'avg_response_time': statistics.mean(data['response_times']),
                'median_response_time': statistics.median(data['response_times']),
                'max_response_time': max(data['response_times']),
                'min_response_time': min(data['response_times'])
            }
        
        return {
            'endpoint': endpoint,
            'total_requests': data['total_requests'],
            'unique_ips': len(data['unique_ips']),
            'error_rate': error_rate,
            'bandwidth_mb': data['bandwidth_bytes'] / (1024 * 1024),
            'performance_stats': performance_stats,
            'methods': dict(data['methods']),
            'status_codes': dict(data['status_codes']),
            'top_countries': dict(data['countries'].most_common(5)),
            'top_user_agents': dict(data['user_agents'].most_common(5)),
            'hourly_distribution': dict(data['hourly_distribution']),
            'query_parameters': dict(data['query_parameters'].most_common(10)),
            'api_versions': dict(data['api_versions'])
        }
    
    def get_api_recommendations(self) -> List[Dict[str, Any]]:
        """Generate API-specific recommendations."""
        recommendations = []
        
        # High error rate endpoints
        high_error_endpoints = self._get_highest_error_rate_endpoints()
        if high_error_endpoints:
            recommendations.append({
                'priority': 'High',
                'category': 'API Reliability',
                'issue': f'{len(high_error_endpoints)} endpoints with high error rates',
                'recommendation': 'Investigate and fix endpoints with high error rates',
                'endpoints': list(high_error_endpoints.keys())[:3],
                'details': 'High error rates indicate potential issues with API implementation'
            })
        
        # Slow endpoints
        if self.performance_metrics['slowest_endpoints']:
            slow_endpoints = dict(self.performance_metrics['slowest_endpoints'].most_common(5))
            recommendations.append({
                'priority': 'Medium',
                'category': 'API Performance',
                'issue': f'Slow API endpoints detected',
                'recommendation': 'Optimize slow-performing endpoints',
                'endpoints': list(slow_endpoints.keys()),
                'details': 'Slow API responses impact user experience'
            })
        
        # Security issues
        if any(self.security_issues.values()):
            security_count = sum(len(issues) for issues in self.security_issues.values())
            recommendations.append({
                'priority': 'High',
                'category': 'API Security',
                'issue': f'{security_count} potential security issues detected',
                'recommendation': 'Review API security and implement proper authentication',
                'details': 'Security issues in APIs can lead to data breaches'
            })
        
        # GraphQL specific recommendations
        graphql_summary = self._get_graphql_summary()
        if graphql_summary['active']:
            if graphql_summary['introspection_queries'] > 10:
                recommendations.append({
                    'priority': 'Medium',
                    'category': 'GraphQL Security',
                    'issue': f'{graphql_summary["introspection_queries"]} introspection queries detected',
                    'recommendation': 'Consider disabling GraphQL introspection in production',
                    'details': 'Introspection queries can reveal schema information to attackers'
                })
        
        return recommendations
    
    def export_api_report(self, output_file: str) -> None:
        """Export comprehensive API analysis report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_api_summary(),
            'endpoint_details': {
                endpoint: self.get_endpoint_details(endpoint)
                for endpoint in list(self.api_endpoints.keys())[:50]  # Limit to top 50
            },
            'platforms': self._get_platform_summary(),
            'security_analysis': {
                'unauthenticated_access': dict(self.security_issues['unauthenticated_access']),
                'excessive_requests': dict(self.security_issues['excessive_requests']),
                'suspicious_queries': dict(self.security_issues['suspicious_queries']),
                'potential_abuse': dict(self.security_issues['potential_abuse'])
            },
            'performance_analysis': {
                'slowest_endpoints': dict(self.performance_metrics['slowest_endpoints']),
                'bandwidth_intensive': dict(self.performance_metrics['most_bandwidth_intensive']),
                'most_popular': dict(self.performance_metrics['most_popular'])
            },
            'graphql_analysis': self._get_graphql_summary(),
            'recommendations': self.get_api_recommendations()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
