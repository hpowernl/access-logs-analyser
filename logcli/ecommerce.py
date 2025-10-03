"""E-commerce platform analysis module for Magento, WooCommerce, and Shopware."""

import re
import json
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import parse_qs, urlparse

from .parser import LogParser
from .log_reader import LogTailer


# URL Pattern definitions per platform
MAGENTO_PATTERNS = {
    'checkout': [
        r'^/checkout/?',
        r'/rest/[^/]+/V1/(guest-)?carts',
        r'/customer/section/load.*section_data_ids.*cart',
        r'/rest/[^/]+/V1/carts/mine',
    ],
    'admin': [
        r'^/admin(?!/static)',
        r'^/admin_\w+',
        r'/rest/[^/]+/V1/(orders|products|customers)',
    ],
    'api_rest': [
        r'/rest/[^/]+/V1/',
    ],
    'api_graphql': [
        r'/graphql',
    ],
    'login': [
        r'/customer/account/login',
        r'/rest/[^/]+/V1/integration/(customer|admin)/token',
    ],
    'product': [
        r'/catalog/product/view',
        r'\.html$',
    ],
    'media': [
        r'/media/catalog/product',
        r'/pub/media/catalog',
        r'/pub/static',
    ],
    'search': [
        r'/catalogsearch/result',
        r'/rest/[^/]+/V1/search',
    ],
}

WOOCOMMERCE_PATTERNS = {
    'checkout': [
        r'^/checkout/?',
        r'^/cart/?',
        r'/\?wc-ajax=',
        r'/wc-ajax=',
    ],
    'admin': [
        r'^/wp-admin(?!/admin-ajax)',
        r'/wp-admin/post\.php',
        r'/wp-admin/admin\.php',
    ],
    'api': [
        r'/wp-json/wc/v\d+',
        r'/wp-json/wp/v2',
    ],
    'login': [
        r'/wp-login\.php',
        r'/my-account',
        r'/wp-admin/$',
    ],
    'product': [
        r'^/product/',
        r'^/product-category/',
        r'^/shop/?',
    ],
    'media': [
        r'/wp-content/uploads',
        r'/wp-content/plugins',
        r'/wp-content/themes',
    ],
    'wordpress': [
        r'/wp-cron\.php',
        r'/xmlrpc\.php',
        r'/wp-json/',
    ],
}

SHOPWARE6_PATTERNS = {
    'checkout': [
        r'^/checkout/',
        r'/store-api/checkout/',
    ],
    'admin': [
        r'^/admin(?:#|$)',
        r'/api/_action/',
        r'/api/[^/]+/(order|product|customer)',
    ],
    'api': [
        r'/store-api/',
        r'/api/',
    ],
    'login': [
        r'^/account/login',
        r'/store-api/account/login',
    ],
    'product': [
        r'^/detail/',
        r'^/navigation/',
    ],
    'media': [
        r'^/media/',
        r'^/thumbnail/',
        r'^/bundles/',
    ],
    'search': [
        r'^/suggest',
        r'/store-api/search',
    ],
}


class EcommerceAnalyzer:
    """Analyzes e-commerce specific performance patterns."""
    
    def __init__(self):
        self.parser = LogParser()
        
        # Platform detection
        self.platform_indicators = defaultdict(int)
        self.detected_platform = None
        self.platform_confidence = 0
        
        # Category-based tracking
        self.checkout_requests = []
        self.admin_requests = []
        self.api_requests = []
        self.login_requests = []
        self.product_requests = []
        self.media_requests = []
        self.search_requests = []
        
        # Performance tracking per category
        self.category_response_times = defaultdict(list)
        self.category_errors = defaultdict(int)
        self.category_request_count = defaultdict(int)
        self.category_bytes = defaultdict(int)
        
        # Detailed tracking
        self.slow_requests = defaultdict(list)  # >2s per category
        self.failed_requests = defaultdict(list)  # 5xx errors
        self.endpoint_stats = defaultdict(lambda: {
            'count': 0,
            'response_times': [],
            'errors': 0,
            'bytes': 0
        })
        
        # GraphQL tracking (Magento specific)
        self.graphql_operations = Counter()  # Track query/mutation types
        self.graphql_queries = []
        self.graphql_errors = []
        
        # Conversion funnel tracking
        self.funnel_visits = defaultdict(int)  # Track visits per funnel step
        self.user_sessions = defaultdict(list)  # Track user paths by IP
        
        # Time-based tracking
        self.hourly_category_stats = defaultdict(lambda: defaultdict(lambda: {
            'requests': 0,
            'response_times': [],
            'errors': 0
        }))
        
        # Checkout error patterns
        self.checkout_error_patterns = Counter()
        self.checkout_error_details = []
        
        # IP-based tracking
        self.login_attempts_by_ip = defaultdict(lambda: {'total': 0, 'failed': 0, 'paths': []})
        self.admin_access_by_ip = defaultdict(lambda: {'requests': 0, 'paths': set()})
        self.checkout_errors_by_ip = defaultdict(lambda: {'errors': 0, 'error_types': []})
        self.api_usage_by_ip = defaultdict(lambda: {'requests': 0, 'endpoints': Counter()})
        self.category_ips = defaultdict(lambda: Counter())  # Track unique IPs per category
        
        # Total stats
        self.total_requests = 0
        self.ecommerce_requests = 0
    
    def detect_platform(self, path: str) -> Optional[str]:
        """Detect e-commerce platform from URL patterns."""
        path_lower = path.lower()
        
        # Check Magento patterns
        magento_score = 0
        if re.search(r'/rest/[^/]+/V1/', path_lower):
            magento_score += 5
        if re.search(r'/customer/section/load', path_lower):
            magento_score += 5
        if re.search(r'/catalogsearch/', path_lower):
            magento_score += 3
        if path_lower.endswith('.html') and not 'wp-' in path_lower:
            magento_score += 1
        
        # Check WooCommerce patterns  
        woocommerce_score = 0
        if 'wp-' in path_lower:
            woocommerce_score += 5
        if re.search(r'/wc-ajax=|/\?wc-ajax=', path_lower):
            woocommerce_score += 5
        if '/wp-json/wc/' in path_lower:
            woocommerce_score += 5
        if '/wp-content/' in path_lower:
            woocommerce_score += 2
        
        # Check Shopware 6 patterns
        shopware_score = 0
        if '/store-api/' in path_lower:
            shopware_score += 5
        if re.search(r'^/detail/|^/navigation/', path_lower):
            shopware_score += 3
        if path_lower.startswith('/api/') and not 'wp-' in path_lower:
            shopware_score += 2
        
        # Update platform indicators
        if magento_score > 0:
            self.platform_indicators['magento'] += magento_score
        if woocommerce_score > 0:
            self.platform_indicators['woocommerce'] += woocommerce_score
        if shopware_score > 0:
            self.platform_indicators['shopware6'] += shopware_score
        
        # Return most likely platform
        if self.platform_indicators:
            detected = max(self.platform_indicators.items(), key=lambda x: x[1])
            return detected[0] if detected[1] > 10 else None
        
        return None
    
    def categorize_request(self, path: str, platform: str) -> Optional[str]:
        """Categorize a request based on platform and URL patterns."""
        if not platform:
            return None
        
        patterns = None
        if platform == 'magento':
            patterns = MAGENTO_PATTERNS
        elif platform == 'woocommerce':
            patterns = WOOCOMMERCE_PATTERNS
        elif platform == 'shopware6':
            patterns = SHOPWARE6_PATTERNS
        else:
            return None
        
        # Check each category
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, path, re.IGNORECASE):
                    return category
        
        return None
    
    def parse_graphql_operation(self, path: str, method: str) -> Optional[str]:
        """Extract GraphQL operation type from request."""
        if '/graphql' not in path.lower() or method != 'POST':
            return None
        
        # Try to extract operation from query params
        parsed = urlparse(path)
        if parsed.query:
            params = parse_qs(parsed.query)
            if 'query' in params:
                query = params['query'][0]
                # Extract operation name
                if 'mutation' in query.lower():
                    match = re.search(r'mutation\s+(\w+)', query, re.IGNORECASE)
                    if match:
                        return f"mutation:{match.group(1)}"
                    return "mutation:unknown"
                elif 'query' in query.lower():
                    match = re.search(r'query\s+(\w+)', query, re.IGNORECASE)
                    if match:
                        return f"query:{match.group(1)}"
                    return "query:unknown"
        
        return "graphql:unknown"
    
    def track_funnel_step(self, path: str, ip: str, timestamp: datetime):
        """Track user through conversion funnel."""
        if not ip or not timestamp:
            return
        
        # Determine funnel step
        path_lower = path.lower()
        step = None
        
        if re.search(r'/(home|index|^/$)', path_lower):
            step = 'homepage'
        elif re.search(r'/(catalog|category|shop)', path_lower):
            step = 'category'
        elif re.search(r'/(product|detail|\.html$)', path_lower):
            step = 'product'
        elif re.search(r'/(cart|basket)', path_lower):
            step = 'cart'
        elif re.search(r'/checkout', path_lower):
            step = 'checkout'
        
        if step:
            self.funnel_visits[step] += 1
            self.user_sessions[ip].append({
                'step': step,
                'timestamp': timestamp,
                'path': path
            })
    
    def analyze_checkout_error(self, path: str, status: int, method: str):
        """Analyze checkout errors for patterns."""
        if status < 400 or 'checkout' not in path.lower():
            return
        
        # Categorize error
        error_type = None
        
        if status == 400:
            error_type = "bad_request"
        elif status == 401:
            error_type = "unauthorized"
        elif status == 403:
            error_type = "forbidden"
        elif status == 404:
            error_type = "not_found"
        elif status == 500:
            error_type = "server_error"
        elif status == 502:
            error_type = "bad_gateway"
        elif status == 503:
            error_type = "service_unavailable"
        elif status == 504:
            error_type = "timeout"
        else:
            error_type = f"http_{status}"
        
        # Track specific checkout endpoint errors
        if 'cart' in path.lower():
            self.checkout_error_patterns[f"cart_{error_type}"] += 1
        elif 'payment' in path.lower():
            self.checkout_error_patterns[f"payment_{error_type}"] += 1
        elif 'shipping' in path.lower():
            self.checkout_error_patterns[f"shipping_{error_type}"] += 1
        else:
            self.checkout_error_patterns[f"checkout_{error_type}"] += 1
        
        self.checkout_error_details.append({
            'path': path,
            'status': status,
            'method': method,
            'error_type': error_type,
            'timestamp': self.current_timestamp,
            'ip': self.current_ip
        })
        
        # Track errors by IP for deeper analysis
        if self.current_ip:
            self.checkout_errors_by_ip[self.current_ip]['errors'] += 1
            self.checkout_errors_by_ip[self.current_ip]['error_types'].append(error_type)
    
    def get_deep_checkout_analysis(self) -> Dict[str, Any]:
        """Get comprehensive checkout error analysis."""
        if not self.checkout_error_details:
            return None
            
        analysis = {
            'total_errors': len(self.checkout_error_details),
            'error_patterns': dict(self.checkout_error_patterns),
            'error_details': [],
            'ip_analysis': {},
            'timeline_analysis': {},
            'critical_issues': []
        }
        
        # Analyze by IP - find suspicious patterns
        for ip, data in self.checkout_errors_by_ip.items():
            if data['errors'] >= 5:  # Threshold for suspicious activity
                error_type_counter = Counter(data['error_types'])
                analysis['ip_analysis'][ip] = {
                    'total_errors': data['errors'],
                    'most_common_error': error_type_counter.most_common(1)[0] if error_type_counter else None,
                    'error_types': dict(error_type_counter)
                }
                
                # Flag potential bot attacks or misconfigurations
                if error_type_counter.most_common(1)[0][0] == 'http_429' and data['errors'] > 10:
                    analysis['critical_issues'].append({
                        'type': 'RATE_LIMIT_EXCESS',
                        'ip': ip,
                        'errors': data['errors'],
                        'description': 'Excessive rate limiting on checkout - potential bot or misconfigured integration'
                    })
        
        # Timeline analysis - find patterns over time
        hourly_errors = defaultdict(int)
        for error in self.checkout_error_details:
            if error.get('timestamp'):
                hour_key = error['timestamp'].replace(minute=0, second=0, microsecond=0)
                hourly_errors[hour_key] += 1
        
        analysis['timeline_analysis'] = dict(hourly_errors)
        
        # Critical error analysis
        server_errors = [e for e in self.checkout_error_details if e['status'] >= 500]
        if server_errors:
            analysis['critical_issues'].append({
                'type': 'SERVER_ERRORS',
                'count': len(server_errors),
                'description': f'Server errors (5xx) detected - investigate server stability'
            })
        
        # Rate limit analysis
        rate_limit_errors = [e for e in self.checkout_error_details if e['status'] == 429]
        if rate_limit_errors:
            analysis['critical_issues'].append({
                'type': 'RATE_LIMITING',
                'count': len(rate_limit_errors),
                'description': 'HTTP 429 errors indicate aggressive rate limiting - check rate limit configuration'
            })
        
        # Detailed error examples for troubleshooting
        analysis['error_details'] = self.checkout_error_details[-50:]  # Last 50 errors
        
        return analysis
    
    def analyze_entry(self, log_entry: Dict[str, Any]):
        """Analyze a single log entry for e-commerce patterns."""
        self.total_requests += 1
        
        path = log_entry.get('path', '/')
        method = log_entry.get('method', 'GET')
        status = log_entry.get('status', 0)
        response_time = log_entry.get('response_time', 0)
        bytes_sent = log_entry.get('bytes_sent', 0)
        timestamp = log_entry.get('timestamp')
        
        # Detect platform
        detected = self.detect_platform(path)
        
        # Use most confident platform
        if self.platform_indicators:
            platform_data = max(self.platform_indicators.items(), key=lambda x: x[1])
            self.detected_platform = platform_data[0]
            total_score = sum(self.platform_indicators.values())
            self.platform_confidence = (platform_data[1] / total_score * 100) if total_score > 0 else 0
        
        # Categorize request
        category = self.categorize_request(path, self.detected_platform)
        
        # Track conversion funnel (for all requests, not just categorized ones)
        ip = log_entry.get('ip')
        if ip:
            self.track_funnel_step(path, str(ip), timestamp)
        
        # Parse GraphQL operations
        if category == 'api_graphql':
            operation = self.parse_graphql_operation(path, method)
            if operation:
                self.graphql_operations[operation] += 1
                self.graphql_queries.append({
                    'operation': operation,
                    'timestamp': timestamp,
                    'response_time': response_time,
                    'status': status
                })
                if status >= 400:
                    self.graphql_errors.append({
                        'operation': operation,
                        'status': status,
                        'timestamp': timestamp
                    })
        
        # Analyze checkout errors
        if category == 'checkout' and status >= 400:
            self.analyze_checkout_error(path, status, method)
        
        if category:
            self.ecommerce_requests += 1
            
            # Track by category
            self.category_request_count[category] += 1
            if response_time > 0:
                self.category_response_times[category].append(response_time)
            self.category_bytes[category] += bytes_sent
            
            # Time-based tracking
            if timestamp:
                hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
                self.hourly_category_stats[hour_key][category]['requests'] += 1
                if response_time > 0:
                    self.hourly_category_stats[hour_key][category]['response_times'].append(response_time)
                if status >= 400:
                    self.hourly_category_stats[hour_key][category]['errors'] += 1
            
            # IP-based tracking
            if ip:
                ip_str = str(ip)
                self.category_ips[category][ip_str] += 1
                
                # Track login attempts
                if category == 'login':
                    self.login_attempts_by_ip[ip_str]['total'] += 1
                    self.login_attempts_by_ip[ip_str]['paths'].append(path)
                    if status >= 400:
                        self.login_attempts_by_ip[ip_str]['failed'] += 1
                
                # Track admin access
                if category == 'admin':
                    self.admin_access_by_ip[ip_str]['requests'] += 1
                    self.admin_access_by_ip[ip_str]['paths'].add(path)
                
                # Track checkout errors
                if category == 'checkout' and status >= 400:
                    self.checkout_errors_by_ip[ip_str]['errors'] += 1
                    self.checkout_errors_by_ip[ip_str]['error_types'].append(status)
                
                # Track API usage
                if category in ['api', 'api_rest', 'api_graphql']:
                    self.api_usage_by_ip[ip_str]['requests'] += 1
                    self.api_usage_by_ip[ip_str]['endpoints'][path] += 1
            
            # Track errors
            if status >= 400:
                self.category_errors[category] += 1
                
                if status >= 500:
                    self.failed_requests[category].append({
                        'timestamp': timestamp,
                        'path': path,
                        'method': method,
                        'status': status,
                        'response_time': response_time
                    })
            
            # Track slow requests
            if response_time > 2.0:
                self.slow_requests[category].append({
                    'timestamp': timestamp,
                    'path': path,
                    'method': method,
                    'status': status,
                    'response_time': response_time,
                    'bytes_sent': bytes_sent
                })
            
            # Store in category list
            request_data = {
                'timestamp': timestamp,
                'path': path,
                'method': method,
                'status': status,
                'response_time': response_time,
                'bytes_sent': bytes_sent
            }
            
            if category == 'checkout':
                self.checkout_requests.append(request_data)
            elif category == 'admin':
                self.admin_requests.append(request_data)
            elif category in ['api', 'api_rest', 'api_graphql']:
                self.api_requests.append(request_data)
            elif category == 'login':
                self.login_requests.append(request_data)
            elif category == 'product':
                self.product_requests.append(request_data)
            elif category == 'media':
                self.media_requests.append(request_data)
            elif category == 'search':
                self.search_requests.append(request_data)
            
            # Track endpoint-level stats
            endpoint = f"{method} {path}"
            self.endpoint_stats[endpoint]['count'] += 1
            if response_time > 0:
                self.endpoint_stats[endpoint]['response_times'].append(response_time)
            if status >= 400:
                self.endpoint_stats[endpoint]['errors'] += 1
            self.endpoint_stats[endpoint]['bytes'] += bytes_sent
    
    def get_category_stats(self, category: str) -> Dict[str, Any]:
        """Get statistics for a specific category."""
        count = self.category_request_count[category]
        if count == 0:
            return {}
        
        response_times = self.category_response_times[category]
        errors = self.category_errors[category]
        bytes_total = self.category_bytes[category]
        
        stats = {
            'count': count,
            'errors': errors,
            'error_rate': (errors / count * 100) if count > 0 else 0,
            'bytes_total': bytes_total,
            'bytes_avg': bytes_total / count if count > 0 else 0,
        }
        
        if response_times:
            stats['response_time_avg'] = statistics.mean(response_times)
            stats['response_time_median'] = statistics.median(response_times)
            stats['response_time_p95'] = (
                statistics.quantiles(response_times, n=20)[18] 
                if len(response_times) > 19 
                else max(response_times)
            )
            stats['response_time_max'] = max(response_times)
            stats['slow_count'] = len([t for t in response_times if t > 2.0])
        else:
            stats['response_time_avg'] = 0
            stats['response_time_median'] = 0
            stats['response_time_p95'] = 0
            stats['response_time_max'] = 0
            stats['slow_count'] = 0
        
        return stats
    
    def get_platform_summary(self) -> Dict[str, Any]:
        """Get overall platform detection and summary."""
        return {
            'detected_platform': self.detected_platform,
            'confidence': self.platform_confidence,
            'total_requests': self.total_requests,
            'ecommerce_requests': self.ecommerce_requests,
            'ecommerce_percentage': (
                self.ecommerce_requests / self.total_requests * 100 
                if self.total_requests > 0 else 0
            ),
            'platform_scores': dict(self.platform_indicators)
        }
    
    def get_slowest_endpoints(self, category: str, limit: int = 10) -> List[Tuple[str, float]]:
        """Get slowest endpoints for a specific category."""
        category_endpoints = []
        
        for endpoint, stats in self.endpoint_stats.items():
            if stats['response_times'] and stats['count'] >= 5:
                # Check if endpoint belongs to category
                method, path = endpoint.split(' ', 1)
                if self.categorize_request(path, self.detected_platform) == category:
                    avg_time = statistics.mean(stats['response_times'])
                    category_endpoints.append((endpoint, avg_time))
        
        return sorted(category_endpoints, key=lambda x: x[1], reverse=True)[:limit]
    
    def get_recommendations(self) -> List[Dict[str, Any]]:
        """Generate e-commerce specific recommendations."""
        recommendations = []
        
        # Check checkout performance
        checkout_stats = self.get_category_stats('checkout')
        if checkout_stats and checkout_stats['count'] > 10:
            if checkout_stats['error_rate'] > 1:
                recommendations.append({
                    'category': 'Checkout',
                    'priority': 'Critical',
                    'issue': f"High error rate: {checkout_stats['error_rate']:.1f}%",
                    'recommendation': 'Investigate checkout errors immediately - lost revenue!',
                    'impact': 'Direct revenue impact'
                })
            
            if checkout_stats['response_time_p95'] > 3:
                recommendations.append({
                    'category': 'Checkout',
                    'priority': 'High',
                    'issue': f"Slow checkout: P95 = {checkout_stats['response_time_p95']:.2f}s",
                    'recommendation': 'Optimize checkout flow, cache cart data, reduce external calls',
                    'impact': 'Affects conversion rate'
                })
        
        # Check admin performance
        admin_stats = self.get_category_stats('admin')
        if admin_stats and admin_stats['count'] > 50:
            if admin_stats['response_time_avg'] > 2:
                recommendations.append({
                    'category': 'Admin',
                    'priority': 'Medium',
                    'issue': f"Slow admin panel: avg {admin_stats['response_time_avg']:.2f}s",
                    'recommendation': 'Enable admin caching, optimize queries, consider full-page cache',
                    'impact': 'Staff productivity'
                })
        
        # Check API performance
        api_stats = self.get_category_stats('api') or self.get_category_stats('api_rest')
        if api_stats and api_stats['count'] > 100:
            if api_stats['error_rate'] > 5:
                recommendations.append({
                    'category': 'API',
                    'priority': 'High',
                    'issue': f"High API error rate: {api_stats['error_rate']:.1f}%",
                    'recommendation': 'Review API error logs, implement rate limiting, add monitoring',
                    'impact': 'Third-party integrations'
                })
        
        # Check media performance
        media_stats = self.get_category_stats('media')
        if media_stats and media_stats['count'] > 1000:
            if media_stats['bytes_avg'] > 200 * 1024:  # >200KB avg
                recommendations.append({
                    'category': 'Media',
                    'priority': 'Medium',
                    'issue': f"Large images: avg {media_stats['bytes_avg']/1024:.0f}KB",
                    'recommendation': 'Implement WebP, add CDN, enable lazy loading, optimize images',
                    'impact': 'Page load speed & bandwidth costs'
                })
        
        # Check login security
        login_stats = self.get_category_stats('login')
        if login_stats and login_stats['count'] > 0:
            if login_stats['error_rate'] > 30:
                recommendations.append({
                    'category': 'Security',
                    'priority': 'High',
                    'issue': f"High login failure rate: {login_stats['error_rate']:.1f}%",
                    'recommendation': 'Possible brute force attack - enable rate limiting & 2FA',
                    'impact': 'Security risk'
                })
        
        return recommendations
    
    def get_graphql_statistics(self) -> Dict[str, Any]:
        """Get GraphQL query statistics (Magento specific)."""
        if not self.graphql_queries:
            return {}
        
        # Top operations
        top_operations = self.graphql_operations.most_common(10)
        
        # Performance by operation
        operation_perf = defaultdict(list)
        for query in self.graphql_queries:
            operation_perf[query['operation']].append(query['response_time'])
        
        operation_stats = {}
        for op, times in operation_perf.items():
            if times:
                operation_stats[op] = {
                    'count': len(times),
                    'avg_response_time': statistics.mean(times),
                    'max_response_time': max(times),
                    'errors': len([q for q in self.graphql_queries 
                                 if q['operation'] == op and q['status'] >= 400])
                }
        
        return {
            'total_queries': len(self.graphql_queries),
            'total_errors': len(self.graphql_errors),
            'error_rate': (len(self.graphql_errors) / len(self.graphql_queries) * 100) 
                         if self.graphql_queries else 0,
            'top_operations': top_operations,
            'operation_stats': operation_stats,
            'unique_operations': len(self.graphql_operations)
        }
    
    def get_conversion_funnel(self) -> Dict[str, Any]:
        """Get conversion funnel statistics."""
        if not self.funnel_visits:
            return {}
        
        # Calculate drop-off rates
        steps = ['homepage', 'category', 'product', 'cart', 'checkout']
        funnel_data = {}
        
        prev_count = None
        for step in steps:
            count = self.funnel_visits.get(step, 0)
            drop_off = 0
            
            if prev_count and prev_count > 0:
                drop_off = ((prev_count - count) / prev_count * 100)
            
            funnel_data[step] = {
                'visits': count,
                'drop_off_rate': drop_off if prev_count else 0
            }
            
            prev_count = count if count > 0 else prev_count
        
        # Calculate conversion rate (homepage to checkout)
        homepage_visits = self.funnel_visits.get('homepage', 0)
        checkout_visits = self.funnel_visits.get('checkout', 0)
        conversion_rate = (checkout_visits / homepage_visits * 100) if homepage_visits > 0 else 0
        
        # Analyze user paths
        complete_paths = 0
        abandoned_carts = 0
        
        for ip, sessions in self.user_sessions.items():
            steps_visited = set(s['step'] for s in sessions)
            if 'checkout' in steps_visited:
                complete_paths += 1
            if 'cart' in steps_visited and 'checkout' not in steps_visited:
                abandoned_carts += 1
        
        return {
            'funnel': funnel_data,
            'conversion_rate': conversion_rate,
            'complete_paths': complete_paths,
            'abandoned_carts': abandoned_carts,
            'cart_abandonment_rate': (abandoned_carts / (abandoned_carts + complete_paths) * 100) 
                                     if (abandoned_carts + complete_paths) > 0 else 0
        }
    
    def get_checkout_error_analysis(self) -> Dict[str, Any]:
        """Get detailed checkout error analysis."""
        if not self.checkout_error_details:
            return {}
        
        # Most common error patterns
        top_patterns = self.checkout_error_patterns.most_common(10)
        
        # Group errors by type
        errors_by_type = defaultdict(int)
        for detail in self.checkout_error_details:
            errors_by_type[detail['error_type']] += 1
        
        # Identify critical issues
        critical_issues = []
        if self.checkout_error_patterns.get('payment_server_error', 0) > 5:
            critical_issues.append({
                'issue': 'Payment gateway errors',
                'count': self.checkout_error_patterns['payment_server_error'],
                'severity': 'CRITICAL'
            })
        
        if self.checkout_error_patterns.get('cart_server_error', 0) > 10:
            critical_issues.append({
                'issue': 'Cart system errors',
                'count': self.checkout_error_patterns['cart_server_error'],
                'severity': 'HIGH'
            })
        
        return {
            'total_errors': len(self.checkout_error_details),
            'error_patterns': dict(top_patterns),
            'errors_by_type': dict(errors_by_type),
            'critical_issues': critical_issues
        }
    
    def get_time_based_analysis(self, category: str) -> Dict[str, Any]:
        """Get time-based performance analysis for a category."""
        if not self.hourly_category_stats:
            return {}
        
        hourly_data = []
        for hour, categories in sorted(self.hourly_category_stats.items()):
            if category in categories:
                stats = categories[category]
                if stats['requests'] > 0:
                    avg_rt = (statistics.mean(stats['response_times']) 
                             if stats['response_times'] else 0)
                    error_rate = (stats['errors'] / stats['requests'] * 100)
                    
                    hourly_data.append({
                        'hour': hour.strftime('%Y-%m-%d %H:00'),
                        'requests': stats['requests'],
                        'avg_response_time': avg_rt,
                        'error_rate': error_rate,
                        'errors': stats['errors']
                    })
        
        if not hourly_data:
            return {}
        
        # Find peak hour
        peak_hour = max(hourly_data, key=lambda x: x['requests'])
        
        # Find worst performance hour
        worst_hour = max(hourly_data, key=lambda x: x['avg_response_time'])
        
        return {
            'hourly_breakdown': hourly_data,
            'peak_hour': peak_hour,
            'worst_performance_hour': worst_hour,
            'hours_analyzed': len(hourly_data)
        }
    
    def get_ip_statistics(self, category: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top IPs for a specific category."""
        if category not in self.category_ips or not self.category_ips[category]:
            return []
        
        top_ips = []
        for ip, count in self.category_ips[category].most_common(limit):
            ip_data = {
                'ip': ip,
                'requests': count
            }
            
            # Add category-specific details
            if category == 'login' and ip in self.login_attempts_by_ip:
                login_data = self.login_attempts_by_ip[ip]
                ip_data['total_attempts'] = login_data['total']
                ip_data['failed_attempts'] = login_data['failed']
                ip_data['success_rate'] = ((login_data['total'] - login_data['failed']) / 
                                          login_data['total'] * 100) if login_data['total'] > 0 else 0
            
            if category == 'admin' and ip in self.admin_access_by_ip:
                admin_data = self.admin_access_by_ip[ip]
                ip_data['admin_requests'] = admin_data['requests']
                ip_data['unique_paths'] = len(admin_data['paths'])
            
            if category == 'checkout' and ip in self.checkout_errors_by_ip:
                error_data = self.checkout_errors_by_ip[ip]
                ip_data['checkout_errors'] = error_data['errors']
                ip_data['error_types'] = dict(Counter(error_data['error_types']))
            
            if category in ['api', 'api_rest', 'api_graphql'] and ip in self.api_usage_by_ip:
                api_data = self.api_usage_by_ip[ip]
                ip_data['api_requests'] = api_data['requests']
                ip_data['unique_endpoints'] = len(api_data['endpoints'])
                ip_data['top_endpoints'] = dict(api_data['endpoints'].most_common(3))
            
            top_ips.append(ip_data)
        
        return top_ips
    
    def get_login_security_details(self) -> Dict[str, Any]:
        """Get detailed login security analysis with IPs."""
        if not self.login_attempts_by_ip:
            return {}
        
        # Find suspicious IPs (high failure rate)
        suspicious_ips = []
        for ip, data in self.login_attempts_by_ip.items():
            if data['total'] >= 5:  # At least 5 attempts
                failure_rate = (data['failed'] / data['total'] * 100)
                if failure_rate > 50:  # >50% failure rate
                    suspicious_ips.append({
                        'ip': ip,
                        'total_attempts': data['total'],
                        'failed_attempts': data['failed'],
                        'failure_rate': failure_rate,
                        'severity': 'HIGH' if failure_rate > 80 else 'MEDIUM'
                    })
        
        # Sort by failure rate and attempt count
        suspicious_ips.sort(key=lambda x: (x['failure_rate'], x['total_attempts']), reverse=True)
        
        return {
            'total_ips': len(self.login_attempts_by_ip),
            'suspicious_ips': suspicious_ips[:10],  # Top 10 suspicious
            'total_suspicious': len(suspicious_ips)
        }
    
    def get_admin_access_details(self) -> Dict[str, Any]:
        """Get detailed admin access analysis with IPs."""
        if not self.admin_access_by_ip:
            return {}
        
        # Sort by request count
        top_admin_ips = sorted(
            self.admin_access_by_ip.items(),
            key=lambda x: x[1]['requests'],
            reverse=True
        )[:10]
        
        admin_ips = []
        for ip, data in top_admin_ips:
            admin_ips.append({
                'ip': ip,
                'requests': data['requests'],
                'unique_paths': len(data['paths']),
                'sample_paths': list(data['paths'])[:3]  # Show first 3 paths
            })
        
        return {
            'total_admin_ips': len(self.admin_access_by_ip),
            'top_ips': admin_ips
        }
    
    def get_enhanced_recommendations(self) -> List[Dict[str, Any]]:
        """Get enhanced recommendations with specific action items."""
        recommendations = self.get_recommendations()
        
        # Add GraphQL-specific recommendations
        graphql_stats = self.get_graphql_statistics()
        if graphql_stats and graphql_stats.get('total_queries', 0) > 100:
            if graphql_stats['error_rate'] > 5:
                recommendations.append({
                    'category': 'GraphQL API',
                    'priority': 'High',
                    'issue': f"GraphQL error rate: {graphql_stats['error_rate']:.1f}%",
                    'recommendation': 'Review failing GraphQL operations, add query complexity limits',
                    'impact': 'API reliability',
                    'action_items': [
                        'Check top failing GraphQL operations',
                        'Implement query depth limiting',
                        'Add better error handling',
                        'Monitor query complexity'
                    ]
                })
        
        # Add funnel-specific recommendations
        funnel = self.get_conversion_funnel()
        if funnel and funnel.get('cart_abandonment_rate', 0) > 50:
            recommendations.append({
                'category': 'Conversion Funnel',
                'priority': 'Critical',
                'issue': f"Cart abandonment rate: {funnel['cart_abandonment_rate']:.1f}%",
                'recommendation': 'Optimize checkout flow, reduce friction, investigate cart errors',
                'impact': 'Direct revenue loss',
                'action_items': [
                    'Simplify checkout steps',
                    'Add guest checkout option',
                    'Optimize payment flow',
                    'Review shipping calculations',
                    'Check for checkout errors'
                ]
            })
        
        # Add checkout error recommendations
        checkout_errors = self.get_checkout_error_analysis()
        if checkout_errors and checkout_errors.get('critical_issues'):
            for issue in checkout_errors['critical_issues']:
                recommendations.append({
                    'category': 'Checkout Errors',
                    'priority': issue['severity'],
                    'issue': f"{issue['issue']}: {issue['count']} occurrences",
                    'recommendation': 'Immediate investigation required - affecting customer purchases',
                    'impact': 'Revenue loss & customer frustration',
                    'action_items': [
                        'Check application logs for error details',
                        'Verify third-party service status',
                        'Test checkout flow manually',
                        'Enable detailed error logging'
                    ]
                })
        
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'Critical': 1, 'HIGH': 2, 'High': 3, 'Medium': 4, 'Low': 5}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 10))
        
        return recommendations
    
    def export_report(self) -> Dict[str, Any]:
        """Export comprehensive e-commerce analysis report."""
        platform_summary = self.get_platform_summary()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'platform': platform_summary,
            'categories': {
                'checkout': self.get_category_stats('checkout'),
                'admin': self.get_category_stats('admin'),
                'api': self.get_category_stats('api') or self.get_category_stats('api_rest'),
                'login': self.get_category_stats('login'),
                'product': self.get_category_stats('product'),
                'media': self.get_category_stats('media'),
                'search': self.get_category_stats('search'),
            },
            'slow_requests_by_category': {
                category: len(requests)
                for category, requests in self.slow_requests.items()
            },
            'failed_requests_by_category': {
                category: len(requests)
                for category, requests in self.failed_requests.items()
            },
            'graphql_statistics': self.get_graphql_statistics(),
            'conversion_funnel': self.get_conversion_funnel(),
            'checkout_errors': self.get_checkout_error_analysis(),
            'recommendations': self.get_enhanced_recommendations()
        }
        
        return report

