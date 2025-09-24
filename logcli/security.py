"""Security analysis module for detecting attacks and suspicious patterns."""

import re
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Tuple
from pathlib import Path

from .parser import LogParser
from .log_reader import LogTailer
from .config import PLATFORM_SECURITY


class SecurityAnalyzer:
    """Analyzes logs for security threats and attack patterns."""
    
    def __init__(self):
        self.parser = LogParser()
        
        # Attack pattern counters
        self.attack_patterns = Counter()
        self.brute_force_attempts = defaultdict(list)
        self.sql_injection_attempts = defaultdict(list)
        self.suspicious_user_agents = Counter()
        self.failed_logins = defaultdict(int)
        self.directory_traversal = defaultdict(list)
        self.xss_attempts = defaultdict(list)
        self.command_injection = defaultdict(list)
        
        # IP-based tracking
        self.ip_request_counts = defaultdict(int)
        self.ip_error_rates = defaultdict(lambda: {'total': 0, 'errors': 0})
        self.ip_status_codes = defaultdict(lambda: defaultdict(int))
        self.ip_methods = defaultdict(lambda: defaultdict(int))
        self.ip_paths = defaultdict(lambda: defaultdict(int))
        self.suspicious_ips = set()
        
        # Rate limiting detection
        self.ip_request_times = defaultdict(list)
        self.potential_ddos_ips = set()
        
        # Additional metrics
        self.total_requests = 0
        self.total_errors = 0
        self.unique_ips = set()
        self.scan_attempts = defaultdict(list)  # Directory/file scanning
        self.admin_access_attempts = defaultdict(list)
        
        # Define attack patterns
        self._init_attack_patterns()

        # E-commerce platform detection (compact structures)
        # platform_events[platform][event_type][ip] -> count
        def _event_bucket():
            return defaultdict(int)
        def _event_types():
            return defaultdict(_event_bucket)
        self.platform_events = defaultdict(_event_types)
        # simple platform weights to impact threat score
        self.platform_weights = {
            'wordpress': {
                'bruteforce': 8, 'xmlrpc_abuse': 6, 'admin_probe': 4,
                'api_enum': 3, 'sensitive_access': 10, 'backup_probe': 5
            },
            'woocommerce': {
                'checkout_fail': 5, 'api_enum': 4, 'webhook_probe': 3
            },
            'shopware': {
                'admin_probe': 6, 'api_enum': 4, 'recovery_probe': 7, 'sensitive_access': 8
            },
            'magento': {
                'bruteforce': 8, 'api_enum': 4, 'setup_probe': 9, 'sensitive_access': 10
            }
        }
        
        # Blocked traffic statistics
        self.blocked = {
            'total': 0,
            'countries': Counter(),
            'paths': Counter(),
            'user_agents': Counter(),
            'ips': Counter(),
            'hours': Counter(),
            'status_codes': Counter()
        }
        
    def _init_attack_patterns(self):
        """Initialize regex patterns for various attacks."""
        self.patterns = {
            'sql_injection': [
                r'union\s+select',
                r'or\s+1\s*=\s*1',
                r'drop\s+table',
                r'insert\s+into',
                r'delete\s+from',
                r'update\s+.*set',
                r'exec\s*\(',
                r'sp_executesql',
                r'xp_cmdshell',
                r'information_schema',
                r'mysql\.user',
                r'pg_sleep',
                r'waitfor\s+delay',
                r'benchmark\s*\(',
                r'sleep\s*\(',
                r'load_file\s*\(',
                r'into\s+outfile',
                r'load\s+data\s+infile'
            ],
            'xss': [
                r'<script',
                r'javascript:',
                r'onload\s*=',
                r'onerror\s*=',
                r'onclick\s*=',
                r'onmouseover\s*=',
                r'eval\s*\(',
                r'document\.cookie',
                r'document\.write',
                r'window\.location',
                r'alert\s*\(',
                r'prompt\s*\(',
                r'confirm\s*\('
            ],
            'directory_traversal': [
                r'\.\./',
                r'\.\.\\',
                r'%2e%2e%2f',
                r'%2e%2e/',
                r'..%2f',
                r'%252e%252e%252f',
                r'/etc/passwd',
                r'/etc/shadow',
                r'\\windows\\system32',
                r'\\boot.ini',
                r'/proc/self/environ'
            ],
            'command_injection': [
                r';\s*cat\s+',
                r';\s*ls\s+',
                r';\s*pwd',
                r';\s*id\s*;',
                r';\s*whoami',
                r';\s*uname',
                r';\s*wget\s+',
                r';\s*curl\s+',
                r';\s*nc\s+',
                r';\s*netcat',
                r'\|\s*cat\s+',
                r'\|\s*ls\s+',
                r'`cat\s+',
                r'`ls\s+',
                r'\$\(cat\s+',
                r'\$\(ls\s+'
            ],
            'file_inclusion': [
                r'file://',
                r'php://filter',
                r'php://input',
                r'data://text',
                r'expect://',
                r'zip://',
                r'phar://',
                r'include\s*\(',
                r'require\s*\(',
                r'file_get_contents\s*\('
            ],
            'web_shell': [
                r'c99\.php',
                r'r57\.php',
                r'shell\.php',
                r'cmd\.php',
                r'backdoor\.php',
                r'webshell\.php',
                r'eval\s*\(\$_',
                r'system\s*\(\$_',
                r'exec\s*\(\$_',
                r'passthru\s*\(\$_',
                r'shell_exec\s*\(\$_'
            ]
        }
        
        # Compile patterns for better performance
        self.compiled_patterns = {}
        for category, pattern_list in self.patterns.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in pattern_list
            ]
        
        # Pre-compile scanning and admin patterns for performance
        self.compiled_scan_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in [
                r'\.php$', r'\.asp$', r'\.jsp$', r'\.cgi$',
                r'/backup/', r'/bak/', r'/old/', r'/tmp/',
                r'\.bak$', r'\.backup$', r'\.old$', r'\.orig$',
                r'\.sql$', r'\.zip$', r'\.tar$', r'\.gz$',
                r'/config/', r'/configuration/', r'/settings/',
                r'/test/', r'/testing/', r'/debug/',
                r'\.git/', r'\.svn/', r'\.env$',
                r'/robots\.txt$', r'/sitemap\.xml$'
            ]
        ]
        
        self.compiled_admin_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in [
                r'/admin', r'/administrator', r'/wp-admin', r'/wp-login',
                r'/phpmyadmin', r'/pma/', r'/mysql/', r'/database/',
                r'/control', r'/panel/', r'/dashboard/', r'/manage/',
                r'/config/', r'/configuration/', r'/settings/',
                r'/server-info', r'/server-status', r'/info\.php',
                r'/phpinfo', r'/test\.php', r'/shell\.php'
            ]
        ]
        
        # Suspicious user agent patterns
        self.suspicious_ua_patterns = [
            r'sqlmap',
            r'nikto',
            r'nmap',
            r'masscan',
            r'zmap',
            r'dirb',
            r'dirbuster',
            r'gobuster',
            r'wpscan',
            r'burp',
            r'w3af',
            r'acunetix',
            r'nessus',
            r'openvas',
            r'havij',
            r'pangolin',
            r'libwww-perl',
            r'python-urllib',
            r'python-requests/\d+\.\d+\.\d+$',
            r'^curl/',
            r'^wget/',
            r'scanner',
            r'exploit',
            r'payload',
            r'injection',
            r'<script'
        ]
        
        self.compiled_ua_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.suspicious_ua_patterns
        ]

        # Compact platform-specific patterns
        def _rc(pats):
            return [re.compile(p, re.IGNORECASE) for p in pats]
        self.compiled_platform_patterns = {
            'wordpress': {
                'login': _rc([r'/wp-login\.php', r'/wp-admin/?']),
                'xmlrpc': _rc([r'/xmlrpc\.php$']),
                'api_enum': _rc([r'/wp-json/', r'[?&]author=\d+', r'/wp-json/wp/v2/users']),
                'sensitive': _rc([r'/wp-config\.php', r'/readme\.html', r'/license\.txt']),
                'backup': _rc([r'/wp-.*\.(zip|tar\.gz|sql|sql\.gz)(?:$|\?)'])
            },
            'woocommerce': {
                'api_enum': _rc([r'/wp-json/wc/(v\d+)/', r'/wp-json/wc/.*?/products']),
                'checkout_fail': _rc([r'/checkout', r'/wc-ajax/']),
                'webhook_probe': _rc([r'/wc-api/'])
            },
            'shopware': {
                # SW5 and SW6 common surfaces
                'admin': _rc([r'^/backend/', r'^/admin/']),
                'api_enum': _rc([r'^/api/', r'^/store-api/']),
                'recovery': _rc([r'/recovery/(install|update)/']),
                'sensitive': _rc([r'^/engine/', r'^/var/log/'])
            },
            'magento': {
                'login': _rc([r'^/(index\.php/)?admin/?', r'^/admin/?']),
                'api_enum': _rc([r'^/rest/V1/', r'^/oauth/']),
                'setup': _rc([r'^/setup/?']),
                'sensitive': _rc([r'/app/etc/(env\.php|local\.xml)$', r'^/var/log/'])
            }
        }

        # Incorporate custom Magento admin path if configured
        try:
            custom_admin = (PLATFORM_SECURITY.get('magento_admin_path', '') or '').strip()
        except Exception:
            custom_admin = ''
        if custom_admin:
            # Normalize to '/path/' without leading index.php
            if not custom_admin.startswith('/'):
                custom_admin = '/' + custom_admin
            # Allow given value with or without trailing slash
            custom_clean = custom_admin.strip('/')
            # Build regexes for both direct and index.php prefixed forms
            admin_regexes = [
                rf'^/{re.escape(custom_clean)}/?',
                rf'^/(index\.php/){re.escape(custom_clean)}/?'
            ]
            self.compiled_platform_patterns['magento']['login'].extend(_rc(admin_regexes))

    def record_blocked(self, log_entry: Dict[str, Any]) -> None:
        """Record a blocked request (e.g., 403/444/495-499) for reporting purposes."""
        try:
            status = int(log_entry.get('status', 0))
        except (ValueError, TypeError):
            status = 0
        ip = str(log_entry.get('ip') or log_entry.get('remote_addr') or '')
        path = log_entry.get('path') or ''
        user_agent = log_entry.get('user_agent') or ''
        country = (log_entry.get('country') or 'Unknown') or 'Unknown'
        ts = log_entry.get('timestamp')
        hour = ts.hour if ts else None

        self.blocked['total'] += 1
        self.blocked['status_codes'][status] += 1
        if ip:
            self.blocked['ips'][ip] += 1
        if path:
            self.blocked['paths'][path] += 1
        if user_agent:
            self.blocked['user_agents'][user_agent] += 1
        if country and country != '-':
            self.blocked['countries'][country] += 1
        if hour is not None:
            self.blocked['hours'][hour] += 1

    def get_blocked_summary(self) -> Dict[str, Any]:
        """Get a compact summary of blocked traffic."""
        return {
            'total': self.blocked['total'],
            'top_status_codes': dict(self.blocked['status_codes'].most_common(10)),
            'top_countries': dict(self.blocked['countries'].most_common(10)),
            'top_paths': dict(self.blocked['paths'].most_common(10)),
            'top_user_agents': dict(self.blocked['user_agents'].most_common(10)),
            'top_ips': dict(self.blocked['ips'].most_common(10)),
            'hourly_distribution': dict(self.blocked['hours'])
        }
        
    def analyze_file(self, file_path: str):
        """Analyze a single log file for security threats."""
        file_path = Path(file_path)
        
        with LogTailer(str(file_path), follow=False) as tailer:
            for line in tailer.tail():
                if not line.strip():
                    continue
                    
                log_entry = self.parser.parse_log_line(line)
                if not log_entry:
                    continue
                    
                self._analyze_entry(log_entry)
    
    def _analyze_entry(self, log_entry: Dict[str, Any]):
        """Analyze a single log entry for security threats."""
        ip = str(log_entry.get('ip') or log_entry.get('remote_addr', 'unknown'))
        path = log_entry.get('path', '')
        user_agent = log_entry.get('user_agent', '')
        # Ensure status is an integer for comparisons
        raw_status = log_entry.get('status', 0)
        try:
            status = int(raw_status)
        except (ValueError, TypeError):
            status = 0
        method = log_entry.get('method', 'GET')
        timestamp = log_entry.get('timestamp')
        
        # Update global counters
        self.total_requests += 1
        self.unique_ips.add(ip)
        if status >= 400:
            self.total_errors += 1
        
        # Track IP activity with more detail
        self.ip_request_counts[ip] += 1
        self.ip_error_rates[ip]['total'] += 1
        self.ip_status_codes[ip][status] += 1
        self.ip_methods[ip][method] += 1
        self.ip_paths[ip][path] += 1
        
        if status >= 400:
            self.ip_error_rates[ip]['errors'] += 1
        
        # Track request timing for rate limiting detection
        if timestamp:
            self.ip_request_times[ip].append(timestamp)
            # Keep only recent requests (last hour)
            cutoff_time = timestamp - timedelta(hours=1) if isinstance(timestamp, datetime) else None
            if cutoff_time:
                self.ip_request_times[ip] = [
                    t for t in self.ip_request_times[ip] 
                    if isinstance(t, datetime) and t >= cutoff_time
                ]
                
                # Check for potential DDoS (>100 requests per hour from single IP)
                if len(self.ip_request_times[ip]) > 100:
                    self.potential_ddos_ips.add(ip)
        
        # Check for scanning behavior
        self._check_scanning_behavior(ip, path, status)
        
        # Check for admin access attempts
        self._check_admin_access(ip, path, status, timestamp)
        
        # Analyze path for attack patterns
        full_request = f"{method} {path}"
        self._check_attack_patterns(ip, full_request, user_agent)
        
        # Check for brute force attempts
        self._check_brute_force(ip, path, status, timestamp)
        
        # Platform-specific compact checks
        self._check_platforms(ip, path, method, status, timestamp, user_agent)

        # Analyze user agent
        self._check_suspicious_user_agent(ip, user_agent)
        
        # Check for high error rates from single IP
        if self.ip_request_counts[ip] > 10:  # Only check IPs with significant activity
            error_rate = self.ip_error_rates[ip]['errors'] / self.ip_error_rates[ip]['total']
            if error_rate > 0.8:  # More than 80% errors
                self.suspicious_ips.add(ip)
    
    def _check_attack_patterns(self, ip: str, request: str, user_agent: str):
        """Check request and user agent for attack patterns."""
        request_lower = (request or "").lower()
        ua_lower = (user_agent or "").lower()
        
        # Check SQL injection patterns
        for pattern in self.compiled_patterns['sql_injection']:
            if pattern.search(request_lower) or pattern.search(ua_lower):
                self.sql_injection_attempts[ip].append({
                    'request': request,
                    'user_agent': user_agent,
                    'timestamp': datetime.now(),
                    'pattern': pattern.pattern
                })
                self.attack_patterns['SQL Injection'] += 1
                break
        
        # Check XSS patterns
        for pattern in self.compiled_patterns['xss']:
            if pattern.search(request_lower) or pattern.search(ua_lower):
                self.xss_attempts[ip].append({
                    'request': request,
                    'user_agent': user_agent,
                    'timestamp': datetime.now(),
                    'pattern': pattern.pattern
                })
                self.attack_patterns['XSS'] += 1
                break
        
        # Check directory traversal
        for pattern in self.compiled_patterns['directory_traversal']:
            if pattern.search(request_lower):
                self.directory_traversal[ip].append({
                    'request': request,
                    'timestamp': datetime.now(),
                    'pattern': pattern.pattern
                })
                self.attack_patterns['Directory Traversal'] += 1
                break
        
        # Check command injection
        for pattern in self.compiled_patterns['command_injection']:
            if pattern.search(request_lower):
                self.command_injection[ip].append({
                    'request': request,
                    'timestamp': datetime.now(),
                    'pattern': pattern.pattern
                })
                self.attack_patterns['Command Injection'] += 1
                break
        
        # Check file inclusion
        for pattern in self.compiled_patterns['file_inclusion']:
            if pattern.search(request_lower):
                self.attack_patterns['File Inclusion'] += 1
                break
        
        # Check web shell
        for pattern in self.compiled_patterns['web_shell']:
            if pattern.search(request_lower):
                self.attack_patterns['Web Shell'] += 1
                break

    def _record_platform_event(self, platform: str, event_type: str, ip: str, weight_hint: int = 0):
        self.platform_events[platform][event_type][ip] += 1
        # mark IP suspicious for impactful events
        if weight_hint >= 6:
            self.suspicious_ips.add(ip)

    def _check_platforms(self, ip: str, path: str, method: str, status: int, timestamp: datetime, user_agent: str):
        p = (path or '').lower()
        # WordPress
        if PLATFORM_SECURITY.get('enable_wordpress', True):
            wp = self.compiled_platform_patterns['wordpress']
            if any(r.search(p) for r in wp['login']):
                if status in [401, 403, 404]:
                    self._record_platform_event('wordpress', 'bruteforce', ip, self.platform_weights['wordpress']['bruteforce'])
            if any(r.search(p) for r in wp['xmlrpc']) and method.upper() == 'POST':
                self._record_platform_event('wordpress', 'xmlrpc_abuse', ip, self.platform_weights['wordpress']['xmlrpc_abuse'])
            if any(r.search(p) for r in wp['api_enum']):
                self._record_platform_event('wordpress', 'api_enum', ip, self.platform_weights['wordpress']['api_enum'])
            if any(r.search(p) for r in wp['sensitive']):
                self._record_platform_event('wordpress', 'sensitive_access', ip, self.platform_weights['wordpress']['sensitive_access'])
            if any(r.search(p) for r in wp['backup']):
                self._record_platform_event('wordpress', 'backup_probe', ip, self.platform_weights['wordpress']['backup_probe'])

        # WooCommerce
        if PLATFORM_SECURITY.get('enable_woocommerce', True):
            wc = self.compiled_platform_patterns['woocommerce']
            if any(r.search(p) for r in wc['api_enum']):
                self._record_platform_event('woocommerce', 'api_enum', ip, self.platform_weights['woocommerce']['api_enum'])
            if any(r.search(p) for r in wc['checkout_fail']) and method.upper() == 'POST' and status in [400, 401, 402, 403]:
                self._record_platform_event('woocommerce', 'checkout_fail', ip, self.platform_weights['woocommerce']['checkout_fail'])
            if any(r.search(p) for r in wc['webhook_probe']):
                self._record_platform_event('woocommerce', 'webhook_probe', ip, self.platform_weights['woocommerce']['webhook_probe'])

        # Shopware 5/6
        if PLATFORM_SECURITY.get('enable_shopware', True):
            sw = self.compiled_platform_patterns['shopware']
            if any(r.search(p) for r in sw['admin']) and status in [401, 403, 404]:
                self._record_platform_event('shopware', 'admin_probe', ip, self.platform_weights['shopware']['admin_probe'])
            if any(r.search(p) for r in sw['api_enum']):
                self._record_platform_event('shopware', 'api_enum', ip, self.platform_weights['shopware']['api_enum'])
            if any(r.search(p) for r in sw['recovery']):
                self._record_platform_event('shopware', 'recovery_probe', ip, self.platform_weights['shopware']['recovery_probe'])
            if any(r.search(p) for r in sw['sensitive']):
                self._record_platform_event('shopware', 'sensitive_access', ip, self.platform_weights['shopware']['sensitive_access'])

        # Magento 1/2
        if PLATFORM_SECURITY.get('enable_magento', True):
            mg = self.compiled_platform_patterns['magento']
            if any(r.search(p) for r in mg['login']) and status in [401, 403, 404]:
                self._record_platform_event('magento', 'bruteforce', ip, self.platform_weights['magento']['bruteforce'])
            if any(r.search(p) for r in mg['api_enum']):
                self._record_platform_event('magento', 'api_enum', ip, self.platform_weights['magento']['api_enum'])
            if any(r.search(p) for r in mg['setup']):
                self._record_platform_event('magento', 'setup_probe', ip, self.platform_weights['magento']['setup_probe'])
            if any(r.search(p) for r in mg['sensitive']):
                self._record_platform_event('magento', 'sensitive_access', ip, self.platform_weights['magento']['sensitive_access'])
    
    def _check_brute_force(self, ip: str, path: str, status: int, timestamp: datetime):
        """Check for brute force login attempts."""
        # Common login endpoints
        login_patterns = [
            r'/login',
            r'/admin',
            r'/wp-login',
            r'/wp-admin',
            r'/administrator',
            r'/auth',
            r'/signin',
            r'/user/login',
            r'/account/login',
            r'/portal/login'
        ]
        
        path_lower = (path or "").lower()
        is_login_attempt = any(re.search(pattern, path_lower) for pattern in login_patterns)
        
        if is_login_attempt and status in [401, 403, 404]:
            self.brute_force_attempts[ip].append({
                'path': path,
                'status': status,
                'timestamp': timestamp
            })
            self.failed_logins[ip] += 1
    
    def _check_suspicious_user_agent(self, ip: str, user_agent: str):
        """Check for suspicious user agents."""
        if not user_agent or user_agent == '-':
            self.suspicious_user_agents['Empty/Missing User Agent'] += 1
            return
        
        for pattern in self.compiled_ua_patterns:
            if pattern.search(user_agent):
                self.suspicious_user_agents[user_agent] += 1
                break
        
        # Check for very short user agents (often automated tools)
        if user_agent and len(user_agent) < 10:
            self.suspicious_user_agents[user_agent] += 1
        
        # Check for user agents with suspicious keywords
        suspicious_keywords = ['bot', 'crawler', 'spider', 'scan', 'hack', 'exploit', 'test']
        ua_lower = (user_agent or "").lower()
        if any(keyword in ua_lower for keyword in suspicious_keywords):
            # But exclude legitimate bots
            legitimate_bots = ['googlebot', 'bingbot', 'slurp', 'duckduckbot', 'facebookexternalhit']
            if not any(bot in ua_lower for bot in legitimate_bots):
                self.suspicious_user_agents[user_agent] += 1
    
    def _check_scanning_behavior(self, ip: str, path: str, status: int):
        """Check for directory/file scanning behavior."""
        # Use pre-compiled patterns for better performance
        if any(pattern.search(path) for pattern in self.compiled_scan_patterns):
            self.scan_attempts[ip].append({
                'path': path,
                'status': status,
                'timestamp': datetime.now()
            })
    
    def _check_admin_access(self, ip: str, path: str, status: int, timestamp: datetime):
        """Check for admin/sensitive area access attempts."""
        # Use pre-compiled patterns for better performance
        if any(pattern.search(path) for pattern in self.compiled_admin_patterns):
            self.admin_access_attempts[ip].append({
                'path': path,
                'status': status,
                'timestamp': timestamp
            })
    
    def get_attack_patterns(self) -> Dict[str, int]:
        """Get detected attack patterns."""
        return dict(self.attack_patterns.most_common())
    
    def get_brute_force_attempts(self, threshold: int = 10) -> Dict[str, int]:
        """Get IPs with brute force attempts above threshold."""
        return {ip: count for ip, count in self.failed_logins.items() if count >= threshold}
    
    def get_sql_injection_attempts(self) -> Dict[str, List[Dict]]:
        """Get SQL injection attempts by IP."""
        return dict(self.sql_injection_attempts)
    
    def get_suspicious_user_agents(self) -> List[Tuple[str, int]]:
        """Get suspicious user agents."""
        return self.suspicious_user_agents.most_common(50)
    
    def get_suspicious_ips(self) -> List[Dict[str, Any]]:
        """Get list of suspicious IPs with details."""
        suspicious = []
        
        for ip in self.suspicious_ips:
            error_rate = self.ip_error_rates[ip]['errors'] / max(self.ip_error_rates[ip]['total'], 1)
            
            suspicious.append({
                'ip': ip,
                'total_requests': self.ip_request_counts[ip],
                'error_rate': error_rate * 100,
                'failed_logins': self.failed_logins.get(ip, 0),
                'attack_attempts': {
                    'sql_injection': len(self.sql_injection_attempts.get(ip, [])),
                    'xss': len(self.xss_attempts.get(ip, [])),
                    'directory_traversal': len(self.directory_traversal.get(ip, [])),
                    'command_injection': len(self.command_injection.get(ip, []))
                }
            })
        
        # Sort by threat score (combination of error rate and attack attempts)
        for item in suspicious:
            # platform contribution
            platform_score = 0
            for platform, weights in self.platform_weights.items():
                for event_type, weight in weights.items():
                    count = self.platform_events[platform][event_type].get(item['ip'], 0)
                    platform_score += count * weight
            threat_score = (
                item['error_rate'] * 0.3 +
                sum(item['attack_attempts'].values()) * 10 +
                item['failed_logins'] * 2 +
                platform_score
            )
            item['threat_score'] = threat_score
        
        return sorted(suspicious, key=lambda x: x['threat_score'], reverse=True)
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get comprehensive security summary."""
        total_attacks = sum(self.attack_patterns.values())
        total_ips_analyzed = len(self.ip_request_counts)
        suspicious_ip_count = len(self.suspicious_ips)
        
        # Calculate additional metrics
        error_rate = (self.total_errors / max(self.total_requests, 1)) * 100
        scanning_ips = len([ip for ip, scans in self.scan_attempts.items() if len(scans) >= 5])
        admin_access_ips = len([ip for ip, attempts in self.admin_access_attempts.items() if len(attempts) >= 3])
        
        return {
            'total_requests': self.total_requests,
            'total_errors': self.total_errors,
            'global_error_rate': error_rate,
            'unique_ips': len(self.unique_ips),
            'total_attack_attempts': total_attacks,
            'attack_types_detected': len(self.attack_patterns),
            'total_ips_analyzed': total_ips_analyzed,
            'suspicious_ips': suspicious_ip_count,
            'suspicious_ip_percentage': (suspicious_ip_count / max(total_ips_analyzed, 1)) * 100,
            'potential_ddos_ips': len(self.potential_ddos_ips),
            'scanning_ips': scanning_ips,
            'admin_access_ips': admin_access_ips,
            'top_attack_types': dict(self.attack_patterns.most_common(5)),
            'brute_force_ips': len([ip for ip, count in self.failed_logins.items() if count >= 5]),
            'sql_injection_ips': len(self.sql_injection_attempts),
            'xss_attempt_ips': len(self.xss_attempts),
            'directory_traversal_ips': len(self.directory_traversal),
            'command_injection_ips': len(self.command_injection),
            'suspicious_user_agents': len(self.suspicious_user_agents),
            'platform': {
                'wordpress': {
                    'bruteforce_ips': len(self.platform_events['wordpress']['bruteforce']),
                    'xmlrpc_abuse_ips': len(self.platform_events['wordpress']['xmlrpc_abuse']),
                    'api_enum_ips': len(self.platform_events['wordpress']['api_enum']),
                    'sensitive_ips': len(self.platform_events['wordpress']['sensitive_access'])
                },
                'woocommerce': {
                    'api_enum_ips': len(self.platform_events['woocommerce']['api_enum']),
                    'checkout_fail_ips': len(self.platform_events['woocommerce']['checkout_fail'])
                },
                'shopware': {
                    'admin_probe_ips': len(self.platform_events['shopware']['admin_probe']),
                    'api_enum_ips': len(self.platform_events['shopware']['api_enum']),
                    'recovery_probe_ips': len(self.platform_events['shopware']['recovery_probe'])
                },
                'magento': {
                    'bruteforce_ips': len(self.platform_events['magento']['bruteforce']),
                    'api_enum_ips': len(self.platform_events['magento']['api_enum']),
                    'setup_probe_ips': len(self.platform_events['magento']['setup_probe']),
                    'sensitive_ips': len(self.platform_events['magento']['sensitive_access'])
                }
            }
        }
    
    def export_security_report(self, output_file: str):
        """Export detailed security report to JSON."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': self.get_security_summary(),
            'attack_patterns': dict(self.attack_patterns),
            'suspicious_ips': self.get_suspicious_ips(),
            'platform_events': {
                platform: {
                    event_type: dict(sorted(events.items(), key=lambda kv: kv[1], reverse=True))
                    for event_type, events in event_types.items()
                }
                for platform, event_types in self.platform_events.items()
            },
            'brute_force_attempts': {
                ip: {
                    'failed_logins': count,
                    'attempts': [
                        {
                            'path': attempt['path'],
                            'status': attempt['status'],
                            'timestamp': attempt['timestamp'].isoformat() if attempt['timestamp'] else None
                        } for attempt in attempts
                    ]
                }
                for ip, attempts in self.brute_force_attempts.items()
                if len(attempts) >= 5  # Only include significant attempts
            },
            'sql_injection_attempts': {
                ip: [
                    {
                        'request': attempt['request'],
                        'pattern': attempt['pattern'],
                        'timestamp': attempt['timestamp'].isoformat() if attempt['timestamp'] else None
                    } for attempt in attempts
                ]
                for ip, attempts in self.sql_injection_attempts.items()
            },
            'suspicious_user_agents': dict(self.suspicious_user_agents.most_common(100))
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def get_blacklist_recommendations(self, min_threat_score: float = 50.0) -> List[str]:
        """Get IP addresses recommended for blacklisting."""
        suspicious_ips = self.get_suspicious_ips()
        return [ip['ip'] for ip in suspicious_ips if ip['threat_score'] >= min_threat_score]
    
    def get_scanning_ips(self, min_scans: int = 5) -> Dict[str, int]:
        """Get IPs with scanning behavior above threshold."""
        return {ip: len(scans) for ip, scans in self.scan_attempts.items() if len(scans) >= min_scans}
    
    def get_admin_access_ips(self, min_attempts: int = 3) -> Dict[str, int]:
        """Get IPs with admin access attempts above threshold."""
        return {ip: len(attempts) for ip, attempts in self.admin_access_attempts.items() if len(attempts) >= min_attempts}
    
    def get_ddos_candidates(self) -> List[str]:
        """Get IPs that might be performing DDoS attacks."""
        return list(self.potential_ddos_ips)
    
    def get_top_error_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get IPs with highest error rates."""
        error_ips = []
        for ip, error_data in self.ip_error_rates.items():
            if error_data['total'] >= 10:  # Only consider IPs with significant activity
                error_rate = (error_data['errors'] / error_data['total']) * 100
                error_ips.append({
                    'ip': ip,
                    'total_requests': error_data['total'],
                    'errors': error_data['errors'],
                    'error_rate': error_rate
                })
        
        return sorted(error_ips, key=lambda x: x['error_rate'], reverse=True)[:limit]
