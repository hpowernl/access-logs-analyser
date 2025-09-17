"""Bot analysis module for classifying and analyzing bot behavior."""

import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Set, Tuple, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .parser import LogParser
from .log_reader import LogTailer


class BotAnalyzer:
    """Analyzes bot behavior patterns and classifies bot types."""
    
    def __init__(self):
        self.parser = LogParser()
        
        # Bot classification
        self.bot_requests = defaultdict(list)
        self.human_requests = defaultdict(list)
        self.unknown_bots = Counter()
        
        # Bot behavior patterns
        self.bot_paths = defaultdict(Counter)
        self.bot_intervals = defaultdict(list)
        self.bot_sessions = defaultdict(list)
        
        # Resource usage
        self.bot_response_times = defaultdict(list)
        self.bot_bandwidth = defaultdict(int)
        self.bot_errors = defaultdict(int)
        
        # Legitimacy scoring
        self.legitimacy_scores = {}
        
        # Initialize bot patterns
        self._init_bot_patterns()
        
    def _init_bot_patterns(self):
        """Initialize bot classification patterns."""
        self.bot_signatures = {
            # Search Engine Bots (Legitimate)
            'googlebot': {
                'patterns': [r'googlebot', r'google web preview'],
                'type': 'search_engine',
                'legitimate': True,
                'description': 'Google search crawler'
            },
            'bingbot': {
                'patterns': [r'bingbot', r'msnbot'],
                'type': 'search_engine',
                'legitimate': True,
                'description': 'Microsoft Bing crawler'
            },
            'slurp': {
                'patterns': [r'slurp'],
                'type': 'search_engine',
                'legitimate': True,
                'description': 'Yahoo search crawler'
            },
            'duckduckbot': {
                'patterns': [r'duckduckbot'],
                'type': 'search_engine',
                'legitimate': True,
                'description': 'DuckDuckGo crawler'
            },
            'baiduspider': {
                'patterns': [r'baiduspider'],
                'type': 'search_engine',
                'legitimate': True,
                'description': 'Baidu search crawler'
            },
            'yandexbot': {
                'patterns': [r'yandexbot'],
                'type': 'search_engine',
                'legitimate': True,
                'description': 'Yandex search crawler'
            },
            
            # Social Media Bots (Legitimate)
            'facebookexternalhit': {
                'patterns': [r'facebookexternalhit'],
                'type': 'social_media',
                'legitimate': True,
                'description': 'Facebook link preview bot'
            },
            'twitterbot': {
                'patterns': [r'twitterbot'],
                'type': 'social_media',
                'legitimate': True,
                'description': 'Twitter card validator'
            },
            'linkedinbot': {
                'patterns': [r'linkedinbot'],
                'type': 'social_media',
                'legitimate': True,
                'description': 'LinkedIn content crawler'
            },
            'whatsapp': {
                'patterns': [r'whatsapp'],
                'type': 'social_media',
                'legitimate': True,
                'description': 'WhatsApp link preview'
            },
            'telegrambot': {
                'patterns': [r'telegrambot'],
                'type': 'social_media',
                'legitimate': True,
                'description': 'Telegram link preview'
            },
            
            # Monitoring Bots (Legitimate)
            'pingdom': {
                'patterns': [r'pingdom'],
                'type': 'monitoring',
                'legitimate': True,
                'description': 'Pingdom uptime monitoring'
            },
            'uptimerobot': {
                'patterns': [r'uptimerobot'],
                'type': 'monitoring',
                'legitimate': True,
                'description': 'UptimeRobot monitoring'
            },
            'newrelic': {
                'patterns': [r'newrelic'],
                'type': 'monitoring',
                'legitimate': True,
                'description': 'New Relic monitoring'
            },
            'datadog': {
                'patterns': [r'datadog'],
                'type': 'monitoring',
                'legitimate': True,
                'description': 'Datadog monitoring'
            },
            
            # SEO Tools (Semi-legitimate)
            'ahrefsbot': {
                'patterns': [r'ahrefsbot'],
                'type': 'seo_tool',
                'legitimate': True,
                'description': 'Ahrefs SEO crawler'
            },
            'semrushbot': {
                'patterns': [r'semrushbot'],
                'type': 'seo_tool',
                'legitimate': True,
                'description': 'SEMrush crawler'
            },
            'mj12bot': {
                'patterns': [r'mj12bot'],
                'type': 'seo_tool',
                'legitimate': True,
                'description': 'Majestic SEO crawler'
            },
            'dotbot': {
                'patterns': [r'dotbot'],
                'type': 'seo_tool',
                'legitimate': True,
                'description': 'Moz crawler'
            },
            
            # Generic/Suspicious Bots
            'generic_bot': {
                'patterns': [r'\bbot\b', r'\bcrawler\b', r'\bspider\b'],
                'type': 'generic',
                'legitimate': False,
                'description': 'Generic bot or crawler'
            },
            'python_requests': {
                'patterns': [r'python-requests', r'python-urllib'],
                'type': 'script',
                'legitimate': False,
                'description': 'Python HTTP library'
            },
            'curl': {
                'patterns': [r'^curl/'],
                'type': 'script',
                'legitimate': False,
                'description': 'cURL command line tool'
            },
            'wget': {
                'patterns': [r'^wget/'],
                'type': 'script',
                'legitimate': False,
                'description': 'Wget command line tool'
            },
            'guzzlehttp': {
                'patterns': [r'guzzlehttp'],
                'type': 'script',
                'legitimate': False,
                'description': 'PHP HTTP client library'
            },
            
            # Security Scanners (Malicious)
            'security_scanner': {
                'patterns': [r'sqlmap', r'nikto', r'nmap', r'masscan', r'dirb', r'gobuster', r'wpscan'],
                'type': 'security_scanner',
                'legitimate': False,
                'description': 'Security scanning tool'
            },
            'vulnerability_scanner': {
                'patterns': [r'acunetix', r'nessus', r'openvas', r'burp', r'w3af'],
                'type': 'vulnerability_scanner',
                'legitimate': False,
                'description': 'Vulnerability scanner'
            },
            
            # AI Bots and LLM Crawlers (New Category)
            'chatgpt_bot': {
                'patterns': [r'chatgpt', r'gpt-bot', r'openai', r'gpt-4', r'gpt-3\.5'],
                'type': 'ai_llm',
                'legitimate': True,
                'description': 'ChatGPT/OpenAI bot'
            },
            'claude_bot': {
                'patterns': [r'claude', r'anthropic', r'claude-bot'],
                'type': 'ai_llm',
                'legitimate': True,
                'description': 'Claude AI bot'
            },
            'bard_bot': {
                'patterns': [r'bard', r'google-bard', r'palm-bot'],
                'type': 'ai_llm',
                'legitimate': True,
                'description': 'Google Bard/PaLM bot'
            },
            'copilot_bot': {
                'patterns': [r'copilot', r'github-copilot', r'microsoft-copilot'],
                'type': 'ai_llm',
                'legitimate': True,
                'description': 'Microsoft Copilot bot'
            },
            'perplexity_bot': {
                'patterns': [r'perplexity', r'perplexitybot'],
                'type': 'ai_llm',
                'legitimate': True,
                'description': 'Perplexity AI bot'
            },
            
            # AI Training Data Crawlers
            'common_crawl': {
                'patterns': [r'ccbot', r'common-crawl', r'commoncrawl'],
                'type': 'ai_training',
                'legitimate': True,
                'description': 'Common Crawl data collection bot'
            },
            'ai2_bot': {
                'patterns': [r'ai2bot', r'allen-institute'],
                'type': 'ai_training',
                'legitimate': True,
                'description': 'AI2 research crawler'
            },
            'anthropic_crawler': {
                'patterns': [r'anthropic-ai', r'claude-web'],
                'type': 'ai_training',
                'legitimate': True,
                'description': 'Anthropic data crawler'
            },
            
            # AI Research and Academic Bots
            'academic_ai_bot': {
                'patterns': [r'research-bot', r'academic-crawler', r'university-bot'],
                'type': 'ai_research',
                'legitimate': True,
                'description': 'Academic AI research bot'
            },
            'huggingface_bot': {
                'patterns': [r'huggingface', r'hf-bot'],
                'type': 'ai_research',
                'legitimate': True,
                'description': 'Hugging Face model bot'
            },
            
            # AI Content Generation Bots
            'ai_content_bot': {
                'patterns': [r'jasper', r'copy\.ai', r'writesonic', r'contentbot'],
                'type': 'ai_content',
                'legitimate': True,
                'description': 'AI content generation bot'
            },
            'ai_image_bot': {
                'patterns': [r'midjourney', r'dall-e', r'stable-diffusion', r'imagen'],
                'type': 'ai_content',
                'legitimate': True,
                'description': 'AI image generation bot'
            },
            
            # AI SEO and Marketing Bots
            'ai_seo_bot': {
                'patterns': [r'ai-seo', r'rank-math-ai', r'yoast-ai', r'surfer-ai'],
                'type': 'ai_seo',
                'legitimate': True,
                'description': 'AI-powered SEO bot'
            },
            'ai_marketing_bot': {
                'patterns': [r'marketo-ai', r'hubspot-ai', r'salesforce-ai'],
                'type': 'ai_marketing',
                'legitimate': True,
                'description': 'AI marketing automation bot'
            },
            
            # Conversational AI and Chatbots
            'chatbot': {
                'patterns': [r'chatbot', r'virtual-assistant', r'dialogflow', r'rasa'],
                'type': 'ai_conversational',
                'legitimate': True,
                'description': 'Conversational AI chatbot'
            },
            'voice_assistant': {
                'patterns': [r'alexa', r'siri', r'google-assistant', r'cortana'],
                'type': 'ai_conversational',
                'legitimate': True,
                'description': 'Voice assistant bot'
            },
            
            # AI API and Service Bots
            'ai_api_bot': {
                'patterns': [r'ai-api', r'ml-service', r'neural-bot', r'tensorflow-bot'],
                'type': 'ai_service',
                'legitimate': True,
                'description': 'AI API service bot'
            },
            'automated_ai_bot': {
                'patterns': [r'automated-ai', r'ai-automation', r'ml-automation'],
                'type': 'ai_service',
                'legitimate': False,  # Could be aggressive
                'description': 'Automated AI service bot'
            }
        }
        
        # Compile patterns for better performance
        self.compiled_patterns = {}
        for bot_name, info in self.bot_signatures.items():
            self.compiled_patterns[bot_name] = [
                re.compile(pattern, re.IGNORECASE) for pattern in info['patterns']
            ]
    
    def analyze_file(self, file_path: str):
        """Analyze a single log file for bot behavior."""
        file_path = Path(file_path)
        
        with LogTailer(str(file_path), follow=False) as tailer:
            for line in tailer.tail():
                if not line.strip():
                    continue
                    
                log_entry = self.parser.parse_log_line(line)
                if not log_entry:
                    continue
                    
                self._analyze_entry(log_entry)
        
        # Calculate legitimacy scores after processing all entries
        self._calculate_legitimacy_scores()
    
    def _analyze_entry(self, log_entry: Dict[str, Any]):
        """Analyze a single log entry for bot behavior."""
        user_agent = log_entry.get('user_agent', '')
        ip = str(log_entry.get('ip', 'unknown'))
        path = log_entry.get('path', '/')
        timestamp = log_entry.get('timestamp', datetime.now())
        response_time = log_entry.get('response_time', 0)
        bytes_sent = log_entry.get('bytes_sent', 0)
        status = log_entry.get('status', 200)
        referer = log_entry.get('referer', '')
        
        # Classify bot type
        bot_type = self._classify_bot(user_agent)
        
        if bot_type:
            # This is a bot
            self.bot_requests[bot_type].append({
                'ip': ip,
                'timestamp': timestamp,
                'path': path,
                'response_time': response_time,
                'bytes_sent': bytes_sent,
                'status': status,
                'referer': referer,
                'user_agent': user_agent
            })
            
            # Track bot behavior patterns
            self.bot_paths[bot_type][path] += 1
            self.bot_response_times[bot_type].append(response_time)
            self.bot_bandwidth[bot_type] += bytes_sent
            
            if status >= 400:
                self.bot_errors[bot_type] += 1
            
            # Track request intervals for this bot
            if bot_type in self.bot_sessions and self.bot_sessions[bot_type]:
                last_request = self.bot_sessions[bot_type][-1]['timestamp']
                interval = (timestamp - last_request).total_seconds()
                self.bot_intervals[bot_type].append(interval)
            
            self.bot_sessions[bot_type].append({
                'ip': ip,
                'timestamp': timestamp,
                'path': path
            })
            
        else:
            # Check if it might be an unknown bot
            if self._is_likely_bot(user_agent, path, referer):
                self.unknown_bots[user_agent] += 1
            else:
                # Human request
                self.human_requests[ip].append({
                    'timestamp': timestamp,
                    'path': path,
                    'user_agent': user_agent
                })
    
    def _classify_bot(self, user_agent: str) -> Optional[str]:
        """Classify bot type based on user agent."""
        if not user_agent or user_agent == '-':
            return None
        
        ua_lower = user_agent.lower()
        
        # Check against known bot patterns
        for bot_name, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(ua_lower):
                    return bot_name
        
        return None
    
    def _is_likely_bot(self, user_agent: str, path: str, referer: str) -> bool:
        """Determine if an unclassified request is likely from a bot."""
        if not user_agent:
            return True
        
        # Check for bot-like characteristics
        bot_indicators = 0
        
        # Very short or very long user agents
        if len(user_agent) < 10 or len(user_agent) > 500:
            bot_indicators += 1
        
        # No referer (common for bots)
        if not referer or referer == '-':
            bot_indicators += 1
        
        # Accessing robot.txt, sitemap, or common bot paths
        bot_paths = ['/robots.txt', '/sitemap.xml', '/wp-admin', '/admin', '/.env', '/config']
        if any(bot_path in path.lower() for bot_path in bot_paths):
            bot_indicators += 1
        
        # Suspicious user agent patterns
        suspicious_patterns = [
            r'http', r'scan', r'check', r'test', r'monitor', r'fetch',
            r'download', r'extract', r'parse', r'collect', r'gather'
        ]
        ua_lower = user_agent.lower()
        if any(re.search(pattern, ua_lower) for pattern in suspicious_patterns):
            bot_indicators += 1
        
        # Simple user agents (often scripts)
        if re.match(r'^[a-z]+/[\d.]+$', user_agent.lower()):
            bot_indicators += 1
        
        return bot_indicators >= 2
    
    def _calculate_legitimacy_scores(self):
        """Calculate legitimacy scores for detected bots."""
        for bot_type, requests in self.bot_requests.items():
            if not requests:
                continue
            
            score = 0.5  # Base score
            
            # Check if it's a known legitimate bot
            if bot_type in self.bot_signatures:
                if self.bot_signatures[bot_type]['legitimate']:
                    score += 0.3
                else:
                    score -= 0.3
            
            # Analyze behavior patterns
            behavior_score = self._analyze_bot_behavior(bot_type, requests)
            score += behavior_score
            
            # Clamp score between 0 and 1
            self.legitimacy_scores[bot_type] = max(0, min(1, score))
    
    def _analyze_bot_behavior(self, bot_type: str, requests: List[Dict]) -> float:
        """Analyze bot behavior to determine legitimacy score adjustment."""
        if len(requests) < 5:
            return 0
        
        behavior_score = 0
        
        # Check request intervals (good bots are polite)
        intervals = self.bot_intervals.get(bot_type, [])
        if intervals:
            avg_interval = statistics.mean(intervals)
            if avg_interval > 1:  # More than 1 second between requests
                behavior_score += 0.1
            elif avg_interval < 0.1:  # Less than 0.1 seconds (very aggressive)
                behavior_score -= 0.2
        
        # Check path diversity (good bots crawl different pages)
        unique_paths = len(set(req['path'] for req in requests))
        path_diversity = unique_paths / len(requests)
        if path_diversity > 0.5:
            behavior_score += 0.1
        elif path_diversity < 0.1:  # Hitting same path repeatedly
            behavior_score -= 0.1
        
        # Check error rate (good bots handle errors gracefully)
        error_count = sum(1 for req in requests if req['status'] >= 400)
        error_rate = error_count / len(requests)
        if error_rate > 0.5:  # High error rate suggests aggressive behavior
            behavior_score -= 0.2
        elif error_rate < 0.1:  # Low error rate is good
            behavior_score += 0.1
        
        # Check if bot respects robots.txt
        robots_requests = [req for req in requests if '/robots.txt' in req['path']]
        if robots_requests:
            behavior_score += 0.1  # Good bots check robots.txt
        
        # Check for suspicious paths
        suspicious_paths = ['/.env', '/config', '/admin', '/wp-admin', '/.git']
        suspicious_requests = [
            req for req in requests 
            if any(sus_path in req['path'] for sus_path in suspicious_paths)
        ]
        if len(suspicious_requests) > len(requests) * 0.1:  # More than 10% suspicious
            behavior_score -= 0.3
        
        return behavior_score
    
    def get_bot_classification(self) -> Dict[str, int]:
        """Get bot classification counts."""
        classification = {}
        
        for bot_type, requests in self.bot_requests.items():
            if bot_type in self.bot_signatures:
                category = self.bot_signatures[bot_type]['type']
                classification[category] = classification.get(category, 0) + len(requests)
            else:
                classification['unknown'] = classification.get('unknown', 0) + len(requests)
        
        # Add unknown bots
        classification['unclassified'] = sum(self.unknown_bots.values())
        
        return classification
    
    def get_behavior_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Analyze and return bot behavior patterns."""
        patterns = {}
        
        for bot_type, requests in self.bot_requests.items():
            if len(requests) < 5:
                continue
            
            intervals = self.bot_intervals.get(bot_type, [])
            avg_interval = statistics.mean(intervals) if intervals else 0
            
            # Most common paths
            top_paths = self.bot_paths[bot_type].most_common(5)
            
            # Request timing patterns
            hours = [req['timestamp'].hour for req in requests]
            hour_distribution = Counter(hours)
            peak_hour = hour_distribution.most_common(1)[0] if hour_distribution else (0, 0)
            
            patterns[bot_type] = {
                'description': self.bot_signatures.get(bot_type, {}).get('description', 'Unknown bot'),
                'frequency': f"{len(requests)} requests",
                'avg_interval': f"{avg_interval:.2f}s between requests",
                'top_paths': [path for path, count in top_paths],
                'peak_hour': f"{peak_hour[0]}:00 ({peak_hour[1]} requests)",
                'impact': self._calculate_bot_impact(bot_type, requests)
            }
        
        return patterns
    
    def _calculate_bot_impact(self, bot_type: str, requests: List[Dict]) -> str:
        """Calculate the impact of a bot on server resources."""
        total_response_time = sum(req['response_time'] for req in requests)
        total_bandwidth = sum(req['bytes_sent'] for req in requests)
        
        impact_score = (
            len(requests) * 0.1 +  # Request count
            total_response_time * 0.5 +  # CPU time
            total_bandwidth / (1024 * 1024) * 0.1  # Bandwidth in MB
        )
        
        if impact_score < 10:
            return "Low"
        elif impact_score < 100:
            return "Medium"
        else:
            return "High"
    
    def get_legitimacy_scores(self) -> Dict[str, float]:
        """Get legitimacy scores for all detected bots."""
        return self.legitimacy_scores
    
    def get_resource_impact(self) -> Dict[str, Any]:
        """Calculate overall resource impact of bot traffic."""
        total_bot_requests = sum(len(requests) for requests in self.bot_requests.values())
        total_human_requests = sum(len(requests) for requests in self.human_requests.values())
        total_requests = total_bot_requests + total_human_requests
        
        total_bot_bandwidth = sum(self.bot_bandwidth.values())
        total_bot_response_time = sum(
            sum(times) for times in self.bot_response_times.values()
        )
        
        avg_bot_response_time = 0
        if total_bot_requests > 0:
            all_bot_times = []
            for times in self.bot_response_times.values():
                all_bot_times.extend(times)
            avg_bot_response_time = statistics.mean(all_bot_times) if all_bot_times else 0
        
        return {
            'total_requests': total_bot_requests,
            'percentage_of_traffic': (total_bot_requests / max(total_requests, 1)) * 100,
            'bandwidth_gb': total_bot_bandwidth / (1024 * 1024 * 1024),
            'avg_response_time': avg_bot_response_time,
            'server_load_pct': min(100, (total_bot_response_time / max(total_requests * 0.1, 1)) * 100),
            'top_resource_bots': sorted(
                [(bot, len(reqs)) for bot, reqs in self.bot_requests.items()],
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }
    
    def get_bot_recommendations(self) -> List[Dict[str, Any]]:
        """Generate recommendations for bot management."""
        recommendations = []
        
        # Check for aggressive bots
        aggressive_bots = []
        for bot_type, intervals in self.bot_intervals.items():
            if intervals:
                avg_interval = statistics.mean(intervals)
                if avg_interval < 0.5 and len(intervals) > 50:  # Very frequent requests
                    aggressive_bots.append((bot_type, avg_interval))
        
        if aggressive_bots:
            recommendations.append({
                'category': 'Rate Limiting',
                'priority': 'High',
                'issue': f'Aggressive bots detected: {len(aggressive_bots)}',
                'recommendation': 'Implement rate limiting for these bots',
                'bots': [f"{bot} ({interval:.2f}s avg interval)" for bot, interval in aggressive_bots[:3]]
            })
        
        # Check for malicious bots
        malicious_bots = [
            bot for bot, score in self.legitimacy_scores.items()
            if score < 0.3 and len(self.bot_requests.get(bot, [])) > 10
        ]
        
        if malicious_bots:
            recommendations.append({
                'category': 'Security',
                'priority': 'High',
                'issue': f'Potentially malicious bots: {len(malicious_bots)}',
                'recommendation': 'Consider blocking these bots',
                'bots': malicious_bots[:5]
            })
        
        # Check bot traffic percentage
        impact = self.get_resource_impact()
        if impact['percentage_of_traffic'] > 50:
            recommendations.append({
                'category': 'Traffic Management',
                'priority': 'Medium',
                'issue': f"Bot traffic is {impact['percentage_of_traffic']:.1f}% of total",
                'recommendation': 'Consider implementing bot-specific caching or CDN rules',
                'details': f"Total bot requests: {impact['total_requests']:,}"
            })
        
        # Check for unknown bots
        if len(self.unknown_bots) > 10:
            recommendations.append({
                'category': 'Bot Detection',
                'priority': 'Low',
                'issue': f'Many unclassified potential bots: {len(self.unknown_bots)}',
                'recommendation': 'Review and classify unknown user agents',
                'top_unknown': [ua for ua, count in self.unknown_bots.most_common(3)]
            })
        
        return recommendations
    
    def get_ai_bot_analysis(self) -> Dict[str, Any]:
        """Get comprehensive AI bot analysis."""
        ai_bot_types = ['ai_llm', 'ai_training', 'ai_research', 'ai_content', 'ai_seo', 'ai_marketing', 'ai_conversational', 'ai_service']
        
        ai_bots = {}
        total_ai_requests = 0
        
        for bot_type, requests in self.bot_requests.items():
            if bot_type in self.bot_signatures and self.bot_signatures[bot_type]['type'] in ai_bot_types:
                ai_category = self.bot_signatures[bot_type]['type']
                if ai_category not in ai_bots:
                    ai_bots[ai_category] = {
                        'bots': {},
                        'total_requests': 0,
                        'unique_ips': set(),
                        'avg_response_time': [],
                        'bandwidth_mb': 0
                    }
                
                ai_bots[ai_category]['bots'][bot_type] = {
                    'requests': len(requests),
                    'description': self.bot_signatures[bot_type]['description'],
                    'legitimate': self.bot_signatures[bot_type]['legitimate']
                }
                ai_bots[ai_category]['total_requests'] += len(requests)
                ai_bots[ai_category]['unique_ips'].update(req['ip'] for req in requests)
                ai_bots[ai_category]['avg_response_time'].extend(self.bot_response_times.get(bot_type, []))
                ai_bots[ai_category]['bandwidth_mb'] += self.bot_bandwidth.get(bot_type, 0) / (1024 * 1024)
                
                total_ai_requests += len(requests)
        
        # Calculate averages and convert sets to counts
        for category in ai_bots:
            ai_bots[category]['unique_ips'] = len(ai_bots[category]['unique_ips'])
            if ai_bots[category]['avg_response_time']:
                ai_bots[category]['avg_response_time'] = statistics.mean(ai_bots[category]['avg_response_time'])
            else:
                ai_bots[category]['avg_response_time'] = 0
        
        return {
            'total_ai_requests': total_ai_requests,
            'ai_categories': ai_bots,
            'ai_percentage': (total_ai_requests / max(sum(len(reqs) for reqs in self.bot_requests.values()), 1)) * 100
        }
    
    def get_ai_training_indicators(self) -> Dict[str, Any]:
        """Detect potential AI training data collection patterns."""
        training_indicators = {
            'high_volume_crawlers': [],
            'suspicious_paths': [],
            'rapid_site_traversal': [],
            'content_focused_bots': []
        }
        
        # Detect high-volume crawlers (potential training data collection)
        for bot_type, requests in self.bot_requests.items():
            if len(requests) > 1000:  # High volume threshold
                intervals = self.bot_intervals.get(bot_type, [])
                if intervals:
                    avg_interval = statistics.mean(intervals)
                    if avg_interval < 1:  # Very frequent requests
                        training_indicators['high_volume_crawlers'].append({
                            'bot': bot_type,
                            'requests': len(requests),
                            'avg_interval': avg_interval,
                            'description': self.bot_signatures.get(bot_type, {}).get('description', 'Unknown')
                        })
        
        # Detect content-focused paths (text, articles, etc.)
        content_paths = ['/blog', '/article', '/post', '/news', '/content', '/page']
        for bot_type, path_counter in self.bot_paths.items():
            content_requests = sum(count for path, count in path_counter.items() 
                                 if any(cp in path.lower() for cp in content_paths))
            total_requests = sum(path_counter.values())
            
            if total_requests > 50 and content_requests / total_requests > 0.7:
                training_indicators['content_focused_bots'].append({
                    'bot': bot_type,
                    'content_percentage': (content_requests / total_requests) * 100,
                    'total_requests': total_requests
                })
        
        return training_indicators
    
    def get_ai_bot_recommendations(self) -> List[Dict[str, Any]]:
        """Generate AI bot-specific recommendations."""
        recommendations = []
        ai_analysis = self.get_ai_bot_analysis()
        training_indicators = self.get_ai_training_indicators()
        
        # High AI traffic recommendation
        if ai_analysis['ai_percentage'] > 30:
            recommendations.append({
                'category': 'AI Bot Management',
                'priority': 'Medium',
                'issue': f"High AI bot traffic: {ai_analysis['ai_percentage']:.1f}% of total bot requests",
                'recommendation': 'Consider implementing AI bot-specific rate limiting and monitoring',
                'details': f"Total AI requests: {ai_analysis['total_ai_requests']:,}"
            })
        
        # Training data collection detection
        if training_indicators['high_volume_crawlers']:
            recommendations.append({
                'category': 'AI Training Data',
                'priority': 'High',
                'issue': f"Detected {len(training_indicators['high_volume_crawlers'])} high-volume crawlers",
                'recommendation': 'Review robots.txt and consider blocking aggressive AI training crawlers',
                'bots': [bot['bot'] for bot in training_indicators['high_volume_crawlers'][:3]]
            })
        
        # Content-focused AI bots
        if training_indicators['content_focused_bots']:
            recommendations.append({
                'category': 'Content Protection',
                'priority': 'Medium',
                'issue': f"AI bots heavily accessing content: {len(training_indicators['content_focused_bots'])} bots",
                'recommendation': 'Consider implementing content protection measures for AI training',
                'bots': [bot['bot'] for bot in training_indicators['content_focused_bots'][:3]]
            })
        
        # LLM bot analysis
        llm_requests = ai_analysis['ai_categories'].get('ai_llm', {}).get('total_requests', 0)
        if llm_requests > 100:
            recommendations.append({
                'category': 'LLM Integration',
                'priority': 'Low',
                'issue': f"Significant LLM bot activity: {llm_requests:,} requests",
                'recommendation': 'Monitor for potential API abuse or unauthorized LLM integrations',
                'details': 'Consider implementing API authentication for LLM services'
            })
        
        return recommendations

    def export_bot_report(self, output_file: str):
        """Export detailed bot analysis report to JSON."""
        import json
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_bot_types': len(self.bot_requests),
                'total_bot_requests': sum(len(reqs) for reqs in self.bot_requests.values()),
                'unknown_bots': len(self.unknown_bots),
                'resource_impact': self.get_resource_impact()
            },
            'bot_classification': self.get_bot_classification(),
            'behavior_patterns': self.get_behavior_patterns(),
            'legitimacy_scores': self.legitimacy_scores,
            'ai_bot_analysis': self.get_ai_bot_analysis(),
            'ai_training_indicators': self.get_ai_training_indicators(),
            'bot_details': {
                bot_type: {
                    'request_count': len(requests),
                    'unique_ips': len(set(req['ip'] for req in requests)),
                    'top_paths': [path for path, count in self.bot_paths[bot_type].most_common(10)],
                    'avg_response_time': statistics.mean(self.bot_response_times[bot_type]) if self.bot_response_times[bot_type] else 0,
                    'error_count': self.bot_errors.get(bot_type, 0),
                    'bandwidth_mb': self.bot_bandwidth[bot_type] / (1024 * 1024),
                    'legitimacy_score': self.legitimacy_scores.get(bot_type, 0.5)
                }
                for bot_type, requests in self.bot_requests.items()
            },
            'unknown_user_agents': dict(self.unknown_bots.most_common(50)),
            'recommendations': self.get_bot_recommendations() + self.get_ai_bot_recommendations()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
