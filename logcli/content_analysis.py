"""Content type and resource analysis module."""

import json
import re
import mimetypes
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Tuple, Optional
from urllib.parse import urlparse
import statistics
from rich.console import Console

console = Console()


class ContentAnalyzer:
    """Analyzes content types, file extensions, and resource distribution."""
    
    def __init__(self):
        """Initialize content analyzer."""
        # Content type tracking
        self.content_types = defaultdict(lambda: {
            'total_requests': 0,
            'unique_ips': set(),
            'total_bandwidth': 0,
            'response_times': [],
            'status_codes': Counter(),
            'countries': Counter(),
            'user_agents': Counter(),
            'referers': Counter(),
            'cache_hits': 0,
            'cache_misses': 0,
            'error_count': 0
        })
        
        # File extension analysis
        self.file_extensions = defaultdict(lambda: {
            'total_requests': 0,
            'total_bandwidth': 0,
            'avg_file_size': 0,
            'file_sizes': [],
            'response_times': [],
            'error_count': 0,
            'popular_files': Counter(),
            'countries': Counter()
        })
        
        # Resource category analysis
        self.resource_categories = defaultdict(lambda: {
            'total_requests': 0,
            'total_bandwidth': 0,
            'avg_response_time': 0,
            'response_times': [],
            'error_rate': 0,
            'cache_effectiveness': 0,
            'files': Counter(),
            'countries': Counter()
        })
        
        # Performance by content type
        self.performance_metrics = {
            'slowest_content_types': Counter(),
            'largest_content_types': Counter(),
            'most_cached': Counter(),
            'highest_error_rate': Counter()
        }
        
        # SEO and optimization analysis
        self.seo_analysis = {
            'missing_images': Counter(),
            'large_images': Counter(),
            'unoptimized_resources': Counter(),
            'broken_links': Counter(),
            'redirect_chains': Counter()
        }
        
        # Initialize content type mappings
        self._init_content_mappings()
    
    def _init_content_mappings(self):
        """Initialize content type and extension mappings."""
        # File extension to content type mapping
        self.extension_to_content_type = {
            # Images
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg', 
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon',
            '.bmp': 'image/bmp',
            '.tiff': 'image/tiff',
            
            # Stylesheets
            '.css': 'text/css',
            '.scss': 'text/scss',
            '.sass': 'text/sass',
            '.less': 'text/less',
            
            # JavaScript
            '.js': 'application/javascript',
            '.jsx': 'application/javascript',
            '.ts': 'application/typescript',
            '.tsx': 'application/typescript',
            '.json': 'application/json',
            
            # Documents
            '.html': 'text/html',
            '.htm': 'text/html',
            '.xml': 'application/xml',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.txt': 'text/plain',
            
            # Media
            '.mp4': 'video/mp4',
            '.avi': 'video/avi',
            '.mov': 'video/quicktime',
            '.wmv': 'video/x-ms-wmv',
            '.mp3': 'audio/mpeg',
            '.wav': 'audio/wav',
            '.ogg': 'audio/ogg',
            
            # Archives
            '.zip': 'application/zip',
            '.rar': 'application/rar',
            '.tar': 'application/tar',
            '.gz': 'application/gzip',
            '.7z': 'application/x-7z-compressed',
            
            # Fonts
            '.woff': 'font/woff',
            '.woff2': 'font/woff2',
            '.ttf': 'font/ttf',
            '.eot': 'application/vnd.ms-fontobject',
            '.otf': 'font/otf'
        }
        
        # Content type to resource category mapping
        self.content_to_category = {
            'text/html': 'HTML Pages',
            'text/css': 'Stylesheets',
            'application/javascript': 'JavaScript',
            'application/json': 'API/JSON',
            'image/jpeg': 'Images',
            'image/png': 'Images',
            'image/gif': 'Images',
            'image/webp': 'Images',
            'image/svg+xml': 'Images',
            'video/mp4': 'Videos',
            'audio/mpeg': 'Audio',
            'application/pdf': 'Documents',
            'font/woff': 'Fonts',
            'font/woff2': 'Fonts',
            'application/zip': 'Archives'
        }
        
        # Resource optimization thresholds
        self.optimization_thresholds = {
            'large_image_size': 1024 * 1024,  # 1MB
            'large_js_size': 512 * 1024,      # 512KB
            'large_css_size': 256 * 1024,     # 256KB
            'slow_response_time': 3.0          # 3 seconds
        }
    
    def analyze_entry(self, log_entry: Dict[str, Any]) -> None:
        """Analyze a single log entry for content patterns."""
        path = log_entry.get('path', '')
        if not path:
            return
        
        # Extract file extension and determine content type
        file_extension = self._get_file_extension(path)
        content_type = self._determine_content_type(path, file_extension)
        resource_category = self._get_resource_category(content_type)
        
        # Analyze content type
        self._analyze_content_type(log_entry, content_type)
        
        # Analyze file extension
        if file_extension:
            self._analyze_file_extension(log_entry, file_extension, path)
        
        # Analyze resource category
        self._analyze_resource_category(log_entry, resource_category, path)
        
        # Performance analysis
        self._analyze_performance(log_entry, content_type, file_extension)
        
        # SEO and optimization analysis
        self._analyze_optimization(log_entry, path, content_type, file_extension)
    
    def _get_file_extension(self, path: str) -> str:
        """Extract file extension from path."""
        # Remove query parameters
        if '?' in path:
            path = path.split('?')[0]
        
        # Extract extension
        if '.' in path:
            extension = '.' + path.split('.')[-1].lower()
            # Handle double extensions like .tar.gz
            if extension in ['.gz', '.bz2'] and '.' in path[:-len(extension)]:
                prev_ext = '.' + path[:-len(extension)].split('.')[-1].lower()
                if prev_ext in ['.tar']:
                    extension = prev_ext + extension
            return extension
        return ''
    
    def _determine_content_type(self, path: str, file_extension: str) -> str:
        """Determine content type from path and extension."""
        # Check extension mapping first
        if file_extension in self.extension_to_content_type:
            return self.extension_to_content_type[file_extension]
        
        # Use mimetypes library as fallback
        content_type, _ = mimetypes.guess_type(path)
        if content_type:
            return content_type
        
        # Fallback based on path patterns
        path_lower = path.lower()
        if '/api/' in path_lower or path_lower.endswith('.json'):
            return 'application/json'
        elif any(pattern in path_lower for pattern in ['/css/', '/styles/']):
            return 'text/css'
        elif any(pattern in path_lower for pattern in ['/js/', '/javascript/', '/scripts/']):
            return 'application/javascript'
        elif any(pattern in path_lower for pattern in ['/images/', '/img/', '/media/']):
            return 'image/unknown'
        elif path_lower.endswith('/') or 'html' in path_lower:
            return 'text/html'
        
        return 'application/octet-stream'  # Default binary
    
    def _get_resource_category(self, content_type: str) -> str:
        """Get resource category from content type."""
        if content_type in self.content_to_category:
            return self.content_to_category[content_type]
        
        # Fallback categorization
        if content_type.startswith('image/'):
            return 'Images'
        elif content_type.startswith('video/'):
            return 'Videos'
        elif content_type.startswith('audio/'):
            return 'Audio'
        elif content_type.startswith('text/'):
            return 'Text Files'
        elif content_type.startswith('application/'):
            if 'json' in content_type:
                return 'API/JSON'
            elif 'javascript' in content_type:
                return 'JavaScript'
            else:
                return 'Applications'
        elif content_type.startswith('font/'):
            return 'Fonts'
        else:
            return 'Other'
    
    def _analyze_content_type(self, log_entry: Dict[str, Any], content_type: str) -> None:
        """Analyze content type metrics."""
        data = self.content_types[content_type]
        
        # Basic metrics
        data['total_requests'] += 1
        
        # IP tracking
        ip = log_entry.get('remote_addr', '')
        if ip:
            data['unique_ips'].add(ip)
        
        # Bandwidth tracking
        bytes_sent = log_entry.get('body_bytes_sent', 0)
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = int(bytes_sent)
            except:
                bytes_sent = 0
        data['total_bandwidth'] += bytes_sent
        
        # Response time tracking
        response_time = log_entry.get('request_time', 0)
        if isinstance(response_time, str):
            try:
                response_time = float(response_time)
            except:
                response_time = 0
        
        if response_time > 0:
            data['response_times'].append(response_time)
        
        # Status code analysis
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        data['status_codes'][status] += 1
        if status >= 400:
            data['error_count'] += 1
        
        # Geographic analysis
        country = log_entry.get('country', '')
        if country and country != '-':
            data['countries'][country] += 1
        
        # User agent analysis
        user_agent = log_entry.get('user_agent', '')
        if user_agent:
            data['user_agents'][user_agent] += 1
        
        # Referer analysis
        referer = log_entry.get('referer', '')
        if referer and referer != '-':
            data['referers'][referer] += 1
        
        # Cache analysis (basic heuristic)
        if status == 304:  # Not Modified
            data['cache_hits'] += 1
        elif status == 200:
            data['cache_misses'] += 1
    
    def _analyze_file_extension(self, log_entry: Dict[str, Any], file_extension: str, path: str) -> None:
        """Analyze file extension metrics."""
        data = self.file_extensions[file_extension]
        
        # Basic metrics
        data['total_requests'] += 1
        
        # File size tracking
        bytes_sent = log_entry.get('body_bytes_sent', 0)
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = int(bytes_sent)
            except:
                bytes_sent = 0
        
        if bytes_sent > 0:
            data['total_bandwidth'] += bytes_sent
            data['file_sizes'].append(bytes_sent)
            data['avg_file_size'] = sum(data['file_sizes']) / len(data['file_sizes'])
        
        # Response time tracking
        response_time = log_entry.get('request_time', 0)
        if isinstance(response_time, str):
            try:
                response_time = float(response_time)
            except:
                response_time = 0
        
        if response_time > 0:
            data['response_times'].append(response_time)
        
        # Error tracking
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        if status >= 400:
            data['error_count'] += 1
        
        # Popular files tracking
        filename = path.split('/')[-1] if '/' in path else path
        data['popular_files'][filename] += 1
        
        # Geographic analysis
        country = log_entry.get('country', '')
        if country and country != '-':
            data['countries'][country] += 1
    
    def _analyze_resource_category(self, log_entry: Dict[str, Any], category: str, path: str) -> None:
        """Analyze resource category metrics."""
        data = self.resource_categories[category]
        
        # Basic metrics
        data['total_requests'] += 1
        
        # Bandwidth tracking
        bytes_sent = log_entry.get('body_bytes_sent', 0)
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = int(bytes_sent)
            except:
                bytes_sent = 0
        data['total_bandwidth'] += bytes_sent
        
        # Response time tracking
        response_time = log_entry.get('request_time', 0)
        if isinstance(response_time, str):
            try:
                response_time = float(response_time)
            except:
                response_time = 0
        
        if response_time > 0:
            data['response_times'].append(response_time)
            data['avg_response_time'] = sum(data['response_times']) / len(data['response_times'])
        
        # Error rate calculation
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        if status >= 400:
            data['error_rate'] = ((data['error_rate'] * (data['total_requests'] - 1)) + 1) / data['total_requests']
        else:
            data['error_rate'] = (data['error_rate'] * (data['total_requests'] - 1)) / data['total_requests']
        
        # File tracking
        filename = path.split('/')[-1] if '/' in path else path
        data['files'][filename] += 1
        
        # Geographic analysis
        country = log_entry.get('country', '')
        if country and country != '-':
            data['countries'][country] += 1
    
    def _analyze_performance(self, log_entry: Dict[str, Any], content_type: str, file_extension: str) -> None:
        """Analyze performance metrics by content type."""
        response_time = log_entry.get('request_time', 0)
        bytes_sent = log_entry.get('body_bytes_sent', 0)
        
        if isinstance(response_time, str):
            try:
                response_time = float(response_time)
            except:
                response_time = 0
        
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = int(bytes_sent)
            except:
                bytes_sent = 0
        
        # Track slow content types
        if response_time > self.optimization_thresholds['slow_response_time']:
            self.performance_metrics['slowest_content_types'][content_type] += 1
        
        # Track large content types
        if bytes_sent > self.optimization_thresholds['large_image_size']:
            self.performance_metrics['largest_content_types'][content_type] += 1
        
        # Track cache effectiveness
        status = log_entry.get('status', 200)
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        if status == 304:  # Cached response
            self.performance_metrics['most_cached'][content_type] += 1
        
        # Track error rates
        if status >= 400:
            self.performance_metrics['highest_error_rate'][content_type] += 1
    
    def _analyze_optimization(self, log_entry: Dict[str, Any], path: str, content_type: str, file_extension: str) -> None:
        """Analyze optimization opportunities."""
        bytes_sent = log_entry.get('body_bytes_sent', 0)
        status = log_entry.get('status', 200)
        
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = int(bytes_sent)
            except:
                bytes_sent = 0
        
        if isinstance(status, str):
            try:
                status = int(status)
            except:
                status = 200
        
        # Large image detection
        if content_type.startswith('image/') and bytes_sent > self.optimization_thresholds['large_image_size']:
            self.seo_analysis['large_images'][path] += 1
        
        # Large JavaScript/CSS detection
        if (content_type == 'application/javascript' and 
            bytes_sent > self.optimization_thresholds['large_js_size']):
            self.seo_analysis['unoptimized_resources'][path] += 1
        elif (content_type == 'text/css' and 
              bytes_sent > self.optimization_thresholds['large_css_size']):
            self.seo_analysis['unoptimized_resources'][path] += 1
        
        # Missing/broken resources
        if status == 404:
            if content_type.startswith('image/'):
                self.seo_analysis['missing_images'][path] += 1
            else:
                self.seo_analysis['broken_links'][path] += 1
        
        # Redirect chains
        if status in [301, 302, 307, 308]:
            self.seo_analysis['redirect_chains'][path] += 1
    
    def get_content_summary(self) -> Dict[str, Any]:
        """Get comprehensive content analysis summary."""
        total_requests = sum(data['total_requests'] for data in self.content_types.values())
        total_bandwidth = sum(data['total_bandwidth'] for data in self.content_types.values())
        
        # Content type distribution
        content_distribution = {}
        for content_type, data in self.content_types.items():
            if data['total_requests'] > 0:
                avg_response_time = sum(data['response_times']) / len(data['response_times']) if data['response_times'] else 0
                error_rate = (data['error_count'] / data['total_requests']) * 100
                cache_hit_rate = (data['cache_hits'] / (data['cache_hits'] + data['cache_misses'])) * 100 if (data['cache_hits'] + data['cache_misses']) > 0 else 0
                
                content_distribution[content_type] = {
                    'requests': data['total_requests'],
                    'percentage': (data['total_requests'] / total_requests) * 100,
                    'bandwidth_mb': data['total_bandwidth'] / (1024 * 1024),
                    'avg_response_time': avg_response_time,
                    'error_rate': error_rate,
                    'cache_hit_rate': cache_hit_rate,
                    'unique_ips': len(data['unique_ips'])
                }
        
        # Resource category analysis
        category_analysis = {}
        for category, data in self.resource_categories.items():
            if data['total_requests'] > 0:
                category_analysis[category] = {
                    'requests': data['total_requests'],
                    'bandwidth_mb': data['total_bandwidth'] / (1024 * 1024),
                    'avg_response_time': data['avg_response_time'],
                    'error_rate': data['error_rate'] * 100,
                    'top_files': dict(data['files'].most_common(5))
                }
        
        # File extension analysis
        extension_analysis = {}
        for extension, data in self.file_extensions.items():
            if data['total_requests'] > 0:
                avg_response_time = sum(data['response_times']) / len(data['response_times']) if data['response_times'] else 0
                extension_analysis[extension] = {
                    'requests': data['total_requests'],
                    'bandwidth_mb': data['total_bandwidth'] / (1024 * 1024),
                    'avg_file_size_kb': data['avg_file_size'] / 1024,
                    'avg_response_time': avg_response_time,
                    'error_count': data['error_count']
                }
        
        return {
            'total_requests': total_requests,
            'total_bandwidth_mb': total_bandwidth / (1024 * 1024),
            'content_distribution': dict(sorted(content_distribution.items(), 
                                               key=lambda x: x[1]['requests'], reverse=True)),
            'category_analysis': dict(sorted(category_analysis.items(), 
                                           key=lambda x: x[1]['requests'], reverse=True)),
            'extension_analysis': dict(sorted(extension_analysis.items(), 
                                            key=lambda x: x[1]['requests'], reverse=True)),
            'performance_issues': self._get_performance_issues(),
            'optimization_opportunities': self._get_optimization_opportunities()
        }
    
    def _get_performance_issues(self) -> Dict[str, Any]:
        """Get performance issues summary."""
        return {
            'slowest_content_types': dict(self.performance_metrics['slowest_content_types'].most_common(5)),
            'largest_content_types': dict(self.performance_metrics['largest_content_types'].most_common(5)),
            'highest_error_rate': dict(self.performance_metrics['highest_error_rate'].most_common(5))
        }
    
    def _get_optimization_opportunities(self) -> Dict[str, Any]:
        """Get optimization opportunities summary."""
        return {
            'large_images': len(self.seo_analysis['large_images']),
            'unoptimized_resources': len(self.seo_analysis['unoptimized_resources']),
            'missing_images': len(self.seo_analysis['missing_images']),
            'broken_links': len(self.seo_analysis['broken_links']),
            'redirect_chains': len(self.seo_analysis['redirect_chains']),
            'top_large_images': dict(self.seo_analysis['large_images'].most_common(5)),
            'top_unoptimized': dict(self.seo_analysis['unoptimized_resources'].most_common(5))
        }
    
    def get_content_recommendations(self) -> List[Dict[str, Any]]:
        """Generate content optimization recommendations."""
        recommendations = []
        
        # Large images recommendation
        if len(self.seo_analysis['large_images']) > 10:
            recommendations.append({
                'priority': 'High',
                'category': 'Image Optimization',
                'issue': f'{len(self.seo_analysis["large_images"])} large images detected',
                'recommendation': 'Optimize images using compression and modern formats (WebP, AVIF)',
                'impact': 'High - Reduces bandwidth usage and improves page load times',
                'files': list(self.seo_analysis['large_images'].keys())[:5]
            })
        
        # Unoptimized resources recommendation
        if len(self.seo_analysis['unoptimized_resources']) > 5:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Resource Optimization',
                'issue': f'{len(self.seo_analysis["unoptimized_resources"])} large JS/CSS files detected',
                'recommendation': 'Minify and compress JavaScript and CSS files',
                'impact': 'Medium - Improves page load performance',
                'files': list(self.seo_analysis['unoptimized_resources'].keys())[:5]
            })
        
        # Missing resources recommendation
        if len(self.seo_analysis['missing_images']) + len(self.seo_analysis['broken_links']) > 20:
            total_missing = len(self.seo_analysis['missing_images']) + len(self.seo_analysis['broken_links'])
            recommendations.append({
                'priority': 'Medium',
                'category': 'Broken Resources',
                'issue': f'{total_missing} missing or broken resources detected',
                'recommendation': 'Fix broken links and missing resources to improve user experience',
                'impact': 'Medium - Reduces 404 errors and improves SEO'
            })
        
        # Cache optimization recommendation
        content_summary = self.get_content_summary()
        low_cache_types = [
            ct for ct, data in content_summary['content_distribution'].items()
            if data['cache_hit_rate'] < 50 and data['requests'] > 100
        ]
        
        if low_cache_types:
            recommendations.append({
                'priority': 'High',
                'category': 'Caching Optimization',
                'issue': f'{len(low_cache_types)} content types have low cache hit rates',
                'recommendation': 'Implement proper caching headers for static resources',
                'impact': 'High - Reduces server load and improves performance',
                'content_types': low_cache_types[:3]
            })
        
        return recommendations
    
    def export_content_report(self, output_file: str) -> None:
        """Export comprehensive content analysis report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_content_summary(),
            'detailed_analysis': {
                'content_types': {
                    ct: {
                        'total_requests': data['total_requests'],
                        'total_bandwidth': data['total_bandwidth'],
                        'avg_response_time': sum(data['response_times']) / len(data['response_times']) if data['response_times'] else 0,
                        'error_rate': (data['error_count'] / data['total_requests']) * 100,
                        'top_countries': dict(data['countries'].most_common(5)),
                        'cache_hit_rate': (data['cache_hits'] / (data['cache_hits'] + data['cache_misses'])) * 100 if (data['cache_hits'] + data['cache_misses']) > 0 else 0
                    }
                    for ct, data in self.content_types.items()
                    if data['total_requests'] > 0
                },
                'file_extensions': {
                    ext: {
                        'total_requests': data['total_requests'],
                        'total_bandwidth': data['total_bandwidth'],
                        'avg_file_size': data['avg_file_size'],
                        'avg_response_time': sum(data['response_times']) / len(data['response_times']) if data['response_times'] else 0,
                        'popular_files': dict(data['popular_files'].most_common(10))
                    }
                    for ext, data in self.file_extensions.items()
                    if data['total_requests'] > 0
                }
            },
            'optimization_analysis': self._get_optimization_opportunities(),
            'recommendations': self.get_content_recommendations()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
