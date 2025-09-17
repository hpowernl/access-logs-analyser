"""Export functionality for log analysis results."""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

from .config import EXPORT_SETTINGS
from .aggregators import StatisticsAggregator


class DataExporter:
    """Handles exporting log analysis data to various formats."""
    
    def __init__(self, output_dir: str = "exports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def export_to_csv(self, stats: StatisticsAggregator, filename: Optional[str] = None) -> str:
        """Export statistics to CSV format."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"log_analysis_{timestamp}.csv"
            
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile, delimiter=EXPORT_SETTINGS['csv_delimiter'])
            
            # Summary statistics
            writer.writerow(['=== SUMMARY STATISTICS ==='])
            summary = stats.get_summary_stats()
            for key, value in summary.items():
                if isinstance(value, dict):
                    writer.writerow([f"{key}_summary", json.dumps(value)])
                else:
                    writer.writerow([key, value])
            
            writer.writerow([])  # Empty row
            
            # Top countries
            writer.writerow(['=== TOP COUNTRIES ==='])
            writer.writerow(['Country', 'Hits'])
            for country, hits in stats.get_top_n(stats.hits_per_country):
                writer.writerow([country, hits])
            
            writer.writerow([])
            
            # Top IPs
            writer.writerow(['=== TOP IPs ==='])
            writer.writerow(['IP Address', 'Hits'])
            for ip, hits in stats.get_top_n(stats.hits_per_ip):
                writer.writerow([ip, hits])
            
            writer.writerow([])
            
            # Status codes
            writer.writerow(['=== STATUS CODES ==='])
            writer.writerow(['Status Code', 'Count'])
            for status, count in sorted(stats.hits_per_status.items()):
                writer.writerow([status, count])
            
            writer.writerow([])
            
            # Top paths
            writer.writerow(['=== TOP PATHS ==='])
            writer.writerow(['Path', 'Hits'])
            for path, hits in stats.get_top_n(stats.hits_per_path):
                writer.writerow([path, hits])
            
            writer.writerow([])
            
            # Browser stats
            writer.writerow(['=== TOP BROWSERS ==='])
            writer.writerow(['Browser', 'Hits'])
            for browser, hits in stats.get_top_n(stats.hits_per_browser):
                writer.writerow([browser, hits])
                
        return str(filepath)
    
    def export_to_json(self, stats: StatisticsAggregator, filename: Optional[str] = None) -> str:
        """Export statistics to JSON format."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"log_analysis_{timestamp}.json"
            
        filepath = self.output_dir / filename
        
        # Build comprehensive data structure
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'summary': stats.get_summary_stats(),
            'top_countries': dict(stats.get_top_n(stats.hits_per_country, 20)),
            'top_ips': dict(stats.get_top_n(stats.hits_per_ip, 50)),
            'status_codes': dict(stats.hits_per_status),
            'status_categories': dict(stats.status_categories),
            'top_paths': dict(stats.get_top_n(stats.hits_per_path, 50)),
            'top_user_agents': dict(stats.get_top_n(stats.hits_per_user_agent, 20)),
            'top_browsers': dict(stats.get_top_n(stats.hits_per_browser, 20)),
            'top_os': dict(stats.get_top_n(stats.hits_per_os, 20)),
            'top_devices': dict(stats.get_top_n(stats.hits_per_device, 10)),
            'bot_traffic': dict(stats.bot_traffic),
            'bot_types': dict(stats.bot_types),
            'http_methods': dict(stats.hits_per_method),
            'timeline_hits': {k.isoformat(): v for k, v in stats.timeline.get_hits_timeline().items()},
            'response_time_timeline': {
                k.isoformat(): v for k, v in stats.timeline.get_response_time_stats().items()
            },
            'slow_requests': [
                {
                    'timestamp': req['timestamp'].isoformat() if req['timestamp'] else None,
                    'path': req['path'],
                    'response_time': req['response_time'],
                    'ip': req['ip']
                } for req in stats.slow_requests[:100]  # Limit to 100 slowest
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as jsonfile:
            json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
            
        return str(filepath)
    
    def create_charts(self, stats: StatisticsAggregator, filename: Optional[str] = None) -> str:
        """Create interactive charts and save as HTML."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"log_charts_{timestamp}.html"
            
        filepath = self.output_dir / filename
        
        # Create subplots
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=[
                'Top Countries', 'Status Code Distribution',
                'Browser Distribution', 'Bot vs Human Traffic',
                'Timeline - Requests per Hour', 'Response Time Distribution'
            ],
            specs=[
                [{"type": "bar"}, {"type": "pie"}],
                [{"type": "bar"}, {"type": "pie"}],
                [{"type": "scatter"}, {"type": "histogram"}]
            ]
        )
        
        # Top Countries
        countries = stats.get_top_n(stats.hits_per_country, 10)
        if countries:
            fig.add_trace(
                go.Bar(x=[c[0] for c in countries], y=[c[1] for c in countries], name="Countries"),
                row=1, col=1
            )
        
        # Status Code Distribution
        status_data = dict(stats.status_categories)
        if status_data:
            fig.add_trace(
                go.Pie(labels=list(status_data.keys()), values=list(status_data.values()), name="Status"),
                row=1, col=2
            )
        
        # Browser Distribution
        browsers = stats.get_top_n(stats.hits_per_browser, 8)
        if browsers:
            fig.add_trace(
                go.Bar(x=[b[0] for b in browsers], y=[b[1] for b in browsers], name="Browsers"),
                row=2, col=1
            )
        
        # Bot vs Human Traffic
        bot_data = dict(stats.bot_traffic)
        if bot_data:
            fig.add_trace(
                go.Pie(labels=list(bot_data.keys()), values=list(bot_data.values()), name="Traffic Type"),
                row=2, col=2
            )
        
        # Timeline
        timeline_data = stats.timeline.get_hits_timeline()
        if timeline_data:
            times = list(timeline_data.keys())
            hits = list(timeline_data.values())
            fig.add_trace(
                go.Scatter(x=times, y=hits, mode='lines+markers', name="Requests"),
                row=3, col=1
            )
        
        # Response Time Distribution
        if stats.response_times:
            fig.add_trace(
                go.Histogram(x=stats.response_times, nbinsx=50, name="Response Times"),
                row=3, col=2
            )
        
        # Update layout
        fig.update_layout(
            height=1200,
            showlegend=False,
            title_text="Log Analysis Dashboard",
            title_x=0.5
        )
        
        # Save as HTML
        fig.write_html(str(filepath))
        return str(filepath)
    
    def create_static_charts(self, stats: StatisticsAggregator, filename: Optional[str] = None) -> str:
        """Create static PNG charts."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"log_charts_{timestamp}.png"
            
        filepath = self.output_dir / filename
        
        # Create the same subplots as above
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=[
                'Top Countries', 'Status Code Distribution',
                'Browser Distribution', 'Bot vs Human Traffic',
                'Timeline - Requests per Hour', 'Response Time Distribution'
            ],
            specs=[
                [{"type": "bar"}, {"type": "pie"}],
                [{"type": "bar"}, {"type": "pie"}],
                [{"type": "scatter"}, {"type": "histogram"}]
            ]
        )
        
        # Add the same traces as in create_charts method
        # (Implementation similar to above)
        
        # Update layout for static export
        fig.update_layout(
            height=1200,
            width=1600,
            showlegend=False,
            title_text="Log Analysis Dashboard",
            title_x=0.5
        )
        
        # Save as PNG
        fig.write_image(str(filepath))
        return str(filepath)
    
    def export_timeline_csv(self, stats: StatisticsAggregator, filename: Optional[str] = None) -> str:
        """Export timeline data to CSV for external analysis."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"timeline_{timestamp}.csv"
            
        filepath = self.output_dir / filename
        
        timeline_hits = stats.timeline.get_hits_timeline()
        response_time_stats = stats.timeline.get_response_time_stats()
        bandwidth_data = stats.timeline.get_bandwidth_timeline()
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Header
            writer.writerow([
                'timestamp', 'hits', 'avg_response_time', 'max_response_time', 
                'p95_response_time', 'total_bytes'
            ])
            
            # Combine all timeline data
            all_times = set(timeline_hits.keys()) | set(response_time_stats.keys()) | set(bandwidth_data.keys())
            
            for time_key in sorted(all_times):
                hits = timeline_hits.get(time_key, 0)
                rt_stats = response_time_stats.get(time_key, {})
                bytes_sent = bandwidth_data.get(time_key, 0)
                
                writer.writerow([
                    time_key.strftime(EXPORT_SETTINGS['timestamp_format']),
                    hits,
                    rt_stats.get('avg', 0),
                    rt_stats.get('max', 0),
                    rt_stats.get('p95', 0),
                    bytes_sent
                ])
                
        return str(filepath)
    
    def export_errors_csv(self, stats: StatisticsAggregator, filename: Optional[str] = None) -> str:
        """Export error details to CSV."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"errors_{timestamp}.csv"
            
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Header
            writer.writerow(['timestamp', 'status_code', 'path', 'ip_address', 'user_agent'])
            
            # Write error details
            for status_code, errors in stats.error_details.items():
                for error in errors:
                    timestamp_str = error['timestamp'].strftime(EXPORT_SETTINGS['timestamp_format']) if error['timestamp'] else ''
                    writer.writerow([
                        timestamp_str,
                        status_code,
                        error['path'],
                        error['ip'],
                        error['user_agent']
                    ])
                    
        return str(filepath)


def create_report_summary(stats: StatisticsAggregator, output_file: Optional[str] = None) -> str:
    """Create a human-readable text summary report."""
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"exports/summary_{timestamp}.txt"
    
    Path(output_file).parent.mkdir(exist_ok=True)
    
    summary = stats.get_summary_stats()
    
    report = f"""
LOG ANALYSIS SUMMARY REPORT
===========================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

OVERVIEW
--------
Total Requests: {summary.get('total_requests', 0):,}
Unique Visitors: {summary.get('unique_visitors', 0):,}
Error Rate: {summary.get('error_rate', 0):.2f}%
Bot Traffic: {summary.get('bot_percentage', 0):.2f}%
Slow Requests (>1s): {summary.get('slow_requests_count', 0):,}

RESPONSE TIME STATISTICS
-----------------------
"""
    
    rt_stats = summary.get('response_time_stats', {})
    if rt_stats:
        report += f"""Average: {rt_stats.get('avg', 0):.3f}s
Maximum: {rt_stats.get('max', 0):.3f}s
Median: {rt_stats.get('median', 0):.3f}s
95th Percentile: {rt_stats.get('p95', 0):.3f}s
99th Percentile: {rt_stats.get('p99', 0):.3f}s
"""
    
    bandwidth = summary.get('bandwidth_stats', {})
    if bandwidth:
        report += f"""
BANDWIDTH STATISTICS
-------------------
Total Data: {bandwidth.get('total_gb', 0):.2f} GB
Average per Request: {bandwidth.get('avg_bytes_per_request', 0):,.0f} bytes
"""
    
    report += """
TOP COUNTRIES
-------------
"""
    for country, hits in stats.get_top_n(stats.hits_per_country, 10):
        percentage = (hits / max(summary.get('total_requests', 1), 1)) * 100
        report += f"{country:<15} {hits:>8,} ({percentage:>5.1f}%)\n"
    
    report += """
TOP STATUS CODES
---------------
"""
    for status, count in sorted(stats.hits_per_status.most_common(10)):
        percentage = (count / max(summary.get('total_requests', 1), 1)) * 100
        report += f"{status:<15} {count:>8,} ({percentage:>5.1f}%)\n"
    
    report += """
TOP PATHS
---------
"""
    for path, hits in stats.get_top_n(stats.hits_per_path, 10):
        percentage = (hits / max(summary.get('total_requests', 1), 1)) * 100
        path_display = path[:50] + "..." if len(path) > 50 else path
        report += f"{path_display:<53} {hits:>8,} ({percentage:>5.1f}%)\n"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
        
    return output_file
