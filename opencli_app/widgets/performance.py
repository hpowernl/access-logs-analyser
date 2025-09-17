"""
Performance widget - simple display of performance metrics
"""

from textual.widgets import Static
from textual.containers import Container

from ..utils import (
    format_number, format_percentage, format_bytes, format_timestamp,
    create_simple_bar
)


class PerformanceWidget(Container):
    """Simple, scrollable performance widget."""
    
    def __init__(self, stats=None, performance_analyzer=None):
        super().__init__()
        self.stats = stats
        self.performance = performance_analyzer
        self._content = Static("", classes="content-area scrollable")
    
    def compose(self):
        yield self._content
    
    def update_content(self, stats=None, performance_analyzer=None):
        """Update the content with new data."""
        if stats is not None:
            self.stats = stats
        if performance_analyzer is not None:
            self.performance = performance_analyzer
        
        self._content.update(self._generate_content())
    
    def _generate_content(self) -> str:
        """Generate simple performance content."""
        if not self.stats or self.stats.total_requests == 0:
            return self._no_data_content()
        
        return self._main_content()
    
    def _no_data_content(self) -> str:
        """Content when no data is available."""
        return f"""[bold]⚡ PERFORMANCE[/bold]
[dim]{format_timestamp()}[/dim]

[yellow]No performance data available yet.[/yellow]

Press 'r' to refresh or '1' for Overview.

[dim]Commands: 1=Overview 2=Performance 3=Security | r=Refresh f=Follow q=Quit[/dim]"""
    
    def _main_content(self) -> str:
        """Main performance content."""
        content = f"""[bold]⚡ PERFORMANCE ANALYSIS[/bold]
[dim]{format_timestamp()}[/dim]

"""
        
        # Response time statistics
        content += self._format_response_times()
        content += "\n\n"
        
        # Slowest endpoints
        content += self._format_slowest_endpoints()
        content += "\n\n"
        
        # Bandwidth analysis
        content += self._format_bandwidth_analysis()
        content += "\n\n"
        
        content += "[dim]Commands: 1=Overview 2=Performance 3=Security | r=Refresh f=Follow q=Quit[/dim]"
        
        return content
    
    def _format_response_times(self) -> str:
        """Format response time statistics."""
        rt_stats = self.stats.get_response_time_stats()
        
        if not rt_stats:
            return "[bold]RESPONSE TIME STATISTICS[/bold]\nNo response time data available"
        
        avg_time = rt_stats.get('avg', 0)
        median_time = rt_stats.get('median', 0)
        p95_time = rt_stats.get('p95', 0)
        p99_time = rt_stats.get('p99', 0)
        max_time = rt_stats.get('max', 0)
        min_time = rt_stats.get('min', 0)
        
        # Color coding based on performance
        def get_time_color(time_val):
            if time_val < 0.5:
                return "green"
            elif time_val < 1.0:
                return "yellow"
            else:
                return "red"
        
        content = "[bold]RESPONSE TIME STATISTICS[/bold]\n"
        content += f"Average:      [{get_time_color(avg_time)}]{avg_time:.3f}s[/{get_time_color(avg_time)}]\n"
        content += f"Median:       {median_time:.3f}s\n"
        content += f"95th %ile:    [{get_time_color(p95_time)}]{p95_time:.3f}s[/{get_time_color(p95_time)}]\n"
        content += f"99th %ile:    [red]{p99_time:.3f}s[/red]\n"
        content += f"Maximum:      [red]{max_time:.3f}s[/red]\n"
        content += f"Minimum:      [green]{min_time:.3f}s[/green]"
        
        return content
    
    def _format_slowest_endpoints(self) -> str:
        """Format slowest endpoints."""
        content = "[bold]SLOWEST ENDPOINTS[/bold]\n"
        
        try:
            if hasattr(self.performance, 'get_slowest_endpoints'):
                slow_endpoints = self.performance.get_slowest_endpoints(8)
                
                if slow_endpoints:
                    max_time = max(time for _, time in slow_endpoints)
                    
                    for endpoint, avg_time in slow_endpoints:
                        color = "green" if avg_time < 0.5 else "yellow" if avg_time < 1.0 else "red"
                        bar = create_simple_bar(avg_time, max_time, 15)
                        
                        # Truncate long endpoints
                        display_endpoint = endpoint[:50] + "..." if len(endpoint) > 50 else endpoint
                        
                        content += f"{display_endpoint:<53} [{color}]{avg_time:.3f}s[/{color}] {bar}\n"
                else:
                    content += "[green]No slow endpoints detected[/green]"
            else:
                content += "[yellow]Endpoint analysis not configured[/yellow]"
        except Exception as e:
            content += f"[red]Error: {str(e)[:60]}[/red]"
        
        return content
    
    def _format_bandwidth_analysis(self) -> str:
        """Format bandwidth analysis."""
        bandwidth = self.stats.get_bandwidth_stats()
        
        content = "[bold]BANDWIDTH ANALYSIS[/bold]\n"
        
        if bandwidth:
            total_bytes = bandwidth.get('total_bytes', 0)
            avg_bytes = bandwidth.get('avg_bytes_per_request', 0)
            
            # Color coding for bandwidth
            gb_val = total_bytes / (1024 * 1024 * 1024)
            if gb_val < 1:
                gb_color = "green"
            elif gb_val < 10:
                gb_color = "yellow"
            else:
                gb_color = "red"
            
            content += f"Total Bandwidth:     [{gb_color}]{format_bytes(total_bytes)}[/{gb_color}]\n"
            content += f"Average per Request: {format_bytes(avg_bytes)}\n"
            content += f"Total Requests:      {format_number(self.stats.total_requests)}"
        else:
            content += "[red]No bandwidth data available[/red]"
        
        return content
