"""
Overview widget - clean and simple display of general statistics
"""

from textual.widgets import Static
from textual.containers import Container, Vertical

from ..utils import (
    format_number, format_percentage, format_bytes, format_timestamp,
    create_table_row, get_top_items, create_simple_bar
)


class OverviewWidget(Container):
    """Simple, scrollable overview widget."""
    
    def __init__(self, stats=None, log_files=None, following=False):
        super().__init__()
        self.stats = stats
        self.log_files = log_files or []
        self.following = following
        self._content = Static("", classes="content-area scrollable")
    
    def compose(self):
        yield self._content
    
    def update_content(self, stats=None, log_files=None, following=None):
        """Update the content with new data."""
        if stats is not None:
            self.stats = stats
        if log_files is not None:
            self.log_files = log_files
        if following is not None:
            self.following = following
        
        self._content.update(self._generate_content())
    
    def _generate_content(self) -> str:
        """Generate simple, clean overview content."""
        if not self.stats or self.stats.total_requests == 0:
            return self._no_data_content()
        
        return self._main_content()
    
    def _no_data_content(self) -> str:
        """Content when no data is available."""
        return f"""[bold]📊 OVERVIEW[/bold]
[dim]{format_timestamp()}[/dim]

[yellow]No log data available yet.[/yellow]

[bold]TEST DATA:[/bold]
Total Requests:  1,234
Unique Visitors: 567
Error Rate:      2.3%
Bandwidth:       45.6 MB

[bold]TOP PAGES[/bold]
1. /index.php                               456 (37.0%) ████████████████████
2. /api/graphql                             234 (19.0%) ██████████
3. /admin/login                             123 (10.0%) █████

[bold]Troubleshooting:[/bold]
• Check if /var/log/nginx/access.log exists
• Verify file permissions  
• Ensure JSON log format
• Press 'r' to refresh

[dim]Commands: r=refresh, f=follow, q=quit[/dim]"""
    
    def _main_content(self) -> str:
        """Main overview content."""
        summary = self.stats.get_summary_stats()
        total_requests = summary.get('total_requests', 0)
        unique_visitors = summary.get('unique_visitors', 0)
        error_rate = summary.get('error_rate', 0)
        bandwidth = self.stats.get_bandwidth_stats()
        
        # Status indicator
        follow_status = "ON" if self.following else "OFF"
        follow_color = "green" if self.following else "red"
        
        content = f"""[bold]📊 OVERVIEW[/bold]
[dim]{format_timestamp()} | Files: {len(self.log_files)} | Following: [{follow_color}]{follow_status}[/{follow_color}][/dim]

[bold]GENERAL STATISTICS[/bold]
Total Requests:  {format_number(total_requests)}
Unique Visitors: {format_number(unique_visitors)}
Error Rate:      {self._format_error_rate(error_rate)}
Bandwidth:       {format_bytes(bandwidth.get('total_bytes', 0))}

"""
        
        # Top pages
        content += self._format_top_pages()
        content += "\n"
        
        # Top visitors
        content += self._format_top_visitors()
        content += "\n"
        
        # Status codes
        content += self._format_status_codes()
        content += "\n"
        
        content += "[dim]Commands: 1=Overview 2=Performance 3=Security | r=Refresh f=Follow q=Quit[/dim]"
        
        return content
    
    def _format_error_rate(self, error_rate: float) -> str:
        """Format error rate with appropriate color."""
        if error_rate > 10:
            return f"[red]{format_percentage(error_rate)}[/red]"
        elif error_rate > 5:
            return f"[yellow]{format_percentage(error_rate)}[/yellow]"
        else:
            return f"[green]{format_percentage(error_rate)}[/green]"
    
    def _format_top_pages(self) -> str:
        """Format top requested pages."""
        top_pages = get_top_items(dict(self.stats.hits_per_path), 8)
        
        if not top_pages:
            return "[bold]TOP PAGES[/bold]\nNo data available"
        
        content = "[bold]TOP PAGES[/bold]\n"
        total_requests = self.stats.total_requests
        
        for i, (path, hits) in enumerate(top_pages, 1):
            pct = (hits / total_requests * 100) if total_requests > 0 else 0
            bar = create_simple_bar(hits, top_pages[0][1], 15)
            
            # Truncate long paths
            display_path = path[:40] + "..." if len(path) > 40 else path
            
            content += f"{i:2d}. {display_path:<43} {format_number(hits):>8} ({format_percentage(pct)}) {bar}\n"
        
        return content
    
    def _format_top_visitors(self) -> str:
        """Format top visitor IPs."""
        top_ips = get_top_items(dict(self.stats.hits_per_ip), 8)
        
        if not top_ips:
            return "[bold]TOP VISITORS[/bold]\nNo data available"
        
        content = "[bold]TOP VISITORS[/bold]\n"
        total_requests = self.stats.total_requests
        
        for i, (ip, hits) in enumerate(top_ips, 1):
            pct = (hits / total_requests * 100) if total_requests > 0 else 0
            bar = create_simple_bar(hits, top_ips[0][1], 10)
            
            content += f"{i:2d}. {ip:<15} {format_number(hits):>8} ({format_percentage(pct)}) {bar}\n"
        
        return content
    
    def _format_status_codes(self) -> str:
        """Format HTTP status codes."""
        status_codes = get_top_items(dict(self.stats.hits_per_status), 6)
        
        if not status_codes:
            return "[bold]STATUS CODES[/bold]\nNo data available"
        
        content = "[bold]STATUS CODES[/bold]\n"
        total_requests = self.stats.total_requests
        
        for status, hits in status_codes:
            pct = (hits / total_requests * 100) if total_requests > 0 else 0
            color = "green" if status < 300 else "yellow" if status < 400 else "red"
            bar = create_simple_bar(hits, status_codes[0][1], 10)
            
            content += f"[{color}]{status}[/{color}] {format_number(hits):>8} ({format_percentage(pct)}) {bar}\n"
        
        return content
