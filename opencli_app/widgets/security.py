"""
Security widget - simple display of security analysis
"""

from textual.widgets import Static
from textual.containers import Container

from ..utils import (
    format_number, format_percentage, format_timestamp,
    get_top_items, get_status_name, create_simple_bar
)


class SecurityWidget(Container):
    """Simple, scrollable security widget."""
    
    def __init__(self, stats=None, security_analyzer=None):
        super().__init__()
        self.stats = stats
        self.security = security_analyzer
        self._content = Static("", classes="content-area scrollable")
    
    def compose(self):
        yield self._content
    
    def update_content(self, stats=None, security_analyzer=None):
        """Update the content with new data."""
        if stats is not None:
            self.stats = stats
        if security_analyzer is not None:
            self.security = security_analyzer
        
        self._content.update(self._generate_content())
    
    def _generate_content(self) -> str:
        """Generate simple security content."""
        if not self.stats or self.stats.total_requests == 0:
            return self._no_data_content()
        
        return self._main_content()
    
    def _no_data_content(self) -> str:
        """Content when no data is available."""
        return f"""[bold]🔒 SECURITY[/bold]
[dim]{format_timestamp()}[/dim]

[yellow]No security data available yet.[/yellow]

[bold]TEST SECURITY DATA:[/bold]

[bold]THREAT OVERVIEW[/bold]
Total Requests:      1,234
Error Requests:      [yellow]45[/yellow]
4xx Client Errors:   [yellow]32[/yellow]
5xx Server Errors:   [red]13[/red]

[bold]TOP ERROR CODES[/bold]
[yellow]404[/yellow] Not Found             23 (1.9%) ████████
[red]500[/red] Internal Server Error  8 (0.6%) ███
[yellow]403[/yellow] Forbidden             6 (0.5%) ██

[bold]SUSPICIOUS ACTIVITY[/bold]
[red]192.168.1.100[/red]  234 (19.0%) [red]HIGH[/red] ████████████
[yellow]10.0.0.50[/yellow]     123 (10.0%) [yellow]MED[/yellow]  ██████

Press 'r' to refresh or '1' for Overview.

[dim]Commands: 1=Overview 2=Performance 3=Security | r=Refresh f=Follow q=Quit[/dim]"""
    
    def _main_content(self) -> str:
        """Main security content."""
        content = f"""[bold]🔒 SECURITY ANALYSIS[/bold]
[dim]{format_timestamp()}[/dim]

"""
        
        # Threat overview
        content += self._format_threat_overview()
        content += "\n\n"
        
        # Error codes
        content += self._format_error_codes()
        content += "\n\n"
        
        # Suspicious activity
        content += self._format_suspicious_activity()
        content += "\n\n"
        
        # Bot traffic
        content += self._format_bot_traffic()
        content += "\n\n"
        
        content += "[dim]Commands: 1=Overview 2=Performance 3=Security | r=Refresh f=Follow q=Quit[/dim]"
        
        return content
    
    def _format_threat_overview(self) -> str:
        """Format threat overview."""
        errors_4xx = sum(count for status, count in self.stats.hits_per_status.items() if 400 <= status < 500)
        errors_5xx = sum(count for status, count in self.stats.hits_per_status.items() if 500 <= status < 600)
        total_errors = errors_4xx + errors_5xx
        
        # Color coding for error counts
        def get_error_color(error_count):
            if error_count > 100:
                return "red"
            elif error_count > 10:
                return "yellow"
            else:
                return "green"
        
        content = "[bold]THREAT OVERVIEW[/bold]\n"
        content += f"Total Requests:      {format_number(self.stats.total_requests)}\n"
        content += f"Error Requests:      [{get_error_color(total_errors)}]{format_number(total_errors)}[/{get_error_color(total_errors)}]\n"
        content += f"4xx Client Errors:   [yellow]{format_number(errors_4xx)}[/yellow]\n"
        content += f"5xx Server Errors:   [red]{format_number(errors_5xx)}[/red]"
        
        return content
    
    def _format_error_codes(self) -> str:
        """Format top error codes."""
        error_codes = [(status, count) for status, count in self.stats.hits_per_status.items() if status >= 400]
        error_codes.sort(key=lambda x: x[1], reverse=True)
        
        if not error_codes:
            return "[bold]TOP ERROR CODES[/bold]\n[green]No error codes detected - excellent![/green]"
        
        content = "[bold]TOP ERROR CODES[/bold]\n"
        total_requests = self.stats.total_requests
        max_count = error_codes[0][1] if error_codes else 1
        
        for status, count in error_codes[:8]:
            pct = (count / total_requests * 100) if total_requests > 0 else 0
            status_name = get_status_name(status)
            color = "yellow" if 400 <= status < 500 else "red"
            bar = create_simple_bar(count, max_count, 12)
            
            content += f"[{color}]{status}[/{color}] {status_name:<20} {format_number(count):>6} ({format_percentage(pct)}) {bar}\n"
        
        return content
    
    def _format_suspicious_activity(self) -> str:
        """Format suspicious IP activity."""
        # Get high activity IPs
        suspicious_ips = []
        for ip, hits in self.stats.hits_per_ip.most_common(15):
            if hits > 50:  # Threshold for suspicious activity
                suspicious_ips.append((ip, hits))
        
        content = "[bold]SUSPICIOUS ACTIVITY[/bold]\n"
        
        if not suspicious_ips:
            return content + "[green]No suspicious activity detected - secure![/green]"
        
        content += "High Activity IPs:\n"
        total_requests = self.stats.total_requests
        max_hits = suspicious_ips[0][1] if suspicious_ips else 1
        
        for ip, hits in suspicious_ips[:8]:
            pct = (hits / total_requests * 100) if total_requests > 0 else 0
            
            # Threat level based on percentage
            if pct > 10:
                threat_color = "red"
                threat_level = "HIGH"
            elif pct > 5:
                threat_color = "yellow"
                threat_level = "MED"
            else:
                threat_color = "green"
                threat_level = "LOW"
            
            bar = create_simple_bar(hits, max_hits, 10)
            
            content += f"[{threat_color}]{ip:<15}[/{threat_color}] {format_number(hits):>6} ({format_percentage(pct)}) [{threat_color}]{threat_level}[/{threat_color}] {bar}\n"
        
        return content
    
    def _format_bot_traffic(self) -> str:
        """Format bot traffic analysis."""
        bot_requests = self.stats.bot_traffic.get('Bot', 0)
        
        content = "[bold]BOT TRAFFIC ANALYSIS[/bold]\n"
        
        if bot_requests > 0:
            total_requests = self.stats.total_requests
            human_requests = total_requests - bot_requests
            bot_pct = (bot_requests / total_requests * 100) if total_requests > 0 else 0
            human_pct = 100 - bot_pct
            
            # Color coding for bot percentage
            if bot_pct < 20:
                bot_color = "green"
            elif bot_pct < 50:
                bot_color = "yellow"
            else:
                bot_color = "red"
            
            bot_bar = create_simple_bar(bot_requests, total_requests, 20)
            human_bar = create_simple_bar(human_requests, total_requests, 20)
            
            content += f"Bot Requests:        [{bot_color}]{format_number(bot_requests)} ({format_percentage(bot_pct)})[/{bot_color}]\n"
            content += f"Human Requests:      [green]{format_number(human_requests)} ({format_percentage(human_pct)})[/green]\n"
            content += f"Bot Activity:        {bot_bar}\n"
            content += f"Human Activity:      {human_bar}"
        else:
            content += "[green]No bot traffic detected[/green]\n"
            content += "[cyan]All traffic appears to be human[/cyan]"
        
        return content
