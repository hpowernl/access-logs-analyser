"""
Heel eenvoudige werkende versie van de log analyzer - nu met echte data
"""

import sys
import os
from pathlib import Path
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, Static, TabbedContent, TabPane

# Add logcli to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from logcli.parser import LogParser
from logcli.filters import LogFilter
from logcli.aggregators import StatisticsAggregator
from logcli.security import SecurityAnalyzer
from logcli.performance import PerformanceAnalyzer
from logcli.main import discover_nginx_logs

class SimpleLogApp(App):
    """Eenvoudige log analyzer die zeker werkt."""
    
    TITLE = "🚀 Simple Log Analyzer - Real Data"
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("1", "show_overview", "Overview"),
        ("2", "show_performance", "Performance"),
        ("3", "show_security", "Security"),
    ]
    
    def __init__(self):
        super().__init__()
        
        # Initialize data components
        self.parser = LogParser()
        self.filter = LogFilter()
        self.stats = StatisticsAggregator()
        self.security = SecurityAnalyzer()
        self.performance = PerformanceAnalyzer()
        
        # State
        self.log_files = []
        self.last_update = None
        
        # Widgets - we'll store references for updates
        self.overview_widget = None
        self.performance_widget = None
        self.security_widget = None
        
        # Load data immediately
        self.load_data()
    
    def load_data(self):
        """Load and process log data."""
        try:
            print("🚀 Loading real log data...")
            
            # Discover log files
            self.log_files = discover_nginx_logs()
            
            if not self.log_files:
                print("📄 No nginx logs found, using sample data...")
                sample_log = Path(__file__).parent.parent / "sample_access.log"
                if sample_log.exists():
                    self.log_files = [str(sample_log)]
                    print(f"✅ Using sample log: {sample_log}")
                else:
                    print("❌ No sample log found either")
                    return
            else:
                print(f"✅ Found {len(self.log_files)} log files")
            
            # Process logs
            self.process_logs()
            self.last_update = datetime.now()
            
            print(f"📊 Loaded {self.stats.total_requests:,} requests")
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            import traceback
            traceback.print_exc()
    
    def process_logs(self):
        """Process log files and update statistics."""
        # Reset statistics
        self.stats.reset()
        self.security.reset()
        self.performance.reset()
        
        total_lines = 0
        parsed_entries = 0
        max_lines_per_file = 1000  # Keep it small for testing
        
        for log_file in self.log_files:
            try:
                print(f"📄 Processing {log_file}...")
                
                if not os.path.exists(log_file):
                    print(f"❌ File not found: {log_file}")
                    continue
                
                with open(log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        if line_num > max_lines_per_file:
                            print(f"⚠️  Reached line limit ({max_lines_per_file}) for {log_file}")
                            break
                        
                        line = line.strip()
                        if not line:
                            continue
                        
                        total_lines += 1
                        
                        try:
                            # Parse log entry
                            entry = self.parser.parse_line(line)
                            if not entry:
                                continue
                            
                            # Apply filters
                            if not self.filter.should_include(entry):
                                continue
                            
                            # Add to statistics
                            self.stats.add_entry(entry)
                            self.security.add_entry(entry)
                            self.performance.add_entry(entry)
                            
                            parsed_entries += 1
                            
                        except Exception as e:
                            # Skip malformed lines silently
                            continue
                            
            except Exception as e:
                print(f"⚠️ Error processing {log_file}: {e}")
                continue
        
        print(f"📊 Processed {total_lines} lines, parsed {parsed_entries} entries")
        print(f"📈 Stats total: {self.stats.total_requests}")
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with TabbedContent(initial="overview"):
            with TabPane("📊 Overview", id="overview"):
                self.overview_widget = Static(self.get_overview_content(), classes="content")
                yield self.overview_widget
            
            with TabPane("⚡ Performance", id="performance"):
                self.performance_widget = Static(self.get_performance_content(), classes="content")
                yield self.performance_widget
            
            with TabPane("🔒 Security", id="security"):
                self.security_widget = Static(self.get_security_content(), classes="content")
                yield self.security_widget
        
        yield Footer()
    
    def get_overview_content(self) -> str:
        """Generate overview content with real data."""
        if self.stats.total_requests == 0:
            return """[bold red]📊 OVERVIEW - No Data[/bold red]

[yellow]No log data loaded yet.[/yellow]

[bold]Troubleshooting:[/bold]
• Check if /var/log/nginx/access.log exists
• Verify file permissions
• Ensure JSON log format
• Press 'r' to refresh

[dim]Commands: r=refresh, 1=Overview 2=Performance 3=Security | q=Quit[/dim]"""
        
        # Real data from stats
        summary = self.stats.get_summary_stats()
        total_requests = summary.get('total_requests', 0)
        unique_visitors = summary.get('unique_visitors', 0)
        error_rate = summary.get('error_rate', 0)
        bandwidth = self.stats.get_bandwidth_stats()
        
        # Format error rate with color
        if error_rate > 10:
            error_display = f"[red]{error_rate:.1f}%[/red]"
        elif error_rate > 5:
            error_display = f"[yellow]{error_rate:.1f}%[/yellow]"
        else:
            error_display = f"[green]{error_rate:.1f}%[/green]"
        
        content = f"""[bold blue]📊 OVERVIEW - REAL DATA[/bold blue]
[dim]Updated: {self.last_update.strftime('%H:%M:%S') if self.last_update else 'Never'} | Files: {len(self.log_files)}[/dim]

[bold green]📈 STATISTICS[/bold green]
Total Requests:  [bold]{total_requests:,}[/bold]
Unique Visitors: [bold]{unique_visitors:,}[/bold]
Error Rate:      {error_display}
Bandwidth:       [bold]{bandwidth.get('total_gb', 0):.2f} GB[/bold]

[bold yellow]🏆 TOP PAGES[/bold yellow]"""
        
        # Top pages
        top_paths = list(self.stats.hits_per_path.most_common(8))
        if top_paths:
            for i, (path, hits) in enumerate(top_paths, 1):
                pct = (hits / total_requests * 100) if total_requests > 0 else 0
                bar_len = min(int(pct / 2), 20)
                bar = "█" * bar_len
                
                # Truncate long paths
                display_path = path[:30] + "..." if len(path) > 30 else path
                content += f"\n{i:2d}. {display_path:<33} {hits:>6,} ({pct:4.1f}%) {bar}"
        else:
            content += "\nNo page data available"
        
        content += f"""

[bold magenta]👥 TOP VISITORS[/bold magenta]"""
        
        # Top IPs
        top_ips = list(self.stats.hits_per_ip.most_common(6))
        if top_ips:
            for i, (ip, hits) in enumerate(top_ips, 1):
                pct = (hits / total_requests * 100) if total_requests > 0 else 0
                bar_len = min(int(pct / 2), 15)
                bar = "▓" * bar_len
                content += f"\n{i:2d}. {ip:<15} {hits:>6,} ({pct:4.1f}%) {bar}"
        else:
            content += "\nNo visitor data available"
        
        content += f"""

[bold red]📊 STATUS CODES[/bold red]"""
        
        # Status codes
        status_codes = list(self.stats.hits_per_status.most_common(6))
        if status_codes:
            for status, hits in status_codes:
                pct = (hits / total_requests * 100) if total_requests > 0 else 0
                color = "green" if status < 300 else "yellow" if status < 400 else "red"
                bar_len = min(int(pct / 2), 12)
                bar = "▒" * bar_len
                content += f"\n[{color}]{status}[/{color}] {hits:>6,} ({pct:4.1f}%) {bar}"
        else:
            content += "\nNo status code data available"
        
        content += "\n\n[dim]Commands: r=refresh, 1=Overview 2=Performance 3=Security | q=Quit[/dim]"
        
        return content
    
    def get_performance_content(self) -> str:
        """Generate performance content with real data."""
        if self.stats.total_requests == 0:
            return """[bold yellow]⚡ PERFORMANCE - No Data[/bold yellow]

[yellow]No performance data available yet.[/yellow]
Press 'r' to refresh or '1' for Overview.

[dim]Commands: r=refresh, 1=Overview 2=Performance 3=Security | q=Quit[/dim]"""
        
        content = f"""[bold yellow]⚡ PERFORMANCE - REAL DATA[/bold yellow]
[dim]Updated: {self.last_update.strftime('%H:%M:%S') if self.last_update else 'Never'}[/dim]

[bold green]🚀 RESPONSE TIME STATISTICS[/bold green]"""
        
        # Response time stats
        rt_stats = self.stats.get_response_time_stats()
        if rt_stats:
            avg_time = rt_stats.get('avg', 0)
            median_time = rt_stats.get('median', 0)
            p95_time = rt_stats.get('p95', 0)
            p99_time = rt_stats.get('p99', 0)
            max_time = rt_stats.get('max', 0)
            min_time = rt_stats.get('min', 0)
            
            # Color coding
            avg_color = "green" if avg_time < 0.5 else "yellow" if avg_time < 1.0 else "red"
            p95_color = "green" if p95_time < 1.0 else "yellow" if p95_time < 2.0 else "red"
            
            content += f"""
Average:      [{avg_color}]{avg_time:.3f}s[/{avg_color}]
Median:       [blue]{median_time:.3f}s[/blue]
95th %ile:    [{p95_color}]{p95_time:.3f}s[/{p95_color}]
99th %ile:    [red]{p99_time:.3f}s[/red]
Maximum:      [red]{max_time:.3f}s[/red]
Minimum:      [green]{min_time:.3f}s[/green]"""
        else:
            content += "\nNo response time data available"
        
        content += f"""

[bold blue]📊 BANDWIDTH ANALYSIS[/bold blue]"""
        
        # Bandwidth stats
        bandwidth = self.stats.get_bandwidth_stats()
        if bandwidth:
            total_gb = bandwidth.get('total_gb', 0)
            avg_bytes = bandwidth.get('avg_bytes_per_request', 0)
            gb_color = "green" if total_gb < 1 else "yellow" if total_gb < 10 else "red"
            
            content += f"""
Total Bandwidth:     [{gb_color}]{total_gb:.2f} GB[/{gb_color}]
Average per Request: [blue]{avg_bytes:,.0f} bytes[/blue]
Total Requests:      [green]{self.stats.total_requests:,}[/green]"""
        else:
            content += "\nNo bandwidth data available"
        
        content += "\n\n[dim]Commands: r=refresh, 1=Overview 2=Performance 3=Security | q=Quit[/dim]"
        
        return content
    
    def get_security_content(self) -> str:
        """Generate security content with real data."""
        if self.stats.total_requests == 0:
            return """[bold red]🔒 SECURITY - No Data[/bold red]

[yellow]No security data available yet.[/yellow]
Press 'r' to refresh or '1' for Overview.

[dim]Commands: r=refresh, 1=Overview 2=Performance 3=Security | q=Quit[/dim]"""
        
        # Error analysis
        errors_4xx = sum(count for status, count in self.stats.hits_per_status.items() if 400 <= status < 500)
        errors_5xx = sum(count for status, count in self.stats.hits_per_status.items() if 500 <= status < 600)
        total_errors = errors_4xx + errors_5xx
        
        # Color coding for error counts
        if total_errors > 100:
            error_color = "red"
        elif total_errors > 10:
            error_color = "yellow"
        else:
            error_color = "green"
        
        content = f"""[bold red]🔒 SECURITY - REAL DATA[/bold red]
[dim]Updated: {self.last_update.strftime('%H:%M:%S') if self.last_update else 'Never'}[/dim]

[bold yellow]🛡️ THREAT OVERVIEW[/bold yellow]
Total Requests:      [bold]{self.stats.total_requests:,}[/bold]
Error Requests:      [{error_color}]{total_errors:,}[/{error_color}]
4xx Client Errors:   [yellow]{errors_4xx:,}[/yellow]
5xx Server Errors:   [red]{errors_5xx:,}[/red]

[bold red]⚠️ TOP ERROR CODES[/bold red]"""
        
        # Error codes
        error_codes = [(status, count) for status, count in self.stats.hits_per_status.items() if status >= 400]
        error_codes.sort(key=lambda x: x[1], reverse=True)
        
        if error_codes:
            for status, count in error_codes[:6]:
                pct = (count / self.stats.total_requests * 100) if self.stats.total_requests > 0 else 0
                color = "yellow" if 400 <= status < 500 else "red"
                bar_len = min(int(pct), 15)
                bar = "▓" * bar_len
                
                # Status name
                status_names = {404: "Not Found", 500: "Server Error", 403: "Forbidden", 401: "Unauthorized"}
                status_name = status_names.get(status, "Unknown")
                
                content += f"\n[{color}]{status}[/{color}] {status_name:<15} {count:>6,} ({pct:4.1f}%) {bar}"
        else:
            content += "\n[green]No error codes detected - excellent![/green]"
        
        content += f"""

[bold magenta]🕵️ SUSPICIOUS ACTIVITY[/bold magenta]"""
        
        # High activity IPs
        suspicious_ips = []
        for ip, hits in self.stats.hits_per_ip.most_common(10):
            if hits > 50:  # Threshold for suspicious
                suspicious_ips.append((ip, hits))
        
        if suspicious_ips:
            for ip, hits in suspicious_ips[:5]:
                pct = (hits / self.stats.total_requests * 100) if self.stats.total_requests > 0 else 0
                
                if pct > 10:
                    threat_level = "HIGH"
                    threat_color = "red"
                elif pct > 5:
                    threat_level = "MED"
                    threat_color = "yellow"
                else:
                    threat_level = "LOW"
                    threat_color = "green"
                
                bar_len = min(int(pct), 15)
                bar = "▓" * bar_len
                content += f"\n[{threat_color}]{ip:<15}[/{threat_color}] {hits:>6,} ({pct:4.1f}%) [{threat_color}]{threat_level}[/{threat_color}] {bar}"
        else:
            content += "\n[green]No suspicious activity detected - secure![/green]"
        
        content += "\n\n[dim]Commands: r=refresh, 1=Overview 2=Performance 3=Security | q=Quit[/dim]"
        
        return content
    
    def action_refresh(self) -> None:
        """Refresh all data and update widgets."""
        self.notify("Refreshing data...", timeout=2)
        self.load_data()
        
        # Update widgets if they exist
        if self.overview_widget:
            self.overview_widget.update(self.get_overview_content())
        if self.performance_widget:
            self.performance_widget.update(self.get_performance_content())
        if self.security_widget:
            self.security_widget.update(self.get_security_content())
        
        self.notify("Data refreshed!", timeout=1)
    
    def action_show_overview(self) -> None:
        """Switch to overview tab."""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = "overview"
    
    def action_show_performance(self) -> None:
        """Switch to performance tab."""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = "performance"
    
    def action_show_security(self) -> None:
        """Switch to security tab."""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = "security"


def run_simple_app():
    """Run the simple app."""
    app = SimpleLogApp()
    app.run()


if __name__ == "__main__":
    run_simple_app()
