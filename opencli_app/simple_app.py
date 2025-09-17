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
        
        # Don't load data here - wait for on_mount
    
    def discover_logs_simple(self):
        """Simple log discovery - copy logcli approach."""
        print("\n=== 🔍 DEBUG: Log Discovery ===")
        print("Current directory:", os.getcwd())
        
        # Try nginx directories
        nginx_dirs = ["/var/log/nginx/", "/var/log/", "/data/web/nginx/"]
        
        for nginx_dir in nginx_dirs:
            print(f"\nChecking {nginx_dir}...")
            if os.path.exists(nginx_dir):
                print(f"✅ Directory exists")
                log_files = self.discover_nginx_logs_simple(nginx_dir)
                if log_files:
                    print(f"✅ Found {len(log_files)} files:")
                    for f in log_files:
                        print(f"   📄 {f}")
                    return log_files
                else:
                    print("⚠️ No access.log files found")
            else:
                print("⚠️ Directory not found")
        
        # Fallback to sample log
        print("\nTrying sample log...")
        sample_log = Path(__file__).parent.parent / "sample_access.log"
        print(f"Looking for: {sample_log.absolute()}")
        
        if sample_log.exists():
            print("✅ Sample log exists")
            try:
                with open(sample_log, 'r') as f:
                    first_line = f.readline().strip()
                    print(f"First line preview: {first_line[:100]}...")
                print(f"✅ Using sample log: {sample_log}")
                return [str(sample_log)]
            except Exception as e:
                print(f"❌ Error reading sample log: {e}")
                return []
        else:
            print("❌ Sample log not found")
            print("\nDebug: Listing parent directory...")
            try:
                parent = sample_log.parent
                print(f"Contents of {parent}:")
                for f in parent.iterdir():
                    print(f"   {f.name}")
            except Exception as e:
                print(f"❌ Error listing directory: {e}")
            return []
    
    def discover_nginx_logs_simple(self, nginx_dir: str):
        """Discover access.log files - exact copy of logcli method."""
        log_dir = Path(nginx_dir)
        if not log_dir.exists():
            return []
        
        log_files = []
        
        # Current access.log
        current_log = log_dir / "access.log"
        if current_log.exists():
            log_files.append(str(current_log))
        
        # Rotated logs (access.log.1, access.log.2, etc.)
        for log_file in log_dir.glob("access.log.*"):
            if not str(log_file).endswith('.gz'):  # Skip .gz for now
                log_files.append(str(log_file))
        
        # Sort by modification time (newest first)
        if log_files:
            log_files.sort(key=lambda x: Path(x).stat().st_mtime, reverse=True)
        
        return log_files
    
    def load_data(self):
        """Load and process log data - simplified approach."""
        try:
            print("🚀 Loading data...")
            
            # Discover log files
            self.log_files = self.discover_logs_simple()
            
            if not self.log_files:
                print("❌ No log files found")
                return
            
            print(f"📄 Processing {len(self.log_files)} files...")
            
            # Process logs
            self.process_logs_simple()
            self.last_update = datetime.now()
            
            print(f"✅ Loaded {self.stats.total_requests:,} requests")
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            import traceback
            traceback.print_exc()
    
    def process_logs_simple(self):
        """Process log files - simplified like logcli."""
        print("\n=== 🔍 DEBUG: Processing Logs ===")
        print("Starting log processing...")
        
        # Reset statistics
        self.stats.reset()
        # SecurityAnalyzer and PerformanceAnalyzer don't have reset() - create new instances
        from logcli.security import SecurityAnalyzer
        from logcli.performance import PerformanceAnalyzer
        self.security = SecurityAnalyzer()
        self.performance = PerformanceAnalyzer()
        
        total_lines = 0
        processed_entries = 0
        
        for log_file in self.log_files:
            print(f"📄 Reading {Path(log_file).name}...")
            
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        
                        line = line.strip()
                        if not line:
                            continue
                        
                        total_lines += 1
                        
                        try:
                            # Parse log entry with correct method name
                            log_entry = self.parser.parse_log_line(line)
                            if not log_entry:
                                continue
                            
                            # Apply filters
                            if not self.filter.should_include(log_entry):
                                continue
                            
                            # Add to statistics
                            self.stats.add_entry(log_entry)
                            self.security.add_entry(log_entry)
                            self.performance.add_entry(log_entry)
                            
                            processed_entries += 1
                            
                            # Show first few entries
                            if processed_entries <= 3:
                                print(f"✅ Entry {processed_entries}: {log_entry.get('request', 'N/A')} -> {log_entry.get('status', 'N/A')}")
                            
                        except Exception as e:
                            if total_lines <= 3:
                                print(f"⚠️ Parse error line {line_num}: {e}")
                            continue
                            
            except Exception as e:
                print(f"❌ Error reading {log_file}: {e}")
                continue
        
        print(f"📊 Processed {total_lines:,} lines, {processed_entries:,} entries")
        print(f"📊 Total requests: {self.stats.total_requests:,}")
        
        if self.stats.total_requests == 0:
            print("❌ No data processed - interface will show 'No Data'")
        else:
            print("✅ Data processed successfully!")
    
    def process_logs(self):
        """Old method - keeping for compatibility."""
        self.process_logs_simple()
    
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
    
    def on_mount(self) -> None:
        """Initialize the application after widgets are created."""
        print("\n=== 🔍 DEBUG: App Initialization ===")
        print("🚀 App mounted, starting initialization...")
        
        print("\n=== 🔍 DEBUG: Widget Status ===")
        print(f"📊 Overview widget:    {'✅' if self.overview_widget else '❌'}")
        print(f"⚡ Performance widget: {'✅' if self.performance_widget else '❌'}")
        print(f"🔒 Security widget:    {'✅' if self.security_widget else '❌'}")
        
        print("\n=== 🔍 DEBUG: Loading Data ===")
        self.load_data()
        
        print("\n=== 🔍 DEBUG: Updating Widgets ===")
        self.update_all_widgets()
        
        print("\n=== 🔍 DEBUG: Initialization Complete ===")
        print(f"✅ Data loaded: {self.stats.total_requests:,} requests")
        print(f"✅ Widgets updated: {datetime.now().strftime('%H:%M:%S')}")
    
    def update_all_widgets(self) -> None:
        """Update all widgets with current data."""
        print(f"🔄 Updating widgets with {self.stats.total_requests} requests")
        
        if self.overview_widget:
            print("📊 Updating overview...")
            self.overview_widget.update(self.get_overview_content())
        else:
            print("⚠️ Overview widget not found")
        
        if self.performance_widget:
            print("⚡ Updating performance...")
            self.performance_widget.update(self.get_performance_content())
        else:
            print("⚠️ Performance widget not found")
        
        if self.security_widget:
            print("🔒 Updating security...")
            self.security_widget.update(self.get_security_content())
        else:
            print("⚠️ Security widget not found")
    
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
        self.update_all_widgets()
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
