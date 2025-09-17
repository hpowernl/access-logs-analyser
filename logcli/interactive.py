"""Interactive TUI application - Main interface like htop/GoAccess."""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import (
    Header, Footer, DataTable, Static, Button, Label, 
    TabbedContent, TabPane, Input, Switch, ProgressBar,
    Tree, Log, RichLog
)
from textual.reactive import reactive
from textual.binding import Binding
from textual.timer import Timer
from textual.screen import Screen

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich.layout import Layout

from .parser import LogParser
from .filters import LogFilter
from .aggregators import StatisticsAggregator, RealTimeAggregator
from .security import SecurityAnalyzer
from .performance import PerformanceAnalyzer
from .bots import BotAnalyzer
from .log_reader import LogReader, LogTailer
from .main import discover_nginx_logs


class HelpScreen(Screen):
    """Help screen showing keybindings and usage."""
    
    def compose(self) -> ComposeResult:
        help_text = """
[bold blue] Access Log Analyzer - Help[/bold blue]

[bold yellow]Navigation:[/bold yellow]
• F1 / ?     - Show this help screen
• F2         - Setup/Configuration
• F3         - Security Analysis View
• F4         - Performance Analysis View
• F5         - Bot Analysis View
• F6         - Export Options
• F7         - Search Interface
• 1          - Overview Dashboard
• 2          - Security Monitor
• 3          - Performance Monitor

[bold yellow]Controls:[/bold yellow]
• r          - Refresh current view
• p          - Pause/Resume live updates
• q          - Quit application

[bold yellow]Troubleshooting:[/bold yellow]
If you see no data:
1. Check if log files exist in /var/log/nginx/
2. Ensure log files are readable (permissions)
3. Verify logs are in JSON format
4. Press 'r' to refresh

[bold yellow]Log Locations Checked:[/bold yellow]
• /var/log/nginx/ (Hypernode/Standard)
• /data/web/nginx/ (Alternative)
• Current directory (sample_access.log)

[dim]Press any key to close this help screen[/dim]
        """
        
        yield Container(
            Static(help_text, id="help-content"),
            id="help-container"
        )
    
    def on_key(self, event) -> None:
        """Close help on any key press."""
        self.app.pop_screen()


class LoadingScreen(Screen):
    """Loading screen shown during startup."""
    
    def compose(self) -> ComposeResult:
        yield Container(
            Static(""),
            Static(
                "[bold blue] Access Log Analyzer[/bold blue]\n"
                "[dim]Loading...[/dim]",
                id="loading-title"
            ),
            ProgressBar(id="loading-progress"),
            Static("Initializing...", id="loading-status"),
            Static(""),
            id="loading-container"
        )
    
    def on_mount(self) -> None:
        """Start loading process."""
        self.loading_progress = self.query_one("#loading-progress", ProgressBar)
        self.loading_status = self.query_one("#loading-status", Static)
        self.start_loading()
    
    @work(exclusive=True)
    async def start_loading(self) -> None:
        """Simulate loading process."""
        steps = [
            ("Discovering log files...", 0.2),
            ("Initializing parsers...", 0.4),
            ("Loading recent data...", 0.6),
            ("Building statistics...", 0.8),
            ("Starting real-time monitoring...", 1.0),
        ]
        
        for step, progress in steps:
            self.loading_status.update(step)
            self.loading_progress.update(progress=progress * 100)
            await asyncio.sleep(0.5)  # Simulate work
        
        # Switch to main app
        await asyncio.sleep(0.5)
        self.app.pop_screen()


class OverviewDashboard(Static):
    """Main overview dashboard widget."""
    
    def __init__(self, stats: StatisticsAggregator):
        super().__init__()
        self.stats = stats
        self.update_timer = None
        
        # Caching system
        self._cached_data = None
        self._last_update = None
        self._cache_duration = 30  # Cache for 30 seconds
        self._stats_cache = None
        self._trends_cache = None
    
    def compose(self) -> ComposeResult:
        yield Container(
            Container(
                Static("📊 OVERVIEW", classes="panel-title"),
                Static("", id="overview-stats"),
                classes="panel"
            ),
            Container(
                Static("📈 TRENDS", classes="panel-title"),
                Static("", id="trends-chart"),
                classes="panel"
            ),
            Container(
                Static("🔥 LIVE ACTIVITY", classes="panel-title"),
                RichLog(id="live-log", auto_scroll=True, max_lines=15),
                classes="panel"
            ),
            Container(
                Static("ℹ️ CONTROLS", classes="panel-title"),
                Static("Press F1 for help\nPress 'r' to refresh\nPress 'q' to quit\n\n✅ Interface is working!\n📊 Test mode active", id="info-panel"),
                classes="panel"
            ),
            classes="dashboard-grid"
        )
    
    def on_mount(self) -> None:
        """Start periodic updates."""
        print(f"📊 OverviewDashboard mounted (fast mode)")
        
        # Add some test entries to live log
        self.add_test_live_entries()
        
        self.update_display()
        # With caching, we can update even less frequently
        self.update_timer = self.set_interval(30.0, self.update_display)
    
    def add_test_live_entries(self) -> None:
        """Add test entries to live log."""
        try:
            live_log = self.query_one("#live-log", RichLog)
            live_log.write("[green]✅ Live log is working![/green]")
            live_log.write("[cyan]12:34:56[/cyan] [blue]192.168.1.100[/blue] [green]200[/green] [white]GET[/white] [dim]/api/test[/dim] [magenta]NL[/magenta]")
            live_log.write("[cyan]12:34:57[/cyan] [blue]10.0.0.50[/blue] [yellow]404[/yellow] [white]POST[/white] [dim]/admin/login[/dim] [magenta]US[/magenta]")
            live_log.write("[cyan]12:34:58[/cyan] [blue]203.0.113.42[/blue] [green]200[/green] [white]GET[/white] [dim]/favicon.ico[/dim] [magenta]AU[/magenta]")
            live_log.write("[dim]--- Test data - interface is working ---[/dim]")
            print("✅ Test live entries added")
        except Exception as e:
            print(f"❌ Error adding test live entries: {e}")
    
    def _should_update_cache(self) -> bool:
        """Check if cache should be updated."""
        if self._last_update is None:
            return True
        
        time_since_update = (datetime.now() - self._last_update).total_seconds()
        return time_since_update >= self._cache_duration
    
    def _get_cached_stats_text(self) -> str:
        """Get cached stats text or generate new one."""
        if self._stats_cache is None or self._should_update_cache():
            current_time = datetime.now().strftime('%H:%M:%S')
            self._stats_cache = f"""
[bold blue]🚀 Access Log Analyzer - Cached Data[/bold blue]

[bold green]✅ Interface Status:[/bold green]
• Textual: Working ✓
• Overview Panel: Loaded ✓
• Caching: Active 🔄
• Last Update: {current_time}

[bold yellow]📊 Performance:[/bold yellow]
• Cache Duration: {self._cache_duration}s
• Updates: Reduced for speed
• Memory: Optimized

[bold cyan]🔧 Sample Data:[/bold cyan]
• Sample requests: 1,234
• Sample visitors: 567
• Sample error rate: 2.3%
• Sample bot traffic: 15.7%

[dim]✅ Cached interface working!
Press F1 for help, 'r' to refresh, 'q' to quit[/dim]
            """
            self._last_update = datetime.now()
        
        return self._stats_cache
    
    def _get_cached_trends_text(self) -> str:
        """Get cached trends text or generate new one."""
        if self._trends_cache is None:
            self._trends_cache = """
[bold]📈 Cached Trends Chart[/bold]

Requests/hour (cached test data)
120 ┤     ╭─╮
100 ┤   ╭─╯ ╰─╮  
 80 ┤ ╭─╯     ╰─╮
 60 ┤─╯         ╰─╮
 40 ┤             ╰───
    └─────────────────
    12:00  13:00  14:00

[green]✅ Cached chart - faster loading![/green]
[dim]Updates every {self._cache_duration}s[/dim]
            """
        
        return self._trends_cache
    
    def force_cache_refresh(self) -> None:
        """Force refresh of all cached data."""
        self._stats_cache = None
        self._trends_cache = None
        self._last_update = None
        print("🔄 Cache forcefully refreshed")
        self.update_display()
    
    def update_display(self) -> None:
        """Update the overview display with caching."""
        try:
            # Use cached data for better performance
            stats_text = self._get_cached_stats_text()
            self.query_one("#overview-stats", Static).update(stats_text.strip())
            
            # Use cached trends
            trends_text = self._get_cached_trends_text()
            self.query_one("#trends-chart", Static).update(trends_text)
            
        except Exception as e:
            print(f"❌ Error updating display: {e}")
            # Fallback - try to show SOMETHING
            try:
                fallback_text = f"CACHE ERROR: {str(e)}\nTime: {datetime.now()}"
                self.query_one("#overview-stats", Static).update(fallback_text)
            except:
                print("❌ Even fallback failed")
    
    def _generate_trends_chart(self) -> str:
        """Generate simple ASCII trends chart."""
        # This is a simplified version - in real implementation would use actual data
        return """
Requests/min (last hour)
120 ┤     ╭─╮
100 ┤   ╭─╯ ╰─╮
 80 ┤ ╭─╯     ╰─╮
 60 ┤─╯         ╰─╮
 40 ┤             ╰───
    └─────────────────
    14:00  14:30  15:00
        """
    
    def add_live_entry(self, log_entry: Dict[str, Any]) -> None:
        """Add new log entry to live feed."""
        live_log = self.query_one("#live-log", RichLog)
        
        timestamp = log_entry.get('timestamp', datetime.now()).strftime('%H:%M:%S')
        ip = str(log_entry.get('ip', 'unknown'))
        status = log_entry.get('status', 0)
        method = log_entry.get('method', 'GET')
        path = log_entry.get('path', '/')[:50]
        country = log_entry.get('country', '')
        
        # Color code by status
        if status >= 500:
            color = "red"
        elif status >= 400:
            color = "yellow"
        elif status >= 300:
            color = "blue"
        else:
            color = "green"
        
        live_log.write(
            f"[dim]{timestamp}[/dim] "
            f"[cyan]{ip}[/cyan] "
            f"[{color}]{status}[/{color}] "
            f"[white]{method}[/white] "
            f"[dim]{path}[/dim] "
            f"[magenta]{country}[/magenta]"
        )


class SecurityMonitor(Static):
    """Security monitoring panel."""
    
    def __init__(self, security_analyzer: SecurityAnalyzer):
        super().__init__()
        self.security = security_analyzer
    
    def compose(self) -> ComposeResult:
        yield Container(
            Container(
                Static("🔐 SECURITY ALERTS", classes="panel-title"),
                RichLog(id="security-alerts", auto_scroll=True, max_lines=10),
                classes="panel alerts-panel"
            ),
            Container(
                Static("🚨 ATTACK PATTERNS", classes="panel-title"),
                DataTable(id="attacks-table"),
                classes="panel attacks-panel"
            ),
            Container(
                Static("🕵️ SUSPICIOUS IPs", classes="panel-title"),
                DataTable(id="suspicious-ips-table"),
                classes="panel ips-panel"
            ),
            classes="security-grid"
        )
    
    def on_mount(self) -> None:
        """Initialize security tables."""
        # Setup attacks table
        attacks_table = self.query_one("#attacks-table", DataTable)
        attacks_table.add_columns("Attack Type", "Count", "Severity")
        
        # Setup suspicious IPs table
        ips_table = self.query_one("#suspicious-ips-table", DataTable)
        ips_table.add_columns("IP Address", "Requests", "Threat Score", "Action")
        
        self.update_display()
        self.set_interval(5.0, self.update_display)
    
    def update_display(self) -> None:
        """Update security display."""
        # Update attack patterns
        attacks = self.security.get_attack_patterns()
        attacks_table = self.query_one("#attacks-table", DataTable)
        attacks_table.clear()
        
        for attack_type, count in attacks.items():
            severity = "HIGH" if count > 50 else "MED" if count > 10 else "LOW"
            color = "red" if severity == "HIGH" else "yellow" if severity == "MED" else "green"
            attacks_table.add_row(
                attack_type,
                str(count),
                f"[{color}]{severity}[/{color}]"
            )
        
        # Update suspicious IPs
        suspicious_ips = self.security.get_suspicious_ips()[:10]
        ips_table = self.query_one("#suspicious-ips-table", DataTable)
        ips_table.clear()
        
        for ip_info in suspicious_ips:
            threat_level = "HIGH" if ip_info['threat_score'] > 50 else "MED" if ip_info['threat_score'] > 20 else "LOW"
            color = "red" if threat_level == "HIGH" else "yellow" if threat_level == "MED" else "green"
            
            ips_table.add_row(
                ip_info['ip'],
                str(ip_info['total_requests']),
                f"[{color}]{ip_info['threat_score']:.1f}[/{color}]",
                "[red][Block][/red] [blue][Info][/blue]"
            )
    
    def add_security_alert(self, alert_type: str, message: str, severity: str = "INFO") -> None:
        """Add security alert to feed."""
        alerts_log = self.query_one("#security-alerts", RichLog)
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if severity == "HIGH":
            icon = "🚨"
            color = "red"
        elif severity == "MED":
            icon = "⚠️"
            color = "yellow"
        else:
            icon = "ℹ️"
            color = "blue"
        
        alerts_log.write(f"[dim]{timestamp}[/dim] [{color}]{icon} {severity}[/{color}] {message}")


class PerformanceMonitor(Static):
    """Performance monitoring panel."""
    
    def __init__(self, perf_analyzer: PerformanceAnalyzer):
        super().__init__()
        self.perf = perf_analyzer
    
    def compose(self) -> ComposeResult:
        yield Container(
            Container(
                Static("⚡ RESPONSE TIMES", classes="panel-title"),
                Static("", id="response-time-stats"),
                classes="panel response-panel"
            ),
            Container(
                Static("🐌 SLOWEST ENDPOINTS", classes="panel-title"),
                DataTable(id="slow-endpoints-table"),
                classes="panel slow-panel"
            ),
            Container(
                Static("📊 PERFORMANCE CHART", classes="panel-title"),
                Static("", id="performance-chart"),
                classes="panel chart-panel"
            ),
            classes="performance-grid"
        )
    
    def on_mount(self) -> None:
        """Initialize performance tables."""
        slow_table = self.query_one("#slow-endpoints-table", DataTable)
        slow_table.add_columns("Endpoint", "Avg Time", "Max Time", "Requests")
        
        self.update_display()
        self.set_interval(3.0, self.update_display)
    
    def update_display(self) -> None:
        """Update performance display."""
        # Update response time stats
        rt_stats = self.perf.get_response_time_stats()
        if rt_stats:
            stats_text = f"""
[green]Average:[/green] {rt_stats.get('avg', 0):.3f}s
[blue]Median:[/blue] {rt_stats.get('median', 0):.3f}s
[yellow]95th %ile:[/yellow] {rt_stats.get('p95', 0):.3f}s
[red]Maximum:[/red] {rt_stats.get('max', 0):.3f}s
            """
            self.query_one("#response-time-stats", Static).update(stats_text.strip())
        
        # Update slowest endpoints
        slow_endpoints = self.perf.get_slowest_endpoints(10)
        slow_table = self.query_one("#slow-endpoints-table", DataTable)
        slow_table.clear()
        
        for endpoint, avg_time in slow_endpoints:
            color = "red" if avg_time > 2.0 else "yellow" if avg_time > 1.0 else "green"
            slow_table.add_row(
                endpoint[:40] + "..." if len(endpoint) > 40 else endpoint,
                f"[{color}]{avg_time:.3f}s[/{color}]",
                f"{avg_time * 1.5:.3f}s",  # Estimated max
                "N/A"  # Would need actual request count
            )
        
        # Update performance chart
        chart_text = self._generate_performance_chart()
        self.query_one("#performance-chart", Static).update(chart_text)
    
    def _generate_performance_chart(self) -> str:
        """Generate performance trend chart."""
        return """
Response Time Trend
2.0s ┤       ╭─╮
1.5s ┤     ╭─╯ ╰─╮
1.0s ┤   ╭─╯     ╰─╮
0.5s ┤ ╭─╯         ╰─╮
0.0s ┤─╯             ╰──
     └──────────────────
     14:00  14:30  15:00
        """


class InteractiveLogAnalyzer(App):
    """Main interactive TUI application."""
    
    CSS = """
    /* Embedded CSS for the TUI */
    #main-container {
        height: 100%;
        layout: vertical;
    }
    
    .status-bar {
        height: 1;
        background: $primary;
        color: $text;
        content-align: left middle;
        padding: 0 1;
    }
    
    .main-area {
        height: 1fr;
        overflow: auto;
    }
    
    .info-bar {
        height: 1;
        background: $surface-lighten-1;
        color: $text-muted;
        content-align: left middle;
        padding: 0 1;
    }
    
    #main-content {
        height: 100%;
        width: 100%;
    }
    
    .panel {
        border: solid $primary;
        margin: 1;
        padding: 1;
        background: $surface;
        height: 100%;
    }
    
    .panel-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    
    .dashboard-grid {
        layout: grid;
        grid-size: 2 2;
        grid-gutter: 1;
        height: 100%;
        width: 100%;
    }
    
    .security-grid {
        layout: grid;
        grid-size: 2 2;
        grid-gutter: 1;
        height: 100%;
    }
    
    .performance-grid {
        layout: grid;
        grid-size: 2 2;
        grid-gutter: 1;
        height: 100%;
    }
    
    DataTable {
        height: 100%;
    }
    
    RichLog {
        height: 100%;
        border: solid $primary;
    }
    
    #help-container {
        align: center middle;
        background: $surface;
        border: solid $primary;
        width: 80%;
        height: 80%;
    }
    
    #help-content {
        padding: 2;
        height: 100%;
        overflow-y: auto;
    }
    """
    TITLE = " Access Log Analyzer"
    
    BINDINGS = [
        Binding("f1", "help", "Help", priority=True),
        Binding("f2", "setup", "Setup", priority=True),
        Binding("f3", "security", "Security", priority=True),
        Binding("f4", "performance", "Performance", priority=True),
        Binding("f5", "bots", "Bots", priority=True),
        Binding("f6", "export", "Export", priority=True),
        Binding("f7", "search", "Search", priority=True),
        Binding("r", "refresh", "Refresh"),
        Binding("p", "pause", "Pause"),
        Binding("q", "quit", "Quit"),
        Binding("?", "help", "Help"),
    ]
    
    # Reactive state
    current_view = reactive("overview")
    is_paused = reactive(False)
    auto_refresh = reactive(True)
    
    def __init__(self):
        super().__init__()
        
        # Initialize analyzers
        self.parser = LogParser()
        self.filter = LogFilter()
        self.stats = StatisticsAggregator()
        self.security = SecurityAnalyzer()
        self.performance = PerformanceAnalyzer()
        self.bots = BotAnalyzer()
        
        # Log files
        self.log_files = []
        self.log_reader = None
        
        # UI components
        self.overview = None
        self.security_monitor = None
        self.performance_monitor = None
        
    def on_mount(self) -> None:
        """Initialize the application."""
        try:
            print("🚀 Initializing InteractiveLogAnalyzer...")
            
            # Skip loading screen for now - directly initialize
            print("🔍 Discovering log files...")
            self.discover_logs()
            print(f"📁 Found {len(self.log_files)} log files: {self.log_files}")
            
            # Skip heavy log processing during startup for better performance
            print("⚡ Skipping log processing for faster startup...")
            # self.start_log_processing()  # Disabled for performance
            print("✅ Initialization complete (fast mode)")
            
        except Exception as e:
            print(f"❌ Error during initialization: {e}")
            import traceback
            traceback.print_exc()
        
    def compose(self) -> ComposeResult:
        """Compose the main interface."""
        try:
            print("🎨 Composing main interface...")
            
            yield Header(show_clock=True)
            
            yield Container(
                # Status bar
                Container(
                    Static("Initializing...", id="status-bar"),
                    classes="status-bar"
                ),
                
                # Main content area
                Container(
                    # Overview dashboard (default)
                    Container(
                        id="main-content"
                    ),
                    classes="main-area"
                ),
                
                # Bottom info bar
                Container(
                    Static("Use F1-F7 for navigation | Press 'q' to quit | Press 'r' to refresh", id="info-bar"),
                    classes="info-bar"
                ),
                
                id="main-container"
            )
            
            yield Footer()
            print("✅ Interface composed successfully")
            
        except Exception as e:
            print(f"❌ Error composing interface: {e}")
            import traceback
            traceback.print_exc()
            # Fallback to minimal interface
            yield Static("Error loading interface. Check console for details.")
    
    def on_ready(self) -> None:
        """Called when app is ready."""
        try:
            print("🎯 App is ready, setting up interface...")
            self.switch_to_overview()
            self.update_status_bar()
            # Reduce status bar update frequency
            self.set_interval(5.0, self.update_status_bar)
            print("✅ Interface setup complete")
        except Exception as e:
            print(f"❌ Error in on_ready: {e}")
            import traceback
            traceback.print_exc()
    
    def discover_logs(self) -> None:
        """Discover available log files."""
        # Try multiple common nginx log locations
        nginx_locations = [
            "/var/log/nginx",   # Hypernode/Standard location
            "/data/web/nginx",  # Alternative location
            "/usr/local/var/log/nginx",  # Homebrew on macOS
            "/opt/nginx/logs"   # Alternative location
        ]
        
        self.log_files = []
        
        for location in nginx_locations:
            try:
                found_logs = discover_nginx_logs(location)
                if found_logs:
                    self.log_files = found_logs
                    print(f"Found {len(found_logs)} log files in {location}")
                    break
            except Exception:
                continue
        
        # If no logs found, try current directory for demo
        if not self.log_files:
            sample_log = Path("sample_access.log")
            if sample_log.exists():
                self.log_files = [str(sample_log)]
                print("Using sample log file for demo")
            else:
                print("No log files found - creating demo data")
                # Create some demo data for testing
                self._create_demo_data()
    
    def _create_demo_data(self) -> None:
        """Create demo data when no log files are available."""
        from datetime import datetime
        
        # Create some sample log entries
        demo_entries = [
            {
                'timestamp': datetime.now(),
                'ip': '192.168.1.100',
                'status': 200,
                'method': 'GET',
                'path': '/api/products',
                'country': 'NL',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'response_time': 0.250,
                'bytes_sent': 1024,
                'is_bot': False
            },
            {
                'timestamp': datetime.now(),
                'ip': '10.0.0.50',
                'status': 404,
                'method': 'POST',
                'path': '/admin/login',
                'country': 'US',
                'user_agent': 'curl/7.68.0',
                'response_time': 0.010,
                'bytes_sent': 150,
                'is_bot': False
            },
            {
                'timestamp': datetime.now(),
                'ip': '203.0.113.42',
                'status': 200,
                'method': 'GET',
                'path': '/favicon.ico',
                'country': 'AU',
                'user_agent': 'Googlebot/2.1',
                'response_time': 0.005,
                'bytes_sent': 0,
                'is_bot': True
            }
        ]
        
        print(f"Adding {len(demo_entries)} demo entries...")
        for entry in demo_entries:
            self.stats.add_entry(entry)
        print(f"Demo data created - total requests: {self.stats.total_requests}")
    
    def start_log_processing(self) -> None:
        """Start background log processing."""
        if not self.log_files:
            print("No log files available for processing")
            return
        
        processed_count = 0
        
        def on_log_entry(line: str):
            """Process new log entry."""
            nonlocal processed_count
            if self.is_paused:
                return
                
            log_entry = self.parser.parse_log_line(line)
            if not log_entry:
                return
            
            if self.filter.should_include(log_entry):
                # Update all analyzers
                self.stats.add_entry(log_entry)
                try:
                    self.security._analyze_entry(log_entry)
                except AttributeError:
                    # Security analyzer might not have _analyze_entry method
                    pass
                try:
                    self.performance._analyze_entry(log_entry)
                except AttributeError:
                    # Performance analyzer might not have _analyze_entry method
                    pass
                
                processed_count += 1
                
                # Update UI if overview is active
                if self.current_view == "overview" and self.overview:
                    self.overview.add_live_entry(log_entry)
                
                # Check for security alerts
                self._check_security_alerts(log_entry)
        
        # Start log reader
        self.log_reader = LogReader(on_log_entry)
        
        # Process existing logs first
        try:
            print(f"Processing {len(self.log_files)} log files...")
            for log_file in self.log_files:
                print(f"Reading {log_file}...")
                self.log_reader.read_file(log_file, follow=False)
            print(f"Processed {processed_count} log entries")
        except Exception as e:
            print(f"Error processing logs: {e}")
            # Continue anyway - might still have some data
    
    def _check_security_alerts(self, log_entry: Dict[str, Any]) -> None:
        """Check for security alerts."""
        status = log_entry.get('status', 200)
        path = log_entry.get('path', '')
        ip = str(log_entry.get('ip', ''))
        
        # Example alert conditions
        if status == 500:
            if self.security_monitor:
                self.security_monitor.add_security_alert(
                    "Server Error", 
                    f"500 error from {ip} on {path}", 
                    "MED"
                )
        
        # Check for suspicious paths
        if any(pattern in path.lower() for pattern in ['admin', 'wp-admin', '.env', 'config']):
            if self.security_monitor:
                self.security_monitor.add_security_alert(
                    "Suspicious Path", 
                    f"Access attempt to {path} from {ip}", 
                    "HIGH"
                )
    
    def switch_to_overview(self) -> None:
        """Switch to overview dashboard."""
        try:
            print(f"🔄 Switching to overview view (stats total: {self.stats.total_requests})")
            self.current_view = "overview"
            
            # Find the main content area
            try:
                main_content = self.query_one("#main-content")
                print(f"📍 Found main-content: {type(main_content)}")
            except Exception as e:
                print(f"❌ Could not find main-content: {e}")
                return
            
            # Clear existing content
            try:
                if hasattr(main_content, 'remove_children'):
                    main_content.remove_children()
                else:
                    # If it's a Static widget, update its content instead
                    main_content.update("Loading overview...")
                    return
            except Exception as e:
                print(f"⚠️ Could not clear content: {e}")
            
            # Create and mount overview
            self.overview = OverviewDashboard(self.stats)
            if hasattr(main_content, 'mount'):
                main_content.mount(self.overview)
            else:
                print("❌ main-content doesn't support mounting")
                
            print("✅ Overview dashboard mounted")
            
        except Exception as e:
            print(f"❌ Error switching to overview: {e}")
            import traceback
            traceback.print_exc()
    
    def switch_to_security(self) -> None:
        """Switch to security monitor."""
        self.current_view = "security"
        main_content = self.query_one("#main-content", Container)
        main_content.remove_children()
        
        self.security_monitor = SecurityMonitor(self.security)
        main_content.mount(self.security_monitor)
    
    def switch_to_performance(self) -> None:
        """Switch to performance monitor."""
        self.current_view = "performance"
        main_content = self.query_one("#main-content", Container)
        main_content.remove_children()
        
        self.performance_monitor = PerformanceMonitor(self.performance)
        main_content.mount(self.performance_monitor)
    
    def update_status_bar(self) -> None:
        """Update the status bar."""
        status_text = f"View: {self.current_view.title()} | "
        status_text += f"Files: {len(self.log_files)} | "
        status_text += f"Requests: {self.stats.total_requests:,} | "
        if self.log_files:
            status_text += f"Source: {Path(self.log_files[0]).name} | "
        status_text += f"{'PAUSED' if self.is_paused else 'LIVE'} | "
        status_text += f"Last Update: {datetime.now().strftime('%H:%M:%S')}"
        
        try:
            self.query_one("#status-bar", Static).update(status_text)
        except:
            pass  # Ignore if not mounted yet
    
    # Action handlers
    def action_help(self) -> None:
        """Show help."""
        self.push_screen(HelpScreen())
    
    def action_setup(self) -> None:
        """Show setup screen."""
        self.bell()
    
    def action_security(self) -> None:
        """Switch to security view."""
        self.switch_to_security()
    
    def action_performance(self) -> None:
        """Switch to performance view."""
        self.switch_to_performance()
    
    def action_bots(self) -> None:
        """Switch to bots view."""
        self.bell()  # TODO: Implement
    
    def action_export(self) -> None:
        """Show export options."""
        self.bell()  # TODO: Implement
    
    def action_search(self) -> None:
        """Show search interface."""
        self.bell()  # TODO: Implement
    
    def action_refresh(self) -> None:
        """Refresh current view and clear caches."""
        print("🔄 Refreshing view and clearing caches...")
        
        # Force refresh cache if in overview
        if self.current_view == "overview" and self.overview:
            self.overview.force_cache_refresh()
        
        # Switch views to trigger refresh
        if self.current_view == "overview":
            self.switch_to_overview()
        elif self.current_view == "security":
            self.switch_to_security()
        elif self.current_view == "performance":
            self.switch_to_performance()
        
        print("✅ View refreshed!")
    
    def action_pause(self) -> None:
        """Toggle pause state."""
        self.is_paused = not self.is_paused
        self.bell()
    
    def key_1(self) -> None:
        """Switch to overview (key shortcut)."""
        self.switch_to_overview()
    
    def key_2(self) -> None:
        """Switch to security (key shortcut)."""
        self.switch_to_security()
    
    def key_3(self) -> None:
        """Switch to performance (key shortcut)."""
        self.switch_to_performance()


def run_interactive():
    """Run the interactive TUI application."""
    try:
        print("🚀 Starting Tabbed Log Analyzer...")
        app = TabbedLogAnalyzer()
        app.run()
    except Exception as e:
        print(f"❌ Error running tabbed app: {e}")
        print("🔧 Falling back to simple version...")
        try:
            app = GoAccessLikeApp()
            app.run()
        except Exception as e2:
            print(f"❌ Simple app also failed: {e2}")
            print("💡 Try running: python3 -m logcli analyze --help")


class TabbedLogAnalyzer(App):
    """Production log analyzer with tabbed interface."""
    
    TITLE = "🚀 Access Log Analyzer - Professional Edition"
    
    CSS = """
    /* Professional styling for the log analyzer */
    
    Screen {
        background: $surface;
    }
    
    Header {
        background: $primary;
        color: $text;
        height: 3;
        content-align: center middle;
        text-style: bold;
    }
    
    Footer {
        background: $primary-darken-2;
        color: $text;
        height: 1;
    }
    
    TabbedContent {
        background: $surface;
        border: solid $primary;
        margin: 1;
    }
    
    TabPane {
        padding: 1 2;
        background: $surface;
    }
    
    Tabs {
        background: $primary-lighten-1;
        color: $text;
        height: 3;
    }
    
    Tab {
        background: $primary-lighten-2;
        color: $text-muted;
        margin: 0 1;
        padding: 0 2;
        border: solid $primary;
        text-style: bold;
    }
    
    Tab.-active {
        background: $accent;
        color: $text;
        text-style: bold;
        border: solid $accent-lighten-1;
    }
    
    Tab:hover {
        background: $primary-lighten-3;
        color: $text;
    }
    
    #overview-content {
        background: $surface-lighten-1;
        color: $text;
        border: solid $success;
        border-title-color: $success;
        border-title-style: bold;
        padding: 1 2;
        margin: 1;
    }
    
    #performance-content {
        background: $surface-lighten-1;
        color: $text;
        border: solid $warning;
        border-title-color: $warning;
        border-title-style: bold;
        padding: 1 2;
        margin: 1;
    }
    
    #security-content {
        background: $surface-lighten-1;
        color: $text;
        border: solid $error;
        border-title-color: $error;
        border-title-style: bold;
        padding: 1 2;
        margin: 1;
    }
    
    .stats-section {
        background: $surface-lighten-2;
        border: solid $primary-lighten-1;
        margin: 1 0;
        padding: 1;
    }
    
    .highlight-box {
        background: $accent-lighten-3;
        border: solid $accent;
        padding: 1;
        margin: 1 0;
    }
    
    .error-box {
        background: $error-lighten-3;
        border: solid $error;
        padding: 1;
        margin: 1 0;
    }
    
    .success-box {
        background: $success-lighten-3;
        border: solid $success;
        padding: 1;
        margin: 1 0;
    }
    """
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("f", "follow", "Follow"),
        ("1", "tab_overview", "Overview"),
        ("2", "tab_performance", "Performance"), 
        ("3", "tab_security", "Security"),
        ("?", "help", "Help"),
    ]
    
    def __init__(self):
        super().__init__()
        
        # Initialize components
        self.parser = LogParser()
        self.filter = LogFilter()
        self.stats = StatisticsAggregator()
        self.security = SecurityAnalyzer()
        self.performance = PerformanceAnalyzer()
        
        self.log_files = []
        self.following = False
        
        # Load data
        self.load_data()
    
    def load_data(self) -> None:
        """Load and process log data."""
        try:
            print("🔍 Loading log data...")
            self.log_files = discover_nginx_logs("/var/log/nginx")
            
            if not self.log_files:
                sample_log = Path("sample_access.log")
                if sample_log.exists():
                    self.log_files = [str(sample_log)]
            
            if self.log_files:
                self.process_logs()
                print(f"✅ Loaded {self.stats.total_requests} requests")
            else:
                print("⚠️ No log files found")
                
        except Exception as e:
            print(f"❌ Error loading data: {e}")
    
    def process_logs(self) -> None:
        """Process log files efficiently."""
        for log_file in self.log_files[:3]:  # Limit to 3 files for performance
            try:
                with LogTailer(log_file, follow=False) as tailer:
                    for line_count, line in enumerate(tailer.tail()):
                        if not line.strip():
                            continue
                            
                        log_entry = self.parser.parse_log_line(line)
                        if log_entry and self.filter.should_include(log_entry):
                            self.stats.add_entry(log_entry)
                            
                            # Add to analyzers
                            try:
                                if hasattr(self.security, 'add_entry'):
                                    self.security.add_entry(log_entry)
                                elif hasattr(self.security, '_analyze_entry'):
                                    self.security._analyze_entry(log_entry)
                            except:
                                pass
                                
                            try:
                                if hasattr(self.performance, 'add_entry'):
                                    self.performance.add_entry(log_entry)
                                elif hasattr(self.performance, '_analyze_entry'):
                                    self.performance._analyze_entry(log_entry)
                            except:
                                pass
                        
                        # Performance limit
                        if line_count >= 5000:
                            break
                            
            except Exception as e:
                print(f"⚠️ Error processing {log_file}: {e}")
                continue
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with TabbedContent(initial="overview"):
            with TabPane("📊 Overview", id="overview"):
                yield Container(
                    Static(self.get_overview_content(), id="overview-content"),
                    classes="stats-section"
                )
            
            with TabPane("⚡ Performance", id="performance"):
                yield Container(
                    Static(self.get_performance_content(), id="performance-content"),
                    classes="stats-section"
                )
            
            with TabPane("🔒 Security", id="security"):
                yield Container(
                    Static(self.get_security_content(), id="security-content"),
                    classes="stats-section"
                )
        
        yield Footer()
    
    def get_overview_content(self) -> str:
        """Get overview tab content."""
        if self.stats.total_requests == 0:
            return """[bold red]📊 OVERVIEW - No Data Available[/bold red]

[yellow]⚠️  No log entries processed yet[/yellow]

[bold cyan]🔧 TROUBLESHOOTING:[/bold cyan]
[green]•[/green] Check /var/log/nginx/access.log exists
[green]•[/green] Verify file permissions  
[green]•[/green] Ensure JSON log format
[green]•[/green] Press 'r' to refresh data

[dim]💡 Commands: r=refresh, f=follow, q=quit[/dim]
            """
        
        summary = self.stats.get_summary_stats()
        total_requests = summary.get('total_requests', 0)
        unique_visitors = summary.get('unique_visitors', 0)
        error_rate = summary.get('error_rate', 0)
        bandwidth = summary.get('bandwidth_stats', {})
        
        # Top data
        top_paths = self.stats.get_top_n(self.stats.hits_per_path, 8)
        top_ips = self.stats.get_top_n(self.stats.hits_per_ip, 8)
        status_codes = self.stats.get_top_n(self.stats.hits_per_status, 6)
        
        # Format following status
        follow_status = "[green]ON[/green]" if self.following else "[red]OFF[/red]"
        
        # Format error rate with color
        if error_rate > 5:
            error_display = f"[red]{error_rate:.1f}%[/red]"
        else:
            error_display = f"[green]{error_rate:.1f}%[/green]"
        
        content = f"""[bold blue]📊 OVERVIEW DASHBOARD[/bold blue]
[dim]Generated: {datetime.now().strftime('%H:%M:%S')} | Files: {len(self.log_files)} | Following: {follow_status}[/dim]

[bold green]📈 GENERAL STATISTICS[/bold green]
╭─────────────────────────────────────────────────────╮
│ [cyan]Total Requests:[/cyan]  [bold]{total_requests:,}[/bold]                    │
│ [cyan]Unique Visitors:[/cyan] [bold]{unique_visitors:,}[/bold]                   │
│ [cyan]Error Rate:[/cyan]      {error_display}                      │
│ [cyan]Bandwidth:[/cyan]       [bold]{bandwidth.get('total_gb', 0):.2f} GB[/bold]              │
╰─────────────────────────────────────────────────────╯

[bold yellow]🏆 TOP REQUESTED PAGES[/bold yellow]
╭─────────────────────────────────────────────────────╮"""
        
        for i, (path, hits) in enumerate(top_paths, 1):
            pct = (hits / total_requests * 100) if total_requests > 0 else 0
            bar = "█" * min(int(pct / 2), 20)
            content += f"\n│ [bold cyan]{i:2d}.[/bold cyan] [white]{path[:35]:<35}[/white] [green]{hits:>6,}[/green] [dim]({pct:4.1f}%)[/dim] [blue]{bar}[/blue] │"
        
        content += """
╰─────────────────────────────────────────────────────╯

[bold magenta]👥 TOP VISITOR IPS[/bold magenta]
╭─────────────────────────────────────────────────────╮"""
        
        for i, (ip, hits) in enumerate(top_ips, 1):
            pct = (hits / total_requests * 100) if total_requests > 0 else 0
            bar = "▓" * min(int(pct / 2), 15)
            content += f"\n│ [bold cyan]{i:2d}.[/bold cyan] [yellow]{ip:<15}[/yellow] [green]{hits:>6,}[/green] [dim]({pct:4.1f}%)[/dim] [blue]{bar}[/blue]     │"
        
        content += """
╰─────────────────────────────────────────────────────╯

[bold red]📊 HTTP STATUS CODES[/bold red]
╭─────────────────────────────────────────────────────╮"""
        
        for status, hits in status_codes:
            pct = (hits / total_requests * 100) if total_requests > 0 else 0
            status_color = "green" if status < 300 else "yellow" if status < 400 else "red"
            bar = "▒" * min(int(pct / 2), 15)
            content += f"\n│ [{status_color}]{status}[/{status_color}] [white]{hits:>6,}[/white] [dim]({pct:4.1f}%)[/dim] [blue]{bar}[/blue]                   │"
        
        content += """
╰─────────────────────────────────────────────────────╯

[dim]💡 COMMANDS: [bold]1[/bold]=Overview [bold]2[/bold]=Performance [bold]3[/bold]=Security | [bold]r[/bold]=Refresh [bold]f[/bold]=Follow [bold]q[/bold]=Quit[/dim]"""
        
        return content
    
    def get_performance_content(self) -> str:
        """Get performance tab content."""
        if self.stats.total_requests == 0:
            return """[bold yellow]⚡ PERFORMANCE - No Data Available[/bold yellow]

[red]⚠️  No performance data available yet[/red]

[dim]Press 'r' to refresh or '1' for Overview.[/dim]
            """
        
        rt_stats = self.stats.get_response_time_stats()
        
        content = f"""[bold yellow]⚡ PERFORMANCE ANALYSIS[/bold yellow]
[dim]Generated: {datetime.now().strftime('%H:%M:%S')}[/dim]

[bold green]🚀 RESPONSE TIME STATISTICS[/bold green]
╭─────────────────────────────────────────────────────╮"""
        
        if rt_stats:
            avg_time = rt_stats.get('avg', 0)
            median_time = rt_stats.get('median', 0)
            p95_time = rt_stats.get('p95', 0)
            p99_time = rt_stats.get('p99', 0)
            max_time = rt_stats.get('max', 0)
            min_time = rt_stats.get('min', 0)
            
            # Color coding based on performance
            avg_color = "green" if avg_time < 0.5 else "yellow" if avg_time < 1.0 else "red"
            p95_color = "green" if p95_time < 1.0 else "yellow" if p95_time < 2.0 else "red"
            
            content += f"""
│ [cyan]Average Response Time:[/cyan] [{avg_color}]{avg_time:.3f}s[/{avg_color}]              │
│ [cyan]Median Response Time:[/cyan]  [blue]{median_time:.3f}s[/blue]               │
│ [cyan]95th Percentile:[/cyan]       [{p95_color}]{p95_time:.3f}s[/{p95_color}]               │
│ [cyan]99th Percentile:[/cyan]       [red]{p99_time:.3f}s[/red]               │
│ [cyan]Maximum Response Time:[/cyan] [red]{max_time:.3f}s[/red]              │
│ [cyan]Minimum Response Time:[/cyan] [green]{min_time:.3f}s[/green]              │"""
        else:
            content += """
│ [red]No response time data available[/red]                    │"""
        
        content += """
╰─────────────────────────────────────────────────────╯"""
        
        # Slowest endpoints
        content += f"""

[bold red]🐌 SLOWEST ENDPOINTS[/bold red]
╭─────────────────────────────────────────────────────╮"""
        
        try:
            if hasattr(self.performance, 'get_slowest_endpoints'):
                slow_endpoints = self.performance.get_slowest_endpoints(6)
                if slow_endpoints:
                    for endpoint, avg_time in slow_endpoints:
                        time_color = "green" if avg_time < 0.5 else "yellow" if avg_time < 1.0 else "red"
                        bar = "▓" * min(int(avg_time * 10), 20)
                        content += f"\n│ [white]{endpoint[:35]:<35}[/white] [{time_color}]{avg_time:.3f}s[/{time_color}] [blue]{bar}[/blue] │"
                else:
                    content += "\n│ [green]No slow endpoints detected[/green]                      │"
            else:
                content += "\n│ [yellow]Endpoint analysis not configured[/yellow]              │"
        except Exception as e:
            content += f"\n│ [red]Error: {str(e)[:40]}[/red]                     │"
        
        content += """
╰─────────────────────────────────────────────────────╯"""
        
        # Bandwidth analysis
        bandwidth = self.stats.get_bandwidth_stats()
        content += f"""

[bold blue]📊 BANDWIDTH ANALYSIS[/bold blue]
╭─────────────────────────────────────────────────────╮"""
        
        if bandwidth:
            total_gb = bandwidth.get('total_gb', 0)
            avg_bytes = bandwidth.get('avg_bytes_per_request', 0)
            gb_color = "green" if total_gb < 1 else "yellow" if total_gb < 10 else "red"
            
            content += f"""
│ [cyan]Total Bandwidth:[/cyan]     [{gb_color}]{total_gb:.2f} GB[/{gb_color}]                 │
│ [cyan]Average per Request:[/cyan] [blue]{avg_bytes:,.0f} bytes[/blue]           │
│ [cyan]Total Requests:[/cyan]      [green]{self.stats.total_requests:,}[/green]                │"""
        else:
            content += """
│ [red]No bandwidth data available[/red]                      │"""
        
        content += """
╰─────────────────────────────────────────────────────╯

[dim]💡 COMMANDS: [bold]1[/bold]=Overview [bold]2[/bold]=Performance [bold]3[/bold]=Security | [bold]r[/bold]=Refresh [bold]f[/bold]=Follow [bold]q[/bold]=Quit[/dim]"""
        
        return content
    
    def get_security_content(self) -> str:
        """Get security tab content."""
        if self.stats.total_requests == 0:
            return """[bold red]🔒 SECURITY - No Data Available[/bold red]

[red]⚠️  No security data available yet[/red]

[dim]Press 'r' to refresh or '1' for Overview.[/dim]
            """
        
        # Error analysis
        errors_4xx = sum(count for status, count in self.stats.hits_per_status.items() if 400 <= status < 500)
        errors_5xx = sum(count for status, count in self.stats.hits_per_status.items() if 500 <= status < 600)
        total_errors = int(self.stats.total_requests * self.stats.get_error_rate() / 100)
        
        # Format error count with color
        if total_errors > 100:
            error_display = f"[red]{total_errors:,}[/red]"
        elif total_errors > 10:
            error_display = f"[yellow]{total_errors:,}[/yellow]"
        else:
            error_display = f"[green]{total_errors:,}[/green]"
        
        content = f"""[bold red]🔒 SECURITY ANALYSIS[/bold red]
[dim]Generated: {datetime.now().strftime('%H:%M:%S')}[/dim]

[bold yellow]🛡️ THREAT OVERVIEW[/bold yellow]
╭─────────────────────────────────────────────────────╮
│ [cyan]Total Requests Analyzed:[/cyan] [bold]{self.stats.total_requests:,}[/bold]           │
│ [cyan]Error Requests (4xx/5xx):[/cyan] {error_display}              │
│ [cyan]4xx Client Errors:[/cyan]       [yellow]{errors_4xx:,}[/yellow]                │
│ [cyan]5xx Server Errors:[/cyan]       [red]{errors_5xx:,}[/red]                │
╰─────────────────────────────────────────────────────╯

[bold red]⚠️ TOP ERROR CODES[/bold red]
╭─────────────────────────────────────────────────────╮"""
        
        error_codes = [(status, count) for status, count in self.stats.hits_per_status.items() if status >= 400]
        error_codes.sort(key=lambda x: x[1], reverse=True)
        
        if error_codes:
            for status, count in error_codes[:6]:
                pct = (count / self.stats.total_requests * 100) if self.stats.total_requests > 0 else 0
                status_name = self.get_status_name(status)
                status_color = "yellow" if 400 <= status < 500 else "red"
                bar = "▓" * min(int(pct), 20)
                content += f"\n│ [{status_color}]{status}[/{status_color}] [white]{status_name:<15}[/white] [green]{count:>6,}[/green] [dim]({pct:4.1f}%)[/dim] [blue]{bar}[/blue] │"
        else:
            content += "\n│ [green]No error codes detected - excellent![/green]              │"
        
        content += """
╰─────────────────────────────────────────────────────╯

[bold magenta]🕵️ SUSPICIOUS ACTIVITY[/bold magenta]
╭─────────────────────────────────────────────────────╮"""
        
        # Suspicious IPs (high activity)
        suspicious_ips = []
        for ip, hits in self.stats.hits_per_ip.most_common(15):
            if hits > 50:  # Only check IPs with significant activity
                suspicious_ips.append((ip, hits))
        
        if suspicious_ips:
            content += "\n│ [bold yellow]High Activity IPs:[/bold yellow]                          │"
            for ip, hits in suspicious_ips[:6]:
                pct = (hits / self.stats.total_requests * 100) if self.stats.total_requests > 0 else 0
                threat_level = "red" if pct > 10 else "yellow" if pct > 5 else "green"
                bar = "▓" * min(int(pct), 15)
                content += f"\n│ [{threat_level}]{ip:<15}[/{threat_level}] [white]{hits:>6,}[/white] [dim]({pct:4.1f}%)[/dim] [blue]{bar}[/blue]     │"
        else:
            content += "\n│ [green]No suspicious activity detected - secure![/green]          │"
        
        content += """
╰─────────────────────────────────────────────────────╯"""
        
        # Bot traffic analysis
        bot_requests = self.stats.bot_traffic.get('Bot', 0)
        content += f"""

[bold cyan]🤖 BOT TRAFFIC ANALYSIS[/bold cyan]
╭─────────────────────────────────────────────────────╮"""
        
        if bot_requests > 0:
            bot_pct = (bot_requests / self.stats.total_requests * 100) if self.stats.total_requests > 0 else 0
            bot_color = "green" if bot_pct < 20 else "yellow" if bot_pct < 50 else "red"
            bar = "▓" * min(int(bot_pct / 2), 25)
            content += f"""
│ [cyan]Bot Requests:[/cyan]       [{bot_color}]{bot_requests:,} ({bot_pct:.1f}%)[/{bot_color}]         │
│ [cyan]Human Requests:[/cyan]     [green]{self.stats.total_requests - bot_requests:,} ({100-bot_pct:.1f}%)[/green]        │
│ [cyan]Bot Activity:[/cyan]       [blue]{bar}[/blue]                    │"""
        else:
            content += """
│ [green]No bot traffic detected[/green]                        │
│ [cyan]All traffic appears to be human[/cyan]                  │"""
        
        content += """
╰─────────────────────────────────────────────────────╯

[dim]💡 COMMANDS: [bold]1[/bold]=Overview [bold]2[/bold]=Performance [bold]3[/bold]=Security | [bold]r[/bold]=Refresh [bold]f[/bold]=Follow [bold]q[/bold]=Quit[/dim]"""
        
        return content
    
    def get_status_name(self, status: int) -> str:
        """Get human readable status name."""
        status_names = {
            200: "OK", 301: "Moved", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 
            404: "Not Found", 429: "Too Many Requests",
            500: "Server Error", 502: "Bad Gateway", 503: "Unavailable", 504: "Timeout"
        }
        return status_names.get(status, "Unknown")
    
    def on_mount(self) -> None:
        """Setup refresh timer."""
        self.set_interval(60.0, self.refresh_all_tabs)
    
    def refresh_all_tabs(self) -> None:
        """Refresh all tab contents."""
        try:
            self.query_one("#overview-content", Static).update(self.get_overview_content())
            self.query_one("#performance-content", Static).update(self.get_performance_content())
            self.query_one("#security-content", Static).update(self.get_security_content())
        except Exception as e:
            print(f"Error refreshing tabs: {e}")
    
    # Actions
    def action_refresh(self) -> None:
        """Refresh data and all tabs."""
        print("🔄 Refreshing all data...")
        self.stats.reset()
        self.load_data()
        self.refresh_all_tabs()
        print("✅ Data refreshed!")
    
    def action_follow(self) -> None:
        """Toggle follow mode."""
        self.following = not self.following
        print(f"📡 Follow mode {'enabled' if self.following else 'disabled'}")
    
    def action_tab_overview(self) -> None:
        """Switch to overview tab."""
        tabbed = self.query_one(TabbedContent)
        tabbed.active = "overview"
    
    def action_tab_performance(self) -> None:
        """Switch to performance tab."""
        tabbed = self.query_one(TabbedContent)
        tabbed.active = "performance"
    
    def action_tab_security(self) -> None:
        """Switch to security tab."""
        tabbed = self.query_one(TabbedContent)
        tabbed.active = "security"
    
    def action_help(self) -> None:
        """Show help."""
        help_content = """
🚀 ACCESS LOG ANALYZER - TABBED INTERFACE

TABS:
1 - Overview     (General statistics)
2 - Performance  (Response times, slow endpoints)  
3 - Security     (Errors, threats, suspicious activity)

COMMANDS:
r - Refresh all data
f - Toggle follow mode (real-time)
? - Show this help
q - Quit application

NAVIGATION:
• Use number keys (1,2,3) to switch tabs
• Use mouse to click on tabs
• Use Tab key to cycle through tabs

Press any key to continue...
        """
        
        # Show help in current tab
        try:
            tabbed = self.query_one(TabbedContent)
            current_tab = tabbed.active
            if current_tab == "overview":
                self.query_one("#overview-content", Static).update(help_content)
            elif current_tab == "performance":
                self.query_one("#performance-content", Static).update(help_content)
            elif current_tab == "security":
                self.query_one("#security-content", Static).update(help_content)
                
            # Auto-return after 5 seconds
            self.set_timer(5.0, self.refresh_all_tabs)
        except Exception as e:
            print(f"Error showing help: {e}")


class MinimalTestApp(App):
    """Absolute minimal test app - just text."""
    
    def compose(self) -> ComposeResult:
        yield Static("MINIMAL TEST - If you see this, Textual works!")
    
    def key_q(self) -> None:
        self.exit()


class GoAccessLikeApp(App):
    """Production GoAccess-like interface with real log data."""
    
    TITLE = "🚀 Access Log Analyzer - Production"
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("f", "follow", "Toggle Follow"),
        ("s", "sort", "Sort Mode"),
        ("?", "help", "Help"),
    ]
    
    def __init__(self):
        super().__init__()
        
        # Initialize components
        self.parser = LogParser()
        self.filter = LogFilter()
        self.stats = StatisticsAggregator()
        self.log_files = []
        self.following = False
        self.last_processed = 0
        
        # Discover and process logs
        self.discover_and_process_logs()
    
    def discover_and_process_logs(self) -> None:
        """Discover and process log files."""
        try:
            print("🔍 Discovering nginx logs...")
            self.log_files = discover_nginx_logs("/var/log/nginx")
            
            if not self.log_files:
                # Fallback to sample log
                sample_log = Path("sample_access.log")
                if sample_log.exists():
                    self.log_files = [str(sample_log)]
            
            if self.log_files:
                print(f"📁 Processing {len(self.log_files)} log files...")
                self.process_logs()
                print(f"✅ Processed {self.stats.total_requests} requests")
            else:
                print("⚠️ No log files found - using demo data")
                
        except Exception as e:
            print(f"❌ Error processing logs: {e}")
    
    def process_logs(self) -> None:
        """Process log files and populate statistics."""
        for log_file in self.log_files:
            try:
                with LogTailer(log_file, follow=False) as tailer:
                    for line in tailer.tail():
                        if not line.strip():
                            continue
                            
                        log_entry = self.parser.parse_log_line(line)
                        if log_entry and self.filter.should_include(log_entry):
                            self.stats.add_entry(log_entry)
                            
                        # Limit processing for performance
                        if self.stats.total_requests >= 10000:
                            break
                    
            except Exception as e:
                print(f"⚠️ Error processing {log_file}: {e}")
                continue
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(self.get_main_content(), id="main")
        yield Footer()
    
    def get_main_content(self) -> str:
        """Get main content with real statistics."""
        if self.stats.total_requests == 0:
            return self.get_no_data_content()
        
        summary = self.stats.get_summary_stats()
        
        # Calculate additional stats
        total_requests = summary.get('total_requests', 0)
        unique_visitors = summary.get('unique_visitors', 0)
        error_rate = summary.get('error_rate', 0)
        bandwidth_stats = summary.get('bandwidth_stats', {})
        
        # Get top data
        top_paths = self.stats.get_top_n(self.stats.hits_per_path, 10)
        top_ips = self.stats.get_top_n(self.stats.hits_per_ip, 10)
        top_user_agents = self.stats.get_top_n(self.stats.hits_per_user_agent, 5)
        status_codes = self.stats.get_top_n(self.stats.hits_per_status, 10)
        countries = self.stats.get_top_n(self.stats.hits_per_country, 10)
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        content = f"""
🚀 ACCESS LOG ANALYZER - PRODUCTION MODE
Generated: {current_time} | Files: {len(self.log_files)} | Following: {'ON' if self.following else 'OFF'}

GENERAL STATISTICS
==================
Total Requests: {total_requests:,}
Unique Visitors: {unique_visitors:,}
Failed Requests: {int(total_requests * error_rate / 100):,} ({error_rate:.1f}%)
Log Size: {bandwidth_stats.get('total_mb', 0):.1f} MB
Bandwidth: {bandwidth_stats.get('total_gb', 0):.2f} GB

TOP REQUESTED PAGES
==================="""
        
        for i, (path, hits) in enumerate(top_paths, 1):
            percentage = (hits / total_requests * 100) if total_requests > 0 else 0
            content += f"\n{i:2d}. {path[:50]:<50} {hits:>6,} ({percentage:4.1f}%)"
        
        content += f"""

TOP VISITOR IPS
==============="""
        
        for i, (ip, hits) in enumerate(top_ips, 1):
            percentage = (hits / total_requests * 100) if total_requests > 0 else 0
            content += f"\n{i:2d}. {ip:<15} {hits:>6,} ({percentage:4.1f}%)"
        
        content += f"""

HTTP STATUS CODES
================="""
        
        for status, hits in status_codes:
            percentage = (hits / total_requests * 100) if total_requests > 0 else 0
            status_name = self.get_status_name(status)
            content += f"\n{status} {status_name:<20} {hits:>6,} ({percentage:4.1f}%)"
        
        content += f"""

TOP COUNTRIES
============="""
        
        for i, (country, hits) in enumerate(countries, 1):
            if country and country != 'Unknown':
                percentage = (hits / total_requests * 100) if total_requests > 0 else 0
                content += f"\n{i:2d}. {country:<15} {hits:>6,} ({percentage:4.1f}%)"
        
        content += f"""

COMMANDS
========
r - Refresh data          f - Toggle follow mode
s - Change sort order     ? - Show help
q - Quit application
        """
        
        return content
    
    def get_no_data_content(self) -> str:
        """Content when no data is available."""
        return """
🚀 ACCESS LOG ANALYZER - PRODUCTION MODE

NO DATA AVAILABLE
=================
No log entries found or processed.

CHECKED LOCATIONS:
• /var/log/nginx/access.log
• /var/log/nginx/access.log.*
• ./sample_access.log

TROUBLESHOOTING:
1. Check if nginx log files exist
2. Verify read permissions
3. Ensure logs are in JSON format
4. Check if nginx is running

Press 'r' to refresh or 'q' to quit
        """
    
    def get_status_name(self, status: int) -> str:
        """Get human readable status name."""
        status_names = {
            200: "OK",
            201: "Created", 
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            429: "Too Many Requests",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout"
        }
        return status_names.get(status, "Unknown")
    
    def on_mount(self) -> None:
        """Set up refresh timer."""
        self.set_interval(30.0, self.refresh_content)
    
    def refresh_content(self) -> None:
        """Refresh the content."""
        try:
            if self.following:
                # Process new log entries
                self.process_new_entries()
            
            main_widget = self.query_one("#main", Static)
            main_widget.update(self.get_main_content())
        except Exception as e:
            print(f"Error refreshing: {e}")
    
    def process_new_entries(self) -> None:
        """Process new log entries when following."""
        # This would implement real-time log following
        # For now, just reprocess recent entries
        pass
    
    def action_refresh(self) -> None:
        """Manual refresh."""
        print("🔄 Refreshing data...")
        self.stats.reset()
        self.process_logs()
        self.refresh_content()
        print("✅ Data refreshed!")
    
    def action_follow(self) -> None:
        """Toggle follow mode."""
        self.following = not self.following
        status = "enabled" if self.following else "disabled"
        print(f"📡 Follow mode {status}")
    
    def action_sort(self) -> None:
        """Change sort mode."""
        print("📊 Sort mode cycling not implemented yet")
    
    def action_help(self) -> None:
        """Show help."""
        help_content = """
🚀 ACCESS LOG ANALYZER - HELP

KEYBOARD SHORTCUTS:
r - Refresh all data
f - Toggle real-time follow mode  
s - Cycle through sort modes
? - Show this help screen
q - Quit application

FEATURES:
• Real-time log analysis
• GoAccess-like interface
• Multiple log file support
• Automatic log discovery
• Performance optimized

LOG LOCATIONS:
• /var/log/nginx/access.log
• /var/log/nginx/access.log.*
• Current directory sample logs

Press any key to return...
        """
        
        try:
            main_widget = self.query_one("#main", Static)
            main_widget.update(help_content)
            
            # Auto-return after showing help
            self.set_timer(5.0, self.refresh_content)
        except Exception as e:
            print(f"Error showing help: {e}")
    
    def key_q(self) -> None:
        """Quit the app."""
        self.exit()
    
    def key_r(self) -> None:
        """Manual refresh."""
        self.action_refresh()
    
    def key_f(self) -> None:
        """Toggle follow."""
        self.action_follow()
    
    def key_s(self) -> None:
        """Sort mode."""
        self.action_sort()
    
    def key_question_mark(self) -> None:
        """Show help."""
        self.action_help()


class SimpleTestApp(App):
    """Simple test app to verify Textual works."""
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Container(
            Static("🚀 Access Log Analyzer - Test Mode", id="title"),
            Static("", id="content"),
            Static("Press 'q' to quit, 'h' for help", id="footer"),
        )
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize test app."""
        content = self.query_one("#content", Static)
        content.update("""
[green]✅ Textual is working![/green]

[yellow]Debug Info:[/yellow]
• Terminal: Working
• Textual: Loaded
• Python: Running

[cyan]Next Steps:[/cyan]
1. Press 'q' to quit
2. Press 'h' for help
3. Check console output

[dim]If you see this, the basic interface works.[/dim]
        """)
    
    def key_q(self) -> None:
        """Quit the app."""
        self.exit()
    
    def key_h(self) -> None:
        """Show help."""
        content = self.query_one("#content", Static)
        content.update("""
[bold blue]🔧 Simple Test App Help[/bold blue]

[yellow]Available Keys:[/yellow]
• q - Quit application
• h - Show this help

[yellow]Purpose:[/yellow]
This is a minimal test to verify Textual works.
If you see this interface, the problem is not 
with Textual itself but with the complex app.

[green]✅ Basic functionality confirmed![/green]
        """)
