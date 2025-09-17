"""Interactive CLI interface using Rich and Textual."""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Header, Footer, DataTable, Static, Button, Label,
    TabbedContent, TabPane, Input, Select, Switch
)
from textual.reactive import reactive
from textual.binding import Binding
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn

from .aggregators import StatisticsAggregator, RealTimeAggregator
from .filters import LogFilter, FilterPresets
from .export import DataExporter, create_report_summary


class LogAnalyzerTUI(App):
    """Main Textual application for log analysis."""
    
    CSS_PATH = "ui.css"
    TITLE = " Access Log Analyzer"
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("f", "toggle_filters", "Filters"),
        Binding("e", "export_data", "Export"),
        Binding("r", "refresh", "Refresh"),
        Binding("t", "toggle_timeline", "Timeline"),
        Binding("ctrl+c", "quit", "Quit", show=False),
    ]
    
    # Reactive attributes
    current_stats = reactive(None)
    filter_active = reactive(False)
    
    def __init__(self, stats_aggregator: StatisticsAggregator, log_filter: LogFilter):
        super().__init__()
        self.stats = stats_aggregator
        self.filter = log_filter
        self.exporter = DataExporter()
        self.refresh_timer = None
        
    def compose(self) -> ComposeResult:
        """Compose the UI layout."""
        yield Header()
        
        with TabbedContent(initial="overview"):
            with TabPane("Overview", id="overview"):
                yield Container(
                    Static(id="summary-stats"),
                    Static(id="quick-stats"),
                    id="overview-container"
                )
            
            with TabPane("Countries", id="countries"):
                yield DataTable(id="countries-table")
            
            with TabPane("IPs", id="ips"):
                yield DataTable(id="ips-table")
            
            with TabPane("Paths", id="paths"):
                yield DataTable(id="paths-table")
            
            with TabPane("Status Codes", id="status"):
                yield DataTable(id="status-table")
            
            with TabPane("User Agents", id="useragents"):
                yield DataTable(id="useragents-table")
            
            with TabPane("Timeline", id="timeline"):
                yield Static(id="timeline-chart")
            
            with TabPane("Filters", id="filters"):
                yield Container(
                    Vertical(
                        Label("Active Filters:"),
                        Static(id="active-filters"),
                        Label("Quick Filters:"),
                        Horizontal(
                            Button("Errors Only", id="filter-errors"),
                            Button("No Bots", id="filter-nobots"),
                            Button("API Only", id="filter-api"),
                            Button("Clear All", id="filter-clear"),
                        ),
                        Label("Country Filter:"),
                        Input(placeholder="Enter countries (e.g., US,GB,DE)", id="country-input"),
                        Button("Apply Country Filter", id="apply-country"),
                        Label("Status Filter:"),
                        Input(placeholder="Enter status codes (e.g., 404,500)", id="status-input"),
                        Button("Apply Status Filter", id="apply-status"),
                        Switch(value=False, id="exclude-bots"),
                        Label("Exclude Bots"),
                    ),
                    id="filters-container"
                )
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the UI when mounted."""
        self.update_all_displays()
        
        # Set up refresh timer
        self.set_interval(2.0, self.update_all_displays)
    
    def update_all_displays(self) -> None:
        """Update all display components with current data."""
        self.update_summary_stats()
        self.update_tables()
        self.update_filters_display()
    
    def update_summary_stats(self) -> None:
        """Update the summary statistics display."""
        summary = self.stats.get_summary_stats()
        time_stats = summary.get('time_range_stats', {})
        
        summary_text = f"""[bold blue]📊 ANALYSIS OVERVIEW[/bold blue]
"""
        
        # Time range information
        if time_stats.get('earliest_timestamp') and time_stats.get('latest_timestamp'):
            summary_text += f"""
[bold cyan]⏰ TIME RANGE[/bold cyan]
From: [green]{time_stats['earliest_timestamp'].strftime('%Y-%m-%d %H:%M:%S')}[/green]
To: [green]{time_stats['latest_timestamp'].strftime('%Y-%m-%d %H:%M:%S')}[/green]
"""
            if time_stats.get('time_span_hours', 0) > 24:
                summary_text += f"Duration: [yellow]{time_stats.get('time_span_days', 0):.1f} days[/yellow]\n"
            else:
                summary_text += f"Duration: [yellow]{time_stats.get('time_span_hours', 0):.1f} hours[/yellow]\n"
        
        summary_text += f"""
[bold green]📈 TRAFFIC STATISTICS[/bold green]
Total Requests: [green]{summary.get('total_requests', 0):,}[/green]
Unique Visitors: [green]{summary.get('unique_visitors', 0):,}[/green]
"""
        
        if time_stats.get('requests_per_hour', 0) > 0:
            summary_text += f"""Requests/Hour: [cyan]{time_stats.get('requests_per_hour', 0):.1f}[/cyan]
Requests/Minute: [cyan]{time_stats.get('requests_per_minute', 0):.1f}[/cyan]
"""
        
        summary_text += f"""Error Rate: [red]{summary.get('error_rate', 0):.2f}%[/red]
Bot Traffic: [yellow]{summary.get('bot_percentage', 0):.2f}%[/yellow]
"""
        
        rt_stats = summary.get('response_time_stats', {})
        if rt_stats:
            summary_text += f"""
[bold purple]⚡ PERFORMANCE[/bold purple]
Average: [cyan]{rt_stats.get('avg', 0):.3f}s[/cyan]
Maximum: [red]{rt_stats.get('max', 0):.3f}s[/red]
95th Percentile: [yellow]{rt_stats.get('p95', 0):.3f}s[/yellow]
"""
        
        bandwidth = summary.get('bandwidth_stats', {})
        if bandwidth:
            summary_text += f"""
[bold magenta]💾 BANDWIDTH[/bold magenta]
Total: [green]{bandwidth.get('total_gb', 0):.2f} GB[/green]
Avg/Request: [cyan]{bandwidth.get('avg_bytes_per_request', 0):,.0f} bytes[/cyan]
"""
        
        summary_widget = self.query_one("#summary-stats", Static)
        summary_widget.update(summary_text)
    
    def update_tables(self) -> None:
        """Update all data tables."""
        self.update_countries_table()
        self.update_ips_table()
        self.update_paths_table()
        self.update_status_table()
        self.update_useragents_table()
    
    def update_countries_table(self) -> None:
        """Update countries table."""
        table = self.query_one("#countries-table", DataTable)
        table.clear(columns=True)
        
        table.add_columns("Country", "Hits", "Percentage")
        
        total_requests = max(self.stats.total_requests, 1)
        for country, hits in self.stats.get_top_n(self.stats.hits_per_country, 20):
            percentage = (hits / total_requests) * 100
            table.add_row(
                country or "Unknown",
                f"{hits:,}",
                f"{percentage:.1f}%"
            )
    
    def update_ips_table(self) -> None:
        """Update IPs table."""
        table = self.query_one("#ips-table", DataTable)
        table.clear(columns=True)
        
        table.add_columns("IP Address", "Hits", "Percentage")
        
        total_requests = max(self.stats.total_requests, 1)
        for ip, hits in self.stats.get_top_n(self.stats.hits_per_ip, 50):
            percentage = (hits / total_requests) * 100
            table.add_row(
                ip,
                f"{hits:,}",
                f"{percentage:.1f}%"
            )
    
    def update_paths_table(self) -> None:
        """Update paths table."""
        table = self.query_one("#paths-table", DataTable)
        table.clear(columns=True)
        
        table.add_columns("Path", "Hits", "Percentage")
        
        total_requests = max(self.stats.total_requests, 1)
        for path, hits in self.stats.get_top_n(self.stats.hits_per_path, 50):
            percentage = (hits / total_requests) * 100
            # Truncate long paths
            display_path = path[:80] + "..." if len(path) > 80 else path
            table.add_row(
                display_path,
                f"{hits:,}",
                f"{percentage:.1f}%"
            )
    
    def update_status_table(self) -> None:
        """Update status codes table."""
        table = self.query_one("#status-table", DataTable)
        table.clear(columns=True)
        
        table.add_columns("Status Code", "Count", "Percentage", "Category")
        
        total_requests = max(self.stats.total_requests, 1)
        for status, count in sorted(self.stats.hits_per_status.items()):
            percentage = (count / total_requests) * 100
            
            # Determine category
            if 200 <= status < 300:
                category = "Success"
            elif 300 <= status < 400:
                category = "Redirect"
            elif 400 <= status < 500:
                category = "Client Error"
            elif 500 <= status < 600:
                category = "Server Error"
            else:
                category = "Other"
            
            table.add_row(
                str(status),
                f"{count:,}",
                f"{percentage:.1f}%",
                category
            )
    
    def update_useragents_table(self) -> None:
        """Update user agents table."""
        table = self.query_one("#useragents-table", DataTable)
        table.clear(columns=True)
        
        table.add_columns("User Agent", "Hits", "Type")
        
        for ua, hits in self.stats.get_top_n(self.stats.hits_per_user_agent, 30):
            # Truncate long user agents
            display_ua = ua[:100] + "..." if len(ua) > 100 else ua
            
            # Determine if it's a bot
            ua_type = "Bot" if any(bot_sig in ua.lower() for bot_sig in ['bot', 'crawler', 'spider']) else "Browser"
            
            table.add_row(
                display_ua,
                f"{hits:,}",
                ua_type
            )
    
    def update_filters_display(self) -> None:
        """Update the active filters display."""
        active_filters = self.filter.get_active_filters()
        
        if active_filters:
            filters_text = "\n".join([f"• {key}: {value}" for key, value in active_filters.items()])
        else:
            filters_text = "No active filters"
        
        filters_widget = self.query_one("#active-filters", Static)
        filters_widget.update(filters_text)
    
    # Button handlers
    @on(Button.Pressed, "#filter-errors")
    def handle_errors_filter(self) -> None:
        """Apply errors only filter."""
        self.filter.update_filters(**FilterPresets.errors_only())
        self.update_filters_display()
    
    @on(Button.Pressed, "#filter-nobots")
    def handle_nobots_filter(self) -> None:
        """Apply no bots filter."""
        self.filter.update_filters(**FilterPresets.no_bots())
        self.update_filters_display()
    
    @on(Button.Pressed, "#filter-api")
    def handle_api_filter(self) -> None:
        """Apply API only filter."""
        self.filter.update_filters(**FilterPresets.api_only())
        self.update_filters_display()
    
    @on(Button.Pressed, "#filter-clear")
    def handle_clear_filters(self) -> None:
        """Clear all filters."""
        self.filter.clear_filters()
        self.update_filters_display()
    
    @on(Button.Pressed, "#apply-country")
    def handle_country_filter(self) -> None:
        """Apply country filter."""
        country_input = self.query_one("#country-input", Input)
        countries = [c.strip().upper() for c in country_input.value.split(",") if c.strip()]
        if countries:
            self.filter.update_filters(countries=countries)
            self.update_filters_display()
            country_input.value = ""
    
    @on(Button.Pressed, "#apply-status")
    def handle_status_filter(self) -> None:
        """Apply status filter."""
        status_input = self.query_one("#status-input", Input)
        try:
            status_codes = [int(s.strip()) for s in status_input.value.split(",") if s.strip()]
            if status_codes:
                self.filter.update_filters(status_codes=status_codes)
                self.update_filters_display()
                status_input.value = ""
        except ValueError:
            pass  # Invalid input, ignore
    
    @on(Switch.Changed, "#exclude-bots")
    def handle_bot_toggle(self, event: Switch.Changed) -> None:
        """Handle bot exclusion toggle."""
        self.filter.update_filters(exclude_bots=event.value)
        self.update_filters_display()
    
    # Action handlers
    def action_toggle_filters(self) -> None:
        """Toggle filters tab."""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = "filters"
    
    def action_export_data(self) -> None:
        """Export current data."""
        try:
            # Export to multiple formats
            csv_file = self.exporter.export_to_csv(self.stats)
            json_file = self.exporter.export_to_json(self.stats)
            summary_file = create_report_summary(self.stats)
            
            self.notify(f"Data exported to: {csv_file}, {json_file}, {summary_file}")
        except Exception as e:
            self.notify(f"Export failed: {str(e)}", severity="error")
    
    def action_refresh(self) -> None:
        """Manually refresh all data."""
        self.update_all_displays()
        self.notify("Data refreshed")
    
    def action_toggle_timeline(self) -> None:
        """Toggle timeline view."""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = "timeline"


class SimpleConsoleUI:
    """Simple console-based UI using Rich for non-interactive mode."""
    
    def __init__(self, stats: StatisticsAggregator):
        self.stats = stats
        self.console = Console()
    
    def display_summary(self) -> None:
        """Display a summary of statistics."""
        summary = self.stats.get_summary_stats()
        time_stats = summary.get('time_range_stats', {})
        
        # Create time range table first
        if time_stats.get('earliest_timestamp') and time_stats.get('latest_timestamp'):
            time_table = Table(title="⏰ Analysis Time Range", show_header=True)
            time_table.add_column("Metric", style="bold cyan")
            time_table.add_column("Value", style="green")
            
            time_table.add_row("From", time_stats['earliest_timestamp'].strftime('%Y-%m-%d %H:%M:%S'))
            time_table.add_row("To", time_stats['latest_timestamp'].strftime('%Y-%m-%d %H:%M:%S'))
            
            if time_stats.get('time_span_hours', 0) > 24:
                time_table.add_row("Duration", f"{time_stats.get('time_span_days', 0):.1f} days")
            else:
                time_table.add_row("Duration", f"{time_stats.get('time_span_hours', 0):.1f} hours")
            
            if time_stats.get('requests_per_hour', 0) > 0:
                time_table.add_row("Requests/Hour", f"{time_stats.get('requests_per_hour', 0):.1f}")
                time_table.add_row("Requests/Minute", f"{time_stats.get('requests_per_minute', 0):.1f}")
            
            self.console.print(time_table)
            self.console.print()
        
        # Create summary table
        summary_table = Table(title="📊 Traffic Statistics", show_header=True)
        summary_table.add_column("Metric", style="bold blue")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Total Requests", f"{summary.get('total_requests', 0):,}")
        summary_table.add_row("Unique Visitors", f"{summary.get('unique_visitors', 0):,}")
        summary_table.add_row("Error Rate", f"{summary.get('error_rate', 0):.2f}%")
        summary_table.add_row("Bot Traffic", f"{summary.get('bot_percentage', 0):.2f}%")
        
        rt_stats = summary.get('response_time_stats', {})
        if rt_stats:
            summary_table.add_row("Avg Response Time", f"{rt_stats.get('avg', 0):.3f}s")
            summary_table.add_row("Max Response Time", f"{rt_stats.get('max', 0):.3f}s")
            summary_table.add_row("95th Percentile", f"{rt_stats.get('p95', 0):.3f}s")
        
        bandwidth = summary.get('bandwidth_stats', {})
        if bandwidth:
            summary_table.add_row("Total Bandwidth", f"{bandwidth.get('total_gb', 0):.2f} GB")
            summary_table.add_row("Avg/Request", f"{bandwidth.get('avg_bytes_per_request', 0):,.0f} bytes")
        
        self.console.print(summary_table)
        self.console.print()
        
        # Top countries
        countries_table = Table(title="Top Countries", show_header=True)
        countries_table.add_column("Country", style="bold")
        countries_table.add_column("Hits", justify="right", style="green")
        countries_table.add_column("Percentage", justify="right", style="cyan")
        
        total = max(summary.get('total_requests', 1), 1)
        for country, hits in self.stats.get_top_n(self.stats.hits_per_country, 10):
            percentage = (hits / total) * 100
            countries_table.add_row(
                country or "Unknown",
                f"{hits:,}",
                f"{percentage:.1f}%"
            )
        
        self.console.print(countries_table)
        self.console.print()
        
        # Status codes
        status_table = Table(title="Status Codes", show_header=True)
        status_table.add_column("Status", style="bold")
        status_table.add_column("Count", justify="right", style="green")
        status_table.add_column("Percentage", justify="right", style="cyan")
        
        for status, count in sorted(self.stats.hits_per_status.items()):
            percentage = (count / total) * 100
            status_table.add_row(
                str(status),
                f"{count:,}",
                f"{percentage:.1f}%"
            )
        
        self.console.print(status_table)
        self.console.print()
        
        # Top User Agents
        ua_table = Table(title="Top User Agents", show_header=True)
        ua_table.add_column("User Agent", style="bold", max_width=80)
        ua_table.add_column("Hits", justify="right", style="green")
        ua_table.add_column("Type", justify="center", style="cyan")
        
        for ua, hits in self.stats.get_top_n(self.stats.hits_per_user_agent, 15):
            # Determine if it's a bot
            ua_type = "Bot" if any(bot_sig in ua.lower() for bot_sig in ['bot', 'crawler', 'spider', 'curl', 'wget']) else "Browser"
            
            # Truncate long user agents
            display_ua = ua[:77] + "..." if len(ua) > 80 else ua
            
            ua_table.add_row(
                display_ua,
                f"{hits:,}",
                ua_type
            )
        
        self.console.print(ua_table)
        self.console.print()
        
        # Top IPs
        ip_table = Table(title="Top IP Addresses", show_header=True)
        ip_table.add_column("IP Address", style="bold")
        ip_table.add_column("Hits", justify="right", style="green")
        ip_table.add_column("Percentage", justify="right", style="cyan")
        
        for ip, hits in self.stats.get_top_n(self.stats.hits_per_ip, 15):
            percentage = (hits / total) * 100
            ip_table.add_row(
                ip,
                f"{hits:,}",
                f"{percentage:.1f}%"
            )
        
        self.console.print(ip_table)
        self.console.print()
        
        # Top Paths
        path_table = Table(title="Top Requested Paths", show_header=True)
        path_table.add_column("Path", style="bold", max_width=60)
        path_table.add_column("Hits", justify="right", style="green")
        path_table.add_column("Percentage", justify="right", style="cyan")
        
        for path, hits in self.stats.get_top_n(self.stats.hits_per_path, 15):
            percentage = (hits / total) * 100
            # Truncate long paths
            display_path = path[:57] + "..." if len(path) > 60 else path
            
            path_table.add_row(
                display_path,
                f"{hits:,}",
                f"{percentage:.1f}%"
            )
        
        self.console.print(path_table)
        self.console.print()
        
        # Bot Analysis
        if self.stats.bot_traffic:
            bot_table = Table(title="Bot Analysis", show_header=True)
            bot_table.add_column("Bot Type", style="bold")
            bot_table.add_column("Requests", justify="right", style="green")
            bot_table.add_column("Percentage", justify="right", style="cyan")
            
            total_bot_requests = self.stats.bot_traffic.get('Bot', 0)
            if total_bot_requests > 0:
                for bot_type, count in self.stats.get_top_n(self.stats.bot_types, 10):
                    percentage = (count / total_bot_requests) * 100
                    bot_table.add_row(
                        bot_type,
                        f"{count:,}",
                        f"{percentage:.1f}%"
                    )
                
                self.console.print(bot_table)
                self.console.print()
        
        # Browser/OS Statistics
        if self.stats.hits_per_browser:
            browser_table = Table(title="Top Browsers", show_header=True)
            browser_table.add_column("Browser", style="bold")
            browser_table.add_column("Hits", justify="right", style="green")
            browser_table.add_column("Percentage", justify="right", style="cyan")
            
            for browser, hits in self.stats.get_top_n(self.stats.hits_per_browser, 10):
                percentage = (hits / total) * 100
                browser_table.add_row(
                    browser,
                    f"{hits:,}",
                    f"{percentage:.1f}%"
                )
            
            self.console.print(browser_table)
            self.console.print()
        
        if self.stats.hits_per_os:
            os_table = Table(title="Top Operating Systems", show_header=True)
            os_table.add_column("Operating System", style="bold")
            os_table.add_column("Hits", justify="right", style="green")
            os_table.add_column("Percentage", justify="right", style="cyan")
            
            for os, hits in self.stats.get_top_n(self.stats.hits_per_os, 10):
                percentage = (hits / total) * 100
                os_table.add_row(
                    os,
                    f"{hits:,}",
                    f"{percentage:.1f}%"
                )
            
            self.console.print(os_table)
    
    def display_live_stats(self, refresh_interval: float = 2.0) -> None:
        """Display live updating statistics."""
        with Live(self.generate_live_display(), refresh_per_second=1/refresh_interval) as live:
            try:
                while True:
                    live.update(self.generate_live_display())
                    import time
                    time.sleep(refresh_interval)
            except KeyboardInterrupt:
                pass
    
    def generate_live_display(self) -> Layout:
        """Generate the live display layout."""
        layout = Layout()
        
        layout.split_column(
            Layout(self.create_summary_panel(), name="summary", size=10),
            Layout(self.create_countries_panel(), name="countries"),
        )
        
        return layout
    
    def create_summary_panel(self) -> Panel:
        """Create summary statistics panel."""
        summary = self.stats.get_summary_stats()
        
        text = f"""Total Requests: {summary.get('total_requests', 0):,}
Unique Visitors: {summary.get('unique_visitors', 0):,}
Error Rate: {summary.get('error_rate', 0):.2f}%
Bot Traffic: {summary.get('bot_percentage', 0):.2f}%

Last Updated: {datetime.now().strftime('%H:%M:%S')}"""
        
        return Panel(text, title="Summary", border_style="blue")
    
    def create_countries_panel(self) -> Panel:
        """Create top countries panel."""
        countries_text = ""
        total = max(self.stats.total_requests, 1)
        
        for country, hits in self.stats.get_top_n(self.stats.hits_per_country, 10):
            percentage = (hits / total) * 100
            countries_text += f"{country or 'Unknown':<15} {hits:>8,} ({percentage:>5.1f}%)\n"
        
        return Panel(countries_text, title="Top Countries", border_style="green")
