"""Main CLI entry point for the log analyzer."""

import sys
import os
import glob
import signal
import asyncio
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .parser import LogParser
from .filters import LogFilter, create_filter_from_preset
from .aggregators import StatisticsAggregator, RealTimeAggregator
from .log_reader import LogReader
from .ui import LogAnalyzerTUI, SimpleConsoleUI
from .export import DataExporter, create_report_summary
from .config import HYPERNODE_SETTINGS
from .hypernode_command import get_hypernode_command


def complete_countries(ctx, param, incomplete):
    """Autocomplete function for country codes."""
    countries = [
        'US', 'GB', 'DE', 'NL', 'FR', 'ES', 'IT', 'CA', 'AU', 'JP',
        'CN', 'IN', 'BR', 'RU', 'MX', 'KR', 'SE', 'NO', 'DK', 'FI',
        'CH', 'AT', 'BE', 'PL', 'CZ', 'PT', 'IE', 'GR', 'HU', 'RO'
    ]
    return [country for country in countries if country.lower().startswith(incomplete.lower())]


def complete_status_codes(ctx, param, incomplete):
    """Autocomplete function for HTTP status codes."""
    status_codes = [
        '200', '201', '204', '301', '302', '304', '400', '401', '403', 
        '404', '405', '429', '500', '502', '503', '504'
    ]
    return [code for code in status_codes if code.startswith(incomplete)]


def complete_filter_presets(ctx, param, incomplete):
    """Autocomplete function for filter presets."""
    presets = ['errors_only', 'success_only', 'no_bots', 'api_only', 'recent_activity']
    return [preset for preset in presets if preset.startswith(incomplete)]


def complete_report_formats(ctx, param, incomplete):
    """Autocomplete function for report formats."""
    formats = ['html', 'json', 'text']
    return [fmt for fmt in formats if fmt.startswith(incomplete)]


console = Console()


def parse_time_filters(from_time: Optional[str], to_time: Optional[str], 
                      last_hours: Optional[int], last_days: Optional[int]) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Parse time filtering parameters into datetime objects."""
    from datetime import datetime, timedelta
    
    start_time = None
    end_time = None
    
    # Handle relative time filters first
    if last_hours:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=last_hours)
    elif last_days:
        end_time = datetime.now()
        start_time = end_time - timedelta(days=last_days)
    
    # Handle absolute time filters (override relative if specified)
    if from_time:
        start_time = parse_datetime_string(from_time)
    if to_time:
        end_time = parse_datetime_string(to_time)
    
    return start_time, end_time


def parse_datetime_string(date_str: str) -> Optional[datetime]:
    """Parse a datetime string in various formats."""
    from datetime import datetime
    
    # Common formats to try
    formats = [
        '%Y-%m-%d %H:%M:%S',    # 2024-01-01 10:30:00
        '%Y-%m-%d %H:%M',       # 2024-01-01 10:30
        '%Y-%m-%d',             # 2024-01-01 (will use 00:00:00)
        '%Y/%m/%d %H:%M:%S',    # 2024/01/01 10:30:00
        '%Y/%m/%d %H:%M',       # 2024/01/01 10:30
        '%Y/%m/%d',             # 2024/01/01
        '%d-%m-%Y %H:%M:%S',    # 01-01-2024 10:30:00
        '%d-%m-%Y %H:%M',       # 01-01-2024 10:30
        '%d-%m-%Y',             # 01-01-2024
        '%d/%m/%Y %H:%M:%S',    # 01/01/2024 10:30:00
        '%d/%m/%Y %H:%M',       # 01/01/2024 10:30
        '%d/%m/%Y',             # 01/01/2024
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    
    console.print(f"[red]Unable to parse datetime: {date_str}[/red]")
    console.print(f"[yellow]Supported formats: YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, etc.[/yellow]")
    return None


def is_hypernode_platform() -> bool:
    """Detect if running on Hypernode platform."""
    # Check for common Hypernode indicators
    hypernode_indicators = [
        '/data/web',  # Common Hypernode directory structure
        '/var/log/nginx',  # Hypernode nginx logs location
        os.path.exists('/etc/hypernode'),  # Hypernode config directory
    ]
    
    return any(os.path.exists(path) for path in hypernode_indicators[:2]) or hypernode_indicators[2]


@click.group(invoke_without_command=True, context_settings={'help_option_names': ['-h', '--help']})
@click.option('--install-completion', is_flag=True, help='Install shell completion for bash/zsh/fish')
@click.pass_context
def cli(ctx, install_completion):
    """🚀 Hypernode Log Analyzer - Advanced CLI tool for Nginx log analysis.
    
    A comprehensive log analysis toolkit specifically designed for Hypernode environments,
    featuring direct log parsing via hypernode-parse-nginx-log command, security analysis, 
    and performance insights.
    
    \b
    Quick Start:
      hlogcli analyze                           # Analyze current day logs
      hlogcli analyze --summary-only            # Quick overview
      hlogcli security                          # Security analysis
      hlogcli perf --response-time-analysis     # Performance analysis
      hlogcli bots                              # Bot analysis and classification
      hlogcli api                               # API endpoint analysis
      hlogcli content                           # Content type and resource analysis
      hlogcli anomalies                         # Anomaly detection and ML analysis
      hlogcli search --status 404               # Search for specific entries
      hlogcli report --format html              # Generate comprehensive reports
    
    \b
    Features:
      • Direct integration with hypernode-parse-nginx-log command
      • Real-time log data retrieval (always fresh, no cache needed)
      • Security threat detection and analysis
      • Performance optimization insights
      • Advanced bot behavior analysis and AI bot detection
      • Advanced search and filtering capabilities
      • Multiple export formats (CSV, JSON, HTML charts)
      • Comprehensive reporting with interactive visualizations
      • Configuration management and user profiles
    """
    if install_completion:
        import subprocess
        import sys
        
        shell = os.environ.get('SHELL', '').split('/')[-1]
        if shell in ['bash', 'zsh', 'fish']:
            try:
                # Generate completion script
                completion_script = f"""
# Hypernode Log Analyzer shell completion
eval "$(_HLOGCLI_COMPLETE={shell}_source hlogcli)"
"""
                
                if shell == 'bash':
                    completion_file = os.path.expanduser('~/.bashrc')
                elif shell == 'zsh':
                    completion_file = os.path.expanduser('~/.zshrc')
                elif shell == 'fish':
                    completion_file = os.path.expanduser('~/.config/fish/config.fish')
                
                # Check if completion is already installed
                if os.path.exists(completion_file):
                    with open(completion_file, 'r') as f:
                        if '_HLOGCLI_COMPLETE' in f.read():
                            console.print(f"[yellow]Shell completion already installed for {shell}[/yellow]")
                            return
                
                # Add completion to shell config
                with open(completion_file, 'a') as f:
                    f.write(completion_script)
                
                console.print(f"[green]✅ Shell completion installed for {shell}![/green]")
                console.print(f"[blue]Please restart your shell or run: source {completion_file}[/blue]")
                
            except Exception as e:
                console.print(f"[red]Failed to install completion: {e}[/red]")
        else:
            console.print(f"[red]Unsupported shell: {shell}. Supported: bash, zsh, fish[/red]")
        
        return
    
    # If no command is specified, show custom help without usage line
    if ctx.invoked_subcommand is None:
        # Show custom help without the "Usage:" line
        help_text = ctx.get_help()
        lines = help_text.split('\n')
        # Skip the first line which contains "Usage: python -m logcli.main..."
        filtered_lines = []
        skip_usage = True
        for line in lines:
            if skip_usage and line.strip().startswith('Usage:'):
                continue
            elif skip_usage and line.strip() == '':
                skip_usage = False
                continue
            else:
                skip_usage = False
                filtered_lines.append(line)
        
        console.print('\n'.join(filtered_lines))
        return

@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--follow', '-f', is_flag=True, help='Follow log files for real-time analysis')
@click.option('--interactive', '-i', is_flag=True, help='Launch interactive TUI')
@click.option('--output', '-o', help='Output directory for exports')
@click.option('--filter-preset', type=click.Choice(['errors_only', 'success_only', 'no_bots', 'api_only', 'recent_activity']))
@click.option('--countries', help='Filter by countries (comma-separated, e.g., US,GB,DE)')
@click.option('--status-codes', help='Filter by status codes (comma-separated, e.g., 404,500)')
@click.option('--exclude-bots', is_flag=True, help='Exclude bot traffic')
@click.option('--from-time', '--from', help='Start time for filtering (YYYY-MM-DD HH:MM:SS or YYYY-MM-DD)')
@click.option('--to-time', '--to', help='End time for filtering (YYYY-MM-DD HH:MM:SS or YYYY-MM-DD)')
@click.option('--last-hours', type=int, help='Show entries from last N hours')
@click.option('--last-days', type=int, help='Show entries from last N days')
@click.option('--export-csv', is_flag=True, help='Export results to CSV')
@click.option('--export-json', is_flag=True, help='Export results to JSON')
@click.option('--export-charts', is_flag=True, help='Export charts to HTML')
@click.option('--summary-only', is_flag=True, help='Show only summary statistics')
@click.option('--yesterday', is_flag=True, help='Analyze yesterday\'s logs instead of today\'s')
def analyze(log_files, follow, interactive, output, filter_preset, countries, status_codes, 
         exclude_bots, from_time, to_time, last_hours, last_days, export_csv, export_json, export_charts, summary_only, yesterday):
    """📊 Analyze Nginx JSON access logs with comprehensive statistics and insights.
    
    This is the main analysis command that provides detailed insights into your web traffic,
    including visitor statistics, geographic distribution, response times, error rates,
    and bot activity analysis.
    
    \b
    🔍 What you'll see:
      • Traffic overview (requests, visitors, error rates)
      • Geographic distribution of visitors
      • Top IP addresses and requested paths
      • User agent analysis (browsers, bots, crawlers)
      • Response time statistics
      • Status code breakdown
      • Bot classification and behavior
    
    \b
    📁 Auto-Discovery:
      By default, automatically finds and analyzes all nginx access logs.
      Works on Hypernode platforms and standard nginx installations.
    
    \b
    💡 Examples:
      hlogcli analyze                           # Full analysis (today's logs)
      hlogcli analyze --yesterday               # Analyze yesterday's logs
      hlogcli analyze --summary-only            # Quick overview only
      hlogcli analyze --countries US,NL,DE     # Filter by countries
      hlogcli analyze --exclude-bots            # Exclude bot traffic
      hlogcli analyze --export-csv --export-charts  # Export results
      
      # Time filtering:
      hlogcli analyze --last-hours 24          # Last 24 hours only
      hlogcli analyze --last-days 7            # Last 7 days only
      hlogcli analyze --from "2024-01-01" --to "2024-01-02"  # Specific date range
      hlogcli analyze --from "2024-01-01 10:00:00"           # From specific datetime
    """
    
    # Note: We no longer use file discovery - data comes from hypernode command
    # The log_files parameter is kept for backward compatibility but ignored
    
    
    # Initialize components
    parser = LogParser()
    log_filter = LogFilter()
    stats = StatisticsAggregator()
    
    # Apply filter preset
    if filter_preset:
        preset_filter = create_filter_from_preset(filter_preset)
        log_filter.update_filters(**preset_filter.filters)
    
    # Apply command line filters
    if countries:
        country_list = [c.strip().upper() for c in countries.split(',')]
        log_filter.add_country_filter(country_list)
    
    if status_codes:
        try:
            status_list = [int(s.strip()) for s in status_codes.split(',')]
            log_filter.add_status_filter(status_list)
        except ValueError:
            console.print("[red]Invalid status codes format[/red]")
            sys.exit(1)
    
    if exclude_bots:
        log_filter.toggle_bot_filter()
    
    # Apply time filters
    if from_time or to_time or last_hours or last_days:
        start_time, end_time = parse_time_filters(from_time, to_time, last_hours, last_days)
        if start_time or end_time:
            log_filter.set_time_range(start_time, end_time)
            if start_time and end_time:
                console.print(f"[blue]Time filter: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}[/blue]")
            elif start_time:
                console.print(f"[blue]Time filter: from {start_time.strftime('%Y-%m-%d %H:%M:%S')}[/blue]")
            elif end_time:
                console.print(f"[blue]Time filter: until {end_time.strftime('%Y-%m-%d %H:%M:%S')}[/blue]")
    
    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        console.print("\n[yellow]Shutting down gracefully...[/yellow]")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if follow and interactive:
            # Real-time interactive mode
            run_interactive_realtime(log_files, parser, log_filter, stats)
        elif follow:
            # Real-time console mode
            run_realtime_console(log_files, parser, log_filter, stats)
        elif interactive:
            # Interactive mode with existing data
            process_hypernode_logs(log_filter, stats, use_yesterday=yesterday)
            run_interactive_static(stats, log_filter)
        else:
            # Batch processing mode with integrated security and API analysis
            security_analyzer, api_analyzer = process_hypernode_logs_with_enhanced_analysis(log_filter, stats, use_yesterday=yesterday)
            
            if summary_only:
                display_summary_only(stats)
                # Display enhanced analysis results at the end for summary mode too
                display_enhanced_security_analysis(security_analyzer)
                display_enhanced_api_analysis(api_analyzer)
            else:
                ui = SimpleConsoleUI(stats)
                ui.display_summary()
                # Display enhanced analysis results at the end
                display_enhanced_security_analysis(security_analyzer)
                display_enhanced_api_analysis(api_analyzer)
            
            # Handle exports
            if any([export_csv, export_json, export_charts]):
                handle_exports(stats, output, export_csv, export_json, export_charts)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)


def process_hypernode_logs(log_filter: LogFilter, stats: StatisticsAggregator, additional_args: Optional[List[str]] = None, use_yesterday: bool = False):
    """Process logs using hypernode-parse-nginx-log command."""
    command = get_hypernode_command()
    
    processed_entries = 0
    total_entries = 0
    
    try:
        for log_entry in command.get_log_entries(additional_args, use_yesterday):
            total_entries += 1
            
            # Apply filters
            if log_filter.should_include(log_entry):
                stats.add_entry(log_entry)
                processed_entries += 1
    
    except Exception as e:
        console.print(f"[red]Error processing Hypernode logs: {str(e)}[/red]")
        raise
    
    console.print(f"[green]Processed {processed_entries:,} entries from {total_entries:,} total entries[/green]")


def process_hypernode_logs_with_enhanced_analysis(log_filter: LogFilter, stats: StatisticsAggregator, additional_args: Optional[List[str]] = None, use_yesterday: bool = False):
    """Process logs with enhanced analysis including security patterns and API misuse detection."""
    from .security import SecurityAnalyzer
    from .api_analysis import APIAnalyzer
    
    command = get_hypernode_command()
    
    # Initialize analyzers
    security_analyzer = SecurityAnalyzer()
    api_analyzer = APIAnalyzer()
    
    processed_entries = 0
    total_entries = 0
    
    try:
        console.print("[blue]Processing logs with enhanced security and API analysis...[/blue]")
        
        for log_entry in command.get_log_entries(additional_args, use_yesterday):
            total_entries += 1
            
            # Apply filters for main stats
            if log_filter.should_include(log_entry):
                stats.add_entry(log_entry)
                processed_entries += 1
            
            # Always analyze for security patterns and API misuse (regardless of filters)
            security_analyzer._analyze_entry(log_entry)
            api_analyzer.analyze_entry(log_entry)
    
    except Exception as e:
        console.print(f"[red]Error processing Hypernode logs with enhanced analysis: {str(e)}[/red]")
        raise
    
    console.print(f"[green]Processed {processed_entries:,} entries from {total_entries:,} total entries[/green]")
    
    # Store analyzers for later display
    return security_analyzer, api_analyzer


def process_hypernode_logs_with_callback(callback_func, analysis_type: str = "analysis", additional_args: Optional[List[str]] = None, use_yesterday: bool = False):
    """Process logs using hypernode command with callback function."""
    command = get_hypernode_command()
    
    processed_entries = 0
    total_entries = 0
    
    try:
        for log_entry in command.get_log_entries(additional_args, use_yesterday):
            total_entries += 1
            callback_func(log_entry)
            processed_entries += 1
    
    except Exception as e:
        console.print(f"[red]Error processing Hypernode logs for {analysis_type}: {str(e)}[/red]")
        raise
    
    console.print(f"[green]Processed {processed_entries:,} entries for {analysis_type}[/green]")


def process_log_files(log_files: List[str], parser: LogParser, log_filter: LogFilter, stats: StatisticsAggregator):
    """Process log files and populate statistics."""
    total_lines = 0
    processed_lines = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        
        for log_file in log_files:
            task = progress.add_task(f"Processing {Path(log_file).name}...", total=None)
            
            try:
                with LogReader(lambda line: None) as reader:  # Dummy callback
                    reader.read_file(log_file, follow=False)
                    
                # Actually process the file
                from .log_reader import LogTailer
                with LogTailer(log_file, follow=False) as tailer:
                    for line in tailer.tail():
                        total_lines += 1
                        
                        # Parse log entry
                        log_entry = parser.parse_log_line(line)
                        if not log_entry:
                            continue
                        
                        # Apply filters
                        if log_filter.should_include(log_entry):
                            stats.add_entry(log_entry)
                            processed_lines += 1
                        
                        # Update progress occasionally
                        if total_lines % 1000 == 0:
                            progress.update(task, description=f"Processing {Path(log_file).name}... ({total_lines:,} lines)")
            
            except Exception as e:
                console.print(f"[red]Error processing {log_file}: {str(e)}[/red]")
                continue
            
            progress.remove_task(task)
    
    console.print(f"[green]Processed {processed_lines:,} entries from {total_lines:,} total lines[/green]")


def process_log_files_with_callback(log_files: List[str], parser: LogParser, callback_func, analysis_type: str = "analysis"):
    """Process log files with a callback function and nice progress display."""
    total_lines = 0
    processed_lines = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        
        for log_file in log_files:
            task = progress.add_task(f"Processing {Path(log_file).name}...", total=None)
            
            try:
                # Actually process the file
                from .log_reader import LogTailer
                with LogTailer(log_file, follow=False) as tailer:
                    for line in tailer.tail():
                        total_lines += 1
                        
                        # Parse log entry
                        log_entry = parser.parse_log_line(line)
                        if log_entry:
                            callback_func(log_entry)
                            processed_lines += 1
                        
                        # Update progress more frequently for better user feedback
                        if total_lines % 500 == 0:
                            progress.update(task, description=f"Processing {Path(log_file).name}... ({total_lines:,} lines)")
                            
                        # Yield control occasionally for better responsiveness
                        if total_lines % 5000 == 0:
                            import time
                            time.sleep(0.001)  # Brief yield
            
            except Exception as e:
                console.print(f"[red]Error processing {log_file}: {str(e)}[/red]")
                continue
            
            progress.remove_task(task)
    
    console.print(f"[green]Processed {processed_lines:,} entries from {total_lines:,} total lines[/green]")


def run_realtime_console(log_files: List[str], parser: LogParser, log_filter: LogFilter, stats: StatisticsAggregator):
    """Run real-time analysis in console mode."""
    console.print("[blue]Starting real-time log analysis... Press Ctrl+C to stop[/blue]")
    
    def on_log_line(line: str):
        log_entry = parser.parse_log_line(line)
        if log_entry and log_filter.should_include(log_entry):
            stats.add_entry(log_entry)
    
    ui = SimpleConsoleUI(stats)
    
    # Start log reading in background
    with LogReader(on_log_line) as reader:
        reader.watch_files(log_files)
        
        try:
            ui.display_live_stats(refresh_interval=2.0)
        except KeyboardInterrupt:
            pass


def run_interactive_realtime(log_files: List[str], parser: LogParser, log_filter: LogFilter, stats: StatisticsAggregator):
    """Run real-time analysis in interactive TUI mode."""
    def on_log_line(line: str):
        log_entry = parser.parse_log_line(line)
        if log_entry and log_filter.should_include(log_entry):
            stats.add_entry(log_entry)
    
    # Start log reading
    with LogReader(on_log_line) as reader:
        reader.watch_files(log_files)
        
        # Run TUI
        app = LogAnalyzerTUI(stats, log_filter)
        app.run()


def display_enhanced_security_analysis(security_analyzer):
    """Display enhanced security analysis with focus on patterns and top abusive IPs."""
    console.print("\n[bold red]🛡️  SECURITY ANALYSIS - PATTERNS & THREATS[/bold red]")
    
    # Get security data
    summary = security_analyzer.get_security_summary()
    suspicious_ips = security_analyzer.get_suspicious_ips()[:15]  # Top 15 most threatening IPs
    attack_patterns = security_analyzer.get_attack_patterns()
    
    # Security patterns overview
    if attack_patterns:
        console.print("\n[bold yellow]🔍 Attack Patterns Detected:[/bold yellow]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Attack Type", style="red", no_wrap=True)
        table.add_column("Attempts", justify="right", style="bright_red")
        
        for pattern, count in sorted(attack_patterns.items(), key=lambda x: x[1], reverse=True)[:10]:
            table.add_row(pattern, f"{count:,}")
        console.print(table)
    
    # Top abusive IP addresses with detailed threat info
    if suspicious_ips:
        console.print(f"\n[bold red]⚠️  Top {len(suspicious_ips)} Most Abusive IP Addresses:[/bold red]")
        table = Table(show_header=True, header_style="bold red")
        table.add_column("IP Address", style="bright_red", no_wrap=True, width=15)
        table.add_column("Threat Score", justify="right", style="red", width=12)
        table.add_column("Requests", justify="right", style="yellow", width=10)
        table.add_column("Error Rate", justify="right", style="orange1", width=10)
        table.add_column("Attack Types", style="bright_red", width=25)
        table.add_column("Failed Logins", justify="right", style="red1", width=12)
        
        for ip_data in suspicious_ips:
            ip = ip_data['ip']
            threat_score = f"{ip_data['threat_score']:.1f}"
            requests = f"{ip_data['total_requests']:,}"
            error_rate = f"{ip_data['error_rate']:.1f}%"
            failed_logins = f"{ip_data['failed_logins']:,}"
            
            # Summarize attack types
            attacks = ip_data['attack_attempts']
            attack_summary = []
            if attacks['sql_injection'] > 0:
                attack_summary.append(f"SQL: {attacks['sql_injection']}")
            if attacks['xss'] > 0:
                attack_summary.append(f"XSS: {attacks['xss']}")
            if attacks['directory_traversal'] > 0:
                attack_summary.append(f"DirTrav: {attacks['directory_traversal']}")
            if attacks['command_injection'] > 0:
                attack_summary.append(f"CmdInj: {attacks['command_injection']}")
            
            attack_text = ", ".join(attack_summary) if attack_summary else "High Error Rate"
            
            table.add_row(ip, threat_score, requests, error_rate, attack_text, failed_logins)
        
        console.print(table)
    
    # Quick summary stats
    console.print(f"\n[bold blue]📊 Security Summary:[/bold blue]")
    console.print(f"  • Total attack attempts: [red]{summary.get('total_attack_attempts', 0):,}[/red]")
    console.print(f"  • Suspicious IPs: [yellow]{summary.get('suspicious_ips', 0):,}[/yellow]")
    console.print(f"  • Potential DDoS IPs: [red]{summary.get('potential_ddos_ips', 0):,}[/red]")
    console.print(f"  • Brute force IPs: [orange1]{summary.get('brute_force_ips', 0):,}[/orange1]")


def display_enhanced_api_analysis(api_analyzer):
    """Display enhanced API analysis with focus on misuse and negative calls."""
    console.print("\n[bold blue]🔌 API ANALYSIS - MISUSE & NEGATIVE PATTERNS[/bold blue]")
    
    # Get API data
    api_summary = api_analyzer.get_api_summary()
    security_issues = api_summary.get('security_issues', {})
    
    # API misuse overview
    console.print("\n[bold yellow]⚠️  API Misuse Patterns:[/bold yellow]")
    table = Table(show_header=True, header_style="bold yellow")
    table.add_column("Issue Type", style="yellow", no_wrap=True)
    table.add_column("Count", justify="right", style="bright_red")
    table.add_column("Description", style="white")
    
    misuse_descriptions = {
        'unauthenticated_access': 'Unauthorized API access attempts',
        'excessive_requests': 'IPs with excessive API requests',
        'suspicious_queries': 'Suspicious query patterns detected',
        'potential_abuse': 'High error rate endpoints (potential abuse)'
    }
    
    for issue_type, count in security_issues.items():
        if count > 0:
            description = misuse_descriptions.get(issue_type, 'Unknown issue type')
            table.add_row(issue_type.replace('_', ' ').title(), f"{count:,}", description)
    
    console.print(table)
    
    # Top problematic endpoints with high error rates
    top_endpoints = api_summary.get('top_endpoints', {})
    highest_error_endpoints = top_endpoints.get('highest_error_rate', {})
    
    if highest_error_endpoints:
        console.print(f"\n[bold red]🚫 API Endpoints with High Error Rates:[/bold red]")
        table = Table(show_header=True, header_style="bold red")
        table.add_column("Endpoint", style="red", no_wrap=False, width=50)
        table.add_column("Error Rate", justify="right", style="bright_red", width=12)
        
        for endpoint, error_rate in list(highest_error_endpoints.items())[:10]:
            table.add_row(endpoint, f"{error_rate:.1f}%")
        console.print(table)
    
    # Get top abusive IPs from API analyzer's security issues
    if hasattr(api_analyzer, 'security_issues') and api_analyzer.security_issues.get('excessive_requests'):
        console.print(f"\n[bold red]🎯 Top IPs with Excessive API Requests:[/bold red]")
        table = Table(show_header=True, header_style="bold red")
        table.add_column("IP Address", style="bright_red", no_wrap=True, width=15)
        table.add_column("Excessive Requests", justify="right", style="red", width=18)
        
        excessive_requests = dict(api_analyzer.security_issues['excessive_requests'].most_common(10))
        for ip, count in excessive_requests.items():
            table.add_row(ip, f"{count:,}")
        console.print(table)
    
    # Quick API summary stats
    console.print(f"\n[bold blue]📊 API Summary:[/bold blue]")
    console.print(f"  • Total API requests: [green]{api_summary.get('total_api_requests', 0):,}[/green]")
    console.print(f"  • Total endpoints: [blue]{api_summary.get('total_endpoints', 0):,}[/blue]")
    console.print(f"  • Overall error rate: [red]{api_summary.get('error_rate', 0):.1f}%[/red]")


def run_interactive_static(stats: StatisticsAggregator, log_filter: LogFilter):
    """Run interactive TUI with static data."""
    app = LogAnalyzerTUI(stats, log_filter)
    app.run()


def display_summary_only(stats: StatisticsAggregator):
    """Display only summary statistics."""
    summary = stats.get_summary_stats()
    time_stats = summary.get('time_range_stats', {})
    
    console.print(f"[bold blue]📊 ANALYSIS SUMMARY[/bold blue]")
    
    # Time range information
    if time_stats.get('earliest_timestamp') and time_stats.get('latest_timestamp'):
        console.print(f"[bold cyan]⏰ TIME RANGE[/bold cyan]")
        console.print(f"  From: [green]{time_stats['earliest_timestamp'].strftime('%Y-%m-%d %H:%M:%S')}[/green]")
        console.print(f"  To: [green]{time_stats['latest_timestamp'].strftime('%Y-%m-%d %H:%M:%S')}[/green]")
        
        if time_stats.get('time_span_hours', 0) > 24:
            console.print(f"  Duration: [yellow]{time_stats.get('time_span_days', 0):.1f} days[/yellow]")
        else:
            console.print(f"  Duration: [yellow]{time_stats.get('time_span_hours', 0):.1f} hours[/yellow]")
        console.print()
    
    # Request statistics
    console.print(f"[bold green]📈 TRAFFIC STATISTICS[/bold green]")
    console.print(f"  Total Requests: [green]{summary.get('total_requests', 0):,}[/green]")
    console.print(f"  Unique Visitors: [green]{summary.get('unique_visitors', 0):,}[/green]")
    
    if time_stats.get('requests_per_hour', 0) > 0:
        console.print(f"  Requests/Hour: [cyan]{time_stats.get('requests_per_hour', 0):.1f}[/cyan]")
        console.print(f"  Requests/Minute: [cyan]{time_stats.get('requests_per_minute', 0):.1f}[/cyan]")
    
    console.print(f"  Error Rate: [red]{summary.get('error_rate', 0):.2f}%[/red]")
    console.print(f"  Bot Traffic: [yellow]{summary.get('bot_percentage', 0):.2f}%[/yellow]")
    
    rt_stats = summary.get('response_time_stats', {})
    if rt_stats:
        console.print()
        console.print(f"[bold purple]⚡ PERFORMANCE[/bold purple]")
        console.print(f"  Avg Response Time: [cyan]{rt_stats.get('avg', 0):.3f}s[/cyan]")
        console.print(f"  Max Response Time: [red]{rt_stats.get('max', 0):.3f}s[/red]")
        console.print(f"  95th Percentile: [yellow]{rt_stats.get('p95', 0):.3f}s[/yellow]")


def handle_exports(stats: StatisticsAggregator, output_dir: Optional[str], 
                  export_csv: bool, export_json: bool, export_charts: bool):
    """Handle data exports."""
    exporter = DataExporter(output_dir or "exports")
    
    exported_files = []
    
    if export_csv:
        csv_file = exporter.export_to_csv(stats)
        exported_files.append(csv_file)
        console.print(f"[green]CSV exported to: {csv_file}[/green]")
    
    if export_json:
        json_file = exporter.export_to_json(stats)
        exported_files.append(json_file)
        console.print(f"[green]JSON exported to: {json_file}[/green]")
    
    if export_charts:
        charts_file = exporter.create_charts(stats)
        exported_files.append(charts_file)
        console.print(f"[green]Charts exported to: {charts_file}[/green]")
    
    # Always create a summary report
    summary_file = create_report_summary(stats, f"{exporter.output_dir}/summary.txt")
    exported_files.append(summary_file)
    console.print(f"[green]Summary report: {summary_file}[/green]")


# Security Analysis Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--scan-attacks', is_flag=True, help='Show detailed attack patterns (default: enabled)')
@click.option('--brute-force-detection', is_flag=True, help='Show detailed brute force attempts (default: enabled)')
@click.option('--sql-injection-patterns', is_flag=True, help='Show detailed SQL injection attempts (default: enabled)')
@click.option('--suspicious-user-agents', is_flag=True, help='Show detailed suspicious user agents (default: enabled)')
@click.option('--show-summary', is_flag=True, default=True, help='Show security summary (default: enabled)')
@click.option('--show-top-threats', is_flag=True, default=True, help='Show top threat IPs (default: enabled)')
@click.option('--show-geographic', is_flag=True, help='Show geographic threat distribution')
@click.option('--show-timeline', is_flag=True, help='Show attack timeline analysis')
@click.option('--threshold', default=5, help='Threshold for brute force detection (default: 5)')
@click.option('--min-threat-score', default=10.0, help='Minimum threat score for IP reporting (default: 10.0)')
@click.option('--detailed', is_flag=True, help='Show all detailed analysis sections')
@click.option('--quiet', is_flag=True, help='Only show summary, suppress detailed output')
@click.option('--yesterday', is_flag=True, help='Analyze yesterday\'s logs instead of today\'s')
@click.option('--export-blacklist', help='Export recommended IP blacklist to file')
@click.option('--ignore-blocked/--no-ignore-blocked', default=True, help='Ignore blocked requests (e.g., 403/444/495-499) during analysis')
@click.option('--blocked-status-codes', default='403,444,495-499', help='Comma-separated status codes/ranges to treat as blocked')
@click.option('--show-blocked', is_flag=True, help='Show blocked traffic summary')
@click.option('--output', '-o', help='Output file for security report')
def security(log_files, scan_attacks, brute_force_detection, 
            sql_injection_patterns, suspicious_user_agents, show_summary, show_top_threats,
            show_geographic, show_timeline, threshold, min_threat_score, detailed, quiet,
            yesterday, export_blacklist, ignore_blocked, blocked_status_codes, show_blocked, output):
    """🔒 Advanced security analysis and threat detection.
    
    Analyze your access logs for security threats, attack patterns, and suspicious activity.
    By default, shows a comprehensive security summary with top threats and recommendations.
    Use specific flags for detailed analysis of different threat categories.
    
    \b
    🚨 Threat Detection (All Enabled by Default):
      • SQL injection attempts and patterns
      • Cross-site scripting (XSS) attacks
      • Directory traversal attempts
      • Command injection patterns
      • File inclusion attacks
      • Web shell detection
      • Brute force login attempts
      • Suspicious user agents and bots
      • High error rate IPs (potential attacks)
      • Threat scoring and IP reputation
    
    \b
    📊 Default Output:
      • Security summary with key metrics
      • Top threat IPs with threat scores
      • Attack type distribution
      • Security recommendations
    
    \b
    💡 Examples:
      hlogcli security                              # Full security analysis (default)
      hlogcli security --quiet                      # Only show summary stats
      hlogcli security --detailed                   # Show all detailed sections
      hlogcli security --threshold 3                # Lower brute force threshold
      hlogcli security --min-threat-score 25        # Higher threat threshold
      hlogcli security --export-blacklist block.txt # Export IPs to block
      hlogcli security --show-geographic            # Geographic threat analysis
      hlogcli security --show-timeline              # Timeline analysis
      hlogcli security -o security-report.json      # Export full report
      
      # Detailed analysis of specific threats:
      hlogcli security --scan-attacks               # Show attack pattern details
      hlogcli security --brute-force-detection      # Show brute force details
      hlogcli security --sql-injection-patterns     # Show SQL injection details
      hlogcli security --suspicious-user-agents     # Show user agent details
    """
    
    # Initialize security analyzer
    from .security import SecurityAnalyzer
    from .filters import LogFilter
    analyzer = SecurityAnalyzer()
    log_filter = LogFilter()
    
    # Process log files with nice progress display
    console.print("[blue]Starting security analysis...[/blue]")
    
    def _parse_code_list(spec: str):
        result = []
        for token in (spec or '').split(','):
            token = token.strip()
            if not token:
                continue
            if '-' in token:
                try:
                    start, end = token.split('-', 1)
                    start_i = int(start)
                    end_i = int(end)
                    if start_i <= end_i:
                        result.extend(list(range(start_i, end_i + 1)))
                except Exception:
                    continue
            else:
                try:
                    result.append(int(token))
                except Exception:
                    continue
        return result

    log_filter.set_ignore_blocked(ignore_blocked)
    log_filter.set_blocked_status_codes(_parse_code_list(blocked_status_codes))

    def analyze_entry(log_entry):
        """Analyze a single log entry for security with blocked pre-filtering."""
        if log_filter.is_blocked(log_entry):
            analyzer.record_blocked(log_entry)
            if log_filter.ignore_blocked:
                return
        analyzer._analyze_entry(log_entry)
    
    process_hypernode_logs_with_callback(analyze_entry, "security analysis", use_yesterday=yesterday)
    
    # Get comprehensive security data
    summary = analyzer.get_security_summary()
    suspicious_ips = analyzer.get_suspicious_ips()

    if show_blocked:
        blocked = analyzer.get_blocked_summary()
        console.print("\n[bold yellow]🚫 BLOCKED TRAFFIC[/bold yellow]")
        console.print(f"  Total blocked: {blocked['total']:,}")
        if blocked['top_status_codes']:
            console.print(f"  Top status: {blocked['top_status_codes']}")
        if blocked['top_countries']:
            console.print(f"  Top countries: {list(blocked['top_countries'].items())[:5]}")
        if blocked['top_paths']:
            console.print(f"  Top paths: {list(blocked['top_paths'].items())[:5]}")
    
    # Show security summary by default (unless quiet mode)
    if show_summary and not quiet:
        console.print("\n[bold blue]🛡️  SECURITY ANALYSIS SUMMARY[/bold blue]")
        console.print(f"  📊 Total Requests: [cyan]{summary['total_requests']:,}[/cyan]")
        console.print(f"  ❌ Total Errors: [red]{summary['total_errors']:,}[/red] ({summary['global_error_rate']:.1f}%)")
        console.print(f"  🌐 Unique IPs: [cyan]{summary['unique_ips']:,}[/cyan]")
        console.print(f"  🚨 Attack Attempts: [red]{summary['total_attack_attempts']:,}[/red]")
        console.print(f"  🎯 Attack Types: [yellow]{summary['attack_types_detected']}[/yellow]")
        
        console.print(f"\n  ⚠️  Threat Analysis:")
        console.print(f"    • Suspicious IPs: [red]{summary['suspicious_ips']}[/red] ({summary['suspicious_ip_percentage']:.1f}%)")
        console.print(f"    • Potential DDoS IPs: [orange1]{summary['potential_ddos_ips']}[/orange1]")
        console.print(f"    • Scanning IPs: [yellow]{summary['scanning_ips']}[/yellow]")
        console.print(f"    • Admin Access IPs: [red]{summary['admin_access_ips']}[/red]")
        
        console.print(f"\n  🔍 Attack Categories:")
        console.print(f"    • Brute Force: [orange1]{summary['brute_force_ips']}[/orange1] IPs")
        console.print(f"    • SQL Injection: [red]{summary['sql_injection_ips']}[/red] IPs")
        console.print(f"    • XSS Attempts: [red]{summary['xss_attempt_ips']}[/red] IPs")
        console.print(f"    • Directory Traversal: [red]{summary['directory_traversal_ips']}[/red] IPs")
        console.print(f"    • Command Injection: [red]{summary['command_injection_ips']}[/red] IPs")
        console.print(f"    • Suspicious User Agents: [yellow]{summary['suspicious_user_agents']}[/yellow]")
        
        # Show compact e-commerce platform metrics if present
        platform = summary.get('platform', {})
        if platform:
            wp = platform.get('wordpress', {})
            wc = platform.get('woocommerce', {})
            sw = platform.get('shopware', {})
            mg = platform.get('magento', {})
            has_any = any([
                wp.get('bruteforce_ips') or wp.get('xmlrpc_abuse_ips') or wp.get('api_enum_ips') or wp.get('sensitive_ips'),
                wc.get('api_enum_ips') or wc.get('checkout_fail_ips'),
                sw.get('admin_probe_ips') or sw.get('api_enum_ips') or sw.get('recovery_probe_ips'),
                mg.get('bruteforce_ips') or mg.get('api_enum_ips') or mg.get('setup_probe_ips') or mg.get('sensitive_ips'),
            ])
            if has_any:
                console.print("\n  🛒 E-commerce Signals:")
                if any(wp.values()):
                    console.print(
                        "    • WordPress: "
                        f"Brute Force [orange1]{wp.get('bruteforce_ips', 0)}[/orange1] IPs, "
                        f"XML-RPC [yellow]{wp.get('xmlrpc_abuse_ips', 0)}[/yellow] IPs, "
                        f"REST Enum [yellow]{wp.get('api_enum_ips', 0)}[/yellow] IPs, "
                        f"Sensitive [red]{wp.get('sensitive_ips', 0)}[/red] IPs"
                    )
                if any(wc.values()):
                    console.print(
                        "    • WooCommerce: "
                        f"API Enum [yellow]{wc.get('api_enum_ips', 0)}[/yellow] IPs, "
                        f"Checkout Fails [orange1]{wc.get('checkout_fail_ips', 0)}[/orange1] IPs"
                    )
                if any(sw.values()):
                    console.print(
                        "    • Shopware: "
                        f"Admin Probes [orange1]{sw.get('admin_probe_ips', 0)}[/orange1] IPs, "
                        f"API Enum [yellow]{sw.get('api_enum_ips', 0)}[/yellow] IPs, "
                        f"Recovery Probes [yellow]{sw.get('recovery_probe_ips', 0)}[/yellow] IPs"
                    )
                if any(mg.values()):
                    console.print(
                        "    • Magento: "
                        f"Brute Force [orange1]{mg.get('bruteforce_ips', 0)}[/orange1] IPs, "
                        f"API Enum [yellow]{mg.get('api_enum_ips', 0)}[/yellow] IPs, "
                        f"Setup Probes [yellow]{mg.get('setup_probe_ips', 0)}[/yellow] IPs, "
                        f"Sensitive [red]{mg.get('sensitive_ips', 0)}[/red] IPs"
                    )
        
        if summary['top_attack_types']:
            console.print("\n  🏆 Top Attack Types:")
            for attack_type, count in summary['top_attack_types'].items():
                console.print(f"    • {attack_type}: [red]{count:,}[/red] attempts")
    
    # Show top threats by default (unless quiet mode)
    if show_top_threats and not quiet and suspicious_ips:
        console.print(f"\n[bold red]⚠️  TOP THREAT IPs (threat score ≥ {min_threat_score})[/bold red]")
        top_threats = [ip for ip in suspicious_ips if ip['threat_score'] >= min_threat_score][:10]
        
        if top_threats:
            for i, ip_data in enumerate(top_threats, 1):
                console.print(f"  {i:2}. [red]{ip_data['ip']}[/red] (Score: [bold red]{ip_data['threat_score']:.1f}[/bold red])")
                console.print(f"      Requests: {ip_data['total_requests']:,}, Error Rate: {ip_data['error_rate']:.1f}%")
                console.print(f"      Failed Logins: {ip_data['failed_logins']}, Attacks: {sum(ip_data['attack_attempts'].values())}")
        else:
            console.print(f"  [green]✅ No high-threat IPs found (threshold: {min_threat_score})[/green]")
    
    # Show detailed sections if requested or --detailed flag is used
    show_detailed = detailed or scan_attacks or brute_force_detection or sql_injection_patterns or suspicious_user_agents
    
    if show_detailed and not quiet:
        if scan_attacks or detailed:
            console.print("\n[bold red]🚨 ATTACK PATTERNS DETECTED[/bold red]")
            attacks = analyzer.get_attack_patterns()
            if attacks:
                for attack_type, count in attacks.items():
                    console.print(f"  • {attack_type}: [red]{count:,}[/red] attempts")
            else:
                console.print("  [green]✅ No attack patterns detected[/green]")
        
        if brute_force_detection or detailed:
            console.print(f"\n[bold yellow]🔒 BRUTE FORCE ANALYSIS (threshold: {threshold})[/bold yellow]")
            brute_force = analyzer.get_brute_force_attempts(threshold)
            if brute_force:
                for ip, attempts in list(brute_force.items())[:15]:  # Limit to top 15
                    console.print(f"  • [red]{ip}[/red]: {attempts} failed login attempts")
            else:
                console.print(f"  [green]✅ No brute force attempts detected (threshold: {threshold})[/green]")
        
        if sql_injection_patterns or detailed:
            console.print("\n[bold red]💉 SQL INJECTION ATTEMPTS[/bold red]")
            sql_attacks = analyzer.get_sql_injection_attempts()
            if sql_attacks:
                for ip, patterns in list(sql_attacks.items())[:15]:  # Limit to top 15
                    console.print(f"  • [red]{ip}[/red]: {len(patterns)} SQL injection patterns")
            else:
                console.print("  [green]✅ No SQL injection attempts detected[/green]")
        
        if suspicious_user_agents or detailed:
            console.print("\n[bold orange1]🕵️  SUSPICIOUS USER AGENTS[/bold orange1]")
            suspicious = analyzer.get_suspicious_user_agents()
            if suspicious:
                for ua, count in suspicious[:15]:  # Limit to top 15
                    ua_display = ua[:80] + "..." if len(ua) > 80 else ua
                    console.print(f"  • [yellow]{ua_display}[/yellow]: {count:,} requests")
            else:
                console.print("  [green]✅ No suspicious user agents detected[/green]")
        
        # Detailed e-commerce platform IPs (top offenders by event)
        platform_events = getattr(analyzer, 'platform_events', {})
        if platform_events and detailed:
            # Build a compact, styled list of top IPs per event type
            lines_printed = 0
            max_lines = 12
            header_printed = False
            def pretty_event(name: str) -> str:
                mapping = {
                    'bruteforce': 'Brute Force',
                    'xmlrpc_abuse': 'XML-RPC',
                    'api_enum': 'API Enum',
                    'sensitive_access': 'Sensitive',
                    'backup_probe': 'Backup Probe',
                    'admin_probe': 'Admin Probe',
                    'recovery_probe': 'Recovery Probe',
                    'setup_probe': 'Setup Probe',
                }
                return mapping.get(name, name.replace('_', ' ').title())
            for platform_name, event_types in platform_events.items():
                for event_type, ip_counts in event_types.items():
                    if not ip_counts:
                        continue
                    if not header_printed:
                        console.print("\n[bold magenta]🛒 E-commerce Platform Events[/bold magenta]")
                        header_printed = True
                    top_ips = sorted(ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
                    joined = ", ".join([f"[red]{ip}[/red]([yellow]{cnt}[/yellow])" for ip, cnt in top_ips])
                    console.print(f"  • {platform_name.title()} – {pretty_event(event_type)}: {joined}")
                    lines_printed += 1
                    if lines_printed >= max_lines:
                        break
                if lines_printed >= max_lines:
                    break
    
    # Show geographic distribution if requested
    if show_geographic and not quiet:
        console.print("\n[bold cyan]🌍 GEOGRAPHIC THREAT DISTRIBUTION[/bold cyan]")
        from .geographic import GeoIPAnalyzer
        geo_analyzer = GeoIPAnalyzer()
        
        # Re-analyze entries for geographic data
        def geo_analyze_entry(log_entry):
            geo_analyzer.analyze_entry(log_entry)
        
        console.print("  [blue]Re-analyzing entries for geographic patterns...[/blue]")
        process_hypernode_logs_with_callback(geo_analyze_entry, "geographic analysis", use_yesterday=yesterday)
        
        geo_summary = geo_analyzer.get_geographic_summary()
        threat_map = geo_analyzer.get_threat_map_data()
        
        if threat_map:
            console.print(f"  🚨 Threat Countries Detected: [red]{len(threat_map)}[/red]")
            for country_code, data in list(threat_map.items())[:10]:
                threat_level = "🔴" if data['threat_level'] >= 4 else "🟡" if data['threat_level'] >= 2 else "🟢"
                console.print(f"    {threat_level} [red]{data['country_name']} ({country_code})[/red]: Score {data['threat_score']:.1f}")
                console.print(f"      └─ {data['suspicious_ips']} suspicious IPs, {data['total_attacks']} attacks")
        else:
            console.print("  [green]✅ No significant geographic threats detected[/green]")
        
        # Show top countries by requests with threat indicators
        if geo_summary['countries_by_requests']:
            console.print(f"\n  📊 Top Countries by Traffic:")
            for country_code, requests in geo_summary['countries_by_requests'][:5]:
                country_name = geo_analyzer._get_country_name(country_code)
                threat_indicator = "🚨" if country_code in threat_map else "✅"
                console.print(f"    {threat_indicator} {country_name} ({country_code}): {requests:,} requests")
    
    # Show timeline analysis if requested
    if show_timeline and not quiet:
        console.print("\n[bold magenta]📈 ATTACK TIMELINE ANALYSIS[/bold magenta]")
        from .timeline import TimelineAnalyzer
        timeline_analyzer = TimelineAnalyzer(granularity='5min')
        
        # Re-analyze entries for timeline data
        def timeline_analyze_entry(log_entry):
            timeline_analyzer.analyze_entry(log_entry)
        
        console.print("  [blue]Analyzing timeline patterns and attack sequences...[/blue]")
        process_hypernode_logs_with_callback(timeline_analyze_entry, "timeline analysis", use_yesterday=yesterday)
        
        timeline_summary = timeline_analyzer.get_timeline_summary()
        attack_timeline = timeline_analyzer.get_attack_timeline()
        
        if timeline_summary.get('total_attacks', 0) > 0:
            console.print(f"  📊 Timeline Overview:")
            console.print(f"    • Total Attacks: [red]{timeline_summary['total_attacks']:,}[/red]")
            console.print(f"    • Attack Rate: [yellow]{timeline_summary['attack_rate']:.1f}%[/yellow]")
            console.print(f"    • Security Incidents: [red]{timeline_summary['security_incidents']}[/red]")
            console.print(f"    • Anomalies Detected: [orange1]{timeline_summary['anomalies_detected']}[/orange1]")
            
            # Show peak attack times
            if timeline_summary['peak_analysis']['peak_attacks'] > 0:
                peak_time = timeline_summary['peak_analysis']['peak_attack_time']
                peak_attacks = timeline_summary['peak_analysis']['peak_attacks']
                console.print(f"    • Peak Attack Time: [red]{peak_time.strftime('%H:%M')} ({peak_attacks} attacks)[/red]")
            
            # Show attack type distribution
            if timeline_summary['attack_distribution']:
                console.print(f"\n  🚨 Attack Types Over Time:")
                for attack_type, count in sorted(timeline_summary['attack_distribution'].items(), 
                                               key=lambda x: x[1], reverse=True)[:5]:
                    console.print(f"    • {attack_type.replace('_', ' ').title()}: [red]{count:,}[/red] attempts")
            
            # Show recent high-activity periods
            if attack_timeline:
                console.print(f"\n  ⏰ Recent High-Activity Periods:")
                recent_attacks = sorted(attack_timeline.items(), key=lambda x: x[0], reverse=True)[:3]
                for time_key, data in recent_attacks:
                    console.print(f"    • [yellow]{time_key.strftime('%H:%M')}[/yellow]: {data['total_attacks']} attacks")
                    console.print(f"      └─ {data['unique_attacking_ips']} unique IPs, {data['error_rate']:.1f}% errors")
        else:
            console.print("  [green]✅ No significant attack timeline patterns detected[/green]")
        
        # Show traffic patterns
        traffic_patterns = timeline_analyzer.get_traffic_patterns()
        if traffic_patterns.get('hourly_analysis'):
            hourly = traffic_patterns['hourly_analysis']
            console.print(f"\n  📈 Traffic Patterns:")
            console.print(f"    • Peak Hour: [cyan]{hourly['peak_hour']['hour']:02d}:00[/cyan] ({hourly['peak_hour']['requests']:,} requests)")
            console.print(f"    • Quiet Hour: [blue]{hourly['quiet_hour']['hour']:02d}:00[/blue] ({hourly['quiet_hour']['requests']:,} requests)")
            
            if traffic_patterns.get('trend_analysis'):
                trend = traffic_patterns['trend_analysis']
                trend_color = "green" if trend['direction'] == 'increasing' else "red" if trend['direction'] == 'decreasing' else "yellow"
                console.print(f"    • Traffic Trend: [{trend_color}]{trend['direction']} ({trend['magnitude_percent']:.1f}%)[/{trend_color}]")
    
    # Export blacklist if requested
    if export_blacklist:
        blacklist_ips = analyzer.get_blacklist_recommendations(min_threat_score)
        if blacklist_ips:
            with open(export_blacklist, 'w') as f:
                for ip in blacklist_ips:
                    f.write(f"{ip}\n")
            console.print(f"[green]Exported {len(blacklist_ips)} IPs to blacklist: {export_blacklist}[/green]")
        else:
            console.print(f"[yellow]No IPs meet the blacklist criteria (threat score ≥ {min_threat_score})[/yellow]")
    
    # Export security report if requested
    if output:
        analyzer.export_security_report(output)
        console.print(f"[green]Security report exported to: {output}[/green]")
    
    # Show final recommendations unless quiet
    if not quiet:
        console.print(f"\n[bold green]💡 RECOMMENDATIONS[/bold green]")
        if summary['total_attack_attempts'] > 100:
            console.print("  • Consider implementing rate limiting")
        if summary['suspicious_ips'] > 10:
            console.print("  • Review and consider blocking suspicious IPs")
        if summary['brute_force_ips'] > 0:
            console.print("  • Implement account lockout policies")
        if summary['sql_injection_ips'] > 0:
            console.print("  • Review application input validation")
        
        console.print(f"\n[dim]💡 Use --detailed for more information, --export-blacklist to export IPs, or --help for all options[/dim]")


# Performance Analysis Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--response-time-analysis', is_flag=True, help='Analyze response times')
@click.option('--slowest', default=10, help='Show N slowest endpoints')
@click.option('--percentiles', is_flag=True, help='Show response time percentiles')
@click.option('--bandwidth-analysis', is_flag=True, help='Analyze bandwidth usage')
@click.option('--cache-analysis', is_flag=True, help='Analyze cache effectiveness')
@click.option('--handler', help='Filter by handler (e.g., varnish, phpfpm)')
@click.option('--yesterday', is_flag=True, help='Analyze yesterday\'s logs instead of today\'s')
@click.option('--output', '-o', help='Output file for performance report')
def perf(log_files, response_time_analysis, slowest, 
         percentiles, bandwidth_analysis, cache_analysis, handler, yesterday, output):
    """⚡ Performance analysis and optimization insights.
    
    Analyze response times, bandwidth usage, and identify performance bottlenecks.
    Get detailed insights into your application's performance characteristics and
    discover optimization opportunities.
    
    \b
    📈 Performance Metrics:
      • Response time statistics (avg, median, 95th/99th percentiles)
      • Slowest endpoints identification
      • Bandwidth usage analysis
      • Cache effectiveness metrics
      • Geographic performance variations
      • Handler-specific performance (PHP-FPM, Varnish, etc.)
    
    \b
    💡 Examples:
      hlogcli perf                              # Basic performance overview
      hlogcli perf --response-time-analysis     # Detailed response time stats
      hlogcli perf --slowest 20                 # Top 20 slowest endpoints
      hlogcli perf --bandwidth-analysis         # Bandwidth usage analysis
      hlogcli perf --cache-analysis --handler varnish  # Cache performance
      hlogcli perf --percentiles -o perf-report.json   # Export with percentiles
    """
    
    # Initialize performance analyzer
    from .performance import PerformanceAnalyzer
    analyzer = PerformanceAnalyzer()
    
    # Process log files with nice progress display
    console.print("[blue]Starting performance analysis...[/blue]")
    
    def analyze_entry(log_entry):
        """Analyze a single log entry for performance."""
        # Apply handler filter if specified
        if handler and log_entry.get('handler') != handler:
            return
        analyzer._analyze_entry(log_entry)
    
    process_hypernode_logs_with_callback(analyze_entry, "performance analysis", use_yesterday=yesterday)
    
    # Check if any specific analysis flags were provided
    has_specific_flags = (response_time_analysis or bandwidth_analysis or 
                         (cache_analysis and handler) or percentiles)
    
    # If no specific flags, show default overview
    if not has_specific_flags:
        console.print("\n[bold cyan]⚡ PERFORMANCE OVERVIEW[/bold cyan]")
        
        # Basic stats
        summary = analyzer.get_performance_summary()
        if summary.get('total_requests', 0) > 0:
            console.print(f"\n[bold]📊 Summary Statistics[/bold]")
            console.print(f"  Total requests analyzed: [green]{summary['total_requests']:,}[/green]")
            console.print(f"  Slow requests (>2s): [yellow]{summary['slow_requests']:,}[/yellow]")
            console.print(f"  Handlers analyzed: {summary['handlers_analyzed']}")
            console.print(f"  Unique endpoints: {summary['endpoints_analyzed']}")
            
            # Response time stats
            rt_stats = summary.get('response_time_stats', {})
            if rt_stats:
                console.print(f"\n[bold]⏱️  Response Time Statistics[/bold]")
                console.print(f"  Average: [cyan]{rt_stats['avg']:.3f}s[/cyan]")
                console.print(f"  Median: {rt_stats['median']:.3f}s")
                console.print(f"  95th percentile: [yellow]{rt_stats['p95']:.3f}s[/yellow]")
                console.print(f"  99th percentile: [red]{rt_stats['p99']:.3f}s[/red]")
                console.print(f"  Max: {rt_stats['max']:.3f}s")
            
            # Handler performance
            handler_perf = analyzer.get_handler_performance()
            if handler_perf:
                console.print(f"\n[bold]🔧 Handler Performance[/bold]")
                for handler_name, stats in sorted(handler_perf.items(), 
                                                 key=lambda x: x[1]['requests'], 
                                                 reverse=True)[:5]:
                    console.print(f"  {handler_name}:")
                    console.print(f"    Requests: {stats['requests']:,}")
                    console.print(f"    Avg response: {stats['avg_response_time']:.3f}s")
                    console.print(f"    P95: {stats['p95_response_time']:.3f}s")
                    if stats['slow_requests'] > 0:
                        console.print(f"    Slow (>2s): [yellow]{stats['slow_requests']:,}[/yellow]")
            
            # Top slowest endpoints
            console.print(f"\n[bold]🐌 Top 10 Slowest Endpoints[/bold]")
            slow_endpoints = analyzer.get_slowest_endpoints(10)
            if slow_endpoints:
                for endpoint, avg_time in slow_endpoints:
                    # Truncate long URLs
                    display_endpoint = endpoint if len(endpoint) <= 70 else endpoint[:67] + "..."
                    color = "red" if avg_time > 5 else "yellow" if avg_time > 2 else "white"
                    console.print(f"  [{color}]{avg_time:.3f}s[/{color}] {display_endpoint}")
            else:
                console.print("  No slow endpoints found")
            
            # Bandwidth stats
            bandwidth = summary.get('bandwidth_stats', {})
            if bandwidth:
                console.print(f"\n[bold]📈 Bandwidth Usage[/bold]")
                console.print(f"  Total transferred: [cyan]{bandwidth['total_gb']:.2f} GB[/cyan]")
                console.print(f"  Average per request: {bandwidth['avg_per_request']/1024:.1f} KB")
                if bandwidth.get('peak_hour') and bandwidth['peak_hour'] != 'N/A':
                    console.print(f"  Peak hour: {bandwidth['peak_hour']} ({bandwidth['peak_hour_gb']:.2f} GB)")
            
            # Optimization recommendations
            recommendations = analyzer.get_optimization_recommendations()
            if recommendations:
                console.print(f"\n[bold]💡 Optimization Recommendations[/bold]")
                for rec in recommendations[:3]:  # Show top 3
                    priority_color = "red" if rec['priority'] == 'High' else "yellow"
                    console.print(f"  [{priority_color}]{rec['priority']}[/{priority_color}] - {rec['category']}")
                    console.print(f"    {rec['recommendation']}")
                
                if len(recommendations) > 3:
                    console.print(f"\n  [dim]... and {len(recommendations) - 3} more recommendations[/dim]")
            
            # Usage hints
            console.print(f"\n[dim]💡 Use flags for detailed analysis:[/dim]")
            console.print(f"[dim]   --response-time-analysis  Detailed response time stats[/dim]")
            console.print(f"[dim]   --slowest 20              Top 20 slowest endpoints[/dim]")
            console.print(f"[dim]   --bandwidth-analysis      Bandwidth usage details[/dim]")
            console.print(f"[dim]   --cache-analysis          Cache effectiveness (requires --handler)[/dim]")
            console.print(f"[dim]   -o report.json            Export full report[/dim]")
        else:
            console.print("\n[yellow]No performance data found. Make sure log files contain valid entries.[/yellow]")
    
    # Generate specific analysis reports if flags are provided
    if response_time_analysis:
        console.print("\n[bold blue]⚡ RESPONSE TIME ANALYSIS[/bold blue]")
        rt_stats = analyzer.get_response_time_stats()
        if rt_stats:
            console.print(f"  Average: {rt_stats['avg']:.3f}s")
            console.print(f"  Median: {rt_stats['median']:.3f}s")
            console.print(f"  95th percentile: {rt_stats['p95']:.3f}s")
            console.print(f"  99th percentile: {rt_stats['p99']:.3f}s")
            console.print(f"  Max: {rt_stats['max']:.3f}s")
    
    if slowest:
        console.print(f"\n[bold yellow]🐌 TOP {slowest} SLOWEST ENDPOINTS[/bold yellow]")
        slow_endpoints = analyzer.get_slowest_endpoints(slowest)
        for endpoint, avg_time in slow_endpoints:
            console.print(f"  {endpoint}: {avg_time:.3f}s average")
    
    if bandwidth_analysis:
        console.print("\n[bold green]📊 BANDWIDTH ANALYSIS[/bold green]")
        bandwidth = analyzer.get_bandwidth_stats()
        if bandwidth:
            console.print(f"  Total data transferred: {bandwidth['total_gb']:.2f} GB")
            console.print(f"  Average per request: {bandwidth['avg_per_request']:,.0f} bytes")
            console.print(f"  Peak hour usage: {bandwidth['peak_hour_gb']:.2f} GB")
    
    if cache_analysis and handler:
        console.print(f"\n[bold cyan]🗄️  CACHE ANALYSIS ({handler})[/bold cyan]")
        cache_stats = analyzer.get_cache_stats(handler)
        console.print(f"  Cache hit ratio: {cache_stats['hit_ratio']:.1f}%")
        console.print(f"  Cache misses: {cache_stats['misses']:,}")
        console.print(f"  Avg response time (cached): {cache_stats['cached_avg']:.3f}s")
        console.print(f"  Avg response time (uncached): {cache_stats['uncached_avg']:.3f}s")
    
    # Export performance report if requested
    if output:
        analyzer.export_performance_report(output)
        console.print(f"[green]Performance report exported to: {output}[/green]")


# API Analysis Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--endpoint-analysis', is_flag=True, help='Detailed endpoint performance analysis')
@click.option('--graphql-analysis', is_flag=True, help='GraphQL-specific analysis')
@click.option('--security-analysis', is_flag=True, help='API security analysis')
@click.option('--performance-analysis', is_flag=True, help='API performance analysis')
@click.option('--top-endpoints', default=10, help='Show top N endpoints')
@click.option('--min-requests', default=10, help='Minimum requests for endpoint analysis')
@click.option('--ignore-blocked/--no-ignore-blocked', default=True, help='Ignore blocked requests (e.g., 403/444/495-499) during analysis')
@click.option('--blocked-status-codes', default='403,444,495-499', help='Comma-separated status codes/ranges to treat as blocked')
@click.option('--show-blocked', is_flag=True, help='Show blocked traffic summary')
@click.option('--yesterday', is_flag=True, help='Analyze yesterday\'s logs instead of today\'s')
@click.option('--output', '-o', help='Output file for API analysis report')
def api(log_files, endpoint_analysis, graphql_analysis,
        security_analysis, performance_analysis, top_endpoints, min_requests, ignore_blocked, blocked_status_codes, show_blocked, yesterday, output):
    """🔌 Advanced API endpoint analysis and performance insights.
    
    Analyze REST APIs, GraphQL endpoints, and API usage patterns to understand
    performance characteristics, security issues, and optimization opportunities.
    Specifically designed for modern web applications with heavy API usage.
    
    \b
    🎯 API Analysis Features:
      • REST API endpoint performance and usage patterns
      • GraphQL query analysis and complexity metrics
      • API versioning and deprecation tracking
      • Authentication and authorization pattern analysis
      • Rate limiting and abuse detection
      • Response time and bandwidth analysis
      • Error rate and reliability metrics
      • Security vulnerability detection
    
    \b
    📊 Analysis Categories:
      • Endpoint Performance: Response times, throughput, error rates
      • Usage Patterns: Most popular endpoints, request methods, parameters
      • Security Issues: Unauthenticated access, suspicious queries, abuse
      • GraphQL Specific: Query complexity, introspection, mutations
      • API Versioning: Version distribution, deprecated endpoint usage
      • Geographic Distribution: API usage by country and region
    
    \b
    💡 Examples:
      hlogcli api                                  # Comprehensive API analysis
      hlogcli api --endpoint-analysis              # Detailed endpoint performance
      hlogcli api --graphql-analysis               # GraphQL-specific insights
      hlogcli api --security-analysis              # API security assessment
      hlogcli api --performance-analysis           # Performance optimization insights
      hlogcli api --top-endpoints 20               # Show top 20 endpoints
      hlogcli api --min-requests 50 -o api-report.json  # Export detailed report
    """
    
    # Initialize API analyzer
    from .api_analysis import APIAnalyzer
    from .filters import LogFilter
    analyzer = APIAnalyzer()
    log_filter = LogFilter()
    
    # Process log files with nice progress display
    console.print("[blue]Starting API endpoint analysis...[/blue]")
    
    def _parse_code_list(spec: str):
        result = []
        for token in (spec or '').split(','):
            token = token.strip()
            if not token:
                continue
            if '-' in token:
                try:
                    start, end = token.split('-', 1)
                    start_i = int(start)
                    end_i = int(end)
                    if start_i <= end_i:
                        result.extend(list(range(start_i, end_i + 1)))
                except Exception:
                    continue
            else:
                try:
                    result.append(int(token))
                except Exception:
                    continue
        return result

    log_filter.set_ignore_blocked(ignore_blocked)
    log_filter.set_blocked_status_codes(_parse_code_list(blocked_status_codes))

    def analyze_entry(log_entry):
        """Analyze a single log entry for API patterns with blocked pre-filtering."""
        if log_filter.is_blocked(log_entry):
            analyzer.record_blocked(log_entry)
            if log_filter.ignore_blocked:
                return
        analyzer.analyze_entry(log_entry)
    
    process_hypernode_logs_with_callback(analyze_entry, "API analysis", use_yesterday=yesterday)
    
    # Get comprehensive API data
    api_summary = analyzer.get_api_summary()
    
    # Show API summary by default
    console.print("\n[bold blue]🔌 API ANALYSIS SUMMARY[/bold blue]")
    if show_blocked:
        blocked = analyzer.get_blocked_summary()
        console.print("\n[bold yellow]🚫 BLOCKED TRAFFIC[/bold yellow]")
        console.print(f"  Total blocked: {blocked['total']:,}")
        if blocked['top_status_codes']:
            console.print(f"  Top status: {blocked['top_status_codes']}")
        if blocked['top_endpoints']:
            console.print(f"  Top endpoints: {list(blocked['top_endpoints'].items())[:5]}")
        if blocked['top_countries']:
            console.print(f"  Top countries: {list(blocked['top_countries'].items())[:5]}")
    console.print(f"  📊 API Overview:")
    console.print(f"    • Total API Requests: [cyan]{api_summary['total_api_requests']:,}[/cyan]")
    console.print(f"    • Unique Endpoints: [cyan]{api_summary['total_endpoints']:,}[/cyan]")
    console.print(f"    • Overall Error Rate: [red]{api_summary['error_rate']:.1f}%[/red]")
    console.print(f"    • Total API Bandwidth: [yellow]{api_summary['total_bandwidth_mb']:.1f} MB[/yellow]")
    
    # Performance statistics
    if api_summary['performance_stats']:
        perf = api_summary['performance_stats']
        console.print(f"\n  ⚡ API Performance:")
        console.print(f"    • Average Response Time: [cyan]{perf['avg_response_time']:.3f}s[/cyan]")
        console.print(f"    • 95th Percentile: [yellow]{perf['p95_response_time']:.3f}s[/yellow]")
        console.print(f"    • Slowest Response: [red]{perf['max_response_time']:.3f}s[/red]")
    
    # Top endpoints
    if api_summary['top_endpoints']['most_popular']:
        console.print(f"\n  🏆 Most Popular API Endpoints:")
        for endpoint, requests in list(api_summary['top_endpoints']['most_popular'].items())[:top_endpoints]:
            endpoint_display = endpoint[:60] + "..." if len(endpoint) > 60 else endpoint
            console.print(f"    • [green]{endpoint_display}[/green]: {requests:,} requests")
    
    # Security issues
    security = api_summary['security_issues']
    if any(security.values()):
        console.print(f"\n  🚨 API Security Issues:")
        if security['unauthenticated_access'] > 0:
            console.print(f"    • Unauthenticated Access: [red]{security['unauthenticated_access']}[/red] endpoints")
        if security['excessive_requests'] > 0:
            console.print(f"    • Excessive Requests: [orange1]{security['excessive_requests']}[/orange1] IPs")
        if security['suspicious_queries'] > 0:
            console.print(f"    • Suspicious Queries: [red]{security['suspicious_queries']}[/red] endpoints")
        if security['potential_abuse'] > 0:
            console.print(f"    • Potential Abuse: [red]{security['potential_abuse']}[/red] endpoints")
    else:
        console.print(f"\n  ✅ No significant API security issues detected")
    
    # Show detailed analysis sections if requested
    if endpoint_analysis:
        console.print("\n[bold yellow]📈 ENDPOINT PERFORMANCE ANALYSIS[/bold yellow]")
        
        # Slowest endpoints
        if api_summary['top_endpoints']['slowest']:
            console.print(f"  🐌 Slowest Endpoints:")
            for endpoint, count in list(api_summary['top_endpoints']['slowest'].items())[:5]:
                endpoint_details = analyzer.get_endpoint_details(endpoint)
                avg_time = endpoint_details['performance_stats'].get('avg_response_time', 0)
                console.print(f"    • [red]{endpoint}[/red]: {avg_time:.3f}s avg ({count:,} slow requests)")
        
        # Highest error rate endpoints
        if api_summary['top_endpoints']['highest_error_rate']:
            console.print(f"\n  ❌ Highest Error Rate Endpoints:")
            for endpoint, error_rate in list(api_summary['top_endpoints']['highest_error_rate'].items())[:5]:
                console.print(f"    • [red]{endpoint}[/red]: {error_rate:.1f}% error rate")
    
    if graphql_analysis:
        graphql_data = api_summary['graphql_analysis']
        console.print("\n[bold magenta]🔍 GRAPHQL ANALYSIS[/bold magenta]")
        
        if graphql_data['active']:
            console.print(f"  📊 GraphQL Activity:")
            console.print(f"    • Total Queries: [cyan]{graphql_data['total_queries']:,}[/cyan]")
            console.print(f"    • Introspection Queries: [yellow]{graphql_data['introspection_queries']:,}[/yellow]")
            console.print(f"    • Average Query Complexity: [cyan]{graphql_data['avg_query_complexity']:.1f}[/cyan]")
            
            if graphql_data['query_types']:
                console.print(f"\n  🔍 Query Types:")
                for query_type, count in graphql_data['query_types'].items():
                    console.print(f"    • {query_type}: [green]{count:,}[/green] queries")
        else:
            console.print("  [yellow]No GraphQL activity detected[/yellow]")
    
    if security_analysis:
        console.print("\n[bold red]🔒 API SECURITY ANALYSIS[/bold red]")
        
        # Detailed security breakdown
        if analyzer.security_issues['unauthenticated_access']:
            console.print(f"  ⚠️  Unauthenticated Access Attempts:")
            for endpoint, count in list(analyzer.security_issues['unauthenticated_access'].most_common(5)):
                console.print(f"    • [red]{endpoint}[/red]: {count:,} attempts")
        
        if analyzer.security_issues['suspicious_queries']:
            console.print(f"\n  🕵️  Suspicious Query Patterns:")
            for endpoint, count in list(analyzer.security_issues['suspicious_queries'].most_common(5)):
                console.print(f"    • [red]{endpoint}[/red]: {count:,} suspicious queries")
    
    if performance_analysis:
        console.print("\n[bold green]📊 API PERFORMANCE ANALYSIS[/bold green]")
        
        # Bandwidth analysis
        if api_summary['top_endpoints']['most_bandwidth']:
            console.print(f"  📈 Most Bandwidth-Intensive Endpoints:")
            for endpoint, count in list(api_summary['top_endpoints']['most_bandwidth'].items())[:5]:
                endpoint_details = analyzer.get_endpoint_details(endpoint)
                bandwidth_mb = endpoint_details['bandwidth_mb']
                console.print(f"    • [yellow]{endpoint}[/yellow]: {bandwidth_mb:.1f} MB total")
    
    # API versioning analysis
    if api_summary['api_patterns']:
        console.print(f"\n  🔢 API Versions in Use:")
        for version, count in list(api_summary['api_patterns'].items())[:5]:
            console.print(f"    • Version {version}: [cyan]{count:,}[/cyan] requests")
    
    # Export API report if requested
    if output:
        analyzer.export_api_report(output)
        console.print(f"[green]API analysis report exported to: {output}[/green]")
    
    # Show recommendations
    recommendations = analyzer.get_api_recommendations()
    if recommendations:
        console.print(f"\n[bold green]💡 API RECOMMENDATIONS[/bold green]")
        for rec in recommendations[:3]:  # Top 3 recommendations
            priority_color = "red" if rec['priority'] == 'High' else "yellow" if rec['priority'] == 'Medium' else "green"
            console.print(f"  [{priority_color}]{rec['category']} ({rec['priority']} Priority)[/{priority_color}]")
            console.print(f"    Issue: {rec['issue']}")
            console.print(f"    Recommendation: {rec['recommendation']}")
            console.print()


# Content Analysis Commands  
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--content-type-analysis', is_flag=True, help='Detailed content type analysis')
@click.option('--file-extension-analysis', is_flag=True, help='File extension analysis')
@click.option('--optimization-analysis', is_flag=True, help='Optimization opportunities analysis')
@click.option('--performance-analysis', is_flag=True, help='Content performance analysis')
@click.option('--seo-analysis', is_flag=True, help='SEO and broken resource analysis')
@click.option('--top-content', default=10, help='Show top N content types/extensions')
@click.option('--yesterday', is_flag=True, help='Analyze yesterday\'s logs instead of today\'s')
@click.option('--output', '-o', help='Output file for content analysis report')
def content(log_files, content_type_analysis, file_extension_analysis,
           optimization_analysis, performance_analysis, seo_analysis, top_content, yesterday, output):
    """📁 Content type and resource distribution analysis.
    
    Analyze content types, file extensions, and resource distribution to understand
    website structure, identify optimization opportunities, and improve performance.
    Perfect for web developers and performance optimization teams.
    
    \b
    📊 Content Analysis Features:
      • Content type distribution and performance metrics
      • File extension analysis and bandwidth usage
      • Resource category breakdown (Images, CSS, JS, etc.)
      • Cache effectiveness analysis by content type
      • Large file detection and optimization opportunities
      • Broken resource identification (404s, missing images)
      • SEO impact analysis of missing resources
      • Geographic content consumption patterns
    
    \b
    🎯 Analysis Categories:
      • Images: JPEG, PNG, WebP, SVG analysis and optimization
      • Stylesheets: CSS performance and size optimization
      • JavaScript: JS bundle analysis and loading performance
      • Documents: PDF, HTML, and document delivery metrics
      • Media: Video and audio content analysis
      • Fonts: Web font performance and caching
      • API Content: JSON and API response analysis
    
    \b
    💡 Examples:
      hlogcli content                                 # Comprehensive content analysis
      hlogcli content --content-type-analysis         # Content type breakdown
      hlogcli content --file-extension-analysis       # File extension metrics
      hlogcli content --optimization-analysis         # Optimization opportunities
      hlogcli content --seo-analysis                  # SEO and broken resources
      hlogcli content --top-content 20 -o content-report.json  # Export detailed report
    """
    
    # Initialize content analyzer
    from .content_analysis import ContentAnalyzer
    analyzer = ContentAnalyzer()
    
    # Process log files with nice progress display
    console.print("[blue]Starting content type and resource analysis...[/blue]")
    
    def analyze_entry(log_entry):
        """Analyze a single log entry for content patterns."""
        analyzer.analyze_entry(log_entry)
    
    process_hypernode_logs_with_callback(analyze_entry, "content analysis", use_yesterday=yesterday)
    
    # Get comprehensive content data
    content_summary = analyzer.get_content_summary()
    
    # Show content summary by default
    console.print("\n[bold blue]📁 CONTENT ANALYSIS SUMMARY[/bold blue]")
    console.print(f"  📊 Content Overview:")
    console.print(f"    • Total Requests: [cyan]{content_summary['total_requests']:,}[/cyan]")
    console.print(f"    • Total Bandwidth: [yellow]{content_summary['total_bandwidth_mb']:.1f} MB[/yellow]")
    console.print(f"    • Content Types: [cyan]{len(content_summary['content_distribution'])}[/cyan]")
    console.print(f"    • File Extensions: [cyan]{len(content_summary['extension_analysis'])}[/cyan]")
    
    # Top content types
    if content_summary['content_distribution']:
        console.print(f"\n  🏆 Top Content Types:")
        for content_type, data in list(content_summary['content_distribution'].items())[:top_content]:
            content_display = content_type[:50] + "..." if len(content_type) > 50 else content_type
            console.print(f"    • [green]{content_display}[/green]: {data['requests']:,} requests ({data['percentage']:.1f}%)")
            console.print(f"      └─ {data['bandwidth_mb']:.1f} MB, {data['avg_response_time']:.3f}s avg, {data['error_rate']:.1f}% errors")
    
    # Resource categories
    if content_summary['category_analysis']:
        console.print(f"\n  📂 Resource Categories:")
        for category, data in list(content_summary['category_analysis'].items())[:5]:
            console.print(f"    • [blue]{category}[/blue]: {data['requests']:,} requests, {data['bandwidth_mb']:.1f} MB")
            console.print(f"      └─ {data['avg_response_time']:.3f}s avg, {data['error_rate']:.1f}% errors")
    
    # Optimization opportunities
    optimization = content_summary['optimization_opportunities']
    if any(optimization.values()):
        console.print(f"\n  🔧 Optimization Opportunities:")
        if optimization['large_images'] > 0:
            console.print(f"    • Large Images: [red]{optimization['large_images']}[/red] files need optimization")
        if optimization['unoptimized_resources'] > 0:
            console.print(f"    • Unoptimized Resources: [orange1]{optimization['unoptimized_resources']}[/orange1] JS/CSS files")
        if optimization['missing_images'] > 0:
            console.print(f"    • Missing Images: [red]{optimization['missing_images']}[/red] broken image links")
        if optimization['broken_links'] > 0:
            console.print(f"    • Broken Links: [red]{optimization['broken_links']}[/red] 404 errors")
        if optimization['redirect_chains'] > 0:
            console.print(f"    • Redirect Chains: [yellow]{optimization['redirect_chains']}[/yellow] redirects")
    else:
        console.print(f"\n  ✅ No major optimization issues detected")
    
    # Show detailed analysis sections if requested
    if content_type_analysis:
        console.print("\n[bold yellow]📄 CONTENT TYPE ANALYSIS[/bold yellow]")
        
        for content_type, data in list(content_summary['content_distribution'].items())[:5]:
            console.print(f"\n  📋 {content_type}:")
            console.print(f"    • Requests: [cyan]{data['requests']:,}[/cyan] ({data['percentage']:.1f}%)")
            console.print(f"    • Bandwidth: [yellow]{data['bandwidth_mb']:.1f} MB[/yellow]")
            console.print(f"    • Avg Response Time: [green]{data['avg_response_time']:.3f}s[/green]")
            console.print(f"    • Error Rate: [red]{data['error_rate']:.1f}%[/red]")
            console.print(f"    • Cache Hit Rate: [blue]{data['cache_hit_rate']:.1f}%[/blue]")
            console.print(f"    • Unique IPs: [cyan]{data['unique_ips']:,}[/cyan]")
    
    if file_extension_analysis:
        console.print("\n[bold green]📎 FILE EXTENSION ANALYSIS[/bold green]")
        
        for extension, data in list(content_summary['extension_analysis'].items())[:top_content]:
            console.print(f"\n  📄 {extension}:")
            console.print(f"    • Requests: [cyan]{data['requests']:,}[/cyan]")
            console.print(f"    • Bandwidth: [yellow]{data['bandwidth_mb']:.1f} MB[/yellow]")
            console.print(f"    • Avg File Size: [blue]{data['avg_file_size_kb']:.1f} KB[/blue]")
            console.print(f"    • Avg Response Time: [green]{data['avg_response_time']:.3f}s[/green]")
            if data['error_count'] > 0:
                console.print(f"    • Errors: [red]{data['error_count']:,}[/red]")
    
    if performance_analysis:
        console.print("\n[bold magenta]⚡ PERFORMANCE ANALYSIS[/bold magenta]")
        
        perf_issues = content_summary['performance_issues']
        
        if perf_issues['slowest_content_types']:
            console.print(f"  🐌 Slowest Content Types:")
            for content_type, count in list(perf_issues['slowest_content_types'].items())[:5]:
                console.print(f"    • [red]{content_type}[/red]: {count:,} slow responses")
        
        if perf_issues['largest_content_types']:
            console.print(f"\n  📈 Largest Content Types:")
            for content_type, count in list(perf_issues['largest_content_types'].items())[:5]:
                console.print(f"    • [yellow]{content_type}[/yellow]: {count:,} large files")
        
        if perf_issues['highest_error_rate']:
            console.print(f"\n  ❌ Highest Error Rates:")
            for content_type, count in list(perf_issues['highest_error_rate'].items())[:5]:
                console.print(f"    • [red]{content_type}[/red]: {count:,} errors")
    
    if optimization_analysis:
        console.print("\n[bold cyan]🔧 OPTIMIZATION ANALYSIS[/bold cyan]")
        
        if optimization['top_large_images']:
            console.print(f"  🖼️  Largest Images:")
            for image, count in list(optimization['top_large_images'].items())[:5]:
                image_display = image[:60] + "..." if len(image) > 60 else image
                console.print(f"    • [red]{image_display}[/red]: {count:,} large requests")
        
        if optimization['top_unoptimized']:
            console.print(f"\n  ⚠️  Unoptimized Resources:")
            for resource, count in list(optimization['top_unoptimized'].items())[:5]:
                resource_display = resource[:60] + "..." if len(resource) > 60 else resource
                console.print(f"    • [orange1]{resource_display}[/orange1]: {count:,} large requests")
    
    if seo_analysis:
        console.print("\n[bold red]🔍 SEO & BROKEN RESOURCE ANALYSIS[/bold red]")
        
        if optimization['missing_images'] > 0:
            console.print(f"  🖼️  Missing Images: [red]{optimization['missing_images']}[/red]")
            if analyzer.seo_analysis['missing_images']:
                console.print(f"    Top missing images:")
                for image, count in list(analyzer.seo_analysis['missing_images'].most_common(3)):
                    image_display = image[:50] + "..." if len(image) > 50 else image
                    console.print(f"      • [red]{image_display}[/red]: {count:,} 404s")
        
        if optimization['broken_links'] > 0:
            console.print(f"\n  🔗 Broken Links: [red]{optimization['broken_links']}[/red]")
            if analyzer.seo_analysis['broken_links']:
                console.print(f"    Top broken links:")
                for link, count in list(analyzer.seo_analysis['broken_links'].most_common(3)):
                    link_display = link[:50] + "..." if len(link) > 50 else link
                    console.print(f"      • [red]{link_display}[/red]: {count:,} 404s")
        
        if optimization['redirect_chains'] > 0:
            console.print(f"\n  🔄 Redirect Chains: [yellow]{optimization['redirect_chains']}[/yellow]")
            if analyzer.seo_analysis['redirect_chains']:
                console.print(f"    Top redirecting resources:")
                for resource, count in list(analyzer.seo_analysis['redirect_chains'].most_common(3)):
                    resource_display = resource[:50] + "..." if len(resource) > 50 else resource
                    console.print(f"      • [yellow]{resource_display}[/yellow]: {count:,} redirects")
    
    # Export content report if requested
    if output:
        analyzer.export_content_report(output)
        console.print(f"[green]Content analysis report exported to: {output}[/green]")
    
    # Show recommendations
    recommendations = analyzer.get_content_recommendations()
    if recommendations:
        console.print(f"\n[bold green]💡 CONTENT OPTIMIZATION RECOMMENDATIONS[/bold green]")
        for rec in recommendations[:3]:  # Top 3 recommendations
            priority_color = "red" if rec['priority'] == 'High' else "yellow" if rec['priority'] == 'Medium' else "green"
            console.print(f"  [{priority_color}]{rec['category']} ({rec['priority']} Priority)[/{priority_color}]")
            console.print(f"    Issue: {rec['issue']}")
            console.print(f"    Recommendation: {rec['recommendation']}")
            console.print(f"    Impact: {rec['impact']}")
            console.print()


# E-commerce Analysis Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--platform', type=click.Choice(['magento', 'woocommerce', 'shopware6', 'auto']), 
              default='auto', help='E-commerce platform (auto-detect by default)')
@click.option('--checkout-analysis', is_flag=True, help='Show ONLY checkout analysis')
@click.option('--admin-analysis', is_flag=True, help='Show ONLY admin analysis')
@click.option('--api-analysis', is_flag=True, help='Show ONLY API analysis')
@click.option('--login-security', is_flag=True, help='Show ONLY login security')
@click.option('--media-analysis', is_flag=True, help='Show ONLY media analysis')
@click.option('--detailed', is_flag=True, help='[DEPRECATED] Same as default now')
@click.option('--yesterday', is_flag=True, help='Analyze yesterday\'s logs instead of today\'s')
@click.option('--output', '-o', help='Output file for e-commerce report')
def ecommerce(log_files, platform, checkout_analysis, admin_analysis, api_analysis,
             login_security, media_analysis, detailed, yesterday, output):
    """🛒 E-commerce platform performance analysis.
    
    Specialized analysis for Magento 2, WooCommerce, and Shopware 6.
    Automatically detects your platform and shows COMPLETE analysis by default!
    
    \b
    📊 Default Analysis (no flags needed):
    • Platform detection with confidence score
    • Complete overview of all categories (checkout, admin, API, login, media)
    • IP address tracking per category
    • GraphQL operations (Magento)
    • Conversion funnel with drop-off rates
    • Checkout error patterns
    • Smart recommendations with action items
    • Full detailed breakdown of ALL sections
    
    \b
    🎯 Individual Flags:
    Use flags to show ONLY specific sections (hides others):
    • --checkout-analysis: Only checkout details
    • --admin-analysis: Only admin panel details
    • --api-analysis: Only API/GraphQL details
    • --login-security: Only login security details
    • --media-analysis: Only media/image details
    
    \b
    💡 Examples:
      hlogcli ecommerce                           # Full analysis (ALL sections!)
      hlogcli ecommerce --platform magento        # Force Magento + full analysis
      hlogcli ecommerce --checkout-analysis       # ONLY checkout section
      hlogcli ecommerce -o ecom-report.json       # Full analysis + export
    """
    from .ecommerce import EcommerceAnalyzer
    
    console.print("[blue]Starting e-commerce analysis...[/blue]")
    
    # Initialize analyzer
    analyzer = EcommerceAnalyzer()
    
    # Process logs
    def analyze_entry(log_entry):
        """Analyze a single log entry for e-commerce patterns."""
        analyzer.analyze_entry(log_entry)
    
    process_hypernode_logs_with_callback(analyze_entry, "e-commerce analysis", use_yesterday=yesterday)
    
    # Get platform summary
    try:
        platform_summary = analyzer.get_platform_summary()
        console.print(f"[dim]DEBUG: Platform summary obtained[/dim]")
    except Exception as e:
        console.print(f"[red]Error getting platform summary: {e}[/red]")
        import traceback
        console.print(f"[red]{traceback.format_exc()}[/red]")
        return
    
    # Check if any specific analysis flags were provided
    has_specific_flags = (checkout_analysis or admin_analysis or api_analysis or 
                         login_security or media_analysis or detailed)
    
    # Show platform detection
    console.print("\n[bold cyan]🛒 E-COMMERCE ANALYSIS[/bold cyan]")
    
    if platform_summary['detected_platform']:
        platform_name = platform_summary['detected_platform'].title()
        confidence = platform_summary['confidence']
        console.print(f"\n[bold]🔍 Platform Detection[/bold]")
        console.print(f"  Detected: [green]{platform_name}[/green] ({confidence:.0f}% confidence)")
        console.print(f"  Total requests: {platform_summary['total_requests']:,}")
        console.print(f"  E-commerce requests: [cyan]{platform_summary['ecommerce_requests']:,}[/cyan] ({platform_summary['ecommerce_percentage']:.1f}%)")
    else:
        console.print("\n[yellow]⚠️  No e-commerce platform detected in logs[/yellow]")
        console.print("Make sure you're analyzing logs from a Magento, WooCommerce, or Shopware 6 site.")
        return
    
    # Always show comprehensive overview for better insights
    # Flags now add EXTRA detailed analysis on top of default
    if True:  # Always show default overview
        # Checkout performance
        checkout_stats = analyzer.get_category_stats('checkout')
        if checkout_stats and checkout_stats['count'] > 0:
            console.print(f"\n[bold]🛍️  Checkout Performance[/bold]")
            console.print(f"  Requests: [cyan]{checkout_stats['count']:,}[/cyan]")
            console.print(f"  Avg response time: {checkout_stats['response_time_avg']:.3f}s")
            console.print(f"  P95: {checkout_stats['response_time_p95']:.3f}s")
            if checkout_stats['errors'] > 0:
                console.print(f"  Errors: [red]{checkout_stats['errors']:,}[/red] ({checkout_stats['error_rate']:.1f}%)")
            if checkout_stats['slow_count'] > 0:
                console.print(f"  Slow (>2s): [yellow]{checkout_stats['slow_count']:,}[/yellow]")
            
            # Show top IPs
            top_ips = analyzer.get_ip_statistics('checkout', limit=5)
            if top_ips:
                console.print(f"  Top IPs:")
                for ip_data in top_ips[:3]:
                    ip_str = f"    • {ip_data['ip']}: {ip_data['requests']} requests"
                    if 'checkout_errors' in ip_data and ip_data['checkout_errors'] > 0:
                        ip_str += f" [red]({ip_data['checkout_errors']} errors)[/red]"
                    console.print(ip_str)
        
        # Admin performance
        admin_stats = analyzer.get_category_stats('admin')
        if admin_stats and admin_stats['count'] > 0:
            console.print(f"\n[bold]💼 Admin Panel[/bold]")
            console.print(f"  Requests: [cyan]{admin_stats['count']:,}[/cyan]")
            console.print(f"  Avg response time: {admin_stats['response_time_avg']:.3f}s")
            console.print(f"  P95: {admin_stats['response_time_p95']:.3f}s")
            if admin_stats['slow_count'] > 0:
                console.print(f"  Slow (>2s): [yellow]{admin_stats['slow_count']:,}[/yellow]")
            
            # Show admin access IPs
            admin_details = analyzer.get_admin_access_details()
            if admin_details and admin_details.get('top_ips'):
                console.print(f"  Admin access IPs ({admin_details['total_admin_ips']} unique):")
                for ip_data in admin_details['top_ips'][:3]:
                    console.print(f"    • {ip_data['ip']}: {ip_data['requests']} requests, {ip_data['unique_paths']} paths")
        
        # API performance
        api_stats = analyzer.get_category_stats('api') or analyzer.get_category_stats('api_rest')
        if api_stats and api_stats['count'] > 0:
            console.print(f"\n[bold]🔌 API Performance[/bold]")
            console.print(f"  Requests: [cyan]{api_stats['count']:,}[/cyan]")
            console.print(f"  Avg response time: {api_stats['response_time_avg']:.3f}s")
            if api_stats['errors'] > 0:
                console.print(f"  Errors: [red]{api_stats['errors']:,}[/red] ({api_stats['error_rate']:.1f}%)")
            
            # Show top API users
            api_category = 'api' if 'api' in analyzer.category_ips else 'api_rest'
            top_api_ips = analyzer.get_ip_statistics(api_category, limit=5)
            if top_api_ips:
                console.print(f"  Top API users:")
                for ip_data in top_api_ips[:3]:
                    console.print(f"    • {ip_data['ip']}: {ip_data['requests']} requests")
        
        # GraphQL (Magento specific)
        graphql_stats = analyzer.get_category_stats('api_graphql')
        if graphql_stats and graphql_stats['count'] > 0:
            console.print(f"\n[bold]🔷 GraphQL API[/bold]")
            console.print(f"  Requests: [cyan]{graphql_stats['count']:,}[/cyan]")
            console.print(f"  Avg response time: {graphql_stats['response_time_avg']:.3f}s")
        
        # Login security
        login_stats = analyzer.get_category_stats('login')
        if login_stats and login_stats['count'] > 0:
            console.print(f"\n[bold]🔐 Login/Authentication[/bold]")
            console.print(f"  Login attempts: [cyan]{login_stats['count']:,}[/cyan]")
            if login_stats['errors'] > 0:
                error_color = "red" if login_stats['error_rate'] > 30 else "yellow"
                console.print(f"  Failed logins: [{error_color}]{login_stats['errors']:,}[/{error_color}] ({login_stats['error_rate']:.1f}%)")
                if login_stats['error_rate'] > 30:
                    console.print(f"  [red]⚠️  High failure rate - possible brute force attack![/red]")
            
            # Show login security details
            login_details = analyzer.get_login_security_details()
            if login_details and login_details.get('suspicious_ips'):
                console.print(f"  Suspicious IPs ({login_details['total_suspicious']} found):")
                for ip_data in login_details['suspicious_ips'][:3]:
                    severity_color = "red" if ip_data['severity'] == 'HIGH' else "yellow"
                    console.print(f"    • [{severity_color}]{ip_data['ip']}[/{severity_color}]: {ip_data['total_attempts']} attempts, "
                                f"{ip_data['failed_attempts']} failed ({ip_data['failure_rate']:.0f}%)")
        
        # Media performance
        media_stats = analyzer.get_category_stats('media')
        if media_stats and media_stats['count'] > 0:
            console.print(f"\n[bold]🖼️  Media/Images[/bold]")
            console.print(f"  Requests: [cyan]{media_stats['count']:,}[/cyan]")
            console.print(f"  Total bandwidth: {media_stats['bytes_total']/1024/1024/1024:.2f} GB")
            console.print(f"  Avg file size: {media_stats['bytes_avg']/1024:.1f} KB")
            if media_stats['bytes_avg'] > 200 * 1024:  # >200KB
                console.print(f"  [yellow]⚠️  Large images detected - consider optimization[/yellow]")
        
        # Product pages
        product_stats = analyzer.get_category_stats('product')
        if product_stats and product_stats['count'] > 0:
            console.print(f"\n[bold]📦 Product Pages[/bold]")
            console.print(f"  Requests: [cyan]{product_stats['count']:,}[/cyan]")
            console.print(f"  Avg response time: {product_stats['response_time_avg']:.3f}s")
        
        # Search
        search_stats = analyzer.get_category_stats('search')
        if search_stats and search_stats['count'] > 0:
            console.print(f"\n[bold]🔍 Search[/bold]")
            console.print(f"  Requests: [cyan]{search_stats['count']:,}[/cyan]")
            console.print(f"  Avg response time: {search_stats['response_time_avg']:.3f}s")
        
        # GraphQL Statistics (Magento specific)
        try:
            graphql_stats = analyzer.get_graphql_statistics()
            console.print(f"[dim]DEBUG: GraphQL stats obtained: {bool(graphql_stats)}[/dim]")
            if graphql_stats and graphql_stats.get('total_queries', 0) > 0:
                console.print(f"\n[bold]🔷 GraphQL API (Magento)[/bold]")
                console.print(f"  Total queries: [cyan]{graphql_stats['total_queries']:,}[/cyan]")
                console.print(f"  Unique operations: {graphql_stats['unique_operations']}")
                if graphql_stats['total_errors'] > 0:
                    error_color = "red" if graphql_stats['error_rate'] > 5 else "yellow"
                    console.print(f"  Errors: [{error_color}]{graphql_stats['total_errors']:,}[/{error_color}] ({graphql_stats['error_rate']:.1f}%)")
                
                if graphql_stats['top_operations']:
                    console.print(f"  Top operations:")
                    for operation, count in graphql_stats['top_operations'][:3]:
                        console.print(f"    • {operation}: {count:,}")
        except Exception as e:
            console.print(f"[red]Error getting GraphQL stats: {e}[/red]")
        
        # Conversion Funnel
        try:
            funnel = analyzer.get_conversion_funnel()
            console.print(f"[dim]DEBUG: Funnel obtained: {bool(funnel)}[/dim]")
            if funnel and funnel.get('funnel'):
                console.print(f"\n[bold]🎯 Conversion Funnel[/bold]")
                for step, data in funnel['funnel'].items():
                    if data['visits'] > 0:
                        drop_off_indicator = ""
                        if data['drop_off_rate'] > 50:
                            drop_off_indicator = f" [red](↓ {data['drop_off_rate']:.0f}% drop-off!)[/red]"
                        elif data['drop_off_rate'] > 30:
                            drop_off_indicator = f" [yellow](↓ {data['drop_off_rate']:.0f}% drop-off)[/yellow]"
                        console.print(f"  {step.title()}: {data['visits']:,}{drop_off_indicator}")
                
                if funnel.get('cart_abandonment_rate', 0) > 0:
                    console.print(f"  Cart abandonment: [yellow]{funnel['cart_abandonment_rate']:.1f}%[/yellow]")
        except Exception as e:
            console.print(f"[red]Error getting conversion funnel: {e}[/red]")
        
        # Deep Checkout Analysis
        console.print(f"\n[bold blue]🔍 Deep Checkout Analysis[/bold blue]")
        detailed_checkout = analyzer.get_deep_checkout_analysis()
        if detailed_checkout and detailed_checkout.get('total_errors', 0) > 0:
            console.print(f"[red]Total checkout errors: {detailed_checkout['total_errors']:,}[/red]")
            
            # Critical Issues Analysis
            if detailed_checkout.get('critical_issues'):
                console.print(f"\n[bold red]🚨 CRITICAL ISSUES FOUND:[/bold red]")
                for issue in detailed_checkout['critical_issues']:
                    if issue['type'] == 'RATE_LIMIT_EXCESS':
                        console.print(f"  • [red]EXCESSIVE RATE LIMITING[/red] from IP: [yellow]{issue['ip']}[/yellow]")
                        console.print(f"    → {issue['errors']} rate limit errors (possible bot attack or misconfiguration)")
                    elif issue['type'] == 'SERVER_ERRORS':
                        console.print(f"  • [red]SERVER STABILITY ISSUES[/red]: {issue['count']} server errors")
                        console.print(f"    → {issue['description']}")
                    elif issue['type'] == 'RATE_LIMITING':
                        console.print(f"  • [yellow]RATE LIMIT CONFIGURATION[/yellow]: {issue['count']} HTTP 429 errors")
                        console.print(f"    → {issue['description']}")
            
            # Detailed Error Pattern Breakdown
            console.print(f"\n[bold]📊 Error Pattern Analysis:[/bold]")
            error_pattern_descriptions = {
                'cart_http_429': '🛒 Cart rate limiting (users blocked from cart actions)',
                'checkout_http_429': '💳 Checkout rate limiting (payment page blocked)',
                'checkout_server_error': '❌ Server errors during checkout (5xx errors)',
                'cart_http_500': '🔄 Cart server crashes',
                'payment_http_400': '✏️ Payment validation failures',
                'checkout_not_found': '📄 Missing checkout pages',
                'checkout_http_403': '🚫 Access denied to checkout'
            }
            
            sorted_patterns = sorted(detailed_checkout['error_patterns'].items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns[:5]:
                description = error_pattern_descriptions.get(pattern, pattern)
                # Calculate impact percentage
                impact_pct = (count / detailed_checkout['total_errors']) * 100
                color = "red" if impact_pct > 25 else "yellow" if impact_pct > 10 else "blue"
                console.print(f"  • [{color}]{description}[/{color}]")
                console.print(f"    → {count:,} errors ({impact_pct:.1f}% of total)")
            
            # IP-Level Security Analysis  
            if detailed_checkout.get('ip_analysis'):
                console.print(f"\n[bold]🔒 Security Analysis by IP:[/bold]")
                sorted_ips = sorted(detailed_checkout['ip_analysis'].items(), key=lambda x: x[1]['total_errors'], reverse=True)
                for ip, data in sorted_ips[:5]:
                    threat_level = "HIGH" if data['total_errors'] > 20 else "MEDIUM" if data['total_errors'] > 5 else "LOW"
                    color = "red" if threat_level == "HIGH" else "yellow" if threat_level == "MEDIUM" else "blue"
                    
                    console.print(f"  • [{color}]{ip}[/{color}] ({threat_level} threat)")
                    console.print(f"    → {data['total_errors']} checkout errors")
                    
                    if data['most_common_error']:
                        error_type = data['most_common_error'][0]
                        error_count = data['most_common_error'][1]
                        console.print(f"    → Most common: {error_type} ({error_count}x)")
                
                
            # Checkout Performance Timeline
            if detailed_checkout.get('timeline_analysis'):
                console.print(f"\n[bold]⏰ Error Timeline (recent hours):[/bold]")
                timeline_items = list(detailed_checkout['timeline_analysis'].items())
                timeline_items.sort()
                recent_hours = timeline_items[-6:] if len(timeline_items) > 6 else timeline_items
                for hour, count in recent_hours:
                    if hour:
                        hour_str = hour.strftime('%H:00')
                        perf_status = "🔴 CRITICAL" if count > 50 else "🟡 HIGH" if count > 20 else "🔵 NORMAL"
                        console.print(f"  • [blue]{hour_str}[/blue]: {count} errors [{perf_status}]")
        else:
            console.print(f"[green]✅ No checkout errors detected![/green]")
        
        # Recommendations
        try:
            recommendations = analyzer.get_enhanced_recommendations()
            console.print(f"[dim]DEBUG: Recommendations obtained: {len(recommendations) if recommendations else 0}[/dim]")
            if recommendations:
                console.print(f"\n[bold]💡 Recommendations[/bold]")
                for rec in recommendations[:5]:  # Top 5
                    priority_color = "red" if rec['priority'] in ['Critical', 'CRITICAL'] else "yellow" if rec['priority'] in ['High', 'HIGH'] else "blue"
                    console.print(f"  [{priority_color}]{rec['priority']}[/{priority_color}] - {rec['category']}")
                    console.print(f"    {rec['recommendation']}")
                    if 'action_items' in rec and rec['action_items']:
                        console.print(f"    [dim]Actions: {', '.join(rec['action_items'][:2])}[/dim]")
        except Exception as e:
            console.print(f"[red]Error getting recommendations: {e}[/red]")
        
        # Usage hints for flags that filter to show ONLY specific sections
        console.print(f"\n[dim]━━━━━ DETAILED BREAKDOWN ━━━━━[/dim]")
        console.print(f"[dim]💡 Use flags to show ONLY specific sections (filters output):[/dim]")
        console.print(f"[dim]   --checkout-analysis   ONLY checkout details (hides all else)[/dim]")
        console.print(f"[dim]   --admin-analysis      ONLY admin panel details[/dim]")
        console.print(f"[dim]   --api-analysis        ONLY API/GraphQL details[/dim]")
        console.print(f"[dim]   --login-security      ONLY login security details[/dim]")
        console.print(f"[dim]   --media-analysis      ONLY media/image details[/dim]")
    
    # Show ALL detailed analysis sections by default (no flags needed!)
    # Flags can be used to show ONLY specific sections
    show_all = not (checkout_analysis or admin_analysis or api_analysis or 
                    login_security or media_analysis)
    
    # Debug: Show what flags are set
    console.print(f"\n[dim]🔧 DEBUG: Flags - checkout:{checkout_analysis}, admin:{admin_analysis}, api:{api_analysis}, login:{login_security}, media:{media_analysis}, show_all:{show_all}[/dim]")
    
    # Detailed analysis sections (always shown unless user picks specific ones)
    if checkout_analysis or show_all:
        console.print(f"\n[bold blue]🛍️  CHECKOUT ANALYSIS[/bold blue]")
        checkout_stats = analyzer.get_category_stats('checkout')
        
        if checkout_stats and checkout_stats['count'] > 0:
            console.print(f"  Total checkout requests: {checkout_stats['count']:,}")
            console.print(f"  Average response time: {checkout_stats['response_time_avg']:.3f}s")
            console.print(f"  Median response time: {checkout_stats['response_time_median']:.3f}s")
            console.print(f"  95th percentile: {checkout_stats['response_time_p95']:.3f}s")
            console.print(f"  Max response time: {checkout_stats['response_time_max']:.3f}s")
            console.print(f"  Errors: {checkout_stats['errors']:,} ({checkout_stats['error_rate']:.1f}%)")
            console.print(f"  Slow requests (>2s): {checkout_stats['slow_count']:,}")
            
            # Slowest checkout endpoints
            slowest = analyzer.get_slowest_endpoints('checkout', 5)
            if slowest:
                console.print(f"\n  Slowest endpoints:")
                for endpoint, avg_time in slowest:
                    display_endpoint = endpoint if len(endpoint) <= 60 else endpoint[:57] + "..."
                    console.print(f"    {avg_time:.3f}s - {display_endpoint}")
            
            # Checkout error analysis
            checkout_errors = analyzer.get_checkout_error_analysis()
            if checkout_errors and checkout_errors.get('total_errors', 0) > 0:
                console.print(f"\n  Error Analysis:")
                console.print(f"    Total errors: [red]{checkout_errors['total_errors']:,}[/red]")
                
                if checkout_errors.get('critical_issues'):
                    console.print(f"\n    Critical Issues:")
                    for issue in checkout_errors['critical_issues']:
                        console.print(f"      🚨 {issue['issue']}: {issue['count']} times")
                
                if checkout_errors.get('error_patterns'):
                    console.print(f"\n    Error Patterns:")
                    for pattern, count in list(checkout_errors['error_patterns'].items())[:5]:
                        console.print(f"      • {pattern}: {count}")
            
            # Conversion funnel
            funnel = analyzer.get_conversion_funnel()
            if funnel and funnel.get('funnel'):
                console.print(f"\n  Conversion Funnel:")
                for step, data in funnel['funnel'].items():
                    if data['visits'] > 0:
                        drop_text = f" (↓ {data['drop_off_rate']:.0f}%)" if data['drop_off_rate'] > 0 else ""
                        console.print(f"    {step.title()}: {data['visits']:,}{drop_text}")
                
                if funnel.get('cart_abandonment_rate'):
                    console.print(f"\n    Cart Abandonment Rate: [yellow]{funnel['cart_abandonment_rate']:.1f}%[/yellow]")
                    console.print(f"    Abandoned carts: {funnel['abandoned_carts']:,}")
                    console.print(f"    Completed checkouts: {funnel['complete_paths']:,}")
        else:
            console.print("  No checkout requests found")
    
    if admin_analysis or show_all:
        console.print(f"\n[bold magenta]💼 ADMIN PANEL ANALYSIS[/bold magenta]")
        admin_stats = analyzer.get_category_stats('admin')
        
        if admin_stats and admin_stats['count'] > 0:
            console.print(f"  Total admin requests: {admin_stats['count']:,}")
            console.print(f"  Average response time: {admin_stats['response_time_avg']:.3f}s")
            console.print(f"  95th percentile: {admin_stats['response_time_p95']:.3f}s")
            console.print(f"  Slow requests (>2s): {admin_stats['slow_count']:,}")
            
            # Slowest admin operations
            slowest = analyzer.get_slowest_endpoints('admin', 10)
            if slowest:
                console.print(f"\n  Slowest operations:")
                for endpoint, avg_time in slowest:
                    display_endpoint = endpoint if len(endpoint) <= 60 else endpoint[:57] + "..."
                    color = "red" if avg_time > 5 else "yellow"
                    console.print(f"    [{color}]{avg_time:.3f}s[/{color}] - {display_endpoint}")
        else:
            console.print("  No admin requests found")
    
    if api_analysis or show_all:
        console.print(f"\n[bold green]🔌 API ANALYSIS[/bold green]")
        
        # REST API
        api_stats = analyzer.get_category_stats('api') or analyzer.get_category_stats('api_rest')
        if api_stats and api_stats['count'] > 0:
            console.print(f"  REST API requests: {api_stats['count']:,}")
            console.print(f"  Average response time: {api_stats['response_time_avg']:.3f}s")
            console.print(f"  Errors: {api_stats['errors']:,} ({api_stats['error_rate']:.1f}%)")
        
        # GraphQL
        graphql_stats_detailed = analyzer.get_graphql_statistics()
        if graphql_stats_detailed and graphql_stats_detailed.get('total_queries', 0) > 0:
            console.print(f"\n  GraphQL API (Magento):")
            console.print(f"    Total queries: {graphql_stats_detailed['total_queries']:,}")
            console.print(f"    Unique operations: {graphql_stats_detailed['unique_operations']}")
            console.print(f"    Error rate: {graphql_stats_detailed['error_rate']:.1f}%")
            
            if graphql_stats_detailed.get('top_operations'):
                console.print(f"\n    Top GraphQL Operations:")
                for operation, count in graphql_stats_detailed['top_operations'][:10]:
                    console.print(f"      • {operation}: {count:,}")
            
            if graphql_stats_detailed.get('operation_stats'):
                console.print(f"\n    Performance by Operation:")
                for op, stats in sorted(graphql_stats_detailed['operation_stats'].items(), 
                                       key=lambda x: x[1]['avg_response_time'], 
                                       reverse=True)[:5]:
                    console.print(f"      {op}:")
                    console.print(f"        Requests: {stats['count']}, Avg: {stats['avg_response_time']:.3f}s, Errors: {stats['errors']}")
    
    if login_security or show_all:
        console.print(f"\n[bold red]🔐 LOGIN SECURITY ANALYSIS[/bold red]")
        login_stats = analyzer.get_category_stats('login')
        
        if login_stats and login_stats['count'] > 0:
            console.print(f"  Total login attempts: {login_stats['count']:,}")
            console.print(f"  Failed logins: {login_stats['errors']:,} ({login_stats['error_rate']:.1f}%)")
            
            if login_stats['error_rate'] > 50:
                console.print(f"  [red]🚨 CRITICAL: Very high failure rate - likely brute force attack![/red]")
            elif login_stats['error_rate'] > 30:
                console.print(f"  [yellow]⚠️  WARNING: High failure rate - possible attack[/yellow]")
            else:
                console.print(f"  [green]✅ Login failure rate is normal[/green]")
        else:
            console.print("  No login activity found")
    
    if media_analysis or show_all:
        console.print(f"\n[bold cyan]🖼️  MEDIA ANALYSIS[/bold cyan]")
        media_stats = analyzer.get_category_stats('media')
        
        if media_stats and media_stats['count'] > 0:
            console.print(f"  Total media requests: {media_stats['count']:,}")
            console.print(f"  Total bandwidth: {media_stats['bytes_total']/1024/1024/1024:.2f} GB")
            console.print(f"  Average file size: {media_stats['bytes_avg']/1024:.1f} KB")
            console.print(f"  Average response time: {media_stats['response_time_avg']:.3f}s")
            
            if media_stats['bytes_avg'] > 500 * 1024:
                console.print(f"  [red]⚠️  Very large images (avg >500KB) - urgent optimization needed![/red]")
            elif media_stats['bytes_avg'] > 200 * 1024:
                console.print(f"  [yellow]⚠️  Large images (avg >200KB) - consider WebP, compression, CDN[/yellow]")
            else:
                console.print(f"  [green]✅ Image sizes are reasonable[/green]")
        else:
            console.print("  No media requests found")
    
    # Export report if requested
    if output:
        import json
        report = analyzer.export_report()
        with open(output, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]E-commerce analysis report exported to: {output}[/green]")


# Anomaly Detection Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--sensitivity', default=2.5, type=float, help='Anomaly detection sensitivity (lower = more sensitive)')
@click.option('--window-size', default=60, type=int, help='Analysis window size in minutes')
@click.option('--realtime-alerts', is_flag=True, help='Show real-time critical alerts')
@click.option('--statistical-analysis', is_flag=True, help='Statistical anomaly detection')
@click.option('--behavioral-analysis', is_flag=True, help='Behavioral pattern anomaly detection')
@click.option('--show-timeline', is_flag=True, help='Show anomaly timeline')
@click.option('--recent-hours', default=1, type=int, help='Show anomalies from last N hours')
@click.option('--yesterday', is_flag=True, help='Analyze yesterday\'s logs instead of today\'s')
@click.option('--output', '-o', help='Output file for anomaly detection report')
def anomalies(log_files, sensitivity, window_size, realtime_alerts,
              statistical_analysis, behavioral_analysis, show_timeline, recent_hours, yesterday, output):
    """🤖 Machine learning-based anomaly detection for unusual traffic patterns.
    
    Detect traffic anomalies using statistical analysis and behavioral pattern recognition.
    Identify DDoS attacks, performance issues, security threats, and unusual user behavior
    using advanced algorithms and machine learning techniques.
    
    \b
    🎯 Anomaly Detection Features:
      • Statistical anomaly detection using Z-score analysis
      • Behavioral pattern recognition and learning
      • Real-time critical alert detection (DDoS, performance)
      • Traffic volume and pattern anomalies
      • Geographic and user agent anomalies
      • Attack pattern detection in URLs and requests
      • Response time and error rate spike detection
      • IP behavior analysis and scanning detection
    
    \b
    🔍 Detection Methods:
      • Statistical Analysis: Z-score based anomaly detection
      • Behavioral Learning: Pattern recognition from historical data
      • Real-time Monitoring: Immediate detection of critical issues
      • Time Series Analysis: Traffic pattern and trend analysis
      • Geographic Analysis: Unusual country-based traffic patterns
      • Security Pattern Detection: Attack signatures and suspicious behavior
    
    \b
    ⚠️ Anomaly Types Detected:
      • Traffic Spikes/Drops: Unusual request volume changes
      • DDoS Attacks: High request rates from single IPs
      • Error Rate Spikes: Sudden increases in error responses
      • Response Time Anomalies: Performance degradation detection
      • Geographic Anomalies: Unusual country traffic patterns
      • User Agent Anomalies: Suspicious or unusual client patterns
      • Attack Patterns: Security threat detection in requests
      • Scanning Behavior: Automated scanning and reconnaissance
    
    \b
    💡 Examples:
      hlogcli anomalies                                # Comprehensive anomaly detection
      hlogcli anomalies --sensitivity 2.0             # More sensitive detection
      hlogcli anomalies --realtime-alerts              # Show critical real-time alerts
      hlogcli anomalies --statistical-analysis         # Statistical anomaly analysis
      hlogcli anomalies --behavioral-analysis          # Behavioral pattern analysis
      hlogcli anomalies --show-timeline                # Anomaly timeline view
      hlogcli anomalies --recent-hours 6 -o anomalies.json  # Export 6-hour report
    """
    
    # Initialize anomaly detector
    from .anomaly_detection import AnomalyDetector
    detector = AnomalyDetector(window_size=window_size, sensitivity=sensitivity)
    
    # Process log files with nice progress display
    console.print("[blue]Starting anomaly detection analysis...[/blue]")
    console.print(f"[dim]Sensitivity: {sensitivity}, Window: {window_size} minutes[/dim]")
    
    def analyze_entry(log_entry):
        """Analyze a single log entry for anomalies."""
        detector.analyze_entry(log_entry)
    
    process_hypernode_logs_with_callback(analyze_entry, "anomaly detection", use_yesterday=yesterday)
    
    # Process any remaining minute data
    if detector.current_minute_data['timestamp'] is not None:
        detector._process_completed_minute()
    
    # Get comprehensive anomaly data
    anomaly_summary = detector.get_anomaly_summary()
    recent_anomalies = detector.get_recent_anomalies(hours=recent_hours)
    
    # Show anomaly summary by default
    console.print("\n[bold blue]🤖 ANOMALY DETECTION SUMMARY[/bold blue]")
    console.print(f"  📊 Detection Overview:")
    console.print(f"    • Total Anomalies Detected: [cyan]{anomaly_summary['total_anomalies']:,}[/cyan]")
    console.print(f"    • Recent Anomalies ({recent_hours}h): [yellow]{anomaly_summary['recent_anomalies']:,}[/yellow]")
    console.print(f"    • Critical Anomalies: [red]{anomaly_summary['critical_anomalies']:,}[/red]")
    console.print(f"    • High Severity: [orange1]{anomaly_summary['high_severity_anomalies']:,}[/orange1]")
    console.print(f"    • Medium Severity: [yellow]{anomaly_summary['medium_severity_anomalies']:,}[/yellow]")
    
    # Show top anomaly types
    if anomaly_summary['top_anomaly_types']:
        console.print(f"\n  🏆 Top Anomaly Types:")
        for anomaly_type, count in anomaly_summary['top_anomaly_types'].items():
            type_display = anomaly_type.replace('_', ' ').title()
            console.print(f"    • [red]{type_display}[/red]: {count:,} detections")
    
    # Show baseline metrics if available
    if anomaly_summary['baseline_metrics']:
        baseline = anomaly_summary['baseline_metrics']
        console.print(f"\n  📈 Baseline Metrics:")
        console.print(f"    • Avg Requests/Min: [cyan]{baseline.get('avg_requests_per_minute', 0):.1f}[/cyan]")
        console.print(f"    • Avg Unique IPs/Min: [blue]{baseline.get('avg_unique_ips_per_minute', 0):.1f}[/blue]")
        console.print(f"    • Avg Error Rate: [red]{baseline.get('avg_error_rate_per_minute', 0):.1f}%[/red]")
        console.print(f"    • Avg Response Time: [green]{baseline.get('avg_response_time_per_minute', 0):.3f}s[/green]")
    
    # Show real-time alerts if requested
    if realtime_alerts and recent_anomalies:
        console.print("\n[bold red]🚨 REAL-TIME CRITICAL ALERTS[/bold red]")
        
        critical_alerts = [a for a in recent_anomalies if a['details'].get('severity') == 'Critical']
        if critical_alerts:
            for alert in critical_alerts[-5:]:  # Show last 5 critical alerts
                alert_time = alert['detected_at']
                alert_type = alert['type'].replace('_', ' ').title()
                console.print(f"  🔴 [red]{alert_time}[/red] - {alert_type}")
                
                details = alert['details']
                if alert['type'] == 'ddos_attack':
                    console.print(f"      └─ IP: {details['ip']}, {details['requests_per_minute']} req/min")
                elif alert['type'] == 'critical_response_time':
                    console.print(f"      └─ Path: {details['path']}, {details['response_time']:.2f}s response")
                else:
                    console.print(f"      └─ Confidence: {alert['confidence']:.2f}")
        else:
            console.print("  [green]✅ No critical alerts in recent period[/green]")
    
    # Show statistical analysis if requested
    if statistical_analysis:
        console.print("\n[bold yellow]📊 STATISTICAL ANOMALY ANALYSIS[/bold yellow]")
        
        statistical_anomalies = [a for a in recent_anomalies 
                               if a['type'] in ['traffic_spike', 'traffic_drop', 'error_spike', 
                                              'response_time_spike', 'unusual_ip_activity']]
        
        if statistical_anomalies:
            console.print(f"  📈 Statistical Anomalies Detected: {len(statistical_anomalies)}")
            
            for anomaly in statistical_anomalies[-5:]:  # Show last 5
                details = anomaly['details']
                anomaly_type = anomaly['type'].replace('_', ' ').title()
                z_score = details.get('z_score', 0)
                
                console.print(f"\n  📊 {anomaly_type}:")
                console.print(f"    • Time: [cyan]{anomaly['detected_at']}[/cyan]")
                console.print(f"    • Z-Score: [yellow]{z_score:.2f}[/yellow]")
                console.print(f"    • Confidence: [blue]{anomaly['confidence']:.2f}[/blue]")
                
                if 'actual_requests' in details:
                    console.print(f"    • Actual: [red]{details['actual_requests']}[/red], Expected: [green]{details['expected_requests']:.1f}[/green]")
                elif 'actual_error_rate' in details:
                    console.print(f"    • Error Rate: [red]{details['actual_error_rate']:.1f}%[/red], Expected: [green]{details['expected_error_rate']:.1f}%[/green]")
        else:
            console.print("  [green]✅ No statistical anomalies detected[/green]")
    
    # Show behavioral analysis if requested
    if behavioral_analysis:
        console.print("\n[bold magenta]🧠 BEHAVIORAL ANOMALY ANALYSIS[/bold magenta]")
        
        behavioral_anomalies = [a for a in recent_anomalies 
                              if a['type'] in ['geographic_anomaly', 'user_agent_anomaly', 
                                             'attack_pattern_anomaly', 'scanning_behavior']]
        
        if behavioral_anomalies:
            console.print(f"  🔍 Behavioral Anomalies Detected: {len(behavioral_anomalies)}")
            
            for anomaly in behavioral_anomalies[-5:]:  # Show last 5
                details = anomaly['details']
                anomaly_type = anomaly['type'].replace('_', ' ').title()
                
                console.print(f"\n  🧠 {anomaly_type}:")
                console.print(f"    • Time: [cyan]{anomaly['detected_at']}[/cyan]")
                console.print(f"    • Severity: [red]{details.get('severity', 'Unknown')}[/red]")
                
                if 'country' in details:
                    console.print(f"    • Country: [yellow]{details['country']}[/yellow], Requests: {details['requests']}")
                elif 'user_agent' in details:
                    ua_display = details['user_agent'][:50] + "..." if len(details['user_agent']) > 50 else details['user_agent']
                    console.print(f"    • User Agent: [yellow]{ua_display}[/yellow]")
                elif 'path' in details:
                    console.print(f"    • Path: [red]{details['path']}[/red], Requests: {details['requests']}")
                elif 'ip' in details:
                    console.print(f"    • IP: [red]{details['ip']}[/red], Requests: {details['requests']}")
        else:
            console.print("  [green]✅ No behavioral anomalies detected[/green]")
    
    # Show timeline if requested
    if show_timeline and recent_anomalies:
        console.print(f"\n[bold cyan]⏰ ANOMALY TIMELINE (Last {recent_hours}h)[/bold cyan]")
        
        # Group anomalies by hour
        hourly_anomalies = defaultdict(list)
        for anomaly in recent_anomalies:
            hour = anomaly['detected_at'][:13]  # YYYY-MM-DDTHH
            hourly_anomalies[hour].append(anomaly)
        
        if hourly_anomalies:
            for hour in sorted(hourly_anomalies.keys(), reverse=True)[:12]:  # Last 12 hours
                anomalies_in_hour = hourly_anomalies[hour]
                console.print(f"\n  🕐 {hour}:00")
                
                # Count by severity
                critical = len([a for a in anomalies_in_hour if a['details'].get('severity') == 'Critical'])
                high = len([a for a in anomalies_in_hour if a['details'].get('severity') == 'High'])
                medium = len([a for a in anomalies_in_hour if a['details'].get('severity') == 'Medium'])
                
                console.print(f"    • Total: [cyan]{len(anomalies_in_hour)}[/cyan] anomalies")
                if critical > 0:
                    console.print(f"    • Critical: [red]{critical}[/red]")
                if high > 0:
                    console.print(f"    • High: [orange1]{high}[/orange1]")
                if medium > 0:
                    console.print(f"    • Medium: [yellow]{medium}[/yellow]")
        else:
            console.print("  [green]✅ No anomalies in recent timeline[/green]")
    
    # Export anomaly report if requested
    if output:
        detector.export_anomaly_report(output)
        console.print(f"[green]Anomaly detection report exported to: {output}[/green]")
    
    # Show detailed breakdown if there are anomalies
    if anomaly_summary.get('detailed_breakdown'):
        console.print("\n[bold green]🔍 DETAILED ANOMALY BREAKDOWN[/bold green]")
        breakdown = anomaly_summary['detailed_breakdown']
        
        for anomaly_type, details in list(breakdown.items())[:5]:  # Show top 5 types
            type_display = anomaly_type.replace('_', ' ').title()
            console.print(f"\n  [bold blue]📊 {type_display} ({details['count']} occurrences)[/bold blue]")
            
            # Show time range
            first_occ = details['time_range']['first_occurrence']
            last_occ = details['time_range']['last_occurrence']
            
            # Handle both datetime objects and strings
            if hasattr(first_occ, 'strftime'):
                first_str = first_occ.strftime('%Y-%m-%dT%H:%M')
            else:
                first_str = str(first_occ)[:16]
                
            if hasattr(last_occ, 'strftime'):
                last_str = last_occ.strftime('%Y-%m-%dT%H:%M')
            else:
                last_str = str(last_occ)[:16]
                
            console.print(f"    ⏰ Time Range: {first_str} - {last_str}")
            
            # Show severity distribution
            severity_dist = details['severity_distribution']
            severity_parts = []
            for severity, count in severity_dist.items():
                color = {'Critical': 'red', 'High': 'orange1', 'Medium': 'yellow', 'Low': 'dim'}.get(severity, 'white')
                severity_parts.append(f"[{color}]{count} {severity}[/{color}]")
            console.print(f"    🎯 Severity: {', '.join(severity_parts)}")
            
            # Show impact summary
            impact = details['impact_summary']
            if impact:
                console.print(f"    💥 Impact: {impact.get('estimated_impact', 'Unknown')} ({impact.get('duration_minutes', 0):.1f} min)")
                console.print(f"    📈 Confidence: {impact.get('average_confidence', 0):.2f}")
            
            # Show examples
            if details['examples']:
                console.print(f"    📝 Examples:")
                for example in details['examples'][:2]:  # Show first 2 examples
                    console.print(f"      • {example['timestamp'][:16]}: {example['description']}")
    
    # Show timeline analysis
    if anomaly_summary.get('timeline_analysis'):
        timeline = anomaly_summary['timeline_analysis']
        if timeline.get('hourly_distribution'):
            console.print(f"\n[bold magenta]⏰ ANOMALY TIMELINE ANALYSIS[/bold magenta]")
            console.print(f"  📊 Average anomalies per hour: {timeline.get('average_per_hour', 0)}")
            
            if timeline.get('peak_periods'):
                peak_hours = [f"{h:02d}:00" for h in timeline['peak_periods'][:5]]
                console.print(f"  🔥 Peak anomaly periods: {', '.join(peak_hours)}")
            
            if timeline.get('quiet_periods'):
                quiet_hours = [f"{h:02d}:00" for h in timeline['quiet_periods'][:5]]
                console.print(f"  😴 Quiet periods: {', '.join(quiet_hours)}")
    
    # Show top affected resources
    if anomaly_summary.get('top_affected_resources'):
        resources = anomaly_summary['top_affected_resources']
        console.print(f"\n[bold red]🎯 TOP AFFECTED RESOURCES[/bold red]")
        
        if resources.get('top_ips'):
            console.print(f"  🌐 Most Affected IPs:")
            for ip, count in list(resources['top_ips'].items())[:3]:
                console.print(f"    • {ip}: {count} anomalies")
        
        if resources.get('top_paths'):
            console.print(f"  📁 Most Affected Paths:")
            for path, count in list(resources['top_paths'].items())[:3]:
                path_display = path[:50] + '...' if len(path) > 50 else path
                console.print(f"    • {path_display}: {count} anomalies")
        
        if resources.get('top_countries'):
            console.print(f"  🌍 Most Affected Countries:")
            for country, count in list(resources['top_countries'].items())[:3]:
                console.print(f"    • {country}: {count} anomalies")
    
    # Show historical context
    if anomaly_summary.get('historical_context'):
        context = anomaly_summary['historical_context']
        console.print(f"\n[bold cyan]📅 HISTORICAL CONTEXT[/bold cyan]")
        console.print(f"  🕐 Current Time: {context['current_time'][:16]} ({context['current_weekday']})")
        
        if context.get('baseline_comparison', {}).get('current_hour'):
            hour_baseline = context['baseline_comparison']['current_hour']
            console.print(f"  📊 Expected for hour {hour_baseline['hour']:02d}:00:")
            console.print(f"    • Requests: {hour_baseline['expected_requests']:.1f}")
            console.print(f"    • Error Rate: {hour_baseline['expected_error_rate']:.1f}%")
            console.print(f"    • Unique IPs: {hour_baseline['expected_unique_ips']:.1f}")

    # Show comprehensive recommendations
    recommendations = detector.get_anomaly_recommendations()
    if recommendations:
        console.print("\n[bold yellow]💡 COMPREHENSIVE RECOMMENDATIONS[/bold yellow]")
        for i, rec in enumerate(recommendations[:3], 1):  # Show top 3 recommendations
            priority_color = {
                'Critical': 'red',
                'High': 'orange1',
                'Medium': 'yellow',
                'Low': 'dim'
            }.get(rec['priority'], 'white')
            
            console.print(f"\n  [bold {priority_color}]{i}. {rec['category']}[/bold {priority_color}] ([{priority_color}]{rec['priority']} Priority[/{priority_color}])")
            console.print(f"     Issue: {rec['issue']}")
            console.print(f"     Recommendation: {rec['recommendation']}")
            
            # Show specific changes if available
            if 'specific_changes' in rec:
                console.print(f"     📈 Specific Changes:")
                for change in rec['specific_changes'][:3]:
                    console.print(f"       • {change}")
            
            # Show immediate actions
            if 'immediate_actions' in rec:
                console.print(f"     🚨 Immediate Actions:")
                for action in rec['immediate_actions'][:3]:
                    console.print(f"       • {action}")
            
            # Show business impact
            if 'business_impact' in rec:
                console.print(f"     💼 Business Impact: {rec['business_impact']}")
            
            # Show timeline if available
            if 'timeline' in rec:
                console.print(f"     ⏱️  Timeline: {rec['timeline']}")
        
        # Show summary of remaining recommendations
        if len(recommendations) > 3:
            remaining = len(recommendations) - 3
            console.print(f"\n  [dim]... and {remaining} more recommendations available in detailed report[/dim]")
    else:
        console.print(f"\n[bold green]✅ NO URGENT RECOMMENDATIONS[/bold green]")
        console.print("  Current traffic patterns appear normal with no critical anomalies requiring immediate action.")


# Bot Analysis Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--classify-types', is_flag=True, help='Classify bot types')
@click.option('--behavior-analysis', is_flag=True, help='Analyze bot behavior patterns')
@click.option('--legitimate-vs-malicious', is_flag=True, help='Score bots as good/bad')
@click.option('--impact-analysis', is_flag=True, help='Analyze bot resource impact')
@click.option('--unknown-only', is_flag=True, help='Show only unclassified bots')
@click.option('--ai-bots-only', is_flag=True, help='Show only AI bot analysis')
@click.option('--ai-training-detection', is_flag=True, help='Detect potential AI training data crawlers')
@click.option('--llm-bot-analysis', is_flag=True, help='Detailed LLM bot analysis')
@click.option('--ai-impact-analysis', is_flag=True, help='AI bot resource impact analysis')
@click.option('--yesterday', is_flag=True, help='Analyze yesterday\'s logs instead of today\'s')
@click.option('--output', '-o', help='Output file for bot analysis report')
@click.option('--ignore-blocked/--no-ignore-blocked', default=True, help='Ignore blocked requests (e.g., 403/444/495-499) during analysis')
@click.option('--blocked-status-codes', default='403,444,495-499', help='Comma-separated status codes/ranges to treat as blocked')
@click.option('--show-blocked', is_flag=True, help='Show blocked traffic summary')
def bots(log_files, classify_types, behavior_analysis,
         legitimate_vs_malicious, impact_analysis, unknown_only, ai_bots_only, 
         ai_training_detection, llm_bot_analysis, ai_impact_analysis, yesterday, ignore_blocked, blocked_status_codes, show_blocked, output):
    """🤖 Advanced bot and crawler analysis and classification.
    
    Identify, classify, and analyze bot traffic to understand automated visitors
    to your website. Distinguish between legitimate crawlers (Google, Bing) and
    malicious bots, scrapers, or security scanners.
    
    \b
    🕷️ Bot Classification:
      • Search engine crawlers (Google, Bing, Yahoo, etc.)
      • Social media bots (Facebook, Twitter, LinkedIn)
      • Monitoring services (Pingdom, UptimeRobot)
      • SEO tools and analyzers
      • Malicious scrapers and security scanners
      • Unknown/unclassified bots
      
    \b
    🤖 AI Bot Categories (NEW):
      • Large Language Model bots (ChatGPT, Claude, Bard, Copilot)
      • AI training data crawlers (Common Crawl, AI2)
      • AI research and academic bots (Hugging Face, university crawlers)
      • AI content generation bots (Jasper, Copy.ai, Midjourney)
      • AI SEO and marketing bots (AI-powered tools)
      • Conversational AI and chatbots (virtual assistants)
      • AI API and service bots (automated AI services)
    
    \b
    🔍 Analysis Features:
      • Bot behavior pattern analysis
      • Legitimacy scoring (good vs. bad bots)
      • Resource impact assessment
      • Request frequency analysis
      • Geographic distribution of bots
      • AI training data detection (NEW)
      • LLM bot activity analysis (NEW)
      • AI bot resource impact metrics (NEW)
    
    \b
    💡 Examples:
      hlogcli bots                              # Comprehensive bot analysis (default)
      hlogcli bots --classify-types             # Detailed bot classification
      hlogcli bots --behavior-analysis          # Bot behavior patterns
      hlogcli bots --legitimate-vs-malicious    # Good vs. bad bot scoring
      hlogcli bots --impact-analysis            # Resource usage by bots
      hlogcli bots --unknown-only -o unknown-bots.json  # Export unclassified
      
      # NEW AI Bot Analysis:
      hlogcli bots --ai-bots-only               # Focus on AI bots only
      hlogcli bots --ai-training-detection      # Detect AI training crawlers
      hlogcli bots --llm-bot-analysis           # Detailed LLM bot analysis
      hlogcli bots --ai-impact-analysis         # AI bot resource impact
    """
    
    # Initialize bot analyzer
    from .bots import BotAnalyzer
    from .filters import LogFilter
    analyzer = BotAnalyzer()
    log_filter = LogFilter()
    
    # Process log files with nice progress display
    console.print("[blue]Starting bot analysis...[/blue]")
    
    def _parse_code_list(spec: str):
        result = []
        for token in (spec or '').split(','):
            token = token.strip()
            if not token:
                continue
            if '-' in token:
                try:
                    start, end = token.split('-', 1)
                    start_i = int(start)
                    end_i = int(end)
                    if start_i <= end_i:
                        result.extend(list(range(start_i, end_i + 1)))
                except Exception:
                    continue
            else:
                try:
                    result.append(int(token))
                except Exception:
                    continue
        return result

    log_filter.set_ignore_blocked(ignore_blocked)
    log_filter.set_blocked_status_codes(_parse_code_list(blocked_status_codes))

    def analyze_entry(log_entry):
        """Analyze a single log entry for bots with blocked pre-filtering."""
        if log_filter.is_blocked(log_entry):
            analyzer.record_blocked(log_entry)
            if log_filter.ignore_blocked:
                return
        analyzer._analyze_entry(log_entry)
    
    process_hypernode_logs_with_callback(analyze_entry, "bot analysis", use_yesterday=yesterday)
    
    # Show basic bot overview if no specific options are provided
    show_basic_overview = not any([classify_types, behavior_analysis, legitimate_vs_malicious, 
                                   impact_analysis, unknown_only, ai_bots_only, ai_training_detection, 
                                   llm_bot_analysis, ai_impact_analysis])
    
    if show_basic_overview:
        console.print("\n[bold blue]🤖 COMPREHENSIVE BOT ANALYSIS[/bold blue]")
        
        # Basic classification
        bot_types = analyzer.get_bot_classification()
        total_bot_requests = sum(bot_types.values())
        
        if total_bot_requests > 0:
            # Overall statistics
            console.print(f"  [bold cyan]📊 OVERALL STATISTICS[/bold cyan]")
            console.print(f"    • Total bot requests: [cyan]{total_bot_requests:,}[/cyan]")
            console.print(f"    • Unique bot types detected: [green]{len(analyzer.bot_requests)}[/green]")
            console.print(f"    • Unknown/unclassified bots: [yellow]{len(analyzer.unknown_bots)}[/yellow]")
            
            # Resource impact details
            impact = analyzer.get_resource_impact()
            console.print(f"\n  [bold orange1]📈 RESOURCE IMPACT[/bold orange1]")
            console.print(f"    • Bot traffic percentage: [orange1]{impact['percentage_of_traffic']:.1f}%[/orange1] of total traffic")
            console.print(f"    • Total bandwidth consumed: [yellow]{impact['bandwidth_gb']:.2f} GB[/yellow]")
            console.print(f"    • Average response time: [cyan]{impact['avg_response_time']:.3f}s[/cyan]")
            console.print(f"    • Server load from bots: [red]{impact['server_load_pct']:.1f}%[/red]")
            
            # Bot categories breakdown
            console.print(f"\n  [bold green]🔍 BOT CATEGORIES BREAKDOWN[/bold green]")
            for bot_type, count in sorted(bot_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_bot_requests) * 100
                bar_length = int(percentage / 5)  # Scale bar
                bar = "▓" * bar_length + "░" * (20 - bar_length)
                console.print(f"    • {bot_type.replace('_', ' ').title()}: [green]{count:,}[/green] ({percentage:.1f}%) [{bar}]")
            
            # Top individual bots with more details
            individual_bots = []
            for bot_type, requests in analyzer.bot_requests.items():
                if bot_type in analyzer.bot_signatures:
                    description = analyzer.bot_signatures[bot_type].get('description', bot_type)
                    legitimate = analyzer.bot_signatures[bot_type].get('legitimate', False)
                    bot_category = analyzer.bot_signatures[bot_type].get('type', 'unknown')
                    avg_response = sum(analyzer.bot_response_times.get(bot_type, [0])) / max(len(analyzer.bot_response_times.get(bot_type, [1])), 1)
                    bandwidth_mb = analyzer.bot_bandwidth.get(bot_type, 0) / (1024 * 1024)
                    unique_ips = len(set(req['ip'] for req in requests))
                    individual_bots.append((bot_type, len(requests), description, legitimate, bot_category, avg_response, bandwidth_mb, unique_ips))

            if individual_bots:
                top_bots = sorted(individual_bots, key=lambda x: x[1], reverse=True)[:10]
                console.print(f"\n  [bold bright_blue]🏆 TOP 10 INDIVIDUAL BOTS[/bold bright_blue]")
                for i, (bot_name, count, description, legitimate, category, avg_response, bandwidth_mb, unique_ips) in enumerate(top_bots, 1):
                    legit_icon = "✅" if legitimate else "❌"
                    console.print(f"    {i:2}. {legit_icon} [bright_blue]{bot_name}[/bright_blue] ([dim]{category}[/dim])")
                    console.print(f"        └─ [green]{count:,}[/green] requests from [cyan]{unique_ips}[/cyan] IPs")
                    console.print(f"        └─ Avg response: [yellow]{avg_response:.3f}s[/yellow], Bandwidth: [magenta]{bandwidth_mb:.1f}MB[/magenta]")
                    console.print(f"        └─ {description}")

            # AI bot detailed analysis
            ai_analysis = analyzer.get_ai_bot_analysis()
            if ai_analysis['total_ai_requests'] > 0:
                console.print(f"\n  [bold magenta]🤖 AI BOT DETAILED ANALYSIS[/bold magenta]")
                console.print(f"    • Total AI bot requests: [magenta]{ai_analysis['total_ai_requests']:,}[/magenta]")
                console.print(f"    • AI percentage of bot traffic: [yellow]{ai_analysis['ai_percentage']:.1f}%[/yellow]")
                console.print(f"    • AI categories detected: [cyan]{len(ai_analysis['ai_categories'])}[/cyan]")
                for category, data in ai_analysis['ai_categories'].items():
                    console.print(f"      ◦ {category.replace('_', ' ').title()}: [green]{data['total_requests']:,}[/green] requests")
                    console.print(f"        └─ {data['unique_ips']} IPs, {data['avg_response_time']:.3f}s avg, {data['bandwidth_mb']:.1f}MB")
            else:
                console.print(f"\n  [bold magenta]🤖 AI BOT ANALYSIS[/bold magenta]")
                console.print(f"    • [yellow]No AI bot activity detected[/yellow]")

            # Legitimacy and security analysis
            scores = analyzer.get_legitimacy_scores()
            if scores:
                legitimate_bots = [(bot, score) for bot, score in scores.items() if score > 0.7]
                suspicious_bots = [(bot, score) for bot, score in scores.items() if score < 0.3]
                neutral_bots = [(bot, score) for bot, score in scores.items() if 0.3 <= score <= 0.7]

                console.print(f"\n  [bold green]🛡️  LEGITIMACY & SECURITY ANALYSIS[/bold green]")
                console.print(f"    • Legitimate bots: [green]{len(legitimate_bots)}[/green]")
                console.print(f"    • Suspicious bots: [red]{len(suspicious_bots)}[/red]")
                console.print(f"    • Neutral bots: [yellow]{len(neutral_bots)}[/yellow]")

                if suspicious_bots:
                    console.print(f"\n    [red]⚠️  SUSPICIOUS BOTS:[/red]")
                    for bot, score in sorted(suspicious_bots, key=lambda x: x[1])[:5]:
                        requests_count = len(analyzer.bot_requests.get(bot, []))
                        console.print(f"      • [red]{bot}[/red]: score [bold red]{score:.2f}[/bold red] ({requests_count:,} requests)")

                if legitimate_bots:
                    top_legitimate = sorted(legitimate_bots, key=lambda x: len(analyzer.bot_requests.get(x[0], [])), reverse=True)[:3]
                    console.print(f"\n    [green]✅ TOP LEGITIMATE BOTS:[/green]")
                    for bot, score in top_legitimate:
                        requests_count = len(analyzer.bot_requests.get(bot, []))
                        console.print(f"      • [green]{bot}[/green]: score [bold green]{score:.2f}[/bold green] ({requests_count:,} requests)")

            # Behavior patterns analysis
            patterns = analyzer.get_behavior_patterns()
            if patterns:
                console.print(f"\n  [bold yellow]📊 BEHAVIOR PATTERNS[/bold yellow]")
                for pattern_name, details in list(patterns.items())[:5]:  # Top 5 patterns
                    console.print(f"    • [bright_blue]{pattern_name}[/bright_blue]:")
                    console.print(f"      └─ {details['description']}")
                    console.print(f"      └─ Frequency: {details['frequency']}, Impact: {details['impact']}")

            # Bot recommendations
            recommendations = analyzer.get_bot_recommendations()
            ai_recommendations = analyzer.get_ai_bot_recommendations()
            all_recommendations = recommendations + ai_recommendations

            if all_recommendations:
                console.print(f"\n  [bold green]💡 RECOMMENDATIONS[/bold green]")
                for rec in all_recommendations[:3]:  # Top 3 recommendations
                    priority_color = "red" if rec['priority'] == 'High' else "yellow" if rec['priority'] == 'Medium' else "green"
                    console.print(f"    • [{priority_color}]{rec['category']} ({rec['priority']} Priority)[/{priority_color}]")
                    console.print(f"      └─ {rec['recommendation']}")

            # Unknown bots analysis
            if analyzer.unknown_bots:
                top_unknown = analyzer.unknown_bots.most_common(5)
                console.print(f"\n  [bold orange1]❓ TOP UNKNOWN USER AGENTS[/bold orange1]")
                for ua, count in top_unknown:
                    ua_display = (ua[:60] + "...") if len(ua) > 60 else ua
                    console.print(f"    • [yellow]{count:,}x[/yellow] [dim]{ua_display}[/dim]")

            console.print(f"\n[dim]💡 Use specific options for even more detailed analysis:[/dim]")
            console.print(f"[dim]  • --classify-types for detailed classification[/dim]")
            console.print(f"[dim]  • --ai-bots-only for AI bot analysis[/dim]")
            console.print(f"[dim]  • --behavior-analysis for behavior patterns[/dim]")
            console.print(f"[dim]  • --legitimate-vs-malicious for legitimacy scoring[/dim]")
            console.print(f"[dim]  • --ai-training-detection for AI training crawler detection[/dim]")
            console.print(f"[dim]  • --help for all available options[/dim]")
        else:
            console.print(f"  [yellow]No bot traffic detected in the analyzed logs[/yellow]")
            console.print(f"  [dim]This could mean:[/dim]")
            console.print(f"[dim]    • The logs contain only human traffic[/dim]")
            console.print(f"[dim]    • Bot signatures need updating[/dim]")
            console.print(f"[dim]    • Logs are filtered or incomplete[/dim]")
    
    # Optional blocked traffic section
    if show_blocked:
        blocked = analyzer.get_blocked_summary()
        console.print("\n[bold yellow]🚫 BLOCKED TRAFFIC[/bold yellow]")
        console.print(f"  Total blocked: {blocked['total']:,}")
        if blocked['top_status_codes']:
            console.print(f"  Top status: {blocked['top_status_codes']}")
        if blocked['top_countries']:
            console.print(f"  Top countries: {list(blocked['top_countries'].items())[:5]}")
        if blocked['top_paths']:
            console.print(f"  Top paths: {list(blocked['top_paths'].items())[:5]}")
    # Generate bot analysis reports
    if classify_types:
        console.print("\n[bold blue]🤖 BOT CLASSIFICATION[/bold blue]")
        bot_types = analyzer.get_bot_classification()
        for bot_type, count in bot_types.items():
            console.print(f"  {bot_type}: {count:,} requests")
    
    if behavior_analysis:
        console.print("\n[bold yellow]📊 BOT BEHAVIOR PATTERNS[/bold yellow]")
        patterns = analyzer.get_behavior_patterns()
        for pattern, details in patterns.items():
            console.print(f"  {pattern}: {details['description']}")
            console.print(f"    Frequency: {details['frequency']}")
            console.print(f"    Impact: {details['impact']}")
    
    if legitimate_vs_malicious:
        console.print("\n[bold green]✅ LEGITIMATE vs [bold red]❌ MALICIOUS BOTS[/bold green][/bold red]")
        scores = analyzer.get_legitimacy_scores()
        for bot, score in scores.items():
            color = "green" if score > 0.7 else "red" if score < 0.3 else "yellow"
            console.print(f"  [{color}]{bot}: {score:.2f} legitimacy score[/{color}]")
    
    if impact_analysis:
        console.print("\n[bold orange]📈 BOT RESOURCE IMPACT[/bold orange]")
        impact = analyzer.get_resource_impact()
        console.print(f"  Total bot requests: {impact['total_requests']:,}")
        console.print(f"  Bot bandwidth usage: {impact['bandwidth_gb']:.2f} GB")
        console.print(f"  Average bot response time: {impact['avg_response_time']:.3f}s")
        console.print(f"  Server load from bots: {impact['server_load_pct']:.1f}%")
    
    # NEW AI Bot Analysis Features
    if ai_bots_only or ai_impact_analysis:
        console.print("\n[bold magenta]🤖 AI BOT ANALYSIS[/bold magenta]")
        ai_analysis = analyzer.get_ai_bot_analysis()
        console.print(f"  Total AI bot requests: [cyan]{ai_analysis['total_ai_requests']:,}[/cyan]")
        console.print(f"  AI bot percentage: [yellow]{ai_analysis['ai_percentage']:.1f}%[/yellow] of all bot traffic")
        
        if ai_analysis['ai_categories']:
            console.print(f"\n  🔍 AI Bot Categories:")
            for category, data in ai_analysis['ai_categories'].items():
                console.print(f"    • {category.replace('_', ' ').title()}: [green]{data['total_requests']:,}[/green] requests")
                console.print(f"      └─ Unique IPs: {data['unique_ips']}, Avg Response: {data['avg_response_time']:.3f}s")
                
                if ai_bots_only:
                    for bot_name, bot_data in data['bots'].items():
                        legitimate_icon = "✅" if bot_data['legitimate'] else "❌"
                        console.print(f"        {legitimate_icon} {bot_name}: {bot_data['requests']:,} requests - {bot_data['description']}")
    
    if ai_training_detection:
        console.print("\n[bold red]🎯 AI TRAINING DATA DETECTION[/bold red]")
        training_indicators = analyzer.get_ai_training_indicators()
        
        if training_indicators['high_volume_crawlers']:
            console.print(f"  ⚠️  High-Volume Crawlers (potential training data collection):")
            for crawler in training_indicators['high_volume_crawlers'][:10]:
                console.print(f"    • [red]{crawler['bot']}[/red]: {crawler['requests']:,} requests, {crawler['avg_interval']:.2f}s avg interval")
                console.print(f"      └─ {crawler['description']}")
        else:
            console.print(f"  [green]✅ No high-volume training crawlers detected[/green]")
        
        if training_indicators['content_focused_bots']:
            console.print(f"\n  📄 Content-Focused Bots:")
            for bot in training_indicators['content_focused_bots'][:10]:
                console.print(f"    • [yellow]{bot['bot']}[/yellow]: {bot['content_percentage']:.1f}% content focus ({bot['total_requests']:,} requests)")
        else:
            console.print(f"  [green]✅ No content-focused crawlers detected[/green]")
    
    if llm_bot_analysis:
        console.print("\n[bold cyan]🧠 LLM BOT DETAILED ANALYSIS[/bold cyan]")
        ai_analysis = analyzer.get_ai_bot_analysis()
        llm_data = ai_analysis['ai_categories'].get('ai_llm', {})
        
        if llm_data:
            console.print(f"  Total LLM requests: [cyan]{llm_data['total_requests']:,}[/cyan]")
            console.print(f"  Unique LLM IPs: [cyan]{llm_data['unique_ips']}[/cyan]")
            console.print(f"  Average response time: [cyan]{llm_data['avg_response_time']:.3f}s[/cyan]")
            console.print(f"  Bandwidth usage: [cyan]{llm_data['bandwidth_mb']:.2f} MB[/cyan]")
            
            console.print(f"\n  🤖 Detected LLM Bots:")
            for bot_name, bot_data in llm_data['bots'].items():
                console.print(f"    • [bright_cyan]{bot_name}[/bright_cyan]: {bot_data['requests']:,} requests")
                console.print(f"      └─ {bot_data['description']}")
        else:
            console.print(f"  [yellow]No LLM bot activity detected[/yellow]")
    
    # Show AI-specific recommendations
    if ai_bots_only or ai_training_detection or llm_bot_analysis or ai_impact_analysis:
        ai_recommendations = analyzer.get_ai_bot_recommendations()
        if ai_recommendations:
            console.print(f"\n[bold green]💡 AI BOT RECOMMENDATIONS[/bold green]")
            for rec in ai_recommendations:
                priority_color = "red" if rec['priority'] == 'High' else "yellow" if rec['priority'] == 'Medium' else "green"
                console.print(f"  [{priority_color}]{rec['category']} ({rec['priority']} Priority)[/{priority_color}]")
                console.print(f"    Issue: {rec['issue']}")
                console.print(f"    Recommendation: {rec['recommendation']}")
                if 'bots' in rec:
                    console.print(f"    Affected bots: {', '.join(rec['bots'])}")
                if 'details' in rec:
                    console.print(f"    Details: {rec['details']}")
                console.print()
    
    # Export bot analysis report if requested
    if output:
        analyzer.export_bot_report(output)
        console.print(f"[green]Bot analysis report exported to: {output}[/green]")


# Search and Filter Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--ip', help='Search for specific IP address')
@click.option('--path', help='Search for path pattern (supports regex)')
@click.option('--status', help='Filter by status code(s) (comma-separated)')
@click.option('--user-agent', help='Search user agent pattern (supports regex)')
@click.option('--country', help='Filter by country code(s) (comma-separated)')
@click.option('--time-range', help='Time range (e.g., "2024-01-01 to 2024-01-02")')
@click.option('--last-hours', type=int, help='Show entries from last N hours')
@click.option('--yesterday', is_flag=True, help='Search yesterday\'s logs instead of today\'s')
@click.option('--limit', default=100, help='Limit number of results')
@click.option('--output', '-o', help='Output file for search results')
def search(log_files, ip, path, status, user_agent, 
           country, time_range, last_hours, yesterday, limit, output):
    """🔍 Advanced search and filtering of log entries.
    
    Search through your access logs with powerful filtering capabilities.
    Find specific requests, investigate issues, or extract data matching
    complex criteria using regex patterns and multiple filters.
    
    \b
    🎯 Search Capabilities:
      • IP address matching (exact or partial)
      • Path pattern matching (supports regex)
      • Status code filtering
      • User agent pattern matching (supports regex)
      • Geographic filtering by country codes
      • Time range filtering (absolute or relative)
      • HTTP method filtering
    
    \b
    💡 Examples:
      hlogcli search --ip 192.168.1.100         # Find requests from specific IP
      hlogcli search --status 404,500           # Find all 404 and 500 errors
      hlogcli search --path "/api/.*"           # Find all API requests (regex)
      hlogcli search --user-agent "bot"         # Find bot traffic
      hlogcli search --country US,GB,NL         # Requests from specific countries
      hlogcli search --last-hours 24            # Last 24 hours only
      hlogcli search --status 404 --limit 50 -o 404s.json  # Export 404 errors
      
    \b
    🕐 Time Filtering:
      --last-hours 6                            # Last 6 hours
      --time-range "2024-01-01 to 2024-01-02"  # Specific date range
    """
    
    # Initialize search
    from .search import LogSearch
    searcher = LogSearch()
    
    # Build search criteria
    criteria = {}
    if ip:
        criteria['ip'] = ip
    if path:
        criteria['path'] = path
    if status:
        criteria['status'] = [int(s.strip()) for s in status.split(',')]
    if user_agent:
        criteria['user_agent'] = user_agent
    if country:
        criteria['country'] = [c.strip().upper() for c in country.split(',')]
    if last_hours:
        from datetime import datetime, timedelta
        criteria['time_range'] = (datetime.now() - timedelta(hours=last_hours), datetime.now())
    
    console.print("[blue]Starting search...[/blue]")
    
    # Search through logs with progress display
    results = []
    
    def search_entry(log_entry):
        """Search a single log entry."""
        nonlocal results
        if len(results) >= limit:
            return
        if searcher._matches_criteria(log_entry, criteria):
            results.append(log_entry)
    
    process_hypernode_logs_with_callback(search_entry, "search", use_yesterday=yesterday)
    
    # Display results
    console.print(f"\n[bold green]🔍 SEARCH RESULTS ({len(results)} entries)[/bold green]")
    
    if not results:
        console.print("[yellow]No matching entries found.[/yellow]")
        return
    
    # Show results in a table
    from rich.table import Table
    table = Table(show_header=True)
    table.add_column("Time", style="cyan")
    table.add_column("IP", style="blue")
    table.add_column("Status", style="green")
    table.add_column("Method", style="yellow")
    table.add_column("Path", style="white", max_width=50)
    table.add_column("Country", style="magenta")
    
    for result in results[:20]:  # Show first 20 in table
        table.add_row(
            result['timestamp'].strftime('%H:%M:%S') if result['timestamp'] else '',
            str(result.get('ip', '')),
            str(result.get('status', '')),
            result.get('method', ''),
            result.get('path', '')[:47] + "..." if len(result.get('path', '')) > 50 else result.get('path', ''),
            result.get('country', '')
        )
    
    console.print(table)
    
    if len(results) > 20:
        console.print(f"[dim]... and {len(results) - 20} more entries[/dim]")
    
    # Export if requested
    if output:
        searcher.export_results(results, output)
        console.print(f"[green]Search results exported to: {output}[/green]")

# Make the main command backward compatible
@cli.command(name='main', hidden=True)
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--follow', '-f', is_flag=True, help='Follow log files for real-time analysis')
@click.option('--interactive', '-i', is_flag=True, help='Launch interactive TUI')
@click.option('--output', '-o', help='Output directory for exports')
@click.option('--filter-preset', type=click.Choice(['errors_only', 'success_only', 'no_bots', 'api_only', 'recent_activity']))
@click.option('--countries', help='Filter by countries (comma-separated, e.g., US,GB,DE)')
@click.option('--status-codes', help='Filter by status codes (comma-separated, e.g., 404,500)')
@click.option('--exclude-bots', is_flag=True, help='Exclude bot traffic')
@click.option('--export-csv', is_flag=True, help='Export results to CSV')
@click.option('--export-json', is_flag=True, help='Export results to JSON')
@click.option('--export-charts', is_flag=True, help='Export charts to HTML')
@click.option('--summary-only', is_flag=True, help='Show only summary statistics')
def main_compat(log_files, follow, interactive, output, filter_preset, countries, status_codes, 
         exclude_bots, export_csv, export_json, export_charts, summary_only):
    """Legacy main command for backward compatibility."""
    # Call the analyze command with the same parameters
    from click.testing import CliRunner
    runner = CliRunner()
    
    # Build the command arguments
    args = []
    if follow:
        args.append('--follow')
    if interactive:
        args.append('--interactive')
    if output:
        args.extend(['--output', output])
    if filter_preset:
        args.extend(['--filter-preset', filter_preset])
    if countries:
        args.extend(['--countries', countries])
    if status_codes:
        args.extend(['--status-codes', status_codes])
    if exclude_bots:
        args.append('--exclude-bots')
    if export_csv:
        args.append('--export-csv')
    if export_json:
        args.append('--export-json')
    if export_charts:
        args.append('--export-charts')
    if summary_only:
        args.append('--summary-only')
    
    # Add log files
    args.extend(log_files)
    
    # Call analyze command
    result = runner.invoke(analyze, args)
    if result.exit_code != 0:
        console.print(f"[red]Error: {result.output}[/red]")


if __name__ == "__main__":
    cli()
