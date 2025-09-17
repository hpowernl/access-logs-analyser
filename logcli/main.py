"""Main CLI entry point for the log analyzer."""

import sys
import os
import glob
import signal
import asyncio
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .parser import LogParser
from .filters import LogFilter, create_filter_from_preset
from .aggregators import StatisticsAggregator, RealTimeAggregator
from .log_reader import LogReader
from .ui import LogAnalyzerTUI, SimpleConsoleUI
from .export import DataExporter, create_report_summary
from .config import HYPERNODE_SETTINGS


console = Console()


def is_hypernode_platform() -> bool:
    """Detect if running on Hypernode platform."""
    # Check for common Hypernode indicators
    hypernode_indicators = [
        '/data/web',  # Common Hypernode directory structure
        '/data/log/nginx',  # Hypernode nginx logs location
        os.path.exists('/etc/hypernode'),  # Hypernode config directory
    ]
    
    return any(os.path.exists(path) for path in hypernode_indicators[:2]) or hypernode_indicators[2]


def get_platform_nginx_dir() -> str:
    """Get the appropriate nginx directory for the current platform."""
    if is_hypernode_platform():
        # Check both common Hypernode locations
        for path in ['/data/log/nginx', '/var/log/nginx']:
            if os.path.exists(path):
                return path
        return '/data/log/nginx'  # Default for Hypernode
    return '/var/log/nginx'  # Standard default


@click.group()
def cli():
    """ Access Log Analyzer - Advanced CLI tool for Nginx JSON log analysis."""
    pass

@cli.command()
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
@click.option('--nginx-dir', default=None, help='Nginx log directory (auto-detected for platform)')
@click.option('--no-auto-discover', is_flag=True, help='Disable auto-discovery of log files')
def analyze(log_files, follow, interactive, output, filter_preset, countries, status_codes, 
         exclude_bots, export_csv, export_json, export_charts, summary_only, nginx_dir, no_auto_discover):
    """ Access Log Analyzer - Analyze Nginx JSON access logs with advanced filtering and real-time monitoring.
    
    By default, logcli will auto-discover access.log files in /var/log/nginx.
    
    Examples:
        # Auto-discover and analyze all access logs (default behavior)
        logcli analyze
        
        # Analyze specific log files
        logcli analyze /var/log/nginx/access.log
        
        # Follow logs in real-time with interactive UI
        logcli analyze -f -i
        
        # Use different nginx directory
        logcli analyze --nginx-dir /custom/log/path
        
        # Disable auto-discovery and require manual file specification
        logcli analyze --no-auto-discover /path/to/specific.log
        
        # Filter and export
        logcli analyze --countries US,GB --exclude-bots --export-csv
    """
    
    # Auto-discover log files by default unless disabled or log files are specified
    if not log_files and not no_auto_discover:
        # Use platform-specific nginx directory if not specified
        actual_nginx_dir = nginx_dir or get_platform_nginx_dir()
        log_files = discover_nginx_logs(actual_nginx_dir)
        if not log_files:
            console.print(f"[red]No access.log files found in {actual_nginx_dir}[/red]")
            if is_hypernode_platform():
                console.print(f"[yellow]Hint: This appears to be a Hypernode platform. Logs might be in /data/log/nginx or /var/log/nginx[/yellow]")
            else:
                console.print(f"[yellow]Hint: Specify log files manually or use --nginx-dir to set the correct directory[/yellow]")
            sys.exit(1)
        console.print(f"[green]Discovered {len(log_files)} log files[/green]")
    
    # Validate input
    if not log_files:
        console.print("[red]No log files specified. Use --help for usage information.[/red]")
        sys.exit(1)
    
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
            process_log_files(log_files, parser, log_filter, stats)
            run_interactive_static(stats, log_filter)
        else:
            # Batch processing mode
            process_log_files(log_files, parser, log_filter, stats)
            
            if summary_only:
                display_summary_only(stats)
            else:
                ui = SimpleConsoleUI(stats)
                ui.display_summary()
            
            # Handle exports
            if any([export_csv, export_json, export_charts]):
                handle_exports(stats, output, export_csv, export_json, export_charts)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)


def discover_nginx_logs(nginx_dir: str) -> List[str]:
    """Discover all access.log files in nginx directory."""
    log_dir = Path(nginx_dir)
    if not log_dir.exists():
        return []
    
    # Find all access.log files (including gzipped ones)
    log_files = []
    
    # Current access.log
    current_log = log_dir / "access.log"
    if current_log.exists():
        log_files.append(str(current_log))
    
    # Rotated logs (access.log.1, access.log.2.gz, etc.)
    for log_file in log_dir.glob("access.log.*"):
        log_files.append(str(log_file))
    
    # Sort by modification time (newest first)
    log_files.sort(key=lambda x: Path(x).stat().st_mtime, reverse=True)
    
    return log_files


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


def run_interactive_static(stats: StatisticsAggregator, log_filter: LogFilter):
    """Run interactive TUI with static data."""
    app = LogAnalyzerTUI(stats, log_filter)
    app.run()


def display_summary_only(stats: StatisticsAggregator):
    """Display only summary statistics."""
    summary = stats.get_summary_stats()
    
    console.print(f"[bold blue]SUMMARY[/bold blue]")
    console.print(f"Total Requests: [green]{summary.get('total_requests', 0):,}[/green]")
    console.print(f"Unique Visitors: [green]{summary.get('unique_visitors', 0):,}[/green]")
    console.print(f"Error Rate: [red]{summary.get('error_rate', 0):.2f}%[/red]")
    console.print(f"Bot Traffic: [yellow]{summary.get('bot_percentage', 0):.2f}%[/yellow]")
    
    rt_stats = summary.get('response_time_stats', {})
    if rt_stats:
        console.print(f"Avg Response Time: [cyan]{rt_stats.get('avg', 0):.3f}s[/cyan]")
        console.print(f"Max Response Time: [red]{rt_stats.get('max', 0):.3f}s[/red]")


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
@click.option('--nginx-dir', default=None, help='Nginx log directory (auto-detected for platform)')
@click.option('--no-auto-discover', is_flag=True, help='Disable auto-discovery of log files')
@click.option('--scan-attacks', is_flag=True, help='Scan for attack patterns')
@click.option('--brute-force-detection', is_flag=True, help='Detect brute force attempts')
@click.option('--sql-injection-patterns', is_flag=True, help='Look for SQL injection attempts')
@click.option('--suspicious-user-agents', is_flag=True, help='Find suspicious user agents')
@click.option('--threshold', default=10, help='Threshold for brute force detection')
@click.option('--output', '-o', help='Output file for security report')
def security(log_files, nginx_dir, no_auto_discover, scan_attacks, brute_force_detection, 
            sql_injection_patterns, suspicious_user_agents, threshold, output):
    """Security analysis of access logs."""
    
    # Auto-discover log files by default unless disabled or log files are specified
    if not log_files and not no_auto_discover:
        actual_nginx_dir = nginx_dir or get_platform_nginx_dir()
        log_files = discover_nginx_logs(actual_nginx_dir)
        if not log_files:
            console.print(f"[red]No access.log files found in {actual_nginx_dir}[/red]")
            return
        console.print(f"[green]Discovered {len(log_files)} log files for security analysis[/green]")
    
    if not log_files:
        console.print("[red]No log files specified. Use --help for usage information.[/red]")
        return
    
    # Initialize security analyzer
    from .security import SecurityAnalyzer
    analyzer = SecurityAnalyzer()
    
    # Process log files
    console.print("[blue]Starting security analysis...[/blue]")
    
    for log_file in log_files:
        console.print(f"[cyan]Analyzing {log_file}...[/cyan]")
        analyzer.analyze_file(log_file)
    
    # Generate security report
    if scan_attacks:
        console.print("\n[bold red]🚨 ATTACK PATTERNS DETECTED[/bold red]")
        attacks = analyzer.get_attack_patterns()
        for attack_type, count in attacks.items():
            console.print(f"  {attack_type}: {count} attempts")
    
    if brute_force_detection:
        console.print(f"\n[bold yellow]🔒 BRUTE FORCE ANALYSIS (threshold: {threshold})[/bold yellow]")
        brute_force = analyzer.get_brute_force_attempts(threshold)
        for ip, attempts in brute_force.items():
            console.print(f"  {ip}: {attempts} failed login attempts")
    
    if sql_injection_patterns:
        console.print("\n[bold red]💉 SQL INJECTION ATTEMPTS[/bold red]")
        sql_attacks = analyzer.get_sql_injection_attempts()
        for ip, patterns in sql_attacks.items():
            console.print(f"  {ip}: {len(patterns)} SQL injection patterns")
    
    if suspicious_user_agents:
        console.print("\n[bold orange]🕵️  SUSPICIOUS USER AGENTS[/bold orange]")
        suspicious = analyzer.get_suspicious_user_agents()
        for ua, count in suspicious[:10]:
            console.print(f"  {ua[:80]}... : {count} requests")
    
    # Export security report if requested
    if output:
        analyzer.export_security_report(output)
        console.print(f"[green]Security report exported to: {output}[/green]")


# Performance Analysis Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--nginx-dir', default=None, help='Nginx log directory (auto-detected for platform)')
@click.option('--no-auto-discover', is_flag=True, help='Disable auto-discovery of log files')
@click.option('--response-time-analysis', is_flag=True, help='Analyze response times')
@click.option('--slowest', default=10, help='Show N slowest endpoints')
@click.option('--percentiles', is_flag=True, help='Show response time percentiles')
@click.option('--bandwidth-analysis', is_flag=True, help='Analyze bandwidth usage')
@click.option('--cache-analysis', is_flag=True, help='Analyze cache effectiveness')
@click.option('--handler', help='Filter by handler (e.g., varnish, phpfpm)')
@click.option('--output', '-o', help='Output file for performance report')
def perf(log_files, nginx_dir, no_auto_discover, response_time_analysis, slowest, 
         percentiles, bandwidth_analysis, cache_analysis, handler, output):
    """Performance analysis of access logs."""
    
    # Auto-discover log files by default unless disabled or log files are specified
    if not log_files and not no_auto_discover:
        actual_nginx_dir = nginx_dir or get_platform_nginx_dir()
        log_files = discover_nginx_logs(actual_nginx_dir)
        if not log_files:
            console.print(f"[red]No access.log files found in {actual_nginx_dir}[/red]")
            return
        console.print(f"[green]Discovered {len(log_files)} log files for performance analysis[/green]")
    
    if not log_files:
        console.print("[red]No log files specified. Use --help for usage information.[/red]")
        return
    
    # Initialize performance analyzer
    from .performance import PerformanceAnalyzer
    analyzer = PerformanceAnalyzer()
    
    # Process log files
    console.print("[blue]Starting performance analysis...[/blue]")
    
    for log_file in log_files:
        console.print(f"[cyan]Analyzing {log_file}...[/cyan]")
        analyzer.analyze_file(log_file, handler_filter=handler)
    
    # Generate performance reports
    if response_time_analysis:
        console.print("\n[bold blue]⚡ RESPONSE TIME ANALYSIS[/bold blue]")
        rt_stats = analyzer.get_response_time_stats()
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


# Bot Analysis Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--nginx-dir', default=None, help='Nginx log directory (auto-detected for platform)')
@click.option('--no-auto-discover', is_flag=True, help='Disable auto-discovery of log files')
@click.option('--classify-types', is_flag=True, help='Classify bot types')
@click.option('--behavior-analysis', is_flag=True, help='Analyze bot behavior patterns')
@click.option('--legitimate-vs-malicious', is_flag=True, help='Score bots as good/bad')
@click.option('--impact-analysis', is_flag=True, help='Analyze bot resource impact')
@click.option('--unknown-only', is_flag=True, help='Show only unclassified bots')
@click.option('--output', '-o', help='Output file for bot analysis report')
def bots(log_files, nginx_dir, no_auto_discover, classify_types, behavior_analysis,
         legitimate_vs_malicious, impact_analysis, unknown_only, output):
    """Advanced bot and crawler analysis."""
    
    # Auto-discover log files by default unless disabled or log files are specified
    if not log_files and not no_auto_discover:
        actual_nginx_dir = nginx_dir or get_platform_nginx_dir()
        log_files = discover_nginx_logs(actual_nginx_dir)
        if not log_files:
            console.print(f"[red]No access.log files found in {actual_nginx_dir}[/red]")
            return
        console.print(f"[green]Discovered {len(log_files)} log files for bot analysis[/green]")
    
    if not log_files:
        console.print("[red]No log files specified. Use --help for usage information.[/red]")
        return
    
    # Initialize bot analyzer
    from .bots import BotAnalyzer
    analyzer = BotAnalyzer()
    
    # Process log files
    console.print("[blue]Starting bot analysis...[/blue]")
    
    for log_file in log_files:
        console.print(f"[cyan]Analyzing {log_file}...[/cyan]")
        analyzer.analyze_file(log_file)
    
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
    
    # Export bot analysis report if requested
    if output:
        analyzer.export_bot_report(output)
        console.print(f"[green]Bot analysis report exported to: {output}[/green]")


# Search and Filter Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--nginx-dir', default=None, help='Nginx log directory (auto-detected for platform)')
@click.option('--no-auto-discover', is_flag=True, help='Disable auto-discovery of log files')
@click.option('--ip', help='Search for specific IP address')
@click.option('--path', help='Search for path pattern (supports regex)')
@click.option('--status', help='Filter by status code(s) (comma-separated)')
@click.option('--user-agent', help='Search user agent pattern (supports regex)')
@click.option('--country', help='Filter by country code(s) (comma-separated)')
@click.option('--time-range', help='Time range (e.g., "2024-01-01 to 2024-01-02")')
@click.option('--last-hours', type=int, help='Show entries from last N hours')
@click.option('--limit', default=100, help='Limit number of results')
@click.option('--output', '-o', help='Output file for search results')
def search(log_files, nginx_dir, no_auto_discover, ip, path, status, user_agent, 
           country, time_range, last_hours, limit, output):
    """Search and filter log entries with advanced criteria."""
    
    # Auto-discover log files by default unless disabled or log files are specified
    if not log_files and not no_auto_discover:
        actual_nginx_dir = nginx_dir or get_platform_nginx_dir()
        log_files = discover_nginx_logs(actual_nginx_dir)
        if not log_files:
            console.print(f"[red]No access.log files found in {actual_nginx_dir}[/red]")
            return
        console.print(f"[green]Discovered {len(log_files)} log files for search[/green]")
    
    if not log_files:
        console.print("[red]No log files specified. Use --help for usage information.[/red]")
        return
    
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
    
    # Search through files
    results = []
    for log_file in log_files:
        console.print(f"[cyan]Searching {log_file}...[/cyan]")
        file_results = searcher.search_file(log_file, criteria, limit=limit)
        results.extend(file_results)
        
        if len(results) >= limit:
            results = results[:limit]
            break
    
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


# Report Generation Commands
@cli.command()
@click.argument('log_files', nargs=-1, type=click.Path(exists=True))
@click.option('--nginx-dir', default=None, help='Nginx log directory (auto-detected for platform)')
@click.option('--no-auto-discover', is_flag=True, help='Disable auto-discovery of log files')
@click.option('--daily', is_flag=True, help='Generate daily report')
@click.option('--weekly', is_flag=True, help='Generate weekly report')
@click.option('--security-summary', is_flag=True, help='Include security summary')
@click.option('--performance-summary', is_flag=True, help='Include performance summary')
@click.option('--bot-summary', is_flag=True, help='Include bot analysis summary')
@click.option('--format', default='html', type=click.Choice(['html', 'json', 'text']), help='Report format')
@click.option('--output', '-o', help='Output directory for reports')
def report(log_files, nginx_dir, no_auto_discover, daily, weekly, security_summary, 
           performance_summary, bot_summary, format, output):
    """Generate comprehensive analysis reports."""
    
    # Auto-discover log files by default unless disabled or log files are specified
    if not log_files and not no_auto_discover:
        actual_nginx_dir = nginx_dir or get_platform_nginx_dir()
        log_files = discover_nginx_logs(actual_nginx_dir)
        if not log_files:
            console.print(f"[red]No access.log files found in {actual_nginx_dir}[/red]")
            return
        console.print(f"[green]Discovered {len(log_files)} log files for reporting[/green]")
    
    if not log_files:
        console.print("[red]No log files specified. Use --help for usage information.[/red]")
        return
    
    # Initialize report generator
    from .reports import ReportGenerator
    generator = ReportGenerator(output_dir=output or "reports")
    
    console.print("[blue]Generating comprehensive report...[/blue]")
    
    # Analyze logs for report
    from .aggregators import StatisticsAggregator
    stats = StatisticsAggregator()
    
    # Process log files
    process_log_files(log_files, LogParser(), LogFilter(), stats)
    
    # Generate different sections based on options
    sections = ['overview']  # Always include overview
    
    if security_summary:
        sections.append('security')
    if performance_summary:
        sections.append('performance')
    if bot_summary:
        sections.append('bots')
    
    # If no specific sections requested, include all
    if not any([security_summary, performance_summary, bot_summary]):
        sections.extend(['security', 'performance', 'bots'])
    
    # Generate report
    report_file = generator.generate_report(
        stats=stats,
        sections=sections,
        format=format,
        report_type='daily' if daily else 'weekly' if weekly else 'comprehensive'
    )
    
    console.print(f"[green]Report generated: {report_file}[/green]")


# Configuration Management Commands
@cli.command()
@click.option('--init', is_flag=True, help='Initialize configuration')
@click.option('--show', is_flag=True, help='Show current configuration')
@click.option('--set', help='Set configuration value (key=value)')
@click.option('--profile', help='Configuration profile name')
def config(init, show, set, profile):
    """Manage logcli configuration and profiles."""
    
    from .configuration import ConfigManager
    config_manager = ConfigManager()
    
    if init:
        config_manager.init_config(profile or 'default')
        console.print(f"[green]Configuration initialized for profile: {profile or 'default'}[/green]")
    
    elif show:
        current_config = config_manager.get_config(profile or 'default')
        console.print(f"[bold blue]Configuration for profile: {profile or 'default'}[/bold blue]")
        
        from rich.tree import Tree
        tree = Tree("Configuration")
        
        for section, values in current_config.items():
            section_tree = tree.add(f"[bold]{section}[/bold]")
            if isinstance(values, dict):
                for key, value in values.items():
                    section_tree.add(f"{key}: [green]{value}[/green]")
            else:
                tree.add(f"{section}: [green]{values}[/green]")
        
        console.print(tree)
    
    elif set:
        if '=' not in set:
            console.print("[red]Invalid format. Use key=value[/red]")
            return
        
        key, value = set.split('=', 1)
        config_manager.set_config_value(profile or 'default', key, value)
        console.print(f"[green]Set {key} = {value} for profile: {profile or 'default'}[/green]")
    
    else:
        console.print("[yellow]Use --init, --show, or --set option[/yellow]")


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
@click.option('--nginx-dir', default=None, help='Nginx log directory (auto-detected for platform)')
@click.option('--no-auto-discover', is_flag=True, help='Disable auto-discovery of log files')
def main_compat(log_files, follow, interactive, output, filter_preset, countries, status_codes, 
         exclude_bots, export_csv, export_json, export_charts, summary_only, nginx_dir, no_auto_discover):
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
    if nginx_dir:
        args.extend(['--nginx-dir', nginx_dir])
    if no_auto_discover:
        args.append('--no-auto-discover')
    
    # Add log files
    args.extend(log_files)
    
    # Call analyze command
    result = runner.invoke(analyze, args)
    if result.exit_code != 0:
        console.print(f"[red]Error: {result.output}[/red]")


if __name__ == "__main__":
    cli()
