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
from .cache_processor import CacheAwareProcessor


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


@click.group(invoke_without_command=True)
@click.option('--install-completion', is_flag=True, help='Install shell completion for bash/zsh/fish')
@click.pass_context
def cli(ctx, install_completion):
    """🚀 Hypernode Log Analyzer - Advanced CLI tool for Nginx JSON log analysis.
    
    A comprehensive log analysis toolkit specifically designed for Hypernode environments,
    featuring automatic log discovery, real-time monitoring, security analysis, and 
    performance insights.
    
    \b
    Quick Start:
      hlogcli analyze                    # Auto-discover and analyze all logs (with cache)
      hlogcli analyze --summary-only     # Quick overview
      hlogcli security --scan-attacks    # Security analysis
      hlogcli perf --response-time-analysis  # Performance analysis
      hlogcli cache --info               # View cache statistics
    
    \b
    Features:
      • Auto-discovery of nginx logs (no manual file specification needed)
      • Platform detection for Hypernode environments
      • SQLite cache system for 5-10x faster processing
      • Real-time log monitoring and analysis
      • Security threat detection and analysis
      • Performance optimization insights
      • Bot behavior analysis and classification
      • Advanced search and filtering capabilities
      • Multiple export formats (CSV, JSON, HTML charts)
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
    
    # If no command is specified, show help
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
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
@click.option('--export-csv', is_flag=True, help='Export results to CSV')
@click.option('--export-json', is_flag=True, help='Export results to JSON')
@click.option('--export-charts', is_flag=True, help='Export charts to HTML')
@click.option('--summary-only', is_flag=True, help='Show only summary statistics')
@click.option('--nginx-dir', default=None, help='Nginx log directory (auto-detected for platform)')
@click.option('--no-auto-discover', is_flag=True, help='Disable auto-discovery of log files')
@click.option('--use-cache', is_flag=True, default=True, help='Use SQLite cache for faster processing (default: enabled)')
@click.option('--no-cache', is_flag=True, help='Disable cache and process files fresh')
@click.option('--force-refresh', is_flag=True, help='Force refresh cache even if data is fresh')
@click.option('--cache-info', is_flag=True, help='Show cache information and statistics')
def analyze(log_files, follow, interactive, output, filter_preset, countries, status_codes, 
         exclude_bots, export_csv, export_json, export_charts, summary_only, nginx_dir, no_auto_discover,
         use_cache, no_cache, force_refresh, cache_info):
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
    🗄️ Caching (NEW):
      By default, uses SQLite cache for 5-10x faster processing on repeated runs.
      Cache automatically detects file changes and updates incrementally.
      Old data (>2 days) is automatically cleaned up.
    
    \b
    💡 Examples:
      hlogcli analyze                           # Full analysis with cache (default)
      hlogcli analyze --summary-only            # Quick overview only
      hlogcli analyze -i                        # Interactive TUI mode
      hlogcli analyze -f                        # Real-time monitoring
      hlogcli analyze --countries US,NL,DE     # Filter by countries
      hlogcli analyze --exclude-bots            # Exclude bot traffic
      hlogcli analyze --export-csv --export-charts  # Export results
      hlogcli analyze /path/to/specific.log     # Analyze specific file
      
      # Cache options:
      hlogcli analyze --no-cache                # Disable cache, process fresh
      hlogcli analyze --force-refresh           # Force refresh cached data
      hlogcli analyze --cache-info              # Show cache statistics
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
    
    # Handle cache options
    cache_enabled = use_cache and not no_cache
    
    # Show cache info if requested
    if cache_info:
        processor = CacheAwareProcessor(cache_enabled=cache_enabled)
        cache_stats = processor.get_cache_info()
        if cache_stats:
            console.print(f"\n[bold blue]📊 CACHE INFORMATION[/bold blue]")
            console.print(f"  Database: [cyan]{cache_stats['database_path']}[/cyan]")
            console.print(f"  Size: [yellow]{cache_stats['database_size_mb']:.2f} MB[/yellow]")
            console.print(f"  Entries: [green]{cache_stats['total_entries']:,}[/green]")
            console.print(f"  Files: [green]{cache_stats['total_files']:,}[/green]")
            if cache_stats['oldest_entry'] and cache_stats['newest_entry']:
                console.print(f"  Date range: [cyan]{cache_stats['oldest_entry']} to {cache_stats['newest_entry']}[/cyan]")
            console.print()
        else:
            console.print("[yellow]No cache available or cache is disabled[/yellow]")
        
        if not log_files:
            return
    
    # Initialize components
    parser = LogParser()
    log_filter = LogFilter()
    stats = StatisticsAggregator()
    processor = CacheAwareProcessor(cache_enabled=cache_enabled)
    
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
            processor.process_log_files_cached(log_files, log_filter, stats, force_refresh)
            run_interactive_static(stats, log_filter)
        else:
            # Batch processing mode
            processor.process_log_files_cached(log_files, log_filter, stats, force_refresh)
            
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
@click.option('--export-blacklist', help='Export recommended IP blacklist to file')
@click.option('--output', '-o', help='Output file for security report')
@click.option('--use-cache', is_flag=True, default=True, help='Use SQLite cache for faster processing')
@click.option('--no-cache', is_flag=True, help='Disable cache and process files fresh')
@click.option('--force-refresh', is_flag=True, help='Force refresh cache even if data is fresh')
def security(log_files, nginx_dir, no_auto_discover, scan_attacks, brute_force_detection, 
            sql_injection_patterns, suspicious_user_agents, show_summary, show_top_threats,
            show_geographic, show_timeline, threshold, min_threat_score, detailed, quiet,
            export_blacklist, output, use_cache, no_cache, force_refresh):
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
    parser = LogParser()
    
    # Handle cache options
    cache_enabled = use_cache and not no_cache
    processor = CacheAwareProcessor(cache_enabled=cache_enabled)
    
    # Process log files with nice progress display
    console.print("[blue]Starting security analysis...[/blue]")
    
    def analyze_entry(log_entry):
        """Analyze a single log entry for security."""
        analyzer._analyze_entry(log_entry)
    
    processor.process_with_callback_cached(log_files, analyze_entry, "security analysis", force_refresh)
    
    # Get comprehensive security data
    summary = analyzer.get_security_summary()
    suspicious_ips = analyzer.get_suspicious_ips()
    
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
    
    # Show geographic distribution if requested
    if show_geographic and not quiet:
        console.print("\n[bold cyan]🌍 GEOGRAPHIC THREAT DISTRIBUTION[/bold cyan]")
        # This would require geo-IP lookup - placeholder for now
        console.print("  [dim]Geographic analysis requires GeoIP database (feature coming soon)[/dim]")
    
    # Show timeline analysis if requested
    if show_timeline and not quiet:
        console.print("\n[bold magenta]📈 ATTACK TIMELINE ANALYSIS[/bold magenta]")
        # This would require time-based analysis - placeholder for now
        console.print("  [dim]Timeline analysis feature coming soon[/dim]")
    
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
@click.option('--nginx-dir', default=None, help='Nginx log directory (auto-detected for platform)')
@click.option('--no-auto-discover', is_flag=True, help='Disable auto-discovery of log files')
@click.option('--response-time-analysis', is_flag=True, help='Analyze response times')
@click.option('--slowest', default=10, help='Show N slowest endpoints')
@click.option('--percentiles', is_flag=True, help='Show response time percentiles')
@click.option('--bandwidth-analysis', is_flag=True, help='Analyze bandwidth usage')
@click.option('--cache-analysis', is_flag=True, help='Analyze cache effectiveness')
@click.option('--handler', help='Filter by handler (e.g., varnish, phpfpm)')
@click.option('--output', '-o', help='Output file for performance report')
@click.option('--use-cache', is_flag=True, default=True, help='Use SQLite cache for faster processing')
@click.option('--no-cache', is_flag=True, help='Disable cache and process files fresh')
@click.option('--force-refresh', is_flag=True, help='Force refresh cache even if data is fresh')
def perf(log_files, nginx_dir, no_auto_discover, response_time_analysis, slowest, 
         percentiles, bandwidth_analysis, cache_analysis, handler, output, use_cache, no_cache, force_refresh):
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
    parser = LogParser()
    
    # Handle cache options
    cache_enabled = use_cache and not no_cache
    processor = CacheAwareProcessor(cache_enabled=cache_enabled)
    
    # Process log files with nice progress display
    console.print("[blue]Starting performance analysis...[/blue]")
    
    def analyze_entry(log_entry):
        """Analyze a single log entry for performance."""
        # Apply handler filter if specified
        if handler and log_entry.get('handler') != handler:
            return
        analyzer._analyze_entry(log_entry)
    
    processor.process_with_callback_cached(log_files, analyze_entry, "performance analysis", force_refresh)
    
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
@click.option('--ai-bots-only', is_flag=True, help='Show only AI bot analysis')
@click.option('--ai-training-detection', is_flag=True, help='Detect potential AI training data crawlers')
@click.option('--llm-bot-analysis', is_flag=True, help='Detailed LLM bot analysis')
@click.option('--ai-impact-analysis', is_flag=True, help='AI bot resource impact analysis')
@click.option('--output', '-o', help='Output file for bot analysis report')
@click.option('--use-cache', is_flag=True, default=True, help='Use SQLite cache for faster processing')
@click.option('--no-cache', is_flag=True, help='Disable cache and process files fresh')
@click.option('--force-refresh', is_flag=True, help='Force refresh cache even if data is fresh')
def bots(log_files, nginx_dir, no_auto_discover, classify_types, behavior_analysis,
         legitimate_vs_malicious, impact_analysis, unknown_only, ai_bots_only, 
         ai_training_detection, llm_bot_analysis, ai_impact_analysis, output,
         use_cache, no_cache, force_refresh):
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
      hlogcli bots                              # Basic bot overview
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
    parser = LogParser()
    
    # Handle cache options
    cache_enabled = use_cache and not no_cache
    processor = CacheAwareProcessor(cache_enabled=cache_enabled)
    
    # Process log files with nice progress display
    console.print("[blue]Starting bot analysis...[/blue]")
    
    def analyze_entry(log_entry):
        """Analyze a single log entry for bots."""
        analyzer._analyze_entry(log_entry)
    
    processor.process_with_callback_cached(log_files, analyze_entry, "bot analysis", force_refresh)
    
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
@click.option('--use-cache', is_flag=True, default=True, help='Use SQLite cache for faster processing')
@click.option('--no-cache', is_flag=True, help='Disable cache and process files fresh')
@click.option('--force-refresh', is_flag=True, help='Force refresh cache even if data is fresh')
def search(log_files, nginx_dir, no_auto_discover, ip, path, status, user_agent, 
           country, time_range, last_hours, limit, output, use_cache, no_cache, force_refresh):
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
    
    # Handle cache options
    cache_enabled = use_cache and not no_cache
    processor = CacheAwareProcessor(cache_enabled=cache_enabled)
    
    # Search through files with progress display
    results = []
    parser = LogParser()
    
    def search_entry(log_entry):
        """Search a single log entry."""
        nonlocal results
        if len(results) >= limit:
            return
        if searcher._matches_criteria(log_entry, criteria):
            results.append(log_entry)
    
    processor.process_with_callback_cached(log_files, search_entry, "search", force_refresh)
    
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
    """📋 Generate comprehensive analysis reports in multiple formats.
    
    Create detailed reports combining traffic analysis, security insights, performance
    metrics, and bot activity. Perfect for regular monitoring, compliance reporting,
    or sharing insights with team members.
    
    \b
    📊 Report Sections:
      • Traffic overview and trends
      • Security analysis and threats
      • Performance metrics and bottlenecks  
      • Bot activity and classification
      • Geographic distribution
      • Top pages and resources
      • Error analysis and patterns
    
    \b
    📄 Export Formats:
      • HTML - Interactive charts and visualizations
      • JSON - Machine-readable structured data
      • Text - Plain text summary for scripts/emails
    
    \b
    💡 Examples:
      hlogcli report                            # Comprehensive report (all sections)
      hlogcli report --daily                    # Daily report format
      hlogcli report --weekly                   # Weekly report format
      hlogcli report --security-summary         # Security-focused report
      hlogcli report --performance-summary      # Performance-focused report
      hlogcli report --format json -o report.json  # JSON export
      hlogcli report --format html -o reports/ # HTML with charts
    """
    
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
    
    # Process log files with nice progress display
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


# Cache Management Commands
@cli.command()
@click.option('--info', is_flag=True, help='Show cache information and statistics')
@click.option('--clear', is_flag=True, help='Clear all cached data')
@click.option('--cleanup', is_flag=True, help='Clean up old cached data (older than 2 days)')
@click.option('--max-age-days', default=2, help='Maximum age for cleanup in days (default: 2)')
def cache(info, clear, cleanup, max_age_days):
    """🗄️ Manage SQLite cache for faster log processing.
    
    The cache system stores parsed log data in a SQLite database to dramatically
    speed up repeated analysis. This command provides tools to manage the cache,
    view statistics, and perform maintenance operations.
    
    \b
    🚀 Cache Benefits:
      • 5-10x faster processing for repeated analysis
      • Automatic freshness detection and updates
      • Intelligent file change detection
      • Background cleanup of old data
    
    \b
    💡 Examples:
      hlogcli cache --info                    # Show cache statistics
      hlogcli cache --cleanup                 # Clean old data (>2 days)
      hlogcli cache --cleanup --max-age-days 7  # Clean data older than 7 days
      hlogcli cache --clear                   # Clear entire cache
    """
    from .cache_processor import CacheAwareProcessor
    
    processor = CacheAwareProcessor(cache_enabled=True)
    
    if info:
        cache_stats = processor.get_cache_info()
        if cache_stats:
            console.print(f"\n[bold blue]📊 CACHE STATISTICS[/bold blue]")
            console.print(f"  Database: [cyan]{cache_stats['database_path']}[/cyan]")
            console.print(f"  Size: [yellow]{cache_stats['database_size_mb']:.2f} MB[/yellow]")
            console.print(f"  Total entries: [green]{cache_stats['total_entries']:,}[/green]")
            console.print(f"  Cached files: [green]{cache_stats['total_files']:,}[/green]")
            
            if cache_stats['oldest_entry'] and cache_stats['newest_entry']:
                console.print(f"  Date range: [cyan]{cache_stats['oldest_entry']} to {cache_stats['newest_entry']}[/cyan]")
            
            console.print(f"\n[bold green]💡 CACHE BENEFITS[/bold green]")
            console.print(f"  • Faster processing: Skip parsing for unchanged files")
            console.print(f"  • Automatic cleanup: Old data removed after {max_age_days} days")
            console.print(f"  • Smart updates: Only process new/changed content")
            console.print(f"  • Background maintenance: Keeps cache fresh and efficient")
        else:
            console.print("[yellow]No cache data available[/yellow]")
    
    elif clear:
        from .cache import get_cache_manager
        with get_cache_manager(enabled=True) as cache_manager:
            if cache_manager:
                cache_manager.clear_cache()
                console.print("[green]✅ Cache cleared successfully[/green]")
            else:
                console.print("[red]❌ Unable to access cache[/red]")
    
    elif cleanup:
        from .cache import get_cache_manager
        with get_cache_manager(enabled=True) as cache_manager:
            if cache_manager:
                removed_count = cache_manager.cleanup_old_data(max_age_days)
                if removed_count > 0:
                    console.print(f"[green]✅ Cleaned up {removed_count:,} old entries (older than {max_age_days} days)[/green]")
                else:
                    console.print(f"[yellow]No old data found (older than {max_age_days} days)[/yellow]")
            else:
                console.print("[red]❌ Unable to access cache[/red]")
    
    else:
        # Default: show cache info
        cache_stats = processor.get_cache_info()
        if cache_stats:
            console.print(f"\n[bold blue]📊 CACHE STATUS[/bold blue]")
            console.print(f"  Entries: [green]{cache_stats['total_entries']:,}[/green]")
            console.print(f"  Files: [green]{cache_stats['total_files']:,}[/green]")
            console.print(f"  Size: [yellow]{cache_stats['database_size_mb']:.2f} MB[/yellow]")
            console.print(f"\n[dim]💡 Use --info for detailed statistics, --cleanup to remove old data, or --clear to reset cache[/dim]")
        else:
            console.print("[yellow]Cache is empty or not available[/yellow]")
            console.print("[dim]💡 Cache will be created automatically when you run analysis commands[/dim]")


# Configuration Management Commands
@cli.command()
@click.option('--init', is_flag=True, help='Initialize configuration')
@click.option('--show', is_flag=True, help='Show current configuration')
@click.option('--set', help='Set configuration value (key=value)')
@click.option('--profile', help='Configuration profile name')
def config(init, show, set, profile):
    """⚙️ Manage logcli configuration and user profiles.
    
    Create and manage configuration profiles for different environments
    or use cases. Store frequently used settings, custom thresholds,
    and default options to streamline your workflow.
    
    \b
    🔧 Configuration Features:
      • Multiple named profiles (production, staging, development)
      • Custom default directories and filters
      • Alert thresholds and notification settings
      • Export preferences and output formats
      • Analysis preferences and display options
    
    \b
    💡 Examples:
      hlogcli config --init                     # Initialize default config
      hlogcli config --init --profile staging  # Create staging profile
      hlogcli config --show                    # Show current configuration
      hlogcli config --show --profile prod     # Show production profile
      hlogcli config --set nginx_dir=/var/log/nginx  # Set default directory
      hlogcli config --set threshold=20 --profile staging  # Profile-specific setting
    """
    
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
