"""Main CLI entry point for the log analyzer."""

import sys
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


console = Console()


@click.command()
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
@click.option('--nginx-dir', default='/var/log/nginx', help='Nginx log directory (default: /var/log/nginx)')
@click.option('--auto-discover', is_flag=True, help='Auto-discover access.log files in nginx directory')
def main(log_files, follow, interactive, output, filter_preset, countries, status_codes, 
         exclude_bots, export_csv, export_json, export_charts, summary_only, nginx_dir, auto_discover):
    """NextGen Access Log Analyzer - Analyze Nginx JSON access logs with advanced filtering and real-time monitoring.
    
    Examples:
        # Analyze specific log files
        python -m logcli /var/log/nginx/access.log
        
        # Follow logs in real-time with interactive UI
        python -m logcli -f -i /var/log/nginx/access.log
        
        # Auto-discover and analyze all access logs
        python -m logcli --auto-discover
        
        # Filter and export
        python -m logcli --countries US,GB --exclude-bots --export-csv /var/log/nginx/access.log
    """
    
    # Auto-discover log files if requested
    if auto_discover:
        log_files = discover_nginx_logs(nginx_dir)
        if not log_files:
            console.print(f"[red]No access.log files found in {nginx_dir}[/red]")
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


if __name__ == "__main__":
    main()
