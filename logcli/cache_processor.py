"""Cache-aware log processing functions."""

import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .cache import CacheManager, get_cache_manager
from .parser import LogParser
from .filters import LogFilter
from .aggregators import StatisticsAggregator
from .log_reader import LogTailer

console = Console()


class CacheAwareProcessor:
    """Processes log files with intelligent caching."""
    
    def __init__(self, cache_enabled: bool = True, cache_dir: str = None):
        self.cache_enabled = cache_enabled
        self.cache_dir = cache_dir
        self.parser = LogParser()
        self.cache_manager_settings = {}
        
    def process_log_files_cached(self, 
                                log_files: List[str], 
                                log_filter: LogFilter, 
                                stats: StatisticsAggregator,
                                force_refresh: bool = False) -> Dict[str, Any]:
        """Process log files with caching support.
        
        Args:
            log_files: List of log file paths
            log_filter: Filter to apply to log entries
            stats: Statistics aggregator to populate
            force_refresh: Force refresh cache even if data is fresh
            
        Returns:
            Dictionary with processing statistics
        """
        processing_stats = {
            'total_files': len(log_files),
            'cached_files': 0,
            'processed_files': 0,
            'total_entries': 0,
            'cached_entries': 0,
            'new_entries': 0,
            'processing_time': 0.0,
            'cache_hit_ratio': 0.0
        }
        
        start_time = time.time()
        
        with get_cache_manager(self.cache_dir, self.cache_enabled) as cache_manager:
            if cache_manager and not force_refresh:
                # Apply custom cache settings if provided
                if self.cache_manager_settings:
                    for key, value in self.cache_manager_settings.items():
                        setattr(cache_manager, key, value)
                
                # First, cleanup old data and orphaned entries
                cache_manager.cleanup_old_data()
                cache_manager.cleanup_orphaned_entries()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
                transient=True,
            ) as progress:
                
                main_task = progress.add_task(
                    "Processing log files...", 
                    total=len(log_files)
                )
                
                for file_path in log_files:
                    file_start_time = time.time()
                    file_task = progress.add_task(
                        f"Processing {Path(file_path).name}...", 
                        total=None
                    )
                    
                    try:
                        entries_processed = self._process_single_file(
                            file_path, log_filter, stats, cache_manager, 
                            force_refresh, progress, file_task
                        )
                        
                        processing_stats['total_entries'] += entries_processed['total']
                        processing_stats['cached_entries'] += entries_processed['cached']
                        processing_stats['new_entries'] += entries_processed['new']
                        
                        if entries_processed['cached'] > 0:
                            processing_stats['cached_files'] += 1
                        if entries_processed['new'] > 0:
                            processing_stats['processed_files'] += 1
                            
                    except Exception as e:
                        console.print(f"[red]Error processing {file_path}: {str(e)}[/red]")
                        continue
                    
                    finally:
                        progress.remove_task(file_task)
                        progress.update(main_task, advance=1)
                        
                        file_time = time.time() - file_start_time
                        processing_stats['processing_time'] += file_time
        
        # Calculate cache hit ratio
        if processing_stats['total_entries'] > 0:
            processing_stats['cache_hit_ratio'] = (
                processing_stats['cached_entries'] / processing_stats['total_entries']
            ) * 100
        
        processing_stats['total_time'] = time.time() - start_time
        
        # Display summary
        # self._display_processing_summary(processing_stats)
        
        return processing_stats
    
    def _process_single_file(self, 
                           file_path: str, 
                           log_filter: LogFilter, 
                           stats: StatisticsAggregator,
                           cache_manager: Optional[CacheManager],
                           force_refresh: bool,
                           progress: Progress,
                           task_id) -> Dict[str, int]:
        """Process a single log file with cache support."""
        
        entries_stats = {'total': 0, 'cached': 0, 'new': 0}
        
        # Check if file is cached and fresh
        use_cache = (cache_manager and not force_refresh and 
                    cache_manager.is_file_cached_and_fresh(file_path)[0])
        
        if use_cache:
            # Load from cache
            cached_entries = cache_manager.get_cached_entries(file_path)
            
            progress.update(task_id, description=f"Loading {Path(file_path).name} from cache...")
            
            for entry in cached_entries:
                entries_stats['total'] += 1
                entries_stats['cached'] += 1
                
                if log_filter.should_include(entry):
                    stats.add_entry(entry)
                
                # Update progress occasionally
                if entries_stats['total'] % 1000 == 0:
                    progress.update(task_id, 
                                  description=f"Loading {Path(file_path).name} from cache... ({entries_stats['total']:,})")
        
        else:
            # Process file and cache results
            progress.update(task_id, description=f"Processing {Path(file_path).name}...")
            
            new_entries = []
            file_processing_start = time.time()
            
            try:
                with LogTailer(file_path, follow=False) as tailer:
                    for line in tailer.tail():
                        entries_stats['total'] += 1
                        
                        # Parse log entry
                        log_entry = self.parser.parse_log_line(line)
                        if not log_entry:
                            continue
                        
                        new_entries.append(log_entry)
                        entries_stats['new'] += 1
                        
                        # Apply filters and add to stats
                        if log_filter.should_include(log_entry):
                            stats.add_entry(log_entry)
                        
                        # Update progress occasionally
                        if entries_stats['total'] % 1000 == 0:
                            progress.update(task_id, 
                                          description=f"Processing {Path(file_path).name}... ({entries_stats['total']:,} lines)")
                
                # Cache the processed entries
                if cache_manager and new_entries:
                    processing_time = time.time() - file_processing_start
                    progress.update(task_id, description=f"Caching {Path(file_path).name}...")
                    cache_manager.cache_log_entries(file_path, new_entries, processing_time)
                    
            except Exception as e:
                console.print(f"[red]Error processing {file_path}: {str(e)}[/red]")
                raise
        
        return entries_stats
    
    def _display_processing_summary(self, stats: Dict[str, Any]):
        """Display processing summary."""
        console.print(f"\n[bold blue]📊 PROCESSING SUMMARY[/bold blue]")
        console.print(f"  Files processed: [green]{stats['processed_files']:,}[/green] new, [cyan]{stats['cached_files']:,}[/cyan] from cache")
        console.print(f"  Total entries: [green]{stats['total_entries']:,}[/green]")
        console.print(f"  Cache hit ratio: [cyan]{stats['cache_hit_ratio']:.1f}%[/cyan]")
        console.print(f"  Processing time: [yellow]{stats['total_time']:.2f}s[/yellow]")
        
        if stats['cached_entries'] > 0:
            time_saved = stats['processing_time'] * (stats['cached_entries'] / max(stats['new_entries'], 1))
            console.print(f"  Estimated time saved: [green]{time_saved:.2f}s[/green]")
    
    def process_with_callback_cached(self, 
                                   log_files: List[str], 
                                   callback_func: Callable,
                                   analysis_type: str = "analysis",
                                   force_refresh: bool = False) -> Dict[str, Any]:
        """Process log files with callback function and caching."""
        
        processing_stats = {
            'total_files': len(log_files),
            'cached_files': 0,
            'processed_files': 0,
            'total_entries': 0,
            'cached_entries': 0,
            'new_entries': 0,
            'processing_time': 0.0
        }
        
        start_time = time.time()
        
        with get_cache_manager(self.cache_dir, self.cache_enabled) as cache_manager:
            if cache_manager and not force_refresh:
                cache_manager.cleanup_old_data()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
                transient=True,
            ) as progress:
                
                main_task = progress.add_task(
                    f"Processing files for {analysis_type}...", 
                    total=len(log_files)
                )
                
                for file_path in log_files:
                    file_task = progress.add_task(
                        f"Processing {Path(file_path).name}...", 
                        total=None
                    )
                    
                    try:
                        entries_processed = self._process_single_file_with_callback(
                            file_path, callback_func, cache_manager, 
                            force_refresh, progress, file_task
                        )
                        
                        processing_stats['total_entries'] += entries_processed['total']
                        processing_stats['cached_entries'] += entries_processed['cached']
                        processing_stats['new_entries'] += entries_processed['new']
                        
                        if entries_processed['cached'] > 0:
                            processing_stats['cached_files'] += 1
                        if entries_processed['new'] > 0:
                            processing_stats['processed_files'] += 1
                            
                    except Exception as e:
                        console.print(f"[red]Error processing {file_path}: {str(e)}[/red]")
                        continue
                    
                    finally:
                        progress.remove_task(file_task)
                        progress.update(main_task, advance=1)
        
        processing_stats['total_time'] = time.time() - start_time
        
        # Calculate cache hit ratio
        if processing_stats['total_entries'] > 0:
            processing_stats['cache_hit_ratio'] = (
                processing_stats['cached_entries'] / processing_stats['total_entries']
            ) * 100
        
        console.print(f"[green]Processed {processing_stats['total_entries']:,} entries from {processing_stats['total_files']} files for {analysis_type}[/green]")
        console.print(f"[cyan]Cache hit ratio: {processing_stats['cache_hit_ratio']:.1f}%[/cyan]")
        
        return processing_stats
    
    def _process_single_file_with_callback(self, 
                                         file_path: str,
                                         callback_func: Callable,
                                         cache_manager: Optional[CacheManager],
                                         force_refresh: bool,
                                         progress: Progress,
                                         task_id) -> Dict[str, int]:
        """Process single file with callback function."""
        
        entries_stats = {'total': 0, 'cached': 0, 'new': 0}
        
        # Check cache
        use_cache = (cache_manager and not force_refresh and 
                    cache_manager.is_file_cached_and_fresh(file_path)[0])
        
        if use_cache:
            # Load from cache and apply callback
            cached_entries = cache_manager.get_cached_entries(file_path)
            
            progress.update(task_id, description=f"Loading {Path(file_path).name} from cache...")
            
            for entry in cached_entries:
                entries_stats['total'] += 1
                entries_stats['cached'] += 1
                callback_func(entry)
                
                if entries_stats['total'] % 1000 == 0:
                    progress.update(task_id, 
                                  description=f"Loading {Path(file_path).name} from cache... ({entries_stats['total']:,})")
        
        else:
            # Process fresh
            progress.update(task_id, description=f"Processing {Path(file_path).name}...")
            
            new_entries = []
            file_processing_start = time.time()
            
            with LogTailer(file_path, follow=False) as tailer:
                for line in tailer.tail():
                    entries_stats['total'] += 1
                    
                    log_entry = self.parser.parse_log_line(line)
                    if log_entry:
                        new_entries.append(log_entry)
                        entries_stats['new'] += 1
                        callback_func(log_entry)
                    
                    if entries_stats['total'] % 500 == 0:
                        progress.update(task_id, 
                                      description=f"Processing {Path(file_path).name}... ({entries_stats['total']:,} lines)")
            
            # Cache results
            if cache_manager and new_entries:
                processing_time = time.time() - file_processing_start
                progress.update(task_id, description=f"Caching {Path(file_path).name}...")
                cache_manager.cache_log_entries(file_path, new_entries, processing_time)
        
        return entries_stats
    
    def is_data_fresh(self, log_files: List[str], max_lag_minutes: int = 10) -> bool:
        """Check if cached data is fresh enough.
        
        Args:
            log_files: List of log file paths to check
            max_lag_minutes: Maximum acceptable lag in minutes
            
        Returns:
            True if all files are cached and fresh
        """
        if not self.cache_enabled:
            return False
        
        with get_cache_manager(self.cache_dir, True) as cache_manager:
            if not cache_manager:
                return False
            
            for file_path in log_files:
                is_fresh, metadata = cache_manager.is_file_cached_and_fresh(file_path)
                if not is_fresh:
                    return False
                
                # Additional freshness check
                if metadata:
                    last_processed = datetime.fromisoformat(metadata['last_processed'])
                    lag_minutes = (datetime.now() - last_processed).total_seconds() / 60
                    if lag_minutes > max_lag_minutes:
                        return False
        
        return True
    
    def get_cache_info(self) -> Optional[Dict[str, Any]]:
        """Get cache information and statistics."""
        if not self.cache_enabled:
            return None
        
        with get_cache_manager(self.cache_dir, True) as cache_manager:
            if cache_manager:
                return cache_manager.get_cache_stats()
        
        return None


# Convenience functions for backward compatibility
def process_log_files_with_cache(log_files: List[str], 
                                parser: LogParser, 
                                log_filter: LogFilter, 
                                stats: StatisticsAggregator,
                                cache_enabled: bool = True,
                                force_refresh: bool = False) -> Dict[str, Any]:
    """Process log files with cache support (backward compatible)."""
    processor = CacheAwareProcessor(cache_enabled=cache_enabled)
    return processor.process_log_files_cached(log_files, log_filter, stats, force_refresh)


def process_log_files_with_callback_cached(log_files: List[str], 
                                         parser: LogParser, 
                                         callback_func: Callable, 
                                         analysis_type: str = "analysis",
                                         cache_enabled: bool = True,
                                         force_refresh: bool = False) -> Dict[str, Any]:
    """Process log files with callback and cache support (backward compatible)."""
    processor = CacheAwareProcessor(cache_enabled=cache_enabled)
    return processor.process_with_callback_cached(log_files, callback_func, analysis_type, force_refresh)
