"""Log reading and streaming module."""

import os
import gzip
import time
from pathlib import Path
from typing import Iterator, Optional, Callable, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class LogTailer:
    """Tails log files and yields new lines as they are added."""
    
    def __init__(self, file_path: str, follow: bool = True):
        self.file_path = Path(file_path)
        self.follow = follow
        self.file_handle = None
        self.position = 0
        
    def __enter__(self):
        self.open()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        
    def open(self):
        """Open the log file for reading, supporting gzip files."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.file_path}")
        
        # Check if file is gzipped
        if self.file_path.suffix == '.gz':
            self.file_handle = gzip.open(self.file_path, 'rt', encoding='utf-8', errors='ignore')
        else:
            self.file_handle = open(self.file_path, 'r', encoding='utf-8', errors='ignore')
        
        # If not following from beginning, seek to end (only for non-gzip files)
        if self.follow and self.file_path.suffix != '.gz':
            self.file_handle.seek(0, 2)  # Seek to end
            self.position = self.file_handle.tell()
        else:
            self.position = 0
            
    def close(self):
        """Close the file handle."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
            
    def tail(self) -> Iterator[str]:
        """Generator that yields new lines from the log file."""
        if not self.file_handle:
            raise RuntimeError("File not opened. Use context manager or call open() first.")
            
        while True:
            # Skip rotation check for gzip files (they don't get rotated while reading)
            if self.file_path.suffix != '.gz':
                # Check if file was rotated/recreated
                try:
                    current_size = self.file_path.stat().st_size
                    if current_size < self.position:
                        # File was likely rotated, reopen
                        self.close()
                        self.open()
                        continue
                        
                except FileNotFoundError:
                    # File was deleted, wait for it to be recreated
                    time.sleep(0.1)
                    continue
                
            # Read new lines
            line = self.file_handle.readline()
            if line:
                self.position = self.file_handle.tell()
                yield line.rstrip('\n\r')
            else:
                if not self.follow:
                    break
                time.sleep(0.1)  # Brief pause before checking again


class LogFileWatcher(FileSystemEventHandler):
    """Watches for changes in log files using watchdog."""
    
    def __init__(self, callback: Callable[[str], None]):
        self.callback = callback
        self.tailers = {}  # file_path -> LogTailer
        
    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return
            
        file_path = event.src_path
        if file_path not in self.tailers:
            return
            
        # Read new lines from the modified file
        tailer = self.tailers[file_path]
        try:
            for line in tailer.tail():
                if line.strip():  # Skip empty lines
                    self.callback(line)
        except Exception as e:
            print(f"Error reading from {file_path}: {e}")
            
    def add_file(self, file_path: str):
        """Add a file to watch."""
        if file_path not in self.tailers:
            self.tailers[file_path] = LogTailer(file_path, follow=True)
            self.tailers[file_path].open()
            
    def remove_file(self, file_path: str):
        """Remove a file from watching."""
        if file_path in self.tailers:
            self.tailers[file_path].close()
            del self.tailers[file_path]


class LogReader:
    """Main log reader class that handles multiple input sources."""
    
    def __init__(self, on_log_line: Callable[[str], None]):
        self.on_log_line = on_log_line
        self.observer = None
        self.watcher = None
        self.running = False
        
    def read_file(self, file_path: str, follow: bool = False) -> None:
        """Read from a single log file."""
        with LogTailer(file_path, follow=False) as tailer:
            for line in tailer.tail():
                if line.strip():
                    self.on_log_line(line)
                    
        if follow:
            self.watch_file(file_path)
            
    def watch_file(self, file_path: str) -> None:
        """Watch a file for real-time updates."""
        if not self.observer:
            self.watcher = LogFileWatcher(self.on_log_line)
            self.observer = Observer()
            
        file_path = Path(file_path).resolve()
        directory = file_path.parent
        
        self.watcher.add_file(str(file_path))
        self.observer.schedule(self.watcher, str(directory), recursive=False)
        
        if not self.running:
            self.observer.start()
            self.running = True
            
    def watch_files(self, file_paths: list[str]) -> None:
        """Watch multiple files for real-time updates."""
        for file_path in file_paths:
            self.watch_file(file_path)
            
    def stop_watching(self) -> None:
        """Stop watching files."""
        if self.observer and self.running:
            self.observer.stop()
            self.observer.join()
            self.running = False
            
        if self.watcher:
            for file_path in list(self.watcher.tailers.keys()):
                self.watcher.remove_file(file_path)
                
    def read_from_stdin(self) -> None:
        """Read log lines from stdin (for piped input)."""
        import sys
        try:
            for line in sys.stdin:
                if line.strip():
                    self.on_log_line(line.rstrip('\n\r'))
        except KeyboardInterrupt:
            pass
            
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_watching()


def create_sample_log_file(file_path: str, num_lines: int = 100) -> None:
    """Create a sample JSON log file for testing."""
    import json
    import random
    from datetime import datetime, timedelta
    
    countries = ['US', 'GB', 'DE', 'FR', 'JP', 'CA', 'AU', 'NL', 'SE', 'NO']
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'curl/7.68.0',
        'python-requests/2.28.1'
    ]
    
    status_codes = [200, 200, 200, 200, 301, 302, 404, 403, 500, 502]
    paths = ['/', '/api/users', '/api/products', '/login', '/dashboard', '/static/css/main.css']
    
    base_time = datetime.now() - timedelta(hours=1)
    
    with open(file_path, 'w') as f:
        for i in range(num_lines):
            log_entry = {
                'time': (base_time + timedelta(seconds=i*2)).isoformat() + 'Z',
                'remote_addr': f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'user_agent': random.choice(user_agents),
                'status': random.choice(status_codes),
                'method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
                'path': random.choice(paths),
                'country': random.choice(countries),
                'response_time': round(random.uniform(0.01, 2.0), 3),
                'bytes_sent': random.randint(100, 50000)
            }
            f.write(json.dumps(log_entry) + '\n')
    
    print(f"Created sample log file: {file_path} with {num_lines} entries")
