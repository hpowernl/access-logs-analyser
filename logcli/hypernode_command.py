"""Hypernode command execution module for log data retrieval."""

import subprocess
import sys
from typing import Dict, List, Optional, Any, Iterator
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class HypernodeLogCommand:
    """Manages execution of hypernode-parse-nginx-log command."""
    
    def __init__(self):
        """Initialize the command handler."""
        self.command_path = "/usr/bin/hypernode-parse-nginx-log"
        self.fields = [
            "remote_user", "user_agent", "time", "body_bytes_sent", 
            "remote_addr", "status", "request_time", "host", 
            "ssl_protocol", "country", "port", "referer", 
            "ssl_cipher", "request", "handler", "server_name"
        ]
    
    def is_available(self) -> bool:
        """Check if the hypernode-parse-nginx-log command is available."""
        try:
            result = subprocess.run(
                [self.command_path, "--help"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def execute_command(self, additional_args: Optional[List[str]] = None) -> Iterator[str]:
        """
        Execute the hypernode-parse-nginx-log command and yield lines.
        
        Args:
            additional_args: Additional command arguments (default uses --today)
            
        Yields:
            Raw log lines from the command output
        """
        if not self.is_available():
            raise RuntimeError(
                f"Command {self.command_path} is not available. "
                "This tool only works on Hypernode servers."
            )
        
        # Build command arguments
        cmd = [self.command_path]
        
        # Add field specification
        cmd.extend(["--field", ",".join(self.fields)])
        
        # Add additional arguments (default to --today)
        if additional_args:
            cmd.extend(additional_args)
        else:
            cmd.append("--today")
        
        console.print(f"[blue]Executing: {' '.join(cmd)}[/blue]")
        
        try:
            # Execute command with streaming output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Read lines as they come
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                yield line.rstrip('\n\r')
            
            # Wait for process to complete and check return code
            return_code = process.wait()
            
            if return_code != 0:
                stderr_output = process.stderr.read()
                raise subprocess.CalledProcessError(
                    return_code, cmd, stderr=stderr_output
                )
                
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed with return code {e.returncode}"
            if e.stderr:
                error_msg += f": {e.stderr}"
            raise RuntimeError(error_msg)
        except Exception as e:
            raise RuntimeError(f"Failed to execute command: {str(e)}")
    
    def parse_command_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single line from the command output into a log entry.
        
        Args:
            line: Raw line from command output
            
        Returns:
            Parsed log entry dictionary or None if parsing fails
        """
        if not line.strip():
            return None
        
        try:
            # Split by tab character (TSV format)
            parts = line.split('\t')
            
            if len(parts) != len(self.fields):
                console.print(f"[yellow]Warning: Expected {len(self.fields)} fields, got {len(parts)}[/yellow]")
                return None
            
            # Create log entry dictionary
            log_entry = {}
            for i, field in enumerate(self.fields):
                value = parts[i].strip()
                
                # Convert empty strings to None
                if not value:
                    log_entry[field] = None
                else:
                    log_entry[field] = value
            
            # Post-process specific fields
            log_entry = self._post_process_entry(log_entry)
            
            return log_entry
            
        except Exception as e:
            console.print(f"[red]Error parsing line: {str(e)}[/red]")
            console.print(f"[red]Line: {line}[/red]")
            return None
    
    def _post_process_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Post-process a log entry to convert data types and normalize fields.
        
        Args:
            entry: Raw log entry dictionary
            
        Returns:
            Processed log entry dictionary
        """
        # Convert numeric fields
        if entry.get('body_bytes_sent'):
            try:
                entry['body_bytes_sent'] = int(entry['body_bytes_sent'])
            except ValueError:
                pass
        
        if entry.get('status'):
            try:
                entry['status'] = int(entry['status'])
            except ValueError:
                pass
        
        if entry.get('request_time'):
            try:
                entry['request_time'] = float(entry['request_time'])
            except ValueError:
                pass
        
        if entry.get('port'):
            try:
                entry['port'] = int(entry['port'])
            except ValueError:
                pass
        
        # Parse timestamp (ISO format)
        if entry.get('time'):
            try:
                from datetime import datetime
                # Parse ISO format: 2025-09-17T16:13:48+00:00
                entry['timestamp'] = datetime.fromisoformat(entry['time'])
            except Exception:
                # Keep original string if parsing fails
                pass
        
        # Normalize empty values
        for key, value in entry.items():
            if value == '' or value == '-':
                entry[key] = None
        
        return entry
    
    def get_log_entries(self, additional_args: Optional[List[str]] = None) -> Iterator[Dict[str, Any]]:
        """
        Get parsed log entries from the command.
        
        Args:
            additional_args: Additional command arguments
            
        Yields:
            Parsed log entry dictionaries
        """
        total_lines = 0
        parsed_entries = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Fetching log data from Hypernode...", total=None)
            
            try:
                for line in self.execute_command(additional_args):
                    total_lines += 1
                    
                    # Update progress occasionally
                    if total_lines % 100 == 0:
                        progress.update(task, description=f"Processing {total_lines:,} lines...")
                    
                    # Parse the line
                    entry = self.parse_command_line(line)
                    if entry:
                        parsed_entries += 1
                        yield entry
                
                progress.update(task, description=f"Completed: {parsed_entries:,} entries from {total_lines:,} lines")
                
            except Exception as e:
                progress.update(task, description=f"Error: {str(e)}")
                raise
        
        console.print(f"[green]Successfully processed {parsed_entries:,} log entries from {total_lines:,} lines[/green]")


class MockHypernodeCommand(HypernodeLogCommand):
    """Mock implementation for development/testing when not on Hypernode."""
    
    def __init__(self, sample_file: Optional[str] = None):
        """Initialize mock command with optional sample file."""
        super().__init__()
        self.sample_file = sample_file or "sample_access.log"
    
    def is_available(self) -> bool:
        """Mock is always available for testing."""
        return True
    
    def execute_command(self, additional_args: Optional[List[str]] = None) -> Iterator[str]:
        """
        Mock command execution using sample data.
        
        Yields:
            Mock TSV formatted lines
        """
        console.print(f"[yellow]Mock mode: Using sample data from {self.sample_file}[/yellow]")
        
        # Generate some mock TSV data based on the expected format
        mock_lines = [
            # remote_user, user_agent, time, body_bytes_sent, remote_addr, status, request_time, host, ssl_protocol, country, port, referer, ssl_cipher, request, handler, server_name
            "\tMozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\t2025-09-17T16:13:48+00:00\t352248\t217.21.253.1\t200\t0.013\tn8n.hntestmarvinwp.hypernode.io\tTLSv1.3\tNL\t443\thttps://n8n.hntestmarvinwp.hypernode.io/assets/index-C6LoGNAx.css\tTLS_AES_128_GCM_SHA256\tGET /assets/InterVariable-DiVDrmQJ.woff2 HTTP/2.0\t\tn8n.hntestmarvinwp.hypernode.io",
            "\tMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\t2025-09-17T16:14:02+00:00\t1024\t192.168.1.100\t404\t0.001\ttest.hypernode.io\tTLSv1.3\tUS\t443\t-\tTLS_AES_256_GCM_SHA384\tGET /nonexistent HTTP/2.0\tvarnish\ttest.hypernode.io",
            "\tGooglebot/2.1 (+http://www.google.com/bot.html)\t2025-09-17T16:14:15+00:00\t4567\t66.249.79.123\t200\t0.245\ttest.hypernode.io\tTLSv1.3\tUS\t443\t-\tTLS_AES_128_GCM_SHA256\tGET / HTTP/2.0\tphpfpm\ttest.hypernode.io",
        ]
        
        for line in mock_lines:
            yield line


def get_hypernode_command(use_mock: bool = False, sample_file: Optional[str] = None) -> HypernodeLogCommand:
    """
    Get appropriate command handler (real or mock).
    
    Args:
        use_mock: Force use of mock implementation
        sample_file: Sample file for mock mode
        
    Returns:
        Command handler instance
    """
    if use_mock:
        return MockHypernodeCommand(sample_file)
    
    # Try real command first, fall back to mock
    real_command = HypernodeLogCommand()
    if real_command.is_available():
        return real_command
    else:
        console.print("[yellow]Hypernode command not available, using mock data for development[/yellow]")
        return MockHypernodeCommand(sample_file)
