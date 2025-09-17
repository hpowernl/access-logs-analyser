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
                # Try to handle malformed data
                if len(parts) < len(self.fields):
                    console.print(f"[yellow]Warning: Expected {len(self.fields)} fields, got {len(parts)}. Padding with empty values.[/yellow]")
                    # Pad with empty strings
                    parts.extend([''] * (len(self.fields) - len(parts)))
                else:
                    console.print(f"[yellow]Warning: Expected {len(self.fields)} fields, got {len(parts)}. Truncating.[/yellow]")
                    # Truncate to expected length
                    parts = parts[:len(self.fields)]
            
            # Create log entry dictionary
            log_entry = {}
            for i, field in enumerate(self.fields):
                value = parts[i].strip()
                
                # Convert empty strings or dashes to empty string (not None)
                # This maintains compatibility with existing analyzers
                if not value or value == '-':
                    log_entry[field] = ""
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
        
        # Parse request field to extract method and path
        if entry.get('request'):
            try:
                request_parts = entry['request'].split(' ', 2)
                if len(request_parts) >= 2:
                    entry['method'] = request_parts[0]
                    entry['path'] = request_parts[1]
                    if len(request_parts) >= 3:
                        entry['protocol'] = request_parts[2]
                else:
                    # Fallback for malformed requests
                    entry['method'] = 'GET'
                    entry['path'] = entry['request']
            except Exception:
                # Fallback for any parsing errors
                entry['method'] = 'GET'
                entry['path'] = entry.get('request', '/')
        else:
            # Default values if request is empty
            entry['method'] = 'GET'
            entry['path'] = '/'
        
        # Parse user agent to extract browser, OS, and device info
        entry['parsed_ua'] = self._parse_user_agent(entry.get('user_agent', ''))
        
        # Bot detection
        entry['is_bot'] = self._is_bot(entry.get('user_agent', ''))
        
        # Keep empty values as empty strings for compatibility
        # (analyzers expect strings, not None values)
        
        return entry
    
    def _parse_user_agent(self, user_agent: str) -> Dict[str, str]:
        """
        Parse user agent string to extract browser, OS, and device information.
        
        Args:
            user_agent: User agent string to parse
            
        Returns:
            Dictionary with browser, os, and device information
        """
        if not user_agent:
            return {'browser': 'Unknown', 'os': 'Unknown', 'device': 'Unknown'}
        
        ua_lower = user_agent.lower()
        
        # Browser detection
        browser = 'Unknown'
        if 'chrome' in ua_lower and 'edg' not in ua_lower:
            browser = 'Chrome'
        elif 'firefox' in ua_lower:
            browser = 'Firefox'
        elif 'safari' in ua_lower and 'chrome' not in ua_lower:
            browser = 'Safari'
        elif 'edg' in ua_lower:
            browser = 'Edge'
        elif 'opera' in ua_lower or 'opr' in ua_lower:
            browser = 'Opera'
        elif 'bot' in ua_lower or 'crawler' in ua_lower or 'spider' in ua_lower:
            browser = 'Bot'
        elif any(bot in ua_lower for bot in ['googlebot', 'bingbot', 'slurp', 'duckduckbot']):
            browser = 'Bot'
        
        # OS detection
        os = 'Unknown'
        if 'windows nt 10' in ua_lower:
            os = 'Windows 10'
        elif 'windows nt 6.3' in ua_lower:
            os = 'Windows 8.1'
        elif 'windows nt 6.1' in ua_lower:
            os = 'Windows 7'
        elif 'windows' in ua_lower:
            os = 'Windows'
        elif 'mac os x' in ua_lower or 'macos' in ua_lower:
            os = 'macOS'
        elif 'linux' in ua_lower:
            os = 'Linux'
        elif 'android' in ua_lower:
            os = 'Android'
        elif 'iphone' in ua_lower or 'ios' in ua_lower:
            os = 'iOS'
        
        # Device detection
        device = 'Unknown'
        if 'mobile' in ua_lower or 'iphone' in ua_lower or 'android' in ua_lower:
            device = 'Mobile'
        elif 'tablet' in ua_lower or 'ipad' in ua_lower:
            device = 'Tablet'
        else:
            device = 'Desktop'
        
        return {
            'browser': browser,
            'os': os,
            'device': device
        }
    
    def _is_bot(self, user_agent: str) -> bool:
        """
        Detect if the user agent represents a bot/crawler.
        
        Args:
            user_agent: User agent string to analyze
            
        Returns:
            True if the user agent appears to be a bot
        """
        if not user_agent:
            return False
        
        ua_lower = user_agent.lower()
        
        # Common bot indicators
        bot_keywords = [
            'bot', 'crawler', 'spider', 'scraper', 'crawl',
            'slurp', 'wget', 'curl', 'python-requests', 'http',
            'monitor', 'check', 'test', 'scan', 'fetch',
            'archive', 'index', 'search'
        ]
        
        # Known bot user agents (more comprehensive list based on real data)
        known_bots = [
            'googlebot', 'bingbot', 'slurp', 'duckduckbot',
            'facebookexternalhit', 'twitterbot', 'linkedinbot',
            'whatsapp', 'telegram', 'discord', 'slack',
            'semrushbot', 'ahrefsbot', 'mj12bot', 'dotbot',
            'yandexbot', 'baiduspider', 'sogou', 'exabot',
            'pinterestbot', 'facebot', 'ia_archiver',
            'censysinspect', 'genomecrawler', 'gptbot',
            'googlebot-image', 'googlebot-news', 'googlebot-video'
        ]
        
        # Check for bot keywords
        if any(keyword in ua_lower for keyword in bot_keywords):
            return True
            
        # Check for known bot names
        if any(bot in ua_lower for bot in known_bots):
            return True
            
        # Check for simple patterns (like "python/3.8" or "curl/7.68")
        import re
        if re.match(r'^[a-z-]+/[\d.]+$', ua_lower):
            return True
            
        return False
    
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
        
        # Real sample TSV data from Hypernode server (first 25 entries for comprehensive testing)
        mock_lines = [
            # remote_user, user_agent, time, body_bytes_sent, remote_addr, status, request_time, host, ssl_protocol, country, port, referer, ssl_cipher, request, handler, server_name
            "\tMozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)\t2025-09-17T00:00:00+00:00\t37526\t85.208.96.193\t404\t0.075\twww.tessv.nl\tTLSv1.3\tUS\t443\t\tTLS_AES_128_GCM_SHA256\tGET /go/category/11212447/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (iPhone; CPU iPhone OS 18_6_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 musical_ly_41.6.0 JsSdk/2.0 NetType/2G Channel/App Store ByteLocale/en Region/NL isDarkMode/0 WKWebView/1 RevealType/Dialog\t2025-09-17T00:00:02+00:00\t42569\t2a02:a446:69a0:0:eccf:66c8:1db5:889e\t200\t0.048\twww.tessv.nl\tTLSv1.3\t\t443\thttps://www.tiktok.com/\tTLS_AES_128_GCM_SHA256\tGET /friday-denim/wide-leg/?utm_medium=paid&utm_source=tiktok&utm_campaign=conversie&utm_content=do-conv HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)\t2025-09-17T00:00:03+00:00\t37527\t54.236.1.53\t404\t0.090\twww.tessv.nl\tTLSv1.3\tUS\t443\t\tTLS_AES_128_GCM_SHA256\tGET /desi-top-beige/261750.BEIGE.ML.html HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 musical_ly_41.6.0 JsSdk/2.0 NetType/WIFI Channel/App Store ByteLocale/nl Region/NL isDarkMode/0 WKWebView/1 RevealType/Dialog\t2025-09-17T00:00:06+00:00\t45772\t77.248.239.146\t200\t0.050\twww.tessv.nl\tTLSv1.3\tNL\t443\thttps://www.tiktok.com/\tTLS_AES_128_GCM_SHA256\tGET /carlijn-bomber/2536-C03-116-801-XS.html HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 musical_ly_41.6.0 JsSdk/2.0 NetType/WIFI Channel/App Store ByteLocale/en Region/NL isDarkMode/0 WKWebView/1 RevealType/Dialog\t2025-09-17T00:00:07+00:00\t42572\t217.105.15.171\t200\t0.047\twww.tessv.nl\tTLSv1.3\tNL\t443\thttps://www.tiktok.com/\tTLS_AES_128_GCM_SHA256\tGET /friday-denim/wide-leg/?utm_medium=paid&utm_source=tiktok&utm_campaign=conversion&utm_content=fd-conv HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)\t2025-09-17T00:00:07+00:00\t37527\t185.191.171.12\t404\t0.067\twww.tessv.nl\tTLSv1.3\tGB\t443\t\tTLS_AES_128_GCM_SHA256\tGET /go/product/125705028/dmws-kickoffcountdown-button-url/dmws-kickoffcountdown-button-url HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)\t2025-09-17T00:00:08+00:00\t162\t66.132.153.129\t429\t0.000\t94.76.235.127\tTLSv1.3\tUS\t443\t\tTLS_CHACHA20_POLY1305_SHA256\tGET /robots.txt HTTP/1.1\tphpfpm\tproductiontessv.hypernode.io",
            "\tMozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15\t2025-09-17T00:00:11+00:00\t0\t2001:1c04:4808:2000:f8ce:6be9:c1c9:a0e2\t204\t0.063\twww.tessv.nl\tTLSv1.3\t\t443\thttps://www.tessv.nl/kleding/co-ords/?p=8\tTLS_AES_128_GCM_SHA256\tGET /widgets/checkout/info HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15\t2025-09-17T00:00:11+00:00\t1\t2001:1c04:4808:2000:f8ce:6be9:c1c9:a0e2\t200\t0.066\twww.tessv.nl\tTLSv1.3\t\t443\thttps://www.tessv.nl/kleding/co-ords/?p=8\tTLS_AES_128_GCM_SHA256\tGET /widgets/cbax/analytics/visitors/Navigation HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1\t2025-09-17T00:00:11+00:00\t45011\t62.45.139.224\t200\t0.046\twww.tessv.nl\tTLSv1.3\tNL\t443\t\tTLS_AES_128_GCM_SHA256\tGET / HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1\t2025-09-17T00:00:11+00:00\t0\t62.45.139.224\t204\t0.060\twww.tessv.nl\tTLSv1.3\tNL\t443\thttps://www.tessv.nl/\tTLS_AES_128_GCM_SHA256\tGET /widgets/checkout/info HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1\t2025-09-17T00:00:11+00:00\t1\t62.45.139.224\t200\t0.058\twww.tessv.nl\tTLSv1.3\tNL\t443\thttps://www.tessv.nl/\tTLS_AES_128_GCM_SHA256\tGET /widgets/cbax/analytics/visitors/Navigation HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)\t2025-09-17T00:00:14+00:00\t162\t54.236.1.54\t429\t0.000\twww.tessv.nl\tTLSv1.3\tUS\t443\t\tTLS_AES_128_GCM_SHA256\tGET /new HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)\t2025-09-17T00:00:14+00:00\t162\t85.208.96.204\t429\t0.000\twww.tessv.nl\tTLSv1.3\tUS\t443\t\tTLS_AES_128_GCM_SHA256\tGET /go/product/124433603/dmws-kickoffcountdown-button-url HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)\t2025-09-17T00:00:14+00:00\t45553\t54.236.1.11\t200\t0.456\twww.tessv.nl\tTLSv1.3\tUS\t443\t\tTLS_AES_128_GCM_SHA256\tGET /lianda-jurk/264986-lichtroze-L.html HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1\t2025-09-17T00:00:14+00:00\t1097\t62.45.139.224\t200\t0.035\twww.tessv.nl\tTLSv1.3\tNL\t443\thttps://www.tessv.nl/\tTLS_AES_128_GCM_SHA256\tGET /widgets/menu/offcanvas HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1\t2025-09-17T00:00:15+00:00\t66\t62.45.139.224\t200\t0.038\twww.tessv.nl\tTLSv1.3\tNL\t443\thttps://www.tessv.nl/\tTLS_AES_128_GCM_SHA256\tGET /storefront/script/shopware-analytics-customer HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)\t2025-09-17T00:00:16+00:00\t214926\t20.171.207.44\t200\t0.267\twww.tessv.nl\tTLSv1.3\tUS\t443\t\tTLS_AES_128_GCM_SHA256\tGET /media/82/32/8d/1701696907/charlotte%20jurken-2.jpg HTTP/2.0\t\twww.tessv.nl",
            "\tMozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.127 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\t2025-09-17T00:00:17+00:00\t63597\t66.249.79.231\t301\t0.062\twww.tessv.nl\tTLSv1.3\tUS\t443\t\tTLS_AES_128_GCM_SHA256\tGET /accessoires/schoenen/boots/?mode=list HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tMozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.127 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\t2025-09-17T00:00:18+00:00\t42399\t66.249.79.231\t200\t0.328\twww.tessv.nl\tTLSv1.3\tUS\t443\t\tTLS_AES_128_GCM_SHA256\tGET /schoenen/boots/?mode=list HTTP/2.0\tphpfpm\twww.tessv.nl",
            "\tGooglebot-Image/1.0\t2025-09-17T00:00:21+00:00\t49688\t66.249.79.231\t200\t0.000\twww.tessv.nl\tTLSv1.3\tUS\t443\t\tTLS_AES_128_GCM_SHA256\tGET /thumbnail/06/07/ce/1754901437/01989846dba772d78c95909981521418_500x500.png?ts=1755016598 HTTP/2.0\t\twww.tessv.nl",
            "\tMozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1 musical_ly_41.4.0 JsSdk/2.0 NetType/WIFI Channel/App Store ByteLocale/nl Region/NL isDarkMode/0 WKWebView/1 RevealType/Dialog\t2025-09-17T00:00:21+00:00\t44117\t2a02:a471:2fcf:0:94b0:635a:99d2:9f6e\t200\t0.036\twww.tessv.nl\tTLSv1.3\t\t443\thttps://www.tiktok.com/\tTLS_AES_128_GCM_SHA256\tGET /kleding/collecties/choco-brown/ HTTP/2.0\tphpfpm\twww.tessv.nl",
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
