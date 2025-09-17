"""Search and filtering module for log entries."""

import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from .parser import LogParser
from .log_reader import LogTailer


class LogSearch:
    """Advanced search and filtering for log entries."""
    
    def __init__(self):
        self.parser = LogParser()
    
    def search_file(self, file_path: str, criteria: Dict[str, Any], limit: int = 1000) -> List[Dict[str, Any]]:
        """Search a single log file with given criteria."""
        results = []
        file_path = Path(file_path)
        
        with LogTailer(str(file_path), follow=False) as tailer:
            for line in tailer.tail():
                if not line.strip():
                    continue
                
                if len(results) >= limit:
                    break
                    
                log_entry = self.parser.parse_log_line(line)
                if not log_entry:
                    continue
                
                if self._matches_criteria(log_entry, criteria):
                    results.append(log_entry)
        
        return results
    
    def _matches_criteria(self, log_entry: Dict[str, Any], criteria: Dict[str, Any]) -> bool:
        """Check if log entry matches search criteria."""
        
        # IP address matching
        if 'ip' in criteria:
            ip_str = str(log_entry.get('ip', ''))
            if criteria['ip'] not in ip_str:
                return False
        
        # Path pattern matching (supports regex)
        if 'path' in criteria:
            path = log_entry.get('path', '')
            try:
                if not re.search(criteria['path'], path, re.IGNORECASE):
                    return False
            except re.error:
                # If regex is invalid, do simple string matching
                if criteria['path'].lower() not in (path or "").lower():
                    return False
        
        # Status code matching
        if 'status' in criteria:
            status = log_entry.get('status', 0)
            if status not in criteria['status']:
                return False
        
        # User agent pattern matching (supports regex)
        if 'user_agent' in criteria:
            user_agent = log_entry.get('user_agent', '')
            try:
                if not re.search(criteria['user_agent'], user_agent, re.IGNORECASE):
                    return False
            except re.error:
                # If regex is invalid, do simple string matching
                if criteria['user_agent'].lower() not in (user_agent or "").lower():
                    return False
        
        # Country matching
        if 'country' in criteria:
            country = log_entry.get('country', '').upper()
            if country not in criteria['country']:
                return False
        
        # Time range matching
        if 'time_range' in criteria:
            timestamp = log_entry.get('timestamp')
            if timestamp:
                start_time, end_time = criteria['time_range']
                if not (start_time <= timestamp <= end_time):
                    return False
        
        # Method matching
        if 'method' in criteria:
            method = log_entry.get('method', '').upper()
            if method not in [m.upper() for m in criteria['method']]:
                return False
        
        # Response time range
        if 'response_time_min' in criteria:
            response_time = log_entry.get('response_time', 0)
            if response_time < criteria['response_time_min']:
                return False
        
        if 'response_time_max' in criteria:
            response_time = log_entry.get('response_time', 0)
            if response_time > criteria['response_time_max']:
                return False
        
        # Bytes sent range
        if 'bytes_min' in criteria:
            bytes_sent = log_entry.get('bytes_sent', 0)
            if bytes_sent < criteria['bytes_min']:
                return False
        
        if 'bytes_max' in criteria:
            bytes_sent = log_entry.get('bytes_sent', 0)
            if bytes_sent > criteria['bytes_max']:
                return False
        
        # Handler matching
        if 'handler' in criteria:
            handler = log_entry.get('handler', '')
            if handler not in criteria['handler']:
                return False
        
        return True
    
    def export_results(self, results: List[Dict[str, Any]], output_file: str):
        """Export search results to file."""
        output_path = Path(output_file)
        
        if output_path.suffix.lower() == '.json':
            self._export_json(results, output_file)
        elif output_path.suffix.lower() == '.csv':
            self._export_csv(results, output_file)
        else:
            self._export_text(results, output_file)
    
    def _export_json(self, results: List[Dict[str, Any]], output_file: str):
        """Export results to JSON format."""
        export_data = []
        
        for result in results:
            # Convert datetime objects to strings for JSON serialization
            export_entry = {}
            for key, value in result.items():
                if isinstance(value, datetime):
                    export_entry[key] = value.isoformat()
                elif key == 'ip' and value:
                    export_entry[key] = str(value)
                elif key != 'raw':  # Skip raw log data
                    export_entry[key] = value
            export_data.append(export_entry)
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    def _export_csv(self, results: List[Dict[str, Any]], output_file: str):
        """Export results to CSV format."""
        import csv
        
        if not results:
            return
        
        # Define CSV columns
        columns = [
            'timestamp', 'ip', 'method', 'path', 'status', 'response_time',
            'bytes_sent', 'user_agent', 'country', 'handler', 'referer'
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=columns)
            writer.writeheader()
            
            for result in results:
                row = {}
                for col in columns:
                    value = result.get(col, '')
                    if isinstance(value, datetime):
                        row[col] = value.isoformat()
                    elif col == 'ip' and value:
                        row[col] = str(value)
                    else:
                        row[col] = value
                writer.writerow(row)
    
    def _export_text(self, results: List[Dict[str, Any]], output_file: str):
        """Export results to text format."""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Search Results - {len(results)} entries\n")
            f.write("=" * 50 + "\n\n")
            
            for i, result in enumerate(results, 1):
                f.write(f"Entry {i}:\n")
                f.write(f"  Time: {result.get('timestamp', 'N/A')}\n")
                f.write(f"  IP: {result.get('ip', 'N/A')}\n")
                f.write(f"  Method: {result.get('method', 'N/A')}\n")
                f.write(f"  Path: {result.get('path', 'N/A')}\n")
                f.write(f"  Status: {result.get('status', 'N/A')}\n")
                f.write(f"  Response Time: {result.get('response_time', 'N/A')}s\n")
                f.write(f"  Bytes: {result.get('bytes_sent', 'N/A')}\n")
                f.write(f"  Country: {result.get('country', 'N/A')}\n")
                f.write(f"  User Agent: {result.get('user_agent', 'N/A')[:100]}...\n")
                f.write("\n")


class AdvancedSearch:
    """Advanced search with complex queries and pattern matching."""
    
    def __init__(self):
        self.parser = LogParser()
    
    def search_anomalies(self, file_path: str) -> List[Dict[str, Any]]:
        """Detect anomalous log entries."""
        anomalies = []
        
        # Collect all entries first for statistical analysis
        all_entries = []
        with LogTailer(file_path, follow=False) as tailer:
            for line in tailer.tail():
                if not line.strip():
                    continue
                log_entry = self.parser.parse_log_line(line)
                if log_entry:
                    all_entries.append(log_entry)
        
        if len(all_entries) < 100:  # Need sufficient data for anomaly detection
            return anomalies
        
        # Calculate statistical baselines
        response_times = [e.get('response_time', 0) for e in all_entries if e.get('response_time', 0) > 0]
        bytes_sent = [e.get('bytes_sent', 0) for e in all_entries if e.get('bytes_sent', 0) > 0]
        
        if response_times:
            import statistics
            rt_mean = statistics.mean(response_times)
            rt_stdev = statistics.stdev(response_times) if len(response_times) > 1 else 0
            rt_threshold = rt_mean + (3 * rt_stdev)  # 3 sigma rule
        else:
            rt_threshold = float('inf')
        
        if bytes_sent:
            import statistics
            bytes_mean = statistics.mean(bytes_sent)
            bytes_stdev = statistics.stdev(bytes_sent) if len(bytes_sent) > 1 else 0
            bytes_threshold = bytes_mean + (3 * bytes_stdev)  # 3 sigma rule
        else:
            bytes_threshold = float('inf')
        
        # Find anomalies
        for entry in all_entries:
            anomaly_reasons = []
            
            # Response time anomaly
            rt = entry.get('response_time', 0)
            if rt > rt_threshold:
                anomaly_reasons.append(f"Extremely slow response: {rt:.3f}s")
            
            # Bytes sent anomaly
            bs = entry.get('bytes_sent', 0)
            if bs > bytes_threshold:
                anomaly_reasons.append(f"Extremely large response: {bs:,} bytes")
            
            # Status code anomaly (5xx errors)
            status = entry.get('status', 200)
            if status >= 500:
                anomaly_reasons.append(f"Server error: {status}")
            
            # Suspicious path patterns
            path = entry.get('path', '')
            suspicious_patterns = [
                r'\.\./', r'\.env', r'config', r'admin', r'wp-admin',
                r'\.git', r'\.svn', r'backup', r'sql', r'dump'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    anomaly_reasons.append(f"Suspicious path pattern: {pattern}")
                    break
            
            # Add to anomalies if any reasons found
            if anomaly_reasons:
                entry['anomaly_reasons'] = anomaly_reasons
                entry['anomaly_score'] = len(anomaly_reasons)
                anomalies.append(entry)
        
        # Sort by anomaly score (most anomalous first)
        return sorted(anomalies, key=lambda x: x['anomaly_score'], reverse=True)
    
    def search_attack_patterns(self, file_path: str) -> List[Dict[str, Any]]:
        """Search for known attack patterns."""
        attacks = []
        
        # Define attack patterns
        attack_patterns = {
            'sql_injection': [
                r'union\s+select', r'or\s+1\s*=\s*1', r'drop\s+table',
                r'insert\s+into', r'delete\s+from', r'information_schema'
            ],
            'xss': [
                r'<script', r'javascript:', r'onload\s*=', r'onerror\s*=',
                r'alert\s*\(', r'document\.cookie'
            ],
            'directory_traversal': [
                r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'/etc/passwd',
                r'/etc/shadow', r'\\windows\\system32'
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*pwd', r';\s*whoami',
                r'\|\s*cat\s+', r'`cat\s+', r'\$\(cat\s+'
            ]
        }
        
        # Compile patterns
        compiled_patterns = {}
        for attack_type, patterns in attack_patterns.items():
            compiled_patterns[attack_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
        
        # Search through log file
        with LogTailer(file_path, follow=False) as tailer:
            for line in tailer.tail():
                if not line.strip():
                    continue
                
                log_entry = self.parser.parse_log_line(line)
                if not log_entry:
                    continue
                
                path = log_entry.get('path', '')
                user_agent = log_entry.get('user_agent', '')
                full_request = f"{path} {user_agent}"
                
                detected_attacks = []
                for attack_type, patterns in compiled_patterns.items():
                    for pattern in patterns:
                        if pattern.search(full_request):
                            detected_attacks.append({
                                'type': attack_type,
                                'pattern': pattern.pattern
                            })
                            break  # Only count each attack type once per entry
                
                if detected_attacks:
                    log_entry['detected_attacks'] = detected_attacks
                    log_entry['attack_score'] = len(detected_attacks)
                    attacks.append(log_entry)
        
        return sorted(attacks, key=lambda x: x['attack_score'], reverse=True)
    
    def search_user_sessions(self, file_path: str, ip_address: str) -> List[Dict[str, Any]]:
        """Search for all requests from a specific IP to analyze user session."""
        session_entries = []
        
        with LogTailer(file_path, follow=False) as tailer:
            for line in tailer.tail():
                if not line.strip():
                    continue
                
                log_entry = self.parser.parse_log_line(line)
                if not log_entry:
                    continue
                
                if str(log_entry.get('ip', '')) == ip_address:
                    session_entries.append(log_entry)
        
        # Sort by timestamp
        session_entries.sort(key=lambda x: x.get('timestamp', datetime.min))
        
        # Add session analysis
        if len(session_entries) > 1:
            total_duration = (session_entries[-1].get('timestamp', datetime.now()) - 
                            session_entries[0].get('timestamp', datetime.now())).total_seconds()
            
            unique_paths = len(set(entry.get('path', '') for entry in session_entries))
            error_count = sum(1 for entry in session_entries if entry.get('status', 200) >= 400)
            
            session_summary = {
                'ip': ip_address,
                'total_requests': len(session_entries),
                'session_duration': total_duration,
                'unique_paths': unique_paths,
                'error_rate': (error_count / len(session_entries)) * 100,
                'avg_requests_per_minute': len(session_entries) / max(total_duration / 60, 1)
            }
            
            # Add summary to first entry
            if session_entries:
                session_entries[0]['session_summary'] = session_summary
        
        return session_entries
