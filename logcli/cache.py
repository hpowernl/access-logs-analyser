"""SQLite cache manager for log data."""

import sqlite3
import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class CacheManager:
    """Manages SQLite cache for parsed log data."""
    
    def __init__(self, cache_dir: str = None):
        """Initialize cache manager.
        
        Args:
            cache_dir: Directory for cache database. Defaults to logcli/data/
        """
        if cache_dir is None:
            # Default to logcli/data/ directory
            current_dir = Path(__file__).parent
            cache_dir = current_dir / "data"
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
        self.db_path = self.cache_dir / "cache.db"
        self._connection = None
        
        # Cache settings
        self.max_age_days = 2
        self.freshness_threshold_minutes = 10
        self.batch_size = 1000
        self.aggressive_cache = False  # When True, trust cache more aggressively
        
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection (create if needed)."""
        if self._connection is None:
            self._connection = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False
            )
            self._connection.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrent access
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("PRAGMA cache_size=10000")
            self._connection.execute("PRAGMA temp_store=memory")
            
            self._init_database()
            
        return self._connection
    
    def _migrate_database(self):
        """Migrate existing database to support inode-based caching."""
        conn = self._connection
        
        try:
            # Check if we need to add inode columns
            cursor = conn.execute("PRAGMA table_info(file_metadata)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'file_inode' not in columns:
                console.print("[yellow]Migrating cache database to support logrotate...[/yellow]")
                
                # Add inode columns
                conn.execute("ALTER TABLE file_metadata ADD COLUMN file_inode INTEGER")
                conn.execute("ALTER TABLE file_metadata ADD COLUMN file_device INTEGER")
                
                # Populate inode data for existing entries where files still exist
                cursor = conn.execute("SELECT id, file_path FROM file_metadata")
                for row in cursor:
                    try:
                        stat = os.stat(row[1])
                        conn.execute(
                            "UPDATE file_metadata SET file_inode = ?, file_device = ? WHERE id = ?",
                            (stat.st_ino, stat.st_dev, row[0])
                        )
                    except OSError:
                        # File no longer exists, we'll clean it up later
                        pass
                
                # Create new unique constraint
                conn.execute("DROP INDEX IF EXISTS idx_file_metadata_inode_device")
                conn.execute("CREATE INDEX idx_file_metadata_inode_device ON file_metadata(file_inode, file_device)")
                
                conn.commit()
                console.print("[green]Cache database migration completed![/green]")
                
        except sqlite3.Error as e:
            console.print(f"[yellow]Database migration skipped: {e}[/yellow]")
    
    def _init_database(self):
        """Initialize database schema."""
        conn = self._connection
        
        # Create tables
        conn.executescript("""
            -- Main table for log entries
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_line_number INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                ip TEXT,
                user_agent TEXT,
                method TEXT,
                path TEXT,
                status INTEGER,
                response_time REAL,
                bytes_sent INTEGER,
                country TEXT,
                host TEXT,
                server_name TEXT,
                handler TEXT,
                port TEXT,
                is_bot BOOLEAN,
                parsed_ua_browser TEXT,
                parsed_ua_os TEXT,
                parsed_ua_device TEXT,
                referer TEXT,
                ssl_protocol TEXT,
                ssl_cipher TEXT,
                remote_user TEXT,
                raw_json TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(file_path, file_line_number, file_hash)
            );
            
            -- Metadata for processed files
            CREATE TABLE IF NOT EXISTS file_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_inode INTEGER NOT NULL,
                file_device INTEGER NOT NULL,
                file_size INTEGER NOT NULL,
                file_mtime REAL NOT NULL,
                file_hash TEXT NOT NULL,
                file_signature TEXT,
                lines_processed INTEGER NOT NULL,
                last_processed DATETIME DEFAULT CURRENT_TIMESTAMP,
                processing_time_seconds REAL,
                UNIQUE(file_inode, file_device)
            );
            
            -- Cache configuration and status
            CREATE TABLE IF NOT EXISTS cache_status (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Run database migration for existing databases FIRST
        self._migrate_database()
        
        # Create indexes for performance (after migration)
        conn.executescript("""
            CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_log_entries_ip ON log_entries(ip);
            CREATE INDEX IF NOT EXISTS idx_log_entries_status ON log_entries(status);
            CREATE INDEX IF NOT EXISTS idx_log_entries_path ON log_entries(path);
            CREATE INDEX IF NOT EXISTS idx_log_entries_file_path ON log_entries(file_path);
            CREATE INDEX IF NOT EXISTS idx_log_entries_created_at ON log_entries(created_at);
            CREATE INDEX IF NOT EXISTS idx_file_metadata_path ON file_metadata(file_path);
            CREATE INDEX IF NOT EXISTS idx_file_metadata_mtime ON file_metadata(file_mtime);
            CREATE INDEX IF NOT EXISTS idx_file_metadata_last_processed ON file_metadata(last_processed);
        """)
        
        # Create inode index only if columns exist
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_file_metadata_inode_device ON file_metadata(file_inode, file_device)")
        except sqlite3.OperationalError:
            # Columns don't exist yet, will be created in migration
            pass
        
        conn.commit()
        
        # Set initial cache status
        self._set_cache_status("schema_version", "1.1")  # Updated version
        self._set_cache_status("created_at", datetime.now().isoformat())
    
    def _set_cache_status(self, key: str, value: str):
        """Set cache status value."""
        conn = self._get_connection()
        conn.execute(
            "INSERT OR REPLACE INTO cache_status (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, datetime.now())
        )
        conn.commit()
    
    def _get_cache_status(self, key: str) -> Optional[str]:
        """Get cache status value."""
        conn = self._get_connection()
        cursor = conn.execute("SELECT value FROM cache_status WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row['value'] if row else None
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of file for change detection."""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except (IOError, OSError):
            return ""
    
    def _calculate_file_signature(self, file_path: str) -> str:
        """Calculate fast file signature (first 8KB + last 8KB + size + mtime).
        
        This is much faster than full MD5 for large files and catches most changes.
        """
        try:
            stat = os.stat(file_path)
            file_size = stat.st_size
            file_mtime = stat.st_mtime
            
            hash_md5 = hashlib.md5()
            
            with open(file_path, "rb") as f:
                # Read first 8KB
                first_chunk = f.read(8192)
                hash_md5.update(first_chunk)
                
                # If file is large enough, read last 8KB too
                if file_size > 16384:
                    f.seek(-8192, 2)  # Seek to 8KB from end
                    last_chunk = f.read(8192)
                    hash_md5.update(last_chunk)
                
                # Include file size and mtime in signature
                hash_md5.update(str(file_size).encode())
                hash_md5.update(str(file_mtime).encode())
            
            return hash_md5.hexdigest()
            
        except (IOError, OSError):
            return ""
    
    def is_file_cached_and_fresh(self, file_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Check if file is cached and up-to-date using inode-based detection.
        
        This handles logrotate scenarios where files get moved/renamed.
        
        Returns:
            Tuple of (is_fresh, metadata_dict)
        """
        file_path = str(Path(file_path).resolve())
        
        try:
            # Get current file stats
            stat = os.stat(file_path)
            current_size = stat.st_size
            current_mtime = stat.st_mtime
            current_inode = stat.st_ino
            current_device = stat.st_dev
            
            # First try to find by inode+device (handles logrotate)
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT * FROM file_metadata WHERE file_inode = ? AND file_device = ?",
                (current_inode, current_device)
            )
            row = cursor.fetchone()
            
            # If not found by inode, try by path (fallback for new files)
            if not row:
                cursor = conn.execute(
                    "SELECT * FROM file_metadata WHERE file_path = ?",
                    (file_path,)
                )
                row = cursor.fetchone()
            
            if not row:
                return False, {}
            
            metadata = dict(row)
            
            # Update path if file was found by inode but path changed (logrotate case)
            if metadata['file_path'] != file_path:
                conn.execute(
                    "UPDATE file_metadata SET file_path = ? WHERE file_inode = ? AND file_device = ?",
                    (file_path, current_inode, current_device)
                )
                conn.commit()
                metadata['file_path'] = file_path
            
            # Check if file has changed
            if (metadata['file_size'] != current_size or 
                metadata['file_mtime'] != current_mtime):
                return False, metadata
            
            # Quick freshness check - only do expensive hash check if file seems to have changed
            last_processed = datetime.fromisoformat(metadata['last_processed'])
            age_minutes = (datetime.now() - last_processed).total_seconds() / 60
            
            # If cache is old, only check signature if file modification time is newer than last processing
            if age_minutes > self.freshness_threshold_minutes:
                # Only do signature check if mtime suggests file might have changed
                if current_mtime > last_processed.timestamp():
                    # Use fast signature instead of full hash for better performance
                    current_signature = self._calculate_file_signature(file_path)
                    # Compare with stored hash (fallback if no signature stored)
                    stored_signature = metadata.get('file_signature', metadata['file_hash'])
                    if current_signature != stored_signature:
                        return False, metadata
                # If mtime hasn't changed since last processing, trust the cache even if it's old
            
            return True, metadata
            
        except (OSError, sqlite3.Error):
            return False, {}
    
    def get_cached_entries(self, file_path: str) -> List[Dict[str, Any]]:
        """Get cached log entries for a file using inode-based lookup."""
        file_path = str(Path(file_path).resolve())
        
        try:
            # Get file inode for lookup
            stat = os.stat(file_path)
            file_inode = stat.st_ino
            file_device = stat.st_dev
            
            # Find the actual stored path for this inode
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT file_path FROM file_metadata WHERE file_inode = ? AND file_device = ?",
                (file_inode, file_device)
            )
            row = cursor.fetchone()
            
            if row:
                stored_path = row['file_path']
            else:
                # Fallback to current path
                stored_path = file_path
            
            # Get entries using the stored path
            cursor = conn.execute(
                """SELECT * FROM log_entries 
                   WHERE file_path = ? 
                   ORDER BY file_line_number""",
                (stored_path,)
            )
        except (OSError, sqlite3.Error):
            # Fallback to path-based lookup
            conn = self._get_connection()
            cursor = conn.execute(
                """SELECT * FROM log_entries 
                   WHERE file_path = ? 
                   ORDER BY file_line_number""",
                (file_path,)
            )
        
        entries = []
        for row in cursor:
            entry = dict(row)
            
            # Convert stored data back to proper types
            if entry['timestamp']:
                entry['timestamp'] = datetime.fromisoformat(entry['timestamp'])
            
            if entry['raw_json']:
                try:
                    entry['raw'] = json.loads(entry['raw_json'])
                except json.JSONDecodeError:
                    entry['raw'] = {}
            
            # Reconstruct parsed_ua dict
            entry['parsed_ua'] = {
                'browser': entry['parsed_ua_browser'] or 'Unknown',
                'os': entry['parsed_ua_os'] or 'Unknown',
                'device': entry['parsed_ua_device'] or 'Unknown'
            }
            
            entries.append(entry)
        
        return entries
    
    def cache_log_entries(self, file_path: str, entries: List[Dict[str, Any]], 
                         processing_time: float = 0.0):
        """Cache parsed log entries for a file."""
        file_path = str(Path(file_path).resolve())
        
        if not entries:
            return
        
        conn = self._get_connection()
        
        try:
            # Get current file stats including inode
            stat = os.stat(file_path)
            file_size = stat.st_size
            file_mtime = stat.st_mtime
            file_inode = stat.st_ino
            file_device = stat.st_dev
            file_hash = self._calculate_file_hash(file_path)
            file_signature = self._calculate_file_signature(file_path)
            
            # Clear existing entries for this file
            conn.execute("DELETE FROM log_entries WHERE file_path = ?", (file_path,))
            
            # Prepare batch insert
            insert_sql = """
                INSERT INTO log_entries (
                    file_path, file_line_number, file_hash, timestamp, ip, user_agent,
                    method, path, status, response_time, bytes_sent, country, host,
                    server_name, handler, port, is_bot, parsed_ua_browser, parsed_ua_os,
                    parsed_ua_device, referer, ssl_protocol, ssl_cipher, remote_user, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            # Process entries in batches
            for i in range(0, len(entries), self.batch_size):
                batch = entries[i:i + self.batch_size]
                batch_data = []
                
                for line_num, entry in enumerate(batch, start=i):
                    # Extract parsed_ua components
                    parsed_ua = entry.get('parsed_ua', {})
                    
                    batch_data.append((
                        file_path,
                        line_num,
                        file_hash,
                        entry.get('timestamp').isoformat() if entry.get('timestamp') else None,
                        str(entry.get('ip', '')) if entry.get('ip') else None,
                        entry.get('user_agent', ''),
                        entry.get('method', ''),
                        entry.get('path', ''),
                        entry.get('status', 0),
                        entry.get('response_time', 0.0),
                        entry.get('bytes_sent', 0),
                        entry.get('country', ''),
                        entry.get('host', ''),
                        entry.get('server_name', ''),
                        entry.get('handler', ''),
                        entry.get('port', ''),
                        bool(entry.get('is_bot', False)),
                        parsed_ua.get('browser', ''),
                        parsed_ua.get('os', ''),
                        parsed_ua.get('device', ''),
                        entry.get('referer', ''),
                        entry.get('ssl_protocol', ''),
                        entry.get('ssl_cipher', ''),
                        entry.get('remote_user', ''),
                        json.dumps(entry.get('raw', {})) if entry.get('raw') else None
                    ))
                
                conn.executemany(insert_sql, batch_data)
            
            # Update file metadata with inode information
            conn.execute("""
                INSERT OR REPLACE INTO file_metadata 
                (file_path, file_inode, file_device, file_size, file_mtime, file_hash, file_signature, 
                 lines_processed, last_processed, processing_time_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                file_path, file_inode, file_device, file_size, file_mtime, file_hash, file_signature, 
                len(entries), datetime.now(), processing_time
            ))
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            console.print(f"[red]Error caching entries for {file_path}: {e}[/red]")
            raise
    
    def cleanup_old_data(self, max_age_days: int = None) -> int:
        """Remove cached data older than max_age_days.
        
        Returns:
            Number of entries removed
        """
        if max_age_days is None:
            max_age_days = self.max_age_days
        
        cutoff = datetime.now() - timedelta(days=max_age_days)
        
        conn = self._get_connection()
        
        # Count entries to be removed
        cursor = conn.execute(
            "SELECT COUNT(*) as count FROM log_entries WHERE timestamp < ?",
            (cutoff,)
        )
        count = cursor.fetchone()['count']
        
        if count > 0:
            # Remove old log entries
            conn.execute("DELETE FROM log_entries WHERE timestamp < ?", (cutoff,))
            
            # Remove metadata for files that no longer have entries
            conn.execute("""
                DELETE FROM file_metadata 
                WHERE file_path NOT IN (
                    SELECT DISTINCT file_path FROM log_entries
                )
            """)
            
            conn.commit()
            console.print(f"[yellow]Cleaned up {count:,} old cache entries (older than {max_age_days} days)[/yellow]")
        
        return count
    
    def cleanup_orphaned_entries(self) -> int:
        """Remove cache entries for files that no longer exist.
        
        Returns:
            Number of entries removed
        """
        conn = self._get_connection()
        
        # Find files that no longer exist
        cursor = conn.execute("SELECT DISTINCT file_path FROM file_metadata")
        orphaned_paths = []
        
        for row in cursor:
            file_path = row['file_path']
            if not os.path.exists(file_path):
                orphaned_paths.append(file_path)
        
        if orphaned_paths:
            # Remove entries for non-existent files
            placeholders = ','.join(['?' for _ in orphaned_paths])
            
            # Count entries to be removed
            cursor = conn.execute(
                f"SELECT COUNT(*) as count FROM log_entries WHERE file_path IN ({placeholders})",
                orphaned_paths
            )
            count = cursor.fetchone()['count']
            
            # Remove log entries
            conn.execute(
                f"DELETE FROM log_entries WHERE file_path IN ({placeholders})",
                orphaned_paths
            )
            
            # Remove metadata entries
            conn.execute(
                f"DELETE FROM file_metadata WHERE file_path IN ({placeholders})",
                orphaned_paths
            )
            
            conn.commit()
            
            if count > 0:
                console.print(f"[yellow]Cleaned up {count:,} orphaned cache entries[/yellow]")
            
            return count
        
        return 0
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        conn = self._get_connection()
        
        # Get entry counts
        cursor = conn.execute("SELECT COUNT(*) as count FROM log_entries")
        total_entries = cursor.fetchone()['count']
        
        cursor = conn.execute("SELECT COUNT(*) as count FROM file_metadata")
        total_files = cursor.fetchone()['count']
        
        # Get oldest and newest entries
        cursor = conn.execute(
            "SELECT MIN(timestamp) as oldest, MAX(timestamp) as newest FROM log_entries"
        )
        row = cursor.fetchone()
        oldest = row['oldest']
        newest = row['newest']
        
        # Get database size
        db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
        
        return {
            'total_entries': total_entries,
            'total_files': total_files,
            'oldest_entry': oldest,
            'newest_entry': newest,
            'database_size_mb': db_size / (1024 * 1024),
            'database_path': str(self.db_path)
        }
    
    def clear_cache(self):
        """Clear all cached data."""
        conn = self._get_connection()
        conn.execute("DELETE FROM log_entries")
        conn.execute("DELETE FROM file_metadata")
        conn.commit()
        console.print("[yellow]Cache cleared[/yellow]")
    
    def close(self):
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


@contextmanager
def get_cache_manager(cache_dir: str = None, enabled: bool = True):
    """Context manager for cache operations."""
    if not enabled:
        yield None
        return
    
    manager = CacheManager(cache_dir)
    try:
        yield manager
    finally:
        manager.close()
