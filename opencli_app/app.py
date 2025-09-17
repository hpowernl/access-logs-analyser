"""
Main LogAnalyzerApp - Simple, clean tabbed interface
"""

import sys
import os
from datetime import datetime
from pathlib import Path
from typing import List

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, TabbedContent, TabPane

# Add logcli to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from logcli.parser import LogParser
from logcli.filters import LogFilter
from logcli.aggregators import StatisticsAggregator
from logcli.security import SecurityAnalyzer
from logcli.performance import PerformanceAnalyzer
from logcli.log_reader import LogTailer
from logcli.main import discover_nginx_logs

from .styles import SIMPLE_CSS
from .widgets import OverviewWidget, PerformanceWidget, SecurityWidget


class LogAnalyzerApp(App):
    """Simple, clean log analyzer with tabbed interface."""
    
    TITLE = "🚀 Access Log Analyzer"
    CSS = SIMPLE_CSS
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("f", "toggle_follow", "Toggle Follow"),
        ("1", "show_overview", "Overview"),
        ("2", "show_performance", "Performance"),
        ("3", "show_security", "Security"),
        ("?", "help", "Help"),
    ]
    
    def __init__(self):
        super().__init__()
        
        # Initialize components
        self.parser = LogParser()
        self.filter = LogFilter()
        self.stats = StatisticsAggregator()
        self.security = SecurityAnalyzer()
        self.performance = PerformanceAnalyzer()
        
        # State
        self.log_files: List[str] = []
        self.following = False
        self.last_refresh = None
        
        # Widgets
        self.overview_widget = None
        self.performance_widget = None
        self.security_widget = None
    
    def compose(self) -> ComposeResult:
        """Compose the application layout."""
        yield Header()
        
        with TabbedContent(initial="overview"):
            with TabPane("📊 Overview", id="overview"):
                self.overview_widget = OverviewWidget(
                    stats=self.stats,
                    log_files=self.log_files,
                    following=self.following
                )
                yield self.overview_widget
            
            with TabPane("⚡ Performance", id="performance"):
                self.performance_widget = PerformanceWidget(
                    stats=self.stats,
                    performance_analyzer=self.performance
                )
                yield self.performance_widget
            
            with TabPane("🔒 Security", id="security"):
                self.security_widget = SecurityWidget(
                    stats=self.stats,
                    security_analyzer=self.security
                )
                yield self.security_widget
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the application."""
        print("🚀 Starting Log Analyzer...")
        
        # Load initial data
        self.load_data()
        
        # Set up refresh timer (every 60 seconds)
        self.set_interval(60.0, self.auto_refresh)
        
        print("✅ Log Analyzer ready!")
    
    def load_data(self) -> None:
        """Load and process log data."""
        try:
            print("📁 Discovering log files...")
            self.log_files = discover_nginx_logs()
            
            if not self.log_files:
                print("⚠️  No log files found, using sample data")
                sample_log = Path(__file__).parent.parent / "sample_access.log"
                if sample_log.exists():
                    self.log_files = [str(sample_log)]
            
            print(f"📊 Processing {len(self.log_files)} log files...")
            self.process_logs()
            
            # Update widgets
            self.update_all_widgets()
            
            self.last_refresh = datetime.now()
            print(f"✅ Processed {self.stats.total_requests:,} requests")
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
    
    def process_logs(self) -> None:
        """Process log files and update statistics."""
        # Reset statistics
        self.stats.reset()
        self.security.reset()
        self.performance.reset()
        
        line_count = 0
        max_lines_per_file = 5000  # Limit for performance
        
        for log_file in self.log_files:
            try:
                print(f"📄 Processing {log_file}...")
                
                with open(log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        if line_num > max_lines_per_file:
                            print(f"⚠️  Reached line limit for {log_file}")
                            break
                        
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            # Parse log entry
                            entry = self.parser.parse_line(line)
                            if not entry:
                                continue
                            
                            # Apply filters
                            if not self.filter.should_include(entry):
                                continue
                            
                            # Add to statistics
                            self.stats.add_entry(entry)
                            self.security.add_entry(entry)
                            self.performance.add_entry(entry)
                            
                            line_count += 1
                            
                        except Exception as e:
                            # Skip malformed lines
                            continue
                            
            except Exception as e:
                print(f"⚠️ Error processing {log_file}: {e}")
                continue
        
        print(f"📊 Processed {line_count} log entries")
    
    def update_all_widgets(self) -> None:
        """Update all widget contents."""
        if self.overview_widget:
            self.overview_widget.update_content(
                stats=self.stats,
                log_files=self.log_files,
                following=self.following
            )
        
        if self.performance_widget:
            self.performance_widget.update_content(
                stats=self.stats,
                performance_analyzer=self.performance
            )
        
        if self.security_widget:
            self.security_widget.update_content(
                stats=self.stats,
                security_analyzer=self.security
            )
    
    def auto_refresh(self) -> None:
        """Auto refresh data if following is enabled."""
        if self.following:
            self.action_refresh()
    
    def action_refresh(self) -> None:
        """Refresh all data."""
        self.notify("Refreshing data...", timeout=2)
        self.load_data()
    
    def action_toggle_follow(self) -> None:
        """Toggle follow mode."""
        self.following = not self.following
        status = "ON" if self.following else "OFF"
        self.notify(f"Follow mode: {status}", timeout=2)
        
        # Update widgets to show new following status
        self.update_all_widgets()
    
    def action_show_overview(self) -> None:
        """Switch to overview tab."""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = "overview"
    
    def action_show_performance(self) -> None:
        """Switch to performance tab."""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = "performance"
    
    def action_show_security(self) -> None:
        """Switch to security tab."""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = "security"
    
    def action_help(self) -> None:
        """Show help message."""
        help_text = """
🔧 KEYBOARD SHORTCUTS:

• q - Quit application
• r - Refresh data
• f - Toggle follow mode
• 1 - Overview tab
• 2 - Performance tab  
• 3 - Security tab
• ? - This help

📊 FEATURES:

• Real-time log analysis
• Scrollable content areas
• Auto-refresh in follow mode
• Clean, simple interface
        """
        self.notify(help_text.strip(), timeout=10)


def run_app():
    """Run the log analyzer application."""
    try:
        app = LogAnalyzerApp()
        app.run()
    except Exception as e:
        print(f"❌ Failed to start application: {e}")
        print("💡 Make sure you have installed dependencies:")
        print("   pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":
    run_app()
