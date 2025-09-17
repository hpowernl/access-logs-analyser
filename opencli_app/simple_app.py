"""
Heel eenvoudige werkende versie van de log analyzer
"""

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, Static, TabbedContent, TabPane

class SimpleLogApp(App):
    """Eenvoudige log analyzer die zeker werkt."""
    
    TITLE = "🚀 Simple Log Analyzer"
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("1", "show_overview", "Overview"),
        ("2", "show_performance", "Performance"),
        ("3", "show_security", "Security"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with TabbedContent(initial="overview"):
            with TabPane("📊 Overview", id="overview"):
                yield Static("""[bold]📊 OVERVIEW[/bold]

[green]✅ Interface werkt![/green]

[bold]TEST DATA:[/bold]
Total Requests:  1,234
Unique Visitors: 567
Error Rate:      2.3%
Bandwidth:       45.6 MB

[bold]TOP PAGES[/bold]
1. /index.php          456 (37.0%) ████████████████████
2. /api/graphql        234 (19.0%) ██████████
3. /admin/login        123 (10.0%) █████

[dim]Commands: 1=Overview 2=Performance 3=Security | q=Quit[/dim]""", 
                    classes="content")
            
            with TabPane("⚡ Performance", id="performance"):
                yield Static("""[bold]⚡ PERFORMANCE[/bold]

[green]✅ Performance tab werkt![/green]

[bold]RESPONSE TIME STATISTICS[/bold]
Average:      [green]0.234s[/green]
Median:       0.198s
95th %ile:    [yellow]0.567s[/yellow]
99th %ile:    [red]1.234s[/red]
Maximum:      [red]2.456s[/red]
Minimum:      [green]0.012s[/green]

[bold]SLOWEST ENDPOINTS[/bold]
/api/heavy-query       [red]1.234s[/red] ████████████████
/admin/reports         [yellow]0.876s[/yellow] ████████████
/search/complex        [yellow]0.654s[/yellow] ████████

[dim]Commands: 1=Overview 2=Performance 3=Security | q=Quit[/dim]""", 
                    classes="content")
            
            with TabPane("🔒 Security", id="security"):
                yield Static("""[bold]🔒 SECURITY[/bold]

[green]✅ Security tab werkt![/green]

[bold]THREAT OVERVIEW[/bold]
Total Requests:      1,234
Error Requests:      [yellow]45[/yellow]
4xx Client Errors:   [yellow]32[/yellow]
5xx Server Errors:   [red]13[/red]

[bold]TOP ERROR CODES[/bold]
[yellow]404[/yellow] Not Found             23 (1.9%) ████████
[red]500[/red] Internal Server Error  8 (0.6%) ███
[yellow]403[/yellow] Forbidden             6 (0.5%) ██

[bold]SUSPICIOUS ACTIVITY[/bold]
[red]192.168.1.100[/red]  234 (19.0%) [red]HIGH[/red] ████████████
[yellow]10.0.0.50[/yellow]     123 (10.0%) [yellow]MED[/yellow]  ██████

[dim]Commands: 1=Overview 2=Performance 3=Security | q=Quit[/dim]""", 
                    classes="content")
        
        yield Footer()
    
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


def run_simple_app():
    """Run the simple app."""
    app = SimpleLogApp()
    app.run()


if __name__ == "__main__":
    run_simple_app()
