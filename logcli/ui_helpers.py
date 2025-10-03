"""
UI Helper Functions for consistent formatting across all commands.

This module provides standardized formatting functions to ensure:
- Clear visual hierarchy (main sections, subsections, data items)
- Professional appearance (limited emoji use)
- Consistent indenting and structure
- Easy maintenance and updates
"""

from typing import Optional, Union
from rich.console import Console
from rich.table import Table
from rich.panel import Panel


def print_section_header(
    title: str, 
    emoji: str = "", 
    console: Optional[Console] = None,
    width: int = 63
) -> None:
    """
    Print a main section header with separator lines.
    
    Usage: For command-level headers (one per command output).
    
    Args:
        title: Section title in UPPERCASE
        emoji: Optional single emoji (use sparingly)
        console: Rich Console instance (creates new if None)
        width: Width of separator line
        
    Example:
        print_section_header("SECURITY ANALYSIS", "🛡️")
    """
    if console is None:
        console = Console()
    
    header = f"{emoji} {title}" if emoji else title
    console.print(f"\n{'═' * width}")
    console.print(f"[bold blue]{header}[/bold blue]")
    console.print(f"{'═' * width}\n")


def print_subsection(
    title: str, 
    console: Optional[Console] = None,
    spacing_before: bool = True
) -> None:
    """
    Print a subsection title (level 2 hierarchy).
    
    Usage: For major subdivisions within a command output.
    
    Args:
        title: Subsection title (Title Case recommended)
        console: Rich Console instance
        spacing_before: Add blank line before subsection
        
    Example:
        print_subsection("Performance Metrics")
    """
    if console is None:
        console = Console()
    
    if spacing_before:
        console.print()
    console.print(f"  [bold]{title}[/bold]")


def print_data_item(
    label: str,
    value: Union[str, int, float],
    color: str = "cyan",
    console: Optional[Console] = None,
    indent: int = 4,
    unit: str = ""
) -> None:
    """
    Print a data item with proper indenting and color.
    
    Usage: For individual metrics/statistics.
    
    Args:
        label: Item label/description
        value: The value to display
        color: Color for the value (cyan, green, red, yellow, orange1)
        console: Rich Console instance
        indent: Number of spaces to indent (default: 4)
        unit: Optional unit suffix (e.g., "s", "%", "GB")
        
    Example:
        print_data_item("Total Requests", "1,234", "green")
        print_data_item("Average", "0.123", "cyan", unit="s")
    """
    if console is None:
        console = Console()
    
    spaces = " " * indent
    display_value = f"{value}{unit}" if unit else value
    console.print(f"{spaces}• {label}: [{color}]{display_value}[/{color}]")


def print_subsection_separator(
    console: Optional[Console] = None,
    char: str = "─",
    width: int = 61,
    indent: int = 2
) -> None:
    """
    Print a subtle separator between subsections.
    
    Args:
        console: Rich Console instance
        char: Character to use for separator
        width: Width of separator
        indent: Left indent (to align with subsections)
    """
    if console is None:
        console = Console()
    
    spaces = " " * indent
    console.print(f"{spaces}[dim]{char * width}[/dim]")


def print_nested_item(
    label: str,
    value: Union[str, int, float],
    color: str = "cyan",
    console: Optional[Console] = None,
    indent: int = 6,
    unit: str = ""
) -> None:
    """
    Print a nested/child data item (level 3).
    
    Usage: For data that belongs under a specific data item.
    
    Args:
        label: Item label
        value: Value to display
        color: Color for value
        console: Rich Console instance
        indent: Spaces to indent (default: 6 for level 3)
        unit: Optional unit suffix
        
    Example:
        print_data_item("Checkout Performance", "")
        print_nested_item("Average", "0.456", "cyan", unit="s")
        print_nested_item("P95", "0.850", "yellow", unit="s")
    """
    if console is None:
        console = Console()
    
    spaces = " " * indent
    display_value = f"{value}{unit}" if unit else value
    console.print(f"{spaces}◦ {label}: [{color}]{display_value}[/{color}]")


def create_summary_table(
    title: str,
    data: dict,
    console: Optional[Console] = None,
    show_header: bool = True
) -> None:
    """
    Create a clean summary table for structured data.
    
    Args:
        title: Table title
        data: Dict of {label: (value, color)} or {label: value}
        console: Rich Console instance
        show_header: Whether to show table header
        
    Example:
        create_summary_table(
            "Overview",
            {
                "Total Requests": ("1,234", "green"),
                "Error Rate": ("2.5%", "red")
            }
        )
    """
    if console is None:
        console = Console()
    
    table = Table(title=title, show_header=show_header, show_lines=False)
    table.add_column("Metric", style="bold", no_wrap=True)
    table.add_column("Value", justify="right")
    
    for label, value_info in data.items():
        if isinstance(value_info, tuple):
            value, color = value_info
            table.add_row(label, f"[{color}]{value}[/{color}]")
        else:
            table.add_row(label, str(value_info))
    
    console.print(table)
    console.print()


def print_warning(
    message: str,
    console: Optional[Console] = None,
    indent: int = 4,
    level: str = "warning"
) -> None:
    """
    Print a warning or alert message.
    
    Args:
        message: Warning message
        console: Rich Console instance
        indent: Indentation level
        level: "warning" (yellow), "error" (red), "info" (cyan), "success" (green)
    """
    if console is None:
        console = Console()
    
    colors = {
        "warning": "yellow",
        "error": "red",
        "info": "cyan",
        "success": "green"
    }
    
    color = colors.get(level, "yellow")
    spaces = " " * indent
    console.print(f"{spaces}[{color}]{message}[/{color}]")


def print_recommendation(
    message: str,
    console: Optional[Console] = None,
    indent: int = 4
) -> None:
    """
    Print a recommendation/tip message.
    
    Args:
        message: Recommendation text
        console: Rich Console instance
        indent: Indentation level
    """
    if console is None:
        console = Console()
    
    spaces = " " * indent
    console.print(f"{spaces}[dim]💡 {message}[/dim]")


# Color guidelines and constants
class Colors:
    """Standard colors with semantic meaning."""
    SUCCESS = "green"        # Positive metrics, successes
    ERROR = "red"           # Errors, problems, critical values
    WARNING = "yellow"      # Warnings, medium values
    INFO = "cyan"           # Neutral metrics, counts
    ALERT = "orange1"       # Medium priority warnings
    HEADER = "blue"         # Section headers only
    DIM = "dim"            # Less important info


# Emoji guidelines - use sparingly!
class Emoji:
    """Approved emojis for main section headers only."""
    SECURITY = "🛡️"
    PERFORMANCE = "⚡"
    ECOMMERCE = "🛍️"
    API = "🔌"
    BOTS = "🤖"
    SUMMARY = "📊"
    GEOGRAPHIC = "🌍"
    
    # DO NOT USE these in actual output (for reference only)
    # ❌ Do not use: 📈, ⏰, 💾, 🔍, 📊 in subsections
    # ✅ Use simple bullets: • ◦ instead


def format_number(value: Union[int, float], precision: int = 0) -> str:
    """
    Format a number with thousand separators.
    
    Args:
        value: Number to format
        precision: Decimal places (0 for integers)
        
    Returns:
        Formatted string (e.g., "1,234" or "1,234.56")
    """
    if precision == 0:
        return f"{int(value):,}"
    return f"{float(value):,.{precision}f}"


def format_percentage(value: float, precision: int = 1) -> str:
    """
    Format a percentage value.
    
    Args:
        value: Percentage value (e.g., 2.5 for 2.5%)
        precision: Decimal places
        
    Returns:
        Formatted percentage string (e.g., "2.5%")
    """
    return f"{value:.{precision}f}%"


def format_bytes(bytes_value: Union[int, float], precision: int = 2) -> str:
    """
    Format bytes into human-readable format.
    
    Args:
        bytes_value: Size in bytes
        precision: Decimal places
        
    Returns:
        Formatted string (e.g., "1.23 GB")
    """
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(bytes_value)
    unit_index = 0
    
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    
    return f"{value:.{precision}f} {units[unit_index]}"


def format_duration(seconds: Union[int, float]) -> str:
    """
    Format duration in seconds to human-readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string (e.g., "2.5 hours" or "45 minutes")
    """
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    else:
        return f"{seconds / 86400:.1f} days"


# Example usage and documentation
def print_usage_example():
    """Print an example of how to use these helpers."""
    console = Console()
    
    print_section_header("EXAMPLE OUTPUT", "📊", console)
    
    print_subsection("Overview", console)
    print_data_item("Total Requests", format_number(1234), Colors.SUCCESS, console)
    print_data_item("Error Rate", format_percentage(2.5), Colors.ERROR, console)
    print_data_item("Bot Traffic", format_percentage(15.2), Colors.WARNING, console)
    
    print_subsection("Performance Metrics", console)
    print_data_item("Average", "0.123", Colors.INFO, console, unit="s")
    print_data_item("Maximum", "2.450", Colors.ERROR, console, unit="s")
    print_data_item("95th Percentile", "0.850", Colors.WARNING, console, unit="s")
    
    print_subsection("Nested Example", console)
    print_data_item("Checkout Performance", "", Colors.INFO, console)
    print_nested_item("Average", "0.456", Colors.INFO, console, unit="s")
    print_nested_item("P95", "0.850", Colors.WARNING, console, unit="s")
    print_nested_item("Errors", format_number(5), Colors.ERROR, console)
    
    console.print()
    print_recommendation("Use --detailed for more information", console)


if __name__ == "__main__":
    # Run example when module is executed directly
    print("\n=== UI Helpers Usage Example ===\n")
    print_usage_example()

