"""
Utility functions for the OpenCLI interface
"""

from datetime import datetime
from typing import Dict, List, Tuple, Any


def format_number(num: int) -> str:
    """Format number with thousands separator."""
    return f"{num:,}"


def format_percentage(value: float) -> str:
    """Format percentage with one decimal place."""
    return f"{value:.1f}%"


def format_bytes(bytes_val: float) -> str:
    """Format bytes to human readable format."""
    if bytes_val < 1024:
        return f"{bytes_val:.0f} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val/1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val/(1024*1024):.1f} MB"
    else:
        return f"{bytes_val/(1024*1024*1024):.2f} GB"


def get_status_color(status_code: int) -> str:
    """Get color for HTTP status code."""
    if status_code < 300:
        return "green"
    elif status_code < 400:
        return "yellow"
    else:
        return "red"


def get_status_name(status_code: int) -> str:
    """Get human readable status name."""
    status_names = {
        200: "OK",
        201: "Created", 
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout"
    }
    return status_names.get(status_code, "Unknown")


def create_simple_bar(value: float, max_value: float, width: int = 20) -> str:
    """Create a simple text progress bar."""
    if max_value == 0:
        return "─" * width
    
    filled = int((value / max_value) * width)
    return "█" * filled + "─" * (width - filled)


def format_timestamp() -> str:
    """Get formatted current timestamp."""
    return datetime.now().strftime("%H:%M:%S")


def create_table_row(items: List[str], widths: List[int]) -> str:
    """Create a formatted table row."""
    formatted_items = []
    for item, width in zip(items, widths):
        if len(item) > width:
            item = item[:width-3] + "..."
        formatted_items.append(f"{item:<{width}}")
    
    return " ".join(formatted_items)


def get_top_items(data: Dict[Any, int], limit: int = 10) -> List[Tuple[Any, int]]:
    """Get top N items from a counter dictionary."""
    return sorted(data.items(), key=lambda x: x[1], reverse=True)[:limit]
