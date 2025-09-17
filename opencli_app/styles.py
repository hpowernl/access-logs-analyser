"""
Simple, clean CSS styling for the log analyzer
"""

SIMPLE_CSS = """
/* Clean, simple styling */

Screen {
    background: $surface;
}

Header {
    background: $primary;
    color: $text;
    height: 3;
    content-align: center middle;
    text-style: bold;
}

Footer {
    background: $primary-darken-1;
    color: $text;
    height: 1;
}

TabbedContent {
    background: $surface;
    margin: 1;
}

TabPane {
    padding: 1;
    background: $surface;
}

Tabs {
    background: $primary-lighten-1;
    color: $text;
    height: 3;
}

Tab {
    background: $primary-lighten-2;
    color: $text-muted;
    margin: 0 1;
    padding: 0 2;
    text-style: bold;
}

Tab.-active {
    background: $accent;
    color: $text;
    text-style: bold;
}

Tab:hover {
    background: $primary-lighten-3;
    color: $text;
}

/* Scrollable content areas */
.scrollable {
    overflow-y: auto;
    overflow-x: hidden;
    height: 1fr;
    scrollbar-size-vertical: 1;
}

/* Simple content styling */
.content-area {
    padding: 1;
    background: $surface;
    height: 1fr;
}

/* Status indicators */
.status-good {
    color: $success;
}

.status-warning {
    color: $warning;
}

.status-error {
    color: $error;
}

/* Simple borders */
.bordered {
    border: solid $primary-lighten-1;
}
"""
