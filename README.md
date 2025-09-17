# NextGen Access Log Analyzer

An advanced, real-time CLI tool for analyzing Nginx JSON access logs. This tool provides more comprehensive functionality than GoAccess with interactive filtering, real-time monitoring, and extensive export capabilities.

## ✨ Features

- **Real-time Log Monitoring**: Live tailing of access logs with automatic updates
- **Interactive TUI**: Modern terminal interface built with Textual
- **Advanced Filtering**: Filter by country, IP ranges, bots, status codes, paths, and more
- **Gzip Support**: Automatic support for compressed log files
- **Multiple Export Formats**: CSV, JSON, HTML charts, and text reports
- **Bot Detection**: Intelligent recognition of different bot types
- **Response Time Analysis**: Detailed statistics on response times
- **Bandwidth Tracking**: Monitor data usage and transfer statistics

## 🚀 Installation

### Requirements
- Python 3.8 or higher
- pip

### Installation Steps

1. **Clone the repository:**
```bash
git clone <repository-url>
cd Hypernode-logs
```

2. **Create a virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Install the tool (optional):**
```bash
pip install -e .
```

## 📖 Usage

### Basic Commands

```bash
# Analyze a specific log file
python -m logcli /var/log/nginx/access.log

# Auto-discover all access logs in nginx directory
python -m logcli --auto-discover

# Real-time monitoring with interactive UI
python -m logcli -f -i /var/log/nginx/access.log

# Filter by countries and export to CSV
python -m logcli --countries US,GB,DE --export-csv /var/log/nginx/access.log

# Exclude bots and show only errors
python -m logcli --exclude-bots --filter-preset errors_only /var/log/nginx/access.log
```

### Advanced Options

```bash
# Show all available options
python -m logcli --help

# Use with multiple files (including gzip)
python -m logcli /var/log/nginx/access.log /var/log/nginx/access.log.1.gz

# Export to all formats
python -m logcli --export-csv --export-json --export-charts --output ./exports /var/log/nginx/access.log

# Real-time console mode (no TUI)
python -m logcli -f /var/log/nginx/access.log
```

### Interactive Mode

In interactive mode (TUI), the following keys are available:

- **`q`**: Quit
- **`f`**: Toggle filters tab
- **`e`**: Export data
- **`r`**: Refresh data
- **`t`**: Toggle timeline view

## 🎯 Nginx Log Format

This tool is optimized for Nginx JSON logs with the following format:

```json
{
  "time": "2025-09-17T08:10:17+00:00",
  "remote_addr": "94.124.105.4",
  "host": "example.com",
  "request": "POST /graphql HTTP/1.1",
  "status": "200",
  "body_bytes_sent": "860",
  "referer": "",
  "user_agent": "GuzzleHttp/7",
  "request_time": "0.098",
  "country": "CZ",
  "server_name": "example.com",
  "handler": "phpfpm"
}
```

### Supported Fields

- `time` - Request timestamp
- `remote_addr` - Client IP address
- `host` - Host header
- `request` - HTTP request line (method, path, protocol)
- `status` - HTTP status code
- `body_bytes_sent` - Number of bytes sent
- `user_agent` - User agent string
- `request_time` - Response time in seconds
- `country` - Country code (if available)
- `referer` - Referer header
- `server_name` - Server name
- `handler` - Backend handler (phpfpm, varnish, etc.)

## 📊 Filter Presets

The tool offers several predefined filters:

- **`errors_only`**: Show only 4xx and 5xx responses
- **`success_only`**: Show only 2xx responses  
- **`no_bots`**: Exclude all bot traffic
- **`api_only`**: Show only API endpoints (/api/*)
- **`recent_activity`**: Show only recent activity

## 📈 Export Formats

### CSV Export
Detailed tables with:
- Top countries, IPs, paths, status codes
- Timeline data
- Error details
- Response time statistics

### JSON Export
Complete structured data export with:
- All statistics and counters
- Timeline data
- Slow requests list
- Bot traffic analysis

### HTML Charts
Interactive charts with:
- Country distribution
- Status code breakdown
- Browser statistics
- Timeline visualizations

### Text Reports
Human-readable summaries with:
- Overview statistics
- Top entries per category
- Response time analysis

## 🔧 Configuration

Modify `logcli/config.py` for:

- Bot signature lists
- Alert thresholds
- Timeline granularity
- Export settings
- Default filters

## 📁 Project Structure

```
logcli/
├── __init__.py          # Package initialization
├── __main__.py          # Module entry point
├── main.py              # CLI entry point
├── config.py            # Configuration settings
├── parser.py            # JSON log parsing
├── filters.py           # Filtering logic
├── aggregators.py       # Data aggregation
├── log_reader.py        # File reading & tailing
├── ui.py                # Interactive UI
└── export.py            # Export functionality
```

## 🐛 Troubleshooting

### Common Issues

1. **Permission denied at /var/log/nginx**
   ```bash
   sudo python -m logcli --auto-discover
   ```

2. **Gzip files not being read**
   - Check if the file has a `.gz` extension
   - Ensure the file is not corrupted

3. **No data visible**
   - Check log format (must be JSON)
   - Check if filters are too restrictive
   - Use `--summary-only` for quick check

4. **Performance issues with large files**
   - Use filters to limit data
   - Consider analyzing only recent logs
   - Use `--summary-only` for quick overview

## 🤝 Contributing

Contributions are welcome! Open an issue or pull request.

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Credits

Based on requirements from `idea.md` and optimized for Hypernode/Nginx environments.
