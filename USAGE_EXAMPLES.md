# NextGen Access Log Analyzer - Usage Examples

## 🚀 Quick Start

### Basic Analysis
```bash
# Activate the virtual environment
source venv/bin/activate

# Analyze a specific log file
python3 -m logcli /var/log/nginx/access.log

# Analyze sample data (for testing)
python3 -m logcli sample_access.log
```

### Auto-Discovery
```bash
# Automatically find all access logs in nginx directory
python3 -m logcli --auto-discover

# Specify a different nginx directory
python3 -m logcli --auto-discover --nginx-dir /custom/nginx/logs
```

## 📊 Filtering Examples

### Country Filters
```bash
# Only traffic from Netherlands and Belgium
python3 -m logcli --countries NL,BE sample_access.log

# Only US traffic
python3 -m logcli --countries US sample_access.log --summary-only
```

### Status Code Filters
```bash
# Only errors (4xx and 5xx)
python3 -m logcli --filter-preset errors_only sample_access.log

# Only 404 and 500 errors
python3 -m logcli --status-codes 404,500 sample_access.log

# Only successful requests
python3 -m logcli --filter-preset success_only sample_access.log
```

### Bot Filtering
```bash
# Exclude all bots
python3 -m logcli --exclude-bots sample_access.log

# Only bot traffic (don't use --exclude-bots)
python3 -m logcli sample_access.log
```

### Combined Filters
```bash
# Dutch traffic, no bots, only errors
python3 -m logcli --countries NL --exclude-bots --filter-preset errors_only sample_access.log

# API endpoints only, no bots
python3 -m logcli --filter-preset api_only --exclude-bots sample_access.log
```

## 📈 Export Examples

### CSV Export
```bash
# Export to CSV
python3 -m logcli --export-csv sample_access.log

# Export to custom directory
python3 -m logcli --export-csv --output ./my_exports sample_access.log
```

### JSON Export
```bash
# Export to JSON (structured data)
python3 -m logcli --export-json sample_access.log

# Export all formats
python3 -m logcli --export-csv --export-json --export-charts sample_access.log
```

### Filtered Export
```bash
# Export only Dutch traffic without bots
python3 -m logcli --countries NL --exclude-bots --export-csv sample_access.log

# Export only errors to JSON
python3 -m logcli --filter-preset errors_only --export-json sample_access.log
```

## 🔄 Real-time Monitoring

### Console Monitoring
```bash
# Follow logs in real-time (console output)
python3 -m logcli -f /var/log/nginx/access.log

# Real-time with filters
python3 -m logcli -f --exclude-bots --countries NL /var/log/nginx/access.log
```

### Interactive TUI
```bash
# Launch interactive interface
python3 -m logcli -i sample_access.log

# Real-time interactive interface
python3 -m logcli -f -i /var/log/nginx/access.log

# TUI with auto-discovery
python3 -m logcli -f -i --auto-discover
```

## 🎯 Production Examples

### Hypernode Server Analysis
```bash
# Analyze all Hypernode access logs
sudo python3 -m logcli --auto-discover --nginx-dir /var/log/nginx

# Real-time monitoring of Hypernode logs
sudo python3 -m logcli -f -i --auto-discover --nginx-dir /var/log/nginx

# Export daily reports
sudo python3 -m logcli --auto-discover --export-csv --export-json --output /home/app/reports --nginx-dir /var/log/nginx
```

### Performance Monitoring
```bash
# Monitor only slow requests (use filter in TUI)
python3 -m logcli -f -i /var/log/nginx/access.log

# Export for performance analysis
python3 -m logcli --export-json --output ./performance_reports /var/log/nginx/access.log
```

### Security Monitoring
```bash
# Monitor only errors for security analysis
python3 -m logcli -f --filter-preset errors_only /var/log/nginx/access.log

# Export security events
python3 -m logcli --filter-preset errors_only --export-csv --output ./security_reports /var/log/nginx/access.log
```

### Bot Analysis
```bash
# Analyze only bot traffic
python3 -m logcli sample_access.log  # Bots are included by default

# Compare bot vs human traffic
python3 -m logcli sample_access.log > all_traffic.txt
python3 -m logcli --exclude-bots sample_access.log > human_traffic.txt
```

## 🔧 Advanced Usage

### Multiple Log Files
```bash
# Analyze multiple files simultaneously
python3 -m logcli /var/log/nginx/access.log /var/log/nginx/access.log.1

# Including gzip files
python3 -m logcli /var/log/nginx/access.log /var/log/nginx/access.log.1.gz /var/log/nginx/access.log.2.gz

# All access logs in directory
python3 -m logcli /var/log/nginx/access.log*
```

### Custom Output
```bash
# Summary only for scripts
python3 -m logcli --summary-only sample_access.log

# Export for external tools
python3 -m logcli --export-json --summary-only sample_access.log
```

### Scheduled Reports
```bash
# Cron job for daily reporting
0 6 * * * cd /path/to/logcli && source venv/bin/activate && python3 -m logcli --auto-discover --export-csv --export-json --output /var/reports --nginx-dir /var/log/nginx

# Weekly comprehensive report
0 6 * * 0 cd /path/to/logcli && source venv/bin/activate && python3 -m logcli --auto-discover --export-csv --export-json --export-charts --output /var/reports/weekly --nginx-dir /var/log/nginx
```

## 💡 Tips & Tricks

### Performance Tips
- Use `--summary-only` for quick checks
- Filter data early in the pipeline for better performance
- For large files, use specific filters
- Gzip files are automatically supported

### Monitoring Tips
- Use `-f -i` for best real-time experience
- Combine filters for specific monitoring
- Export regularly for historical analysis
- Use presets for commonly used filters

### Troubleshooting
```bash
# Test with sample data first
python3 -m logcli sample_access.log --summary-only

# Check if JSON format is correct
head -1 /var/log/nginx/access.log | python3 -m json.tool

# Verbose output for debugging
python3 -m logcli --help
```

## 📋 Cheat Sheet

| Command | Description |
|---------|-------------|
| `python3 -m logcli file.log` | Basic analysis |
| `--auto-discover` | Auto-find nginx logs |
| `-f` | Follow/tail logs |
| `-i` | Interactive TUI |
| `--exclude-bots` | Filter out bots |
| `--countries NL,BE` | Filter by countries |
| `--filter-preset errors_only` | Quick error filter |
| `--export-csv` | Export to CSV |
| `--summary-only` | Quick summary |
| `-f -i` | Real-time TUI |

## 🎛️ TUI Controls

In interactive mode:
- **q**: Quit
- **f**: Filters tab
- **e**: Export data
- **r**: Refresh
- **t**: Timeline view
- **Tab**: Switch between tabs
- **Enter**: Activate buttons
