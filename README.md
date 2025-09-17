# Access Log Analyzer

An **enterprise-grade, interactive log analysis platform** for Nginx JSON access logs. Far beyond traditional tools like GoAccess, this platform offers real-time monitoring, advanced security analysis, performance optimization, and intelligent bot detection - all through both an intuitive **interactive TUI** and powerful **CLI commands**.

## ✨ Key Features

### 🎮 **Interactive Terminal Interface**
- **Modern TUI**: Like htop/GoAccess but for log analysis
- **Real-time Updates**: Live streaming data with auto-refresh
- **Multiple Views**: Security, Performance, Bot Analysis, Search
- **Zero Configuration**: Start with `./opencli` - works immediately
- **Intuitive Navigation**: Function keys, arrow keys, shortcuts

### 🔐 **Advanced Security Analysis**
- **Attack Pattern Detection**: SQL injection, XSS, directory traversal
- **Brute Force Detection**: Configurable thresholds and alerts
- **Suspicious IP Tracking**: Threat scoring and blacklist recommendations  
- **Real-time Security Alerts**: Live monitoring of security events
- **Comprehensive Reports**: Detailed security analysis exports

### ⚡ **Performance Optimization**
- **Response Time Analysis**: Percentiles, trends, slowest endpoints
- **Cache Effectiveness**: Varnish/PHP-FPM performance analysis
- **Bandwidth Monitoring**: Usage patterns and optimization tips
- **Performance Recommendations**: Automated suggestions
- **Resource Impact Analysis**: Server load and capacity planning

### 🤖 **Intelligent Bot Management**
- **Advanced Classification**: Search engines, social media, security scanners
- **Behavior Analysis**: Request patterns, intervals, legitimacy scoring
- **Resource Impact**: Bot bandwidth usage and server load
- **Whitelist/Blacklist**: Automated recommendations
- **Unknown Bot Detection**: Pattern-based identification

### 🔍 **Advanced Search & Filtering**
- **Flexible Search**: IP, path patterns (regex), user agents, countries
- **Time-based Filtering**: Last N hours, date ranges
- **Interactive Results**: Real-time search with table display
- **Export Capabilities**: CSV, JSON, text formats
- **Anomaly Detection**: Automatic detection of unusual patterns

### 📊 **Comprehensive Reporting**
- **Multi-format Reports**: HTML dashboards, JSON data, CSV exports
- **Scheduled Reports**: Daily, weekly, custom intervals
- **Executive Summaries**: High-level KPIs and trends
- **Technical Deep-dives**: Detailed analysis for DevOps teams

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

### 🎮 Interactive Mode (Recommended)

**Start the interactive TUI - no configuration needed:**

```bash
./opencli
```

**Navigation:**
- **F1**: Help system
- **F2**: Configuration  
- **F3**: Security analysis
- **F4**: Performance monitoring
- **F5**: Bot analysis
- **F6**: Export/Reports
- **F7**: Search interface
- **R**: Refresh data
- **P**: Pause/Resume
- **Q**: Quit
- **1-3**: Quick view switching

### 🔐 Security Analysis

```bash
# Comprehensive security scan
python -m logcli security --auto-discover --scan-attacks --brute-force-detection

# SQL injection detection
python -m logcli security --auto-discover --sql-injection-patterns

# Suspicious user agents
python -m logcli security --auto-discover --suspicious-user-agents

# Export security report
python -m logcli security --auto-discover --scan-attacks --output security_report.json
```

### ⚡ Performance Analysis

```bash
# Complete performance analysis
python -m logcli perf --auto-discover --response-time-analysis --slowest 10

# Cache effectiveness (Varnish)
python -m logcli perf --auto-discover --cache-analysis --handler varnish

# Bandwidth analysis
python -m logcli perf --auto-discover --bandwidth-analysis

# Export performance report
python -m logcli perf --auto-discover --response-time-analysis --output perf_report.json
```

### 🤖 Bot Analysis

```bash
# Bot classification and behavior
python -m logcli bots --auto-discover --classify-types --behavior-analysis

# Legitimacy scoring
python -m logcli bots --auto-discover --legitimate-vs-malicious

# Resource impact analysis
python -m logcli bots --auto-discover --impact-analysis

# Export bot analysis
python -m logcli bots --auto-discover --classify-types --output bot_report.json
```

### 🔍 Advanced Search

```bash
# Search by IP address
python -m logcli search --auto-discover --ip 192.168.1.100

# Search with regex patterns
python -m logcli search --auto-discover --path "/admin.*" --status 403

# Time-based search
python -m logcli search --auto-discover --last-hours 24 --status 404,500

# Complex search with export
python -m logcli search --auto-discover --country US,GB --status 404 --limit 100 --output results.csv
```

### 📊 Report Generation

```bash
# Daily HTML report
python -m logcli report --auto-discover --daily --format html

# Weekly comprehensive report
python -m logcli report --auto-discover --weekly --security-summary --performance-summary --bot-summary

# Executive summary (JSON)
python -m logcli report --auto-discover --format json --output executive_summary.json
```

### 🔧 Basic Analysis (Legacy)

```bash
# Basic analysis (backward compatible)
python -m logcli analyze --auto-discover

# Real-time monitoring
python -m logcli analyze -f -i --auto-discover

# Filter and export
python -m logcli analyze --countries US,GB,DE --export-csv --auto-discover
```

### ⚙️ Configuration

```bash
# Initialize configuration
python -m logcli config --init --profile production

# Show current settings
python -m logcli config --show

# Set configuration values
python -m logcli config --set nginx_dir=/var/log/nginx --profile production
```

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

## 🎯 Real-World Use Cases

### 🏢 **For System Administrators**
```bash
# Daily security monitoring
./opencli  # Interactive dashboard
python -m logcli security --auto-discover --scan-attacks --output daily_security.json

# Performance health check
python -m logcli perf --auto-discover --response-time-analysis --slowest 20
```

### 🔧 **For DevOps Engineers**  
```bash
# Incident investigation
python -m logcli search --auto-discover --ip 192.168.1.100 --last-hours 48

# Cache optimization
python -m logcli perf --auto-discover --cache-analysis --handler varnish --handler phpfpm

# Bot traffic analysis
python -m logcli bots --auto-discover --impact-analysis --classify-types
```

### 📊 **For Business Analysts**
```bash
# Weekly traffic report
python -m logcli report --auto-discover --weekly --format html --output ./reports/

# Geographic analysis
python -m logcli search --auto-discover --country US,GB,DE,FR --output geo_analysis.csv
```

### 🚨 **For Security Teams**
```bash
# Real-time security monitoring
./opencli  # Use F3 for Security view

# Threat hunting
python -m logcli security --auto-discover --sql-injection-patterns --brute-force-detection

# IP reputation analysis  
python -m logcli search --auto-discover --status 403,404,500 --limit 500 --output suspicious_activity.csv
```

## 🎮 Interactive TUI Features

### **Dashboard Views**
- **Overview**: Real-time statistics, live log feed, trend charts
- **Security**: Attack patterns, suspicious IPs, security alerts
- **Performance**: Response times, slowest endpoints, cache analysis
- **Bots**: Bot classification, behavior patterns, resource impact
- **Search**: Interactive filtering with real-time results

### **Navigation & Shortcuts**
- **Function Keys**: F1-F7 for different views and actions
- **Number Keys**: 1-3 for quick view switching
- **Letter Keys**: R (refresh), P (pause), Q (quit)
- **Arrow Keys**: Navigate tables and lists
- **Enter**: Drill down into details

### **Real-time Features**
- **Live Updates**: Auto-refresh every 1-5 seconds
- **Streaming Logs**: Real-time log entries display
- **Progressive Loading**: Smooth data updates
- **Pause/Resume**: Control data flow

## 📈 Export Formats & Reports

### **CSV Exports**
- **Security Reports**: Attack patterns, suspicious IPs, threat analysis
- **Performance Data**: Response times, slowest endpoints, cache stats
- **Bot Analysis**: Classification, behavior patterns, resource usage
- **Search Results**: Filtered log entries with all fields

### **JSON Exports**
- **Complete Data**: All statistics, counters, and analysis
- **API-Ready**: Structured data for integration
- **Historical Data**: Timeline and trend information
- **Detailed Reports**: In-depth analysis with metadata

### **HTML Reports**
- **Interactive Dashboards**: Charts, graphs, and visualizations  
- **Executive Summaries**: High-level KPIs and trends
- **Technical Deep-dives**: Detailed analysis for technical teams
- **Mobile-Friendly**: Responsive design for all devices

### **Text Reports**
- **Console Output**: Human-readable summaries
- **Email-Ready**: Plain text for automated reporting
- **Log-Friendly**: Structured for log aggregation systems

## 🏗️ Architecture & Components

### **Interactive TUI (Primary Interface)**
```bash
./opencli                    # Launch interactive dashboard
```

### **CLI Commands (Advanced Users)**
- `python -m logcli analyze`   # Basic analysis (legacy)
- `python -m logcli security`  # Security analysis
- `python -m logcli perf`      # Performance analysis  
- `python -m logcli bots`      # Bot analysis
- `python -m logcli search`    # Advanced search
- `python -m logcli report`    # Report generation
- `python -m logcli config`    # Configuration management

### **Core Modules**
```
logcli/
├── interactive.py       # Main TUI application
├── main.py             # CLI command router
├── security.py         # Security analysis engine
├── performance.py      # Performance analysis engine  
├── bots.py             # Bot classification engine
├── search.py           # Advanced search engine
├── parser.py           # JSON log parsing
├── filters.py          # Filtering logic
├── aggregators.py      # Data aggregation
├── log_reader.py       # File reading & tailing
└── export.py           # Export functionality
```

## ⚙️ Configuration & Customization

### **Configuration Profiles**
```bash
# Create production profile
python -m logcli config --init --profile production

# Hypernode-specific settings
python -m logcli config --set nginx_dir=/var/log/nginx --profile hypernode
python -m logcli config --set alert_threshold=100 --profile hypernode
python -m logcli config --set bot_threshold=50 --profile hypernode
```

### **Customizable Settings**
- **Log Directories**: Auto-discovery paths
- **Alert Thresholds**: Security and performance alerts
- **Bot Signatures**: Custom bot detection patterns
- **Export Formats**: Default output formats
- **Refresh Intervals**: TUI update frequencies
- **Color Themes**: Interface customization

## 🚀 Performance & Scalability

### **Optimized for Large Files**
- **Streaming Processing**: Memory-efficient log parsing
- **Gzip Support**: Automatic compressed file handling
- **Incremental Analysis**: Process only new data
- **Background Processing**: Non-blocking UI updates

### **Hypernode Optimizations**
- **Multi-file Support**: Handle 50+ rotated logs
- **Handler Detection**: Varnish vs PHP-FPM analysis
- **Country Integration**: Built-in GeoIP support
- **JSON Format**: Optimized for Nginx JSON logs

## 🐛 Troubleshooting & FAQ

### **Installation Issues**
```bash
# Python version check
python3 --version  # Requires 3.8+

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m logcli --help
```

### **TUI Issues**
```bash
# Terminal compatibility
export TERM=xterm-256color

# Permission issues
chmod +x opencli

# Fallback to CLI mode
python -m logcli analyze --auto-discover
```

### **Log Format Issues**
```bash
# Verify JSON format
head -n 1 /var/log/nginx/access.log | python -m json.tool

# Check file permissions
ls -la /var/log/nginx/access.log

# Test with sample data
python -m logcli analyze sample_access.log
```

### **Performance Issues**
```bash
# Limit analysis scope
python -m logcli analyze --last-hours 24 --auto-discover

# Use summary mode
python -m logcli analyze --summary-only --auto-discover

# Filter data
python -m logcli analyze --exclude-bots --filter-preset errors_only --auto-discover
```

## 🎯 Hypernode-Specific Features

### **Perfect for Your 98.11% Error Rate**
```bash
# Analyze all those 404s
python -m logcli security --auto-discover --scan-attacks

# Find the real problems vs bot noise
python -m logcli bots --auto-discover --classify-types --impact-analysis

# Performance impact analysis
python -m logcli perf --auto-discover --response-time-analysis --cache-analysis
```

### **Varnish + PHP-FPM Analysis**
```bash
# Compare cache performance
python -m logcli perf --auto-discover --cache-analysis --handler varnish
python -m logcli perf --auto-discover --cache-analysis --handler phpfpm

# Interactive monitoring
./opencli  # Use F4 for Performance view
```

## 🤝 Contributing

Contributions are welcome! Open an issue or pull request.

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Credits

Based on requirements from `idea.md` and optimized for Hypernode/Nginx environments.
