# Hypernode Log Analyzer

A comprehensive command-line log analysis platform specifically designed for Hypernode environments. This tool provides advanced security analysis, performance optimization, bot detection, and intelligent log insights through powerful CLI commands.

## Key Features

### Command Line Interface
- **Hypernode Integration**: Direct integration with `hypernode-parse-nginx-log` command
- **Real-time Analysis**: Live log data retrieval (always fresh, no cache needed)
- **Multiple Analysis Types**: Security, Performance, Bot Analysis, API Analysis, Content Analysis
- **Export Capabilities**: Multiple output formats (JSON, CSV, HTML charts)

### Advanced Security Analysis
- **Attack Pattern Detection**: SQL injection, XSS, directory traversal
- **Brute Force Detection**: Configurable thresholds and alerts
- **Suspicious IP Tracking**: Threat scoring and blacklist recommendations
- **Real-time Security Alerts**: Live monitoring of security events
- **Comprehensive Analysis**: Detailed security insights

### Performance Optimization
- **Response Time Analysis**: Percentiles, trends, slowest endpoints
- **Cache Effectiveness**: Varnish/PHP-FPM performance analysis
- **Bandwidth Monitoring**: Usage patterns and optimization tips
- **Performance Recommendations**: Automated suggestions
- **Handler Analysis**: Monitor backend handlers (php-fpm, varnish, etc.)

### Intelligent Bot Management
- **Advanced Classification**: Search engines, social media, security scanners
- **AI Bot Detection**: Modern AI/LLM bot identification and analysis
- **Behavior Analysis**: Request patterns, intervals, legitimacy scoring
- **Resource Impact**: Bot bandwidth usage and server load
- **Training Data Detection**: Identify potential AI training crawlers

### Advanced Search & Filtering
- **Flexible Search**: IP, path patterns (regex), user agents, countries
- **Time-based Filtering**: Last N hours, date ranges, specific time periods
- **Export Capabilities**: CSV, JSON, text formats
- **Anomaly Detection**: Machine learning-based unusual pattern detection

### Comprehensive Analysis
- **Multi-format Exports**: HTML dashboards, JSON data, CSV exports
- **Real-time Analysis**: Live monitoring and insights
- **Executive Summaries**: High-level KPIs and trends
- **Technical Deep-dives**: Detailed analysis for technical teams

### Advanced Analytics
- **E-commerce Analysis**: Platform-specific insights for Magento, WooCommerce, Shopware 6
- **API Analysis**: REST and GraphQL endpoint performance and security
- **Content Analysis**: File types, resource optimization, SEO insights
- **Geographic Analysis**: Country-based traffic distribution and insights
- **Timeline Analysis**: Traffic patterns over time with trend detection
- **Anomaly Detection**: ML-based detection of unusual traffic patterns

### E-commerce Platform Support
- **Magento 2**: Checkout flow, GraphQL query parsing, customer sections, admin API
- **WooCommerce**: AJAX cart, WP-Admin, WordPress REST API
- **Shopware 6**: Store API, headless commerce, admin operations
- **Auto-detection**: Automatically identifies your platform
- **Performance Insights**: Checkout errors, admin slow operations, API bottlenecks
- **Security Analysis**: Login brute force, admin security, API abuse
- **Conversion Funnel**: Full funnel tracking with drop-off analysis
- **GraphQL Analysis**: Operation-level performance tracking (Magento)
- **Smart Recommendations**: Action items with specific implementation steps

## Installation

### Requirements
- Python 3.8 or higher
- pip3
- Access to Hypernode environment (for hypernode-parse-nginx-log command)

### Quick Install

1. **Clone the repository:**
```bash
git clone https://github.com/hpowernl/access-logs-analyser.git
cd access-logs-analyser
```

2. **Run the installation script:**
```bash
chmod +x install.sh
./install.sh
```

This will:
- Install Python dependencies
- Make hlogcli executable
- Optionally install globally to ~/bin

### Manual Install

If you prefer manual installation:
```bash
# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x hlogcli

# Run locally
hlogcli --help
```

## Usage

### Available Commands
- `analyze`: Comprehensive log analysis with traffic insights
- `security`: Security threat detection and analysis
- `perf`: Performance analysis and optimization insights
- `ecommerce`: E-commerce platform analysis (Magento, WooCommerce, Shopware 6)
- `bots`: Bot classification and behavior analysis
- `api`: API endpoint analysis and performance
- `content`: Content type and resource analysis
- `anomalies`: Machine learning-based anomaly detection
- `search`: Advanced search and filtering

## Nginx Log Format

This tool is optimized for Hypernode's Nginx JSON logs with the following format:

```json
{
  "time": "2024-09-17T08:10:17+00:00",
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
- `body_bytes_sent` - Number of Bytes sent
- `user_agent` - User agent string
- `request_time` - Response time in seconds
- `country` - Country code (if available)
- `referer` - Referer header
- `server_name` - Server name
- `handler` - Backend handler (phpfpm, varnish, etc.)

## Export Formats & Analysis

### CSV Exports
- **Security Analysis**: Attack patterns, suspicious IPs, threat analysis
- **Performance Data**: Response times, slowest endpoints, cache stats
- **Bot Analysis**: Classification, behavior patterns, resource usage
- **Search Results**: Filtered log entries with all fields

### JSON Exports
- **Complete Data**: All statistics, counters, and analysis
- **API-Ready**: Structured data for integration
- **Historical Data**: Timeline and trend information
- **Detailed Analysis**: In-depth analysis with metadata

### HTML Analysis
- **Interactive Dashboards**: Charts, graphs, and visualizations  
- **Executive Summaries**: High-level KPIs and trends
- **Technical Deep-dives**: Detailed analysis for technical teams
- **Mobile-Friendly**: Responsive design for all devices

### Text Analysis
- **Console Output**: Human-readable summaries
- **Email-Ready**: Plain text for automated reporting
- **Log-Friendly**: Structured for log aggregation systems

## Architecture & Components

### CLI Commands
- `hlogcli analyze`     # Basic traffic analysis
- `hlogcli security`    # Security threat analysis
- `hlogcli perf`        # Performance analysis
- `hlogcli ecommerce`   # E-commerce platform analysis
- `hlogcli bots`        # Bot classification and analysis
- `hlogcli api`         # API endpoint analysis
- `hlogcli content`     # Content and resource analysis
- `hlogcli anomalies`   # Machine learning anomaly detection
- `hlogcli search`      # Advanced search and filtering

### Core Modules
```
logcli/
├── main.py                  # CLI command router and main entry point
├── hypernode_command.py     # Hypernode command integration
├── security.py             # Security analysis engine
├── performance.py          # Performance analysis engine  
├── ecommerce.py            # E-commerce platform analysis
├── bots.py                 # Bot classification engine
├── api_analysis.py         # API endpoint analysis
├── content_analysis.py     # Content type analysis
├── anomaly_detection.py    # ML-based anomaly detection
├── search.py               # Advanced search engine
├── geographic.py           # Geographic analysis
├── timeline.py             # Timeline and trend analysis
├── parser.py               # JSON log parsing
├── filters.py              # Filtering logic
├── aggregators.py          # Data aggregation
├── log_reader.py           # File reading & tailing
├── export.py               # Export functionality
├── ui.py                   # Console UI components
├── dns_utils.py            # DNS resolution utilities
└── config.py               # Configuration management
```

## Performance & Scalability

### Optimized for Hypernode
- **Direct Integration**: Uses hypernode-parse-nginx-log command
- **Real-time Processing**: Always fresh data, no caching needed
- **Memory Efficient**: Streaming processing for large datasets
- **Handler Detection**: Varnish vs PHP-FPM analysis
- **Country Integration**: Built-in GeoIP support

### Advanced Features
- **Machine Learning**: Anomaly detection with statistical analysis
- **AI Bot Detection**: Modern AI/LLM bot identification
- **Performance Insights**: Cache effectiveness and optimization tips
- **Security Intelligence**: Advanced threat pattern recognition

## Contributing

Contributions are welcome! Open an issue or pull request.

## License

MIT License - see LICENSE file for details.

## Credits

Designed specifically for Hypernode environments with direct integration to hypernode-parse-nginx-log command.