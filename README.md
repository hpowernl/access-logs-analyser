# Hypernode Log Analyzer

A **comprehensive command-line log analysis platform** specifically designed for Hypernode environments. This tool provides advanced security analysis, performance optimization, bot detection, and intelligent log insights through powerful CLI commands.

## ✨ Key Features

### 🔧 **Command Line Interface**
- **Hypernode Integration**: Direct integration with `hypernode-parse-nginx-log` command
- **Real-time Analysis**: Live log data retrieval (always fresh, no cache needed)
- **Multiple Analysis Types**: Security, Performance, Bot Analysis, API Analysis, Content Analysis
- **Export Capabilities**: Multiple output formats (JSON, CSV, HTML charts)

### 🔐 **Advanced Security Analysis**
- **Attack Pattern Detection**: SQL injection, XSS, directory traversal
- **Brute Force Detection**: Configurable thresholds and alerts
- **Suspicious IP Tracking**: Threat scoring and blacklist recommendations
- **Real-time Security Alerts**: Live monitoring of security events
- **Comprehensive Analysis**: Detailed security insights

### ⚡ **Performance Optimization**
- **Response Time Analysis**: Percentiles, trends, slowest endpoints
- **Cache Effectiveness**: Varnish/PHP-FPM performance analysis
- **Bandwidth Monitoring**: Usage patterns and optimization tips
- **Performance Recommendations**: Automated suggestions
- **Handler Analysis**: Monitor backend handlers (php-fpm, varnish, etc.)

### 🤖 **Intelligent Bot Management**
- **Advanced Classification**: Search engines, social media, security scanners
- **AI Bot Detection**: Modern AI/LLM bot identification and analysis
- **Behavior Analysis**: Request patterns, intervals, legitimacy scoring
- **Resource Impact**: Bot bandwidth usage and server load
- **Training Data Detection**: Identify potential AI training crawlers

### 🔍 **Advanced Search & Filtering**
- **Flexible Search**: IP, path patterns (regex), user agents, countries
- **Time-based Filtering**: Last N hours, date ranges, specific time periods
- **Export Capabilities**: CSV, JSON, text formats
- **Anomaly Detection**: Machine learning-based unusual pattern detection

### 📊 **Comprehensive Analysis**
- **Multi-format Exports**: HTML dashboards, JSON data, CSV exports
- **Real-time Analysis**: Live monitoring and insights
- **Executive Summaries**: High-level KPIs and trends
- **Technical Deep-dives**: Detailed analysis for technical teams

### 🆕 **Advanced Analytics**
- **E-commerce Analysis**: Platform-specific insights for Magento, WooCommerce, Shopware 6
- **API Analysis**: REST and GraphQL endpoint performance and security
- **Content Analysis**: File types, resource optimization, SEO insights
- **Geographic Analysis**: Country-based traffic distribution and insights
- **Timeline Analysis**: Traffic patterns over time with trend detection
- **Anomaly Detection**: ML-based detection of unusual traffic patterns

### 🛒 **E-commerce Platform Support (Phase 2 Enhanced!)**
- **Magento 2**: Checkout flow, GraphQL query parsing, customer sections, admin API
- **WooCommerce**: AJAX cart, WP-Admin, WordPress REST API
- **Shopware 6**: Store API, headless commerce, admin operations
- **Auto-detection**: Automatically identifies your platform
- **Performance Insights**: Checkout errors, admin slow operations, API bottlenecks
- **Security Analysis**: Login brute force, admin security, API abuse
- **Conversion Funnel**: Full funnel tracking with drop-off analysis
- **GraphQL Analysis**: Operation-level performance tracking (Magento)
- **Smart Recommendations**: Action items with specific implementation steps

## 🚀 Installation

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
./hlogcli
```

## 📖 Usage

### 🔧 Command Line Interface

**Basic analysis:**
```bash
./hlogcli analyze                    # Analyze current day logs
./hlogcli analyze --yesterday        # Analyze yesterday's logs
./hlogcli analyze --summary-only     # Quick overview only
```

**Available Commands:**
- `analyze`: Comprehensive log analysis with traffic insights
- `security`: Security threat detection and analysis
- `perf`: Performance analysis and optimization insights
- `ecommerce`: E-commerce platform analysis (Magento, WooCommerce, Shopware 6)
- `bots`: Bot classification and behavior analysis
- `api`: API endpoint analysis and performance
- `content`: Content type and resource analysis
- `anomalies`: Machine learning-based anomaly detection
- `search`: Advanced search and filtering

### 🔐 Security Analysis

```bash
# Comprehensive security scan
./hlogcli security --scan-attacks --brute-force-detection

# SQL injection detection
./hlogcli security --sql-injection-patterns

# Suspicious user agents
./hlogcli security --suspicious-user-agents

# Export security analysis
./hlogcli security --scan-attacks --output security_analysis.json

# Show security timeline
./hlogcli security --show-timeline --threshold 5
```

### ⚡ Performance Analysis

```bash
# Default performance overview (NEW: now shows output without flags!)
./hlogcli perf

# Complete performance analysis
./hlogcli perf --response-time-analysis --slowest 10

# Cache effectiveness (Varnish)
./hlogcli perf --cache-analysis --handler varnish

# Bandwidth analysis
./hlogcli perf --bandwidth-analysis

# Export performance analysis
./hlogcli perf --response-time-analysis --output perf_analysis.json

# Show performance percentiles
./hlogcli perf --percentiles --handler phpfpm
```

### 🛒 E-commerce Platform Analysis

**NEW: Specialized analysis for Magento 2, WooCommerce, and Shopware 6!**

```bash
# Auto-detect platform and show overview
./hlogcli ecommerce

# Force specific platform analysis
./hlogcli ecommerce --platform magento
./hlogcli ecommerce --platform woocommerce
./hlogcli ecommerce --platform shopware6

# Detailed analysis sections
./hlogcli ecommerce --checkout-analysis      # Checkout flow performance
./hlogcli ecommerce --admin-analysis         # Admin panel performance
./hlogcli ecommerce --api-analysis           # REST/GraphQL API performance
./hlogcli ecommerce --login-security         # Login security & brute force
./hlogcli ecommerce --media-analysis         # Image/media optimization

# Show all sections
./hlogcli ecommerce --detailed

# Export e-commerce report
./hlogcli ecommerce -o ecommerce_report.json
```

**What it analyzes:**
- 🛍️ **Checkout Performance**: Response times, errors, conversion blockers
- 💼 **Admin Panel**: Backend performance, slow operations
- 🔌 **API Calls**: REST API & GraphQL endpoint performance
- 🔐 **Login Security**: Brute force detection, failed login patterns
- 🖼️ **Media Delivery**: Image sizes, bandwidth usage, optimization opportunities
- 📦 **Product Pages**: Category and product page performance
- 🔍 **Search**: Search functionality performance
- 🎯 **Conversion Funnel**: Track user journey from homepage to checkout
- ⚠️ **Checkout Errors**: Detailed error pattern analysis

**Advanced Features (Phase 2):**
- 🔷 **GraphQL Query Analysis**: Operation tracking, performance per query type (Magento)
- 🎯 **Conversion Funnel Tracking**: Homepage → Category → Product → Cart → Checkout
- 📊 **Cart Abandonment Rate**: Track and analyze abandoned carts
- 🚨 **Critical Issue Detection**: Automatic detection of payment/cart system errors
- 📈 **Enhanced Recommendations**: Action items with specific steps to take
- ⏰ **Time-based Analysis**: Performance trends per category by hour

**Platform-specific features:**
- **Magento 2**: GraphQL operation parsing, query performance, customer sections, Varnish cache
- **WooCommerce**: WP-Admin performance, AJAX cart operations, WordPress REST API
- **Shopware 6**: Store API analysis, headless commerce metrics, admin API

### 🤖 Bot Analysis

```bash
# Bot classification and behavior
./hlogcli bots --classify-types --behavior-analysis

# AI bot analysis
./hlogcli bots --ai-bots-only --llm-bot-analysis

# Legitimacy scoring
./hlogcli bots --legitimate-vs-malicious

# Resource impact analysis
./hlogcli bots --impact-analysis

# AI training detection
./hlogcli bots --ai-training-detection --ai-impact-analysis

# Export bot analysis
./hlogcli bots --classify-types --output bot_analysis.json
```

### 🔌 API Analysis

```bash
# API endpoint analysis
./hlogcli api --endpoint-analysis --top-endpoints 20

# GraphQL analysis
./hlogcli api --graphql-analysis --security-analysis

# API performance analysis
./hlogcli api --performance-analysis --min-requests 5

# Export API analysis
./hlogcli api --endpoint-analysis --output api_analysis.json
```

### 📁 Content Analysis

```bash
# Content type analysis
./hlogcli content --content-type-analysis --file-extension-analysis

# Optimization analysis
./hlogcli content --optimization-analysis --performance-analysis

# SEO analysis
./hlogcli content --seo-analysis --top-content 15

# Export content analysis
./hlogcli content --content-type-analysis --output content_analysis.json
```

### 🤖 Anomaly Detection

```bash
# Statistical anomaly detection
./hlogcli anomalies --statistical-analysis --sensitivity 2.0

# Behavioral analysis
./hlogcli anomalies --behavioral-analysis --show-timeline

# Real-time alerts
./hlogcli anomalies --realtime-alerts --recent-hours 2

# Export anomaly analysis
./hlogcli anomalies --statistical-analysis --output anomalies_analysis.json
```

### 🔍 Advanced Search

```bash
# Search by IP address
./hlogcli search --ip 192.168.1.100

# Search with regex patterns
./hlogcli search --path "/admin.*" --status 403

# Time-based search
./hlogcli search --last-hours 24 --status 404,500

# Complex search with export
./hlogcli search --country US,GB --status 404 --limit 100 --output results.csv

# User agent search
./hlogcli search --user-agent ".*bot.*" --limit 50
```


## 🎯 Nginx Log Format

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
./hlogcli security --scan-attacks --output daily_security.json

# Performance health check
./hlogcli perf --response-time-analysis --slowest 20

# Quick overview
./hlogcli analyze --summary-only
```

### 🔧 **For DevOps Engineers**  
```bash
# Incident investigation
./hlogcli search --ip 192.168.1.100 --last-hours 48

# Cache optimization
./hlogcli perf --cache-analysis --handler varnish --handler phpfpm

# Bot traffic analysis
./hlogcli bots --impact-analysis --classify-types

# Anomaly detection
./hlogcli anomalies --statistical-analysis --behavioral-analysis
```

### 📊 **For Business Analysts**
```bash
# Weekly traffic analysis
./hlogcli analyze --export-charts --output ./reports/

# Geographic analysis
./hlogcli search --country US,GB,DE,FR --output geo_analysis.csv

# Content performance
./hlogcli content --performance-analysis --optimization-analysis
```

### 🚨 **For Security Teams**
```bash
# Security monitoring
./hlogcli security --scan-attacks --brute-force-detection

# Threat hunting
./hlogcli security --sql-injection-patterns --brute-force-detection

# IP reputation analysis  
./hlogcli search --status 403,404,500 --limit 500 --output suspicious_activity.csv

# Real-time anomaly alerts
./hlogcli anomalies --realtime-alerts --recent-hours 1
```

### 🔌 **For API Teams**
```bash
# API endpoint performance
./hlogcli api --endpoint-analysis --performance-analysis

# GraphQL security analysis
./hlogcli api --graphql-analysis --security-analysis

# API bot traffic
./hlogcli bots --ai-bots-only --api-endpoints-only
```

## 📈 Export Formats & Analysis

### **CSV Exports**
- **Security Analysis**: Attack patterns, suspicious IPs, threat analysis
- **Performance Data**: Response times, slowest endpoints, cache stats
- **Bot Analysis**: Classification, behavior patterns, resource usage
- **Search Results**: Filtered log entries with all fields

### **JSON Exports**
- **Complete Data**: All statistics, counters, and analysis
- **API-Ready**: Structured data for integration
- **Historical Data**: Timeline and trend information
- **Detailed Analysis**: In-depth analysis with metadata

### **HTML Analysis**
- **Interactive Dashboards**: Charts, graphs, and visualizations  
- **Executive Summaries**: High-level KPIs and trends
- **Technical Deep-dives**: Detailed analysis for technical teams
- **Mobile-Friendly**: Responsive design for all devices

### **Text Analysis**
- **Console Output**: Human-readable summaries
- **Email-Ready**: Plain text for automated reporting
- **Log-Friendly**: Structured for log aggregation systems

## 🏗️ Architecture & Components

### **CLI Commands**
- `./hlogcli analyze`     # Basic traffic analysis
- `./hlogcli security`    # Security threat analysis
- `./hlogcli perf`        # Performance analysis (now with default overview!)
- `./hlogcli ecommerce`   # E-commerce platform analysis (NEW!)
- `./hlogcli bots`        # Bot classification and analysis
- `./hlogcli api`         # API endpoint analysis
- `./hlogcli content`     # Content and resource analysis
- `./hlogcli anomalies`   # Machine learning anomaly detection
- `./hlogcli search`      # Advanced search and filtering

### **Core Modules**
```
logcli/
├── main.py                  # CLI command router and main entry point
├── hypernode_command.py     # Hypernode command integration
├── security.py             # Security analysis engine
├── performance.py          # Performance analysis engine  
├── ecommerce.py            # E-commerce platform analysis (NEW!)
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

## ⚙️ Configuration & Customization

### **Configuration Profiles**
```bash
# Configuration commands have been removed
```

### **Customizable Settings**
- **Alert Thresholds**: Security and performance alerts
- **Bot Signatures**: Custom bot detection patterns
- **Export Formats**: Default output formats
- **Analysis Parameters**: Sensitivity, window sizes, thresholds
- **Time Ranges**: Default analysis periods

## 🚀 Performance & Scalability

### **Optimized for Hypernode**
- **Direct Integration**: Uses hypernode-parse-nginx-log command
- **Real-time Processing**: Always fresh data, no caching needed
- **Memory Efficient**: Streaming processing for large datasets
- **Handler Detection**: Varnish vs PHP-FPM analysis
- **Country Integration**: Built-in GeoIP support

### **Advanced Features**
- **Machine Learning**: Anomaly detection with statistical analysis
- **AI Bot Detection**: Modern AI/LLM bot identification
- **Performance Insights**: Cache effectiveness and optimization tips
- **Security Intelligence**: Advanced threat pattern recognition

## 🐛 Troubleshooting & FAQ

### **Installation Issues**
```bash
# Python version check
python3 --version  # Requires 3.8+

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
./hlogcli --help
```

### **Hypernode Integration**
```bash
# Check hypernode command availability
hypernode-parse-nginx-log --help

# Test with yesterday's logs
./hlogcli analyze --yesterday

# Log directory detection is now automatic
```

### **Performance Issues**
```bash
# Limit analysis scope
./hlogcli analyze --last-hours 24

# Use summary mode
./hlogcli analyze --summary-only

# Filter data
./hlogcli analyze --exclude-bots --status 200,404
```

## 🎯 Hypernode-Specific Features

### **Perfect for Production Environments**
```bash
# Analyze current traffic
./hlogcli analyze

# Security monitoring
./hlogcli security --scan-attacks --brute-force-detection

# Performance optimization
./hlogcli perf --cache-analysis --response-time-analysis

# Bot management
./hlogcli bots --ai-bots-only --impact-analysis
```

### **Varnish + PHP-FPM Analysis**
```bash
# Compare cache performance
./hlogcli perf --cache-analysis --handler varnish
./hlogcli perf --cache-analysis --handler phpfpm

# Handler-specific analysis
./hlogcli analyze --handler varnish --export-csv
```

### **AI Bot Detection**
```bash
# Modern AI bot analysis
./hlogcli bots --ai-bots-only --llm-bot-analysis

# Training data detection
./hlogcli bots --ai-training-detection --ai-impact-analysis

# Resource impact of AI bots
./hlogcli bots --ai-impact-analysis --behavior-analysis
```

## 🤝 Contributing

Contributions are welcome! Open an issue or pull request.

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Credits

Designed specifically for Hypernode environments with direct integration to hypernode-parse-nginx-log command.