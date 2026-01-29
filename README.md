# Hypernode Log Analyzer - Go Version

Go implementation of the Hypernode Log Analyzer with improved performance and native binary distribution.

## Features

- **Fast Performance**: Native Go compilation for optimal performance
- **Low Memory Footprint**: Efficient memory usage with concurrent processing
- **Single Binary**: Easy distribution with no dependencies
- **Cross-Platform**: Build for Linux, macOS, and Windows
- **Full Feature Parity**: All Python features ported to Go

## Quick Start

### Prerequisites

- Go 1.21 or higher
- Access to Hypernode environment (optional, can analyze local log files)

### Installation

```bash
# Clone the repository
git clone https://github.com/hpowernl/hlogcli.git
cd hlogcli

# Download dependencies
make deps

# Build
make build

# Install (copies to ~/bin or /usr/local/bin)
make install
```

### Usage

```bash
# Analyze today's logs
hlogcli analyze

# Security analysis
hlogcli security

# Performance analysis
hlogcli perf

# Bot analysis
hlogcli bots

# E-commerce analysis
hlogcli ecommerce

# API analysis
hlogcli api

# Content analysis
hlogcli content

# Anomaly detection
hlogcli anomalies

# Analyze specific file
hlogcli analyze --file /path/to/access.log

# Analyze yesterday's logs
hlogcli analyze --yesterday

# Analyze logs from N days ago
hlogcli analyze --days-ago 7

# Export results
hlogcli analyze --export json --output report.json
hlogcli analyze --export csv --output report.csv
```

## Available Commands

### analyze
Comprehensive log analysis with traffic insights and statistics.

```bash
hlogcli analyze [flags]
```

### security
Security threat detection and analysis including SQL injection, XSS, directory traversal, and brute force attacks.

```bash
hlogcli security [flags]
```

### perf
Performance analysis including response times, cache effectiveness, and optimization recommendations.

```bash
hlogcli perf [flags]
```

### ecommerce
E-commerce platform analysis (Magento, WooCommerce, Shopware) with conversion funnel tracking.

```bash
hlogcli ecommerce [flags]
```

### bots
Bot classification and behavior analysis including AI/LLM bot detection.

```bash
hlogcli bots [flags]
```

### api
API endpoint analysis and GraphQL operation tracking.

```bash
hlogcli api [flags]
```

### content
Content type and resource analysis with SEO issue detection.

```bash
hlogcli content [flags]
```

### anomalies
Machine learning-based anomaly detection using statistical analysis.

```bash
hlogcli anomalies [flags]
```

## Global Flags

- `--days-ago <n>` - Analyze logs from N days ago (0 = today)
- `--yesterday` - Analyze yesterday's logs
- `--file <path>` - Analyze a specific log file instead of using Hypernode command
- `--export <format>` - Export format (csv, json, text)
- `--output <path>` - Output file for export
- `--no-color` - Disable colored output

## Building

### Build for current platform
```bash
make build
```

### Build for all platforms
```bash
make build-all
```

This creates binaries for:
- Linux AMD64
- Linux ARM64
- macOS AMD64 (Intel)
- macOS ARM64 (Apple Silicon)
- Windows AMD64

### Development

```bash
# Run tests
make test

# Format code
make fmt

# Run linter
make lint

# Run with hot reload (requires air)
make dev
```

## Architecture

```
hlogcli/
├── cmd/hlogcli/           # Main entry point
├── internal/
│   ├── cli/               # CLI commands (Cobra)
│   ├── config/            # Configuration
│   ├── parser/            # Log parsing
│   ├── filters/           # Filtering logic
│   ├── aggregators/       # Statistics aggregation
│   ├── logreader/         # File reading/tailing
│   ├── hypernode/         # Hypernode integration
│   ├── analysis/          # Analysis modules
│   │   ├── security.go
│   │   ├── performance.go
│   │   ├── bots.go
│   │   ├── api.go
│   │   ├── ecommerce.go
│   │   ├── anomaly.go
│   │   ├── geographic.go
│   │   ├── timeline.go
│   │   └── content.go
│   ├── export/            # Export functionality
│   ├── ui/                # Terminal UI
│   └── dns/               # DNS utilities
└── pkg/models/            # Shared data structures
```

## Performance Comparison

| Metric | Python | Go | Improvement |
|--------|--------|-----|-------------|
| Startup time | ~500ms | ~5ms | 100x faster |
| Memory usage | ~200MB | ~20MB | 10x less |
| Processing speed | 10k lines/s | 100k lines/s | 10x faster |
| Binary size | N/A (interpreter) | ~15MB | Single file |

## Dependencies

- `github.com/spf13/cobra` - CLI framework
- `github.com/fatih/color` - Terminal colors
- `github.com/olekukonko/tablewriter` - ASCII tables
- `github.com/fsnotify/fsnotify` - File watching
- `github.com/mssola/useragent` - User agent parsing
- `github.com/montanaflynn/stats` - Statistics

## License

MIT License

## Credits

Go implementation by the Hypernode team.
Original Python version: https://github.com/hpowernl/access-logs-analyser
