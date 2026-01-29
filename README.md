# Hypernode Log Analyzer

Command-line tool for analyzing Hypernode access logs. Written in Go for optimal performance. Intended for the Hypernode platform (Linux x86_64).

## Features

- Fast: significantly faster than the Python version
- Single binary: no runtime dependencies
- Full analysis: security, performance, bots, e-commerce, APIs and more

## Installation

### Pre-built binary (recommended)

Linux x86_64 (AMD64): `hlogcli`

```bash
wget https://github.com/hpowernl/access-logs-analyser/releases/latest/download/hlogcli
chmod +x hlogcli
./hlogcli --help
```

### Build from source

```bash
git clone https://github.com/hpowernl/access-logs-analyser.git
cd access-logs-analyser
make build
sudo make install
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

# Generate Nginx block configurations (interactive)
hlogcli nginx

# Generate Nginx config with specific option
hlogcli nginx --option critical    # Critical threats only (score >= 70)
hlogcli nginx --option all         # All suspicious IPs
hlogcli nginx --option error100    # 100% error rate only

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

## Available commands

| Command | Description |
|---------|-------------|
| `analyze` | General log analysis with traffic statistics |
| `security` | Security threats: SQL injection, XSS, brute force |
| `nginx` | Generate Nginx deny rules for suspicious IPs |
| `perf` | Performance analysis and optimization tips |
| `ecommerce` | E-commerce analysis (Magento, WooCommerce, Shopware) |
| `bots` | Bot classification and AI/LLM bot detection |
| `api` | API endpoint analysis and GraphQL tracking |
| `content` | Content analysis with SEO issue detection |
| `anomalies` | Anomaly detection with statistics |

## Important flags

| Flag | Description |
|------|-------------|
| `--days-ago <n>` | Analyze logs from N days ago |
| `--yesterday` | Analyze yesterday's logs |
| `--file <path>` | Analyze specific log file |
| `--export <format>` | Export to csv, json or text |
| `--output <path>` | Output file for export |
| `--no-color` | Disable colors |

## Creating a release

New release with automated build (Linux AMD64):

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

This triggers a build for Linux x86_64 (AMD64) and a GitHub Release with the binary and checksums. Available within a few minutes at: https://github.com/hpowernl/access-logs-analyser/releases

## Development

```bash
# Run tests
make test

# Format code
make fmt

# Run linter
make lint

# Build Linux AMD64 binary
make build-all
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

## Performance comparison

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

