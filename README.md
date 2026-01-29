# Hypernode Log Analyzer

Krachtige command-line tool voor het analyseren van Hypernode access logs. Geschreven in Go voor optimale performance.

## Features

- **Snel**: 100x sneller dan de Python versie
- **Single Binary**: Geen dependencies nodig
- **Cross-Platform**: Linux, macOS, en Windows
- **Complete Analyse**: Security, performance, bots, e-commerce, API's en meer

## Installatie

### Optie 1: Pre-built Binary (Aanbevolen)

Download de nieuwste release voor jouw platform:

**Linux:**
```bash
wget https://github.com/hpowernl/access-logs-analyser/releases/latest/download/hlogcli-linux-amd64
chmod +x hlogcli-linux-amd64
sudo mv hlogcli-linux-amd64 /usr/local/bin/hlogcli
```

**macOS:**
```bash
# Intel Mac
wget https://github.com/hpowernl/access-logs-analyser/releases/latest/download/hlogcli-darwin-amd64
chmod +x hlogcli-darwin-amd64
sudo mv hlogcli-darwin-amd64 /usr/local/bin/hlogcli

# Apple Silicon (M1/M2/M3)
wget https://github.com/hpowernl/access-logs-analyser/releases/latest/download/hlogcli-darwin-arm64
chmod +x hlogcli-darwin-arm64
sudo mv hlogcli-darwin-arm64 /usr/local/bin/hlogcli
```

### Optie 2: Vanaf Source Builden

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

## Beschikbare Commands

| Command | Beschrijving |
|---------|--------------|
| `analyze` | Algemene log analyse met verkeer statistieken |
| `security` | Security threats: SQL injection, XSS, brute force |
| `nginx` | Genereer Nginx deny rules voor verdachte IP's |
| `perf` | Performance analyse en optimalisatie tips |
| `ecommerce` | E-commerce analyse (Magento, WooCommerce, Shopware) |
| `bots` | Bot classificatie en AI/LLM bot detectie |
| `api` | API endpoint analyse en GraphQL tracking |
| `content` | Content analyse met SEO issue detectie |
| `anomalies` | Anomalie detectie met statistiek |

## Belangrijke Flags

| Flag | Beschrijving |
|------|--------------|
| `--days-ago <n>` | Analyseer logs van N dagen geleden |
| `--yesterday` | Analyseer gisteren's logs |
| `--file <path>` | Analyseer specifiek log bestand |
| `--export <format>` | Export naar csv, json of text |
| `--output <path>` | Output bestand voor export |
| `--no-color` | Schakel kleuren uit |

## Release Maken

Nieuwe release maken met geautomatiseerde builds voor alle platforms:

```bash
# Maak een nieuwe tag
git tag -a v1.0.0 -m "Release v1.0.0"

# Push de tag naar GitHub
git push origin v1.0.0
```

Dit triggert automatisch:
- ✅ Builds voor Linux (AMD64, ARM64)
- ✅ Builds voor macOS (Intel, Apple Silicon)
- ✅ Builds voor Windows (AMD64)
- ✅ GitHub Release met downloadbare binaries
- ✅ Checksums voor verificatie

De binaries zijn binnen 5 minuten beschikbaar op: `https://github.com/hpowernl/access-logs-analyser/releases`

## Development

```bash
# Testen
make test

# Code formatteren
make fmt

# Linter draaien
make lint

# Build voor alle platforms
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
