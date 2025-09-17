# NextGen Access Log Analyzer - Gebruiksvoorbeelden

## 🚀 Quick Start

### Basis Analyse
```bash
# Activeer de virtual environment
source venv/bin/activate

# Analyseer een specifiek log bestand
python3 -m logcli /var/log/nginx/access.log

# Analyseer sample data (voor testen)
python3 -m logcli sample_access.log
```

### Auto-Discovery
```bash
# Vind automatisch alle access logs in nginx directory
python3 -m logcli --auto-discover

# Specificeer een andere nginx directory
python3 -m logcli --auto-discover --nginx-dir /custom/nginx/logs
```

## 📊 Filtering Voorbeelden

### Land Filters
```bash
# Alleen traffic uit Nederland en België
python3 -m logcli --countries NL,BE sample_access.log

# Alleen US traffic
python3 -m logcli --countries US sample_access.log --summary-only
```

### Status Code Filters
```bash
# Alleen errors (4xx en 5xx)
python3 -m logcli --filter-preset errors_only sample_access.log

# Alleen 404 en 500 errors
python3 -m logcli --status-codes 404,500 sample_access.log

# Alleen succesvolle requests
python3 -m logcli --filter-preset success_only sample_access.log
```

### Bot Filtering
```bash
# Exclude alle bots
python3 -m logcli --exclude-bots sample_access.log

# Alleen bot traffic (gebruik geen --exclude-bots)
python3 -m logcli sample_access.log
```

### Combinatie Filters
```bash
# Nederlandse traffic, geen bots, alleen errors
python3 -m logcli --countries NL --exclude-bots --filter-preset errors_only sample_access.log

# API endpoints alleen, geen bots
python3 -m logcli --filter-preset api_only --exclude-bots sample_access.log
```

## 📈 Export Voorbeelden

### CSV Export
```bash
# Export naar CSV
python3 -m logcli --export-csv sample_access.log

# Export naar custom directory
python3 -m logcli --export-csv --output ./my_exports sample_access.log
```

### JSON Export
```bash
# Export naar JSON (gestructureerde data)
python3 -m logcli --export-json sample_access.log

# Export alle formaten
python3 -m logcli --export-csv --export-json --export-charts sample_access.log
```

### Gefilterde Export
```bash
# Export alleen Nederlandse traffic zonder bots
python3 -m logcli --countries NL --exclude-bots --export-csv sample_access.log

# Export alleen errors naar JSON
python3 -m logcli --filter-preset errors_only --export-json sample_access.log
```

## 🔄 Realtime Monitoring

### Console Monitoring
```bash
# Follow logs in realtime (console output)
python3 -m logcli -f /var/log/nginx/access.log

# Realtime met filters
python3 -m logcli -f --exclude-bots --countries NL /var/log/nginx/access.log
```

### Interactieve TUI
```bash
# Launch interactieve interface
python3 -m logcli -i sample_access.log

# Realtime interactieve interface
python3 -m logcli -f -i /var/log/nginx/access.log

# TUI met auto-discovery
python3 -m logcli -f -i --auto-discover
```

## 🎯 Productie Voorbeelden

### Hypernode Server Analysis
```bash
# Analyseer alle Hypernode access logs
sudo python3 -m logcli --auto-discover --nginx-dir /var/log/nginx

# Realtime monitoring van Hypernode logs
sudo python3 -m logcli -f -i --auto-discover --nginx-dir /var/log/nginx

# Export dagelijkse rapportage
sudo python3 -m logcli --auto-discover --export-csv --export-json --output /home/app/reports --nginx-dir /var/log/nginx
```

### Performance Monitoring
```bash
# Monitor alleen langzame requests (gebruik filter in TUI)
python3 -m logcli -f -i /var/log/nginx/access.log

# Export voor performance analyse
python3 -m logcli --export-json --output ./performance_reports /var/log/nginx/access.log
```

### Security Monitoring
```bash
# Monitor alleen errors voor security analyse
python3 -m logcli -f --filter-preset errors_only /var/log/nginx/access.log

# Export security events
python3 -m logcli --filter-preset errors_only --export-csv --output ./security_reports /var/log/nginx/access.log
```

### Bot Analysis
```bash
# Analyseer alleen bot traffic
python3 -m logcli sample_access.log  # Bots zijn standaard included

# Vergelijk bot vs human traffic
python3 -m logcli sample_access.log > all_traffic.txt
python3 -m logcli --exclude-bots sample_access.log > human_traffic.txt
```

## 🔧 Geavanceerde Gebruik

### Meerdere Log Bestanden
```bash
# Analyseer meerdere bestanden tegelijk
python3 -m logcli /var/log/nginx/access.log /var/log/nginx/access.log.1

# Inclusief gzip bestanden
python3 -m logcli /var/log/nginx/access.log /var/log/nginx/access.log.1.gz /var/log/nginx/access.log.2.gz

# Alle access logs in directory
python3 -m logcli /var/log/nginx/access.log*
```

### Custom Output
```bash
# Alleen summary voor scripts
python3 -m logcli --summary-only sample_access.log

# Export voor externe tools
python3 -m logcli --export-json --summary-only sample_access.log
```

### Scheduled Reports
```bash
# Cron job voor dagelijkse rapportage
0 6 * * * cd /path/to/logcli && source venv/bin/activate && python3 -m logcli --auto-discover --export-csv --export-json --output /var/reports --nginx-dir /var/log/nginx

# Weekly comprehensive report
0 6 * * 0 cd /path/to/logcli && source venv/bin/activate && python3 -m logcli --auto-discover --export-csv --export-json --export-charts --output /var/reports/weekly --nginx-dir /var/log/nginx
```

## 💡 Tips & Tricks

### Performance Tips
- Gebruik `--summary-only` voor snelle checks
- Filter data vroeg in de pipeline voor betere performance
- Voor grote bestanden, gebruik specifieke filters
- Gzip bestanden worden automatisch ondersteund

### Monitoring Tips
- Gebruik `-f -i` voor beste realtime ervaring
- Combineer filters voor specifieke monitoring
- Export regelmatig voor historische analyse
- Gebruik presets voor veelgebruikte filters

### Troubleshooting
```bash
# Test met sample data eerst
python3 -m logcli sample_access.log --summary-only

# Check of JSON format correct is
head -1 /var/log/nginx/access.log | python3 -m json.tool

# Verbose output voor debugging
python3 -m logcli --help
```

## 📋 Cheat Sheet

| Commando | Beschrijving |
|----------|-------------|
| `python3 -m logcli file.log` | Basis analyse |
| `--auto-discover` | Auto-find nginx logs |
| `-f` | Follow/tail logs |
| `-i` | Interactive TUI |
| `--exclude-bots` | Filter out bots |
| `--countries NL,BE` | Filter by countries |
| `--filter-preset errors_only` | Quick error filter |
| `--export-csv` | Export to CSV |
| `--summary-only` | Quick summary |
| `-f -i` | Realtime TUI |

## 🎛️ TUI Controls

In de interactieve modus:
- **q**: Quit
- **f**: Filters tab
- **e**: Export data
- **r**: Refresh
- **t**: Timeline view
- **Tab**: Switch between tabs
- **Enter**: Activate buttons
