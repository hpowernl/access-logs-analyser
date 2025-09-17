# NextGen Access Log Analyzer

Een geavanceerde, realtime CLI-tool voor het analyseren van Nginx JSON access logs. Deze tool biedt uitgebreidere functionaliteit dan GoAccess met interactieve filtering, realtime monitoring, en uitgebreide export mogelijkheden.

## ✨ Features

- **Realtime Log Monitoring**: Live tailing van access logs met automatische updates
- **Interactieve TUI**: Moderne terminal interface gebouwd met Textual
- **Geavanceerde Filtering**: Filter op land, IP-ranges, bots, status codes, paths, en meer
- **Gzip Ondersteuning**: Automatische ondersteuning voor gecomprimeerde log bestanden
- **Multiple Export Formaten**: CSV, JSON, HTML charts, en tekstuele rapporten
- **Bot Detectie**: Intelligente herkenning van verschillende bot types
- **Response Time Analyse**: Gedetailleerde statistieken over response tijden
- **Bandwidth Tracking**: Monitor data usage en transfer statistieken

## 🚀 Installatie

### Vereisten
- Python 3.8 of hoger
- pip

### Installatie Stappen

1. **Clone de repository:**
```bash
git clone <repository-url>
cd Hypernode-logs
```

2. **Maak een virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # Op Windows: venv\\Scripts\\activate
```

3. **Installeer dependencies:**
```bash
pip install -r requirements.txt
```

4. **Installeer de tool (optioneel):**
```bash
pip install -e .
```

## 📖 Gebruik

### Basis Commando's

```bash
# Analyseer een specifiek log bestand
python -m logcli /var/log/nginx/access.log

# Auto-discover alle access logs in nginx directory
python -m logcli --auto-discover

# Realtime monitoring met interactieve UI
python -m logcli -f -i /var/log/nginx/access.log

# Filter op landen en exporteer naar CSV
python -m logcli --countries US,GB,DE --export-csv /var/log/nginx/access.log

# Exclude bots en toon alleen errors
python -m logcli --exclude-bots --filter-preset errors_only /var/log/nginx/access.log
```

### Geavanceerde Opties

```bash
# Alle beschikbare opties
python -m logcli --help

# Gebruik met meerdere bestanden (inclusief gzip)
python -m logcli /var/log/nginx/access.log /var/log/nginx/access.log.1.gz

# Export naar alle formaten
python -m logcli --export-csv --export-json --export-charts --output ./exports /var/log/nginx/access.log

# Realtime console mode (geen TUI)
python -m logcli -f /var/log/nginx/access.log
```

### Interactieve Modus

In de interactieve modus (TUI) zijn de volgende toetsen beschikbaar:

- **`q`**: Quit
- **`f`**: Toggle filters tab
- **`e`**: Export data
- **`r`**: Refresh data
- **`t`**: Toggle timeline view

## 🎯 Nginx Log Formaat

Deze tool is geoptimaliseerd voor Nginx JSON logs met het volgende formaat:

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

### Ondersteunde Velden

- `time` - Timestamp van het request
- `remote_addr` - Client IP adres
- `host` - Host header
- `request` - HTTP request regel (method, path, protocol)
- `status` - HTTP status code
- `body_bytes_sent` - Aantal verzonden bytes
- `user_agent` - User agent string
- `request_time` - Response tijd in seconden
- `country` - Land code (indien beschikbaar)
- `referer` - Referer header
- `server_name` - Server naam
- `handler` - Backend handler (phpfpm, varnish, etc.)

## 📊 Filter Presets

De tool biedt verschillende voorgedefinieerde filters:

- **`errors_only`**: Toon alleen 4xx en 5xx responses
- **`success_only`**: Toon alleen 2xx responses  
- **`no_bots`**: Exclude alle bot traffic
- **`api_only`**: Toon alleen API endpoints (/api/*)
- **`recent_activity`**: Toon alleen recente activiteit

## 📈 Export Formaten

### CSV Export
Gedetailleerde tabellen met:
- Top countries, IPs, paths, status codes
- Timeline data
- Error details
- Response time statistieken

### JSON Export
Volledige gestructureerde data export met:
- Alle statistieken en counters
- Timeline data
- Slow requests lijst
- Bot traffic analyse

### HTML Charts
Interactieve charts met:
- Country distribution
- Status code breakdown
- Browser statistics
- Timeline visualisaties

### Text Reports
Menselijk leesbare samenvattingen met:
- Overview statistieken
- Top entries per categorie
- Response time analyse

## 🔧 Configuratie

Pas `logcli/config.py` aan voor:

- Bot signature lists
- Alert thresholds
- Timeline granulariteit
- Export instellingen
- Default filters

## 📁 Project Structuur

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

### Veelvoorkomende Problemen

1. **Permission denied bij /var/log/nginx**
   ```bash
   sudo python -m logcli --auto-discover
   ```

2. **Gzip bestanden worden niet gelezen**
   - Controleer of het bestand een `.gz` extensie heeft
   - Zorg dat het bestand niet corrupt is

3. **Geen data zichtbaar**
   - Controleer log formaat (moet JSON zijn)
   - Controleer of filters te restrictief zijn
   - Gebruik `--summary-only` voor quick check

4. **Performance problemen met grote bestanden**
   - Gebruik filters om data te beperken
   - Overweeg alleen recente logs te analyseren
   - Gebruik `--summary-only` voor snelle overview

## 🤝 Bijdragen

Bijdragen zijn welkom! Open een issue of pull request.

## 📄 Licentie

MIT License - zie LICENSE bestand voor details.

## 🙏 Credits

Gebaseerd op de requirements uit `idea.md` en geoptimaliseerd voor Hypernode/Nginx omgevingen.
