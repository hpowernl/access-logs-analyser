package parser

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hpowernl/hlogcli/internal/config"
	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/mssola/useragent"
)

// LogParser handles parsing and normalization of log entries
type LogParser struct {
	botSignatures map[string]bool
}

// NewLogParser creates a new log parser instance
func NewLogParser() *LogParser {
	return &LogParser{
		botSignatures: config.BotSignatures,
	}
}

// ParseLine parses a single JSON log line and returns a normalized log entry
func (p *LogParser) ParseLine(line string) (*models.LogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return p.NormalizeLog(raw), nil
}

// NormalizeLog normalizes a raw log entry to a standard format
func (p *LogParser) NormalizeLog(raw map[string]interface{}) *models.LogEntry {
	entry := &models.LogEntry{
		Raw: raw,
	}

	// Parse timestamp
	if timeStr, ok := raw["time"].(string); ok {
		entry.Timestamp = p.parseTimestamp(timeStr)
	} else {
		entry.Timestamp = time.Now()
	}

	// Parse IP address
	if ipStr, ok := raw["remote_addr"].(string); ok {
		entry.IP = p.parseIP(ipStr)
	}

	// Parse user agent
	if ua, ok := raw["user_agent"].(string); ok {
		entry.UserAgent = ua
		entry.ParsedUA = p.parseUserAgent(ua)
		entry.IsBot = p.isBot(ua)
	}

	// Parse HTTP request
	if requestStr, ok := raw["request"].(string); ok {
		method, path := p.parseRequestString(requestStr)
		entry.Method = method
		entry.Path = path
	}

	// Parse status code
	if status, ok := raw["status"].(string); ok {
		fmt.Sscanf(status, "%d", &entry.Status)
	} else if statusFloat, ok := raw["status"].(float64); ok {
		entry.Status = int(statusFloat)
	}

	// Parse referer
	if referer, ok := raw["referer"].(string); ok {
		entry.Referer = referer
	}

	// Parse response time
	if reqTime, ok := raw["request_time"].(string); ok {
		fmt.Sscanf(reqTime, "%f", &entry.ResponseTime)
	} else if reqTimeFloat, ok := raw["request_time"].(float64); ok {
		entry.ResponseTime = reqTimeFloat
	}

	// Parse bytes sent
	if bytes, ok := raw["body_bytes_sent"].(string); ok {
		fmt.Sscanf(bytes, "%d", &entry.BytesSent)
	} else if bytesFloat, ok := raw["body_bytes_sent"].(float64); ok {
		entry.BytesSent = int64(bytesFloat)
	}

	// Parse country
	if country, ok := raw["country"].(string); ok {
		entry.Country = country
	}

	// Parse additional Nginx fields
	if host, ok := raw["host"].(string); ok {
		entry.Host = host
	}
	if serverName, ok := raw["server_name"].(string); ok {
		entry.ServerName = serverName
	}
	if handler, ok := raw["handler"].(string); ok {
		entry.Handler = handler
	}
	if port, ok := raw["port"].(string); ok {
		entry.Port = port
	}
	if sslProto, ok := raw["ssl_protocol"].(string); ok {
		entry.SSLProtocol = sslProto
	}
	if sslCipher, ok := raw["ssl_cipher"].(string); ok {
		entry.SSLCipher = sslCipher
	}
	if remoteUser, ok := raw["remote_user"].(string); ok {
		entry.RemoteUser = remoteUser
	}

	return entry
}

// parseRequestString parses HTTP request string like "POST /graphql HTTP/1.1"
func (p *LogParser) parseRequestString(requestStr string) (method, path string) {
	if requestStr == "" {
		return "GET", "/"
	}

	parts := strings.Split(requestStr, " ")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}

	return "GET", "/"
}

// parseTimestamp parses timestamp from various formats
func (p *LogParser) parseTimestamp(timeStr string) time.Time {
	if timeStr == "" {
		return time.Now()
	}

	// Common timestamp formats
	formats := []string{
		time.RFC3339,                       // "2006-01-02T15:04:05Z07:00"
		"2006-01-02T15:04:05.999999Z",      // ISO with microseconds
		"2006-01-02T15:04:05Z",             // ISO format
		"2006-01-02 15:04:05",              // Standard format
		"02/Jan/2006:15:04:05 -0700",       // Apache/Nginx format
		"2006-01-02T15:04:05-07:00",        // ISO with timezone
		"2006-01-02T15:04:05.999999-07:00", // ISO with microseconds and timezone
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t
		}
	}

	// Try parsing as Unix timestamp
	var timestamp float64
	if _, err := fmt.Sscanf(timeStr, "%f", &timestamp); err == nil {
		return time.Unix(int64(timestamp), 0)
	}

	return time.Now()
}

// parseIP parses IP address from string
func (p *LogParser) parseIP(ipStr string) net.IP {
	if ipStr == "" || ipStr == "-" {
		return nil
	}

	// Handle X-Forwarded-For format (take first IP)
	if strings.Contains(ipStr, ",") {
		ipStr = strings.Split(ipStr, ",")[0]
		ipStr = strings.TrimSpace(ipStr)
	}

	ip := net.ParseIP(ipStr)
	return ip
}

// parseUserAgent parses user agent string
func (p *LogParser) parseUserAgent(uaStr string) *models.UserAgentInfo {
	if uaStr == "" || uaStr == "-" {
		return &models.UserAgentInfo{
			Browser: "Unknown",
			OS:      "Unknown",
			Device:  "Unknown",
		}
	}

	ua := useragent.New(uaStr)

	browser, version := ua.Browser()
	browserStr := browser
	if version != "" {
		browserStr = fmt.Sprintf("%s %s", browser, version)
	}

	osInfo := ua.OS()
	device := "Desktop"
	if ua.Mobile() {
		device = "Mobile"
	} else if ua.Bot() {
		device = "Bot"
	}

	return &models.UserAgentInfo{
		Browser: browserStr,
		OS:      osInfo,
		Device:  device,
	}
}

// isBot detects if user agent is a bot
func (p *LogParser) isBot(uaStr string) bool {
	if uaStr == "" {
		return false
	}

	uaLower := strings.ToLower(uaStr)
	for signature := range p.botSignatures {
		if strings.Contains(uaLower, signature) {
			return true
		}
	}

	return false
}

// GetStatusCategory categorizes HTTP status code
func (p *LogParser) GetStatusCategory(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "success"
	case status >= 300 && status < 400:
		return "redirect"
	case status >= 400 && status < 500:
		return "client_error"
	case status >= 500 && status < 600:
		return "server_error"
	default:
		return "other"
	}
}

// IsErrorStatus checks if a status code is an error
func (p *LogParser) IsErrorStatus(status int) bool {
	return status >= 400
}

// IsSuccessStatus checks if a status code is successful
func (p *LogParser) IsSuccessStatus(status int) bool {
	return status >= 200 && status < 300
}
