package hypernode

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/hpowernl/hlogcli/internal/parser"
	"github.com/hpowernl/hlogcli/pkg/models"
)

// HypernodeCommand provides integration with hypernode-parse-nginx-log command
type HypernodeCommand struct {
	available bool
	parser    *parser.LogParser
}

// NewHypernodeCommand creates a new Hypernode command instance
func NewHypernodeCommand() *HypernodeCommand {
	hc := &HypernodeCommand{
		parser: parser.NewLogParser(),
	}
	hc.available = hc.checkAvailability()
	return hc
}

// IsAvailable checks if the hypernode-parse-nginx-log command is available
func (h *HypernodeCommand) IsAvailable() bool {
	return h.available
}

// checkAvailability checks if the command exists
func (h *HypernodeCommand) checkAvailability() bool {
	cmd := exec.Command("which", "hypernode-parse-nginx-log")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// Execute executes the hypernode-parse-nginx-log command
func (h *HypernodeCommand) Execute(ctx context.Context, args []string, daysAgo int) (<-chan string, <-chan error) {
	lineChan := make(chan string, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(lineChan)
		defer close(errorChan)

		cmdArgs := []string{}

		// Add days ago flag
		if daysAgo > 0 {
			cmdArgs = append(cmdArgs, fmt.Sprintf("--days-ago=%d", daysAgo))
		} else {
			// For today's data, explicitly use --today flag
			// hypernode-parse-nginx-log requires --today to get current day's logs
			cmdArgs = append(cmdArgs, "--today")
		}

		// Add additional args
		cmdArgs = append(cmdArgs, args...)

		cmd := exec.CommandContext(ctx, "hypernode-parse-nginx-log", cmdArgs...)

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			errorChan <- fmt.Errorf("failed to create stdout pipe: %w", err)
			return
		}

		if err := cmd.Start(); err != nil {
			errorChan <- fmt.Errorf("failed to start command: %w", err)
			return
		}

		scanner := bufio.NewScanner(stdout)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				return
			default:
				lineChan <- scanner.Text()
			}
		}

		if err := scanner.Err(); err != nil {
			errorChan <- fmt.Errorf("error reading command output: %w", err)
		}

		if err := cmd.Wait(); err != nil {
			if ctx.Err() != context.Canceled {
				errorChan <- fmt.Errorf("command failed: %w", err)
			}
		}
	}()

	return lineChan, errorChan
}

// GetLogEntries retrieves log entries from hypernode-parse-nginx-log
func (h *HypernodeCommand) GetLogEntries(ctx context.Context, args []string, daysAgo int) (<-chan *models.LogEntry, <-chan error) {
	entryChan := make(chan *models.LogEntry, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(entryChan)
		defer close(errorChan)

		lines, errors := h.Execute(ctx, args, daysAgo)

		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-lines:
				if !ok {
					return
				}
				if entry, err := h.parseLine(line); err == nil && entry != nil {
					entryChan <- entry
				}
			case err, ok := <-errors:
				if ok && err != nil {
					errorChan <- err
				}
			}
		}
	}()

	return entryChan, errorChan
}

// parseLine parses a line from hypernode-parse-nginx-log output
// The command outputs TSV or JSON depending on flags
func (h *HypernodeCommand) parseLine(line string) (*models.LogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}

	// Try to parse as JSON first (default output format)
	if strings.HasPrefix(line, "{") {
		return h.parser.ParseLine(line)
	}

	// Fall back to TSV parsing
	return h.parseTSVLine(line)
}

// parseTSVLine parses a TSV formatted line
func (h *HypernodeCommand) parseTSVLine(line string) (*models.LogEntry, error) {
	parts := strings.Split(line, "\t")
	if len(parts) < 10 {
		// Try parsing as default space-separated format from hypernode-parse-nginx-log
		// Format: "status response_time country ip request"
		// Example: "403  0.000 US 184.105.139.69  GET / HTTP/1.1"
		return h.parseDefaultFormat(line)
	}

	entry := &models.LogEntry{}

	// Parse timestamp (usually first field)
	if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
		entry.Timestamp = t
	} else if t, err := time.Parse(time.RFC3339, parts[0]); err == nil {
		entry.Timestamp = t
	}

	// Parse IP (second field)
	entry.IP = net.ParseIP(parts[1])

	// Parse method and path
	if len(parts) > 2 {
		entry.Method = parts[2]
	}
	if len(parts) > 3 {
		entry.Path = parts[3]
	}

	// Parse status
	if len(parts) > 4 {
		_, _ = fmt.Sscanf(parts[4], "%d", &entry.Status)
	}

	// Parse bytes
	if len(parts) > 5 {
		_, _ = fmt.Sscanf(parts[5], "%d", &entry.BytesSent)
	}

	// Parse response time
	if len(parts) > 6 {
		_, _ = fmt.Sscanf(parts[6], "%f", &entry.ResponseTime)
	}

	// Parse user agent
	if len(parts) > 7 {
		entry.UserAgent = parts[7]
		// Simple bot check
		uaLower := strings.ToLower(entry.UserAgent)
		entry.IsBot = strings.Contains(uaLower, "bot") || strings.Contains(uaLower, "crawler") || strings.Contains(uaLower, "spider")
	}

	// Parse country
	if len(parts) > 8 {
		entry.Country = parts[8]
	}

	// Parse handler
	if len(parts) > 9 {
		entry.Handler = parts[9]
	}

	return entry, nil
}

// parseDefaultFormat parses the default space-separated format from hypernode-parse-nginx-log
// Format: "status response_time country ip request"
// Example: "403  0.000 US 184.105.139.69  GET / HTTP/1.1"
func (h *HypernodeCommand) parseDefaultFormat(line string) (*models.LogEntry, error) {
	// Split by whitespace (handles multiple spaces)
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil, fmt.Errorf("invalid line format: not enough fields")
	}

	entry := &models.LogEntry{
		Timestamp: time.Now(), // Default to current time since not provided
	}

	// Field 0: status code
	_, _ = fmt.Sscanf(fields[0], "%d", &entry.Status)

	// Field 1: response time
	_, _ = fmt.Sscanf(fields[1], "%f", &entry.ResponseTime)

	// Field 2: country code
	entry.Country = fields[2]

	// Field 3: IP address
	entry.IP = net.ParseIP(fields[3])

	// Fields 4+: request (method path protocol)
	if len(fields) >= 5 {
		entry.Method = fields[4]
	}
	if len(fields) >= 6 {
		entry.Path = fields[5]
	}

	return entry, nil
}

// GetHistoricalData retrieves historical data for a specific number of days ago
func (h *HypernodeCommand) GetHistoricalData(ctx context.Context, daysAgo int) ([]*models.LogEntry, error) {
	entries := make([]*models.LogEntry, 0)

	entryChan, errorChan := h.GetLogEntries(ctx, []string{}, daysAgo)

	for {
		select {
		case <-ctx.Done():
			return entries, ctx.Err()
		case entry, ok := <-entryChan:
			if !ok {
				return entries, nil
			}
			entries = append(entries, entry)
		case err, ok := <-errorChan:
			if ok && err != nil {
				return entries, err
			}
		}
	}
}

// GetWeekHistoricalData retrieves historical data for the past week
func (h *HypernodeCommand) GetWeekHistoricalData(ctx context.Context) (map[int][]*models.LogEntry, error) {
	weekData := make(map[int][]*models.LogEntry)

	for day := 1; day <= 7; day++ {
		data, err := h.GetHistoricalData(ctx, day)
		if err != nil {
			return weekData, fmt.Errorf("failed to get data for day %d: %w", day, err)
		}
		weekData[day] = data
	}

	return weekData, nil
}

// GetTodayData retrieves today's log data
func (h *HypernodeCommand) GetTodayData(ctx context.Context) ([]*models.LogEntry, error) {
	return h.GetHistoricalData(ctx, 0)
}

// GetYesterdayData retrieves yesterday's log data
func (h *HypernodeCommand) GetYesterdayData(ctx context.Context) ([]*models.LogEntry, error) {
	return h.GetHistoricalData(ctx, 1)
}

// Options for GetLogEntries
type Options struct {
	DaysAgo        int
	UseYesterday   bool
	AdditionalArgs []string
}

// GetLogEntriesWithOptions retrieves log entries with custom options
func (h *HypernodeCommand) GetLogEntriesWithOptions(ctx context.Context, opts Options) (<-chan *models.LogEntry, <-chan error) {
	daysAgo := opts.DaysAgo
	if opts.UseYesterday {
		daysAgo = 1
	}
	return h.GetLogEntries(ctx, opts.AdditionalArgs, daysAgo)
}

// MockHypernodeCommand provides a mock implementation for testing
type MockHypernodeCommand struct {
	entries []*models.LogEntry
	parser  *parser.LogParser
}

// NewMockHypernodeCommand creates a new mock Hypernode command
func NewMockHypernodeCommand(entries []*models.LogEntry) *MockHypernodeCommand {
	return &MockHypernodeCommand{
		entries: entries,
		parser:  parser.NewLogParser(),
	}
}

// IsAvailable always returns true for mock
func (m *MockHypernodeCommand) IsAvailable() bool {
	return true
}

// Execute returns mock entries
func (m *MockHypernodeCommand) Execute(ctx context.Context, args []string, daysAgo int) (<-chan string, <-chan error) {
	lineChan := make(chan string, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(lineChan)
		defer close(errorChan)

		for _, entry := range m.entries {
			select {
			case <-ctx.Done():
				return
			default:
				// Convert entry back to JSON string
				lineChan <- fmt.Sprintf(`{"time":"%s","remote_addr":"%s","request":"%s %s HTTP/1.1","status":"%d"}`,
					entry.Timestamp.Format(time.RFC3339),
					entry.IP.String(),
					entry.Method,
					entry.Path,
					entry.Status)
			}
		}
	}()

	return lineChan, errorChan
}

// GetLogEntries returns mock log entries
func (m *MockHypernodeCommand) GetLogEntries(ctx context.Context, args []string, daysAgo int) (<-chan *models.LogEntry, <-chan error) {
	entryChan := make(chan *models.LogEntry, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(entryChan)
		defer close(errorChan)

		for _, entry := range m.entries {
			select {
			case <-ctx.Done():
				return
			default:
				entryChan <- entry
			}
		}
	}()

	return entryChan, errorChan
}

// GetHistoricalData returns mock historical data
func (m *MockHypernodeCommand) GetHistoricalData(ctx context.Context, daysAgo int) ([]*models.LogEntry, error) {
	return m.entries, nil
}

// GetWeekHistoricalData returns mock week data
func (m *MockHypernodeCommand) GetWeekHistoricalData(ctx context.Context) (map[int][]*models.LogEntry, error) {
	weekData := make(map[int][]*models.LogEntry)
	for day := 1; day <= 7; day++ {
		weekData[day] = m.entries
	}
	return weekData, nil
}
