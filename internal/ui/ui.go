package ui

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/olekukonko/tablewriter"
)

// ComprehensiveData holds all data for comprehensive analysis display
type ComprehensiveData struct {
	Statistics      *models.Statistics
	SecuritySummary *models.SecuritySummary
	BotSummary      *models.BotSummary
	BrowserStats    []BrowserStat
	OSStats         []OSStat
	PathHandlers    map[string]string
	ReverseDNS      map[string]string
	MaxResponseTime float64
}

// BrowserStat represents browser statistics
type BrowserStat struct {
	Browser string
	Count   int64
}

// OSStat represents OS statistics
type OSStat struct {
	OS    string
	Count int64
}

// ConsoleUI provides console UI functionality
type ConsoleUI struct {
	writer io.Writer
	colors bool
}

// NewConsoleUI creates a new console UI
func NewConsoleUI(enableColors bool) *ConsoleUI {
	return &ConsoleUI{
		writer: os.Stdout,
		colors: enableColors,
	}
}

// DisplayComprehensiveSummary displays a comprehensive analysis summary
func (u *ConsoleUI) DisplayComprehensiveSummary(data *ComprehensiveData) {
	stats := data.Statistics

	// Header
	fmt.Fprintf(u.writer, "\n%s\n", strings.Repeat("═", 63))
	fmt.Fprintf(u.writer, "📊 ANALYSIS SUMMARY\n")
	fmt.Fprintf(u.writer, "%s\n\n", strings.Repeat("═", 63))

	// Time Range
	if stats.TimeRange != nil {
		u.printSectionTitle("Time Range")
		duration := stats.TimeRange.End.Sub(stats.TimeRange.Start)
		hours := duration.Hours()
		u.printKeyValueIndent("From", stats.TimeRange.Start.Format("2006-01-02 15:04:05"))
		u.printKeyValueIndent("To", stats.TimeRange.End.Format("2006-01-02 15:04:05"))
		u.printKeyValueIndent("Duration", fmt.Sprintf("%.1f hours", hours))
	}

	// Traffic Statistics
	u.printSectionTitle("Traffic Statistics")
	u.printKeyValueIndent("Total Requests", formatNumber(stats.TotalRequests))
	u.printKeyValueIndent("Unique Visitors", formatNumber(int64(stats.UniqueIPs)))

	if stats.TimeRange != nil {
		duration := stats.TimeRange.End.Sub(stats.TimeRange.Start)
		if duration.Hours() > 0 {
			reqPerHour := float64(stats.TotalRequests) / duration.Hours()
			reqPerMinute := float64(stats.TotalRequests) / duration.Minutes()
			u.printKeyValueIndent("Requests/Hour", fmt.Sprintf("%.1f", reqPerHour))
			u.printKeyValueIndent("Requests/Minute", fmt.Sprintf("%.1f", reqPerMinute))
		}
	}

	u.printKeyValueIndent("Error Rate", fmt.Sprintf("%.1f%%", stats.ErrorRate*100))
	if stats.TotalRequests > 0 {
		botPct := float64(stats.BotTraffic) / float64(stats.TotalRequests) * 100
		u.printKeyValueIndent("Bot Traffic", fmt.Sprintf("%.1f%%", botPct))
	}

	// Performance Metrics
	u.printSectionTitle("Performance Metrics")
	u.printKeyValueIndent("Average", fmt.Sprintf("%.3fs", stats.AvgResponseTime))
	u.printKeyValueIndent("Maximum", fmt.Sprintf("%.3fs", data.MaxResponseTime))
	u.printKeyValueIndent("95th Percentile", fmt.Sprintf("%.3fs", stats.P95ResponseTime))

	// Bandwidth Usage
	u.printSectionTitle("Bandwidth Usage")
	u.printKeyValueIndent("Total", fmt.Sprintf("%.2f GB", float64(stats.TotalBytes)/1024/1024/1024))
	if stats.TotalRequests > 0 {
		avgBytes := float64(stats.TotalBytes) / float64(stats.TotalRequests)
		u.printKeyValueIndent("Avg/Request", fmt.Sprintf("%s bytes", formatNumber(int64(avgBytes))))
	}

	// Top Countries
	if len(stats.TopCountries) > 0 {
		u.printTableTitle("Top Countries")
		u.printCountriesPercentageTable(stats.TopCountries[:min(10, len(stats.TopCountries))], stats.TotalRequests)
	}

	// Status Codes
	if len(stats.StatusCounts) > 0 {
		u.printTableTitle("Status Codes")
		u.printStatusCodesTable(stats.StatusCounts, stats.TotalRequests)
	}

	// Top User Agents
	if len(stats.TopUserAgents) > 0 {
		u.printTableTitle("Top User Agents")
		u.printUserAgentsTable(stats.TopUserAgents[:min(15, len(stats.TopUserAgents))])
	}

	// Top IP Addresses
	if len(stats.TopIPs) > 0 {
		u.printTableTitle("Top IP Addresses")
		u.printIPsWithDNSTable(stats.TopIPs[:min(15, len(stats.TopIPs))], data.ReverseDNS, stats.TotalRequests)
	}

	// Top Requested Paths
	if len(stats.TopPaths) > 0 {
		u.printTableTitle("Top Requested Paths")
		u.printPathsWithHandlerTable(stats.TopPaths[:min(15, len(stats.TopPaths))], data.PathHandlers, stats.TotalRequests)
	}

	// Top IP Addresses by Country (for top 10 countries)
	topCountries := stats.TopCountries[:min(10, len(stats.TopCountries))]
	for _, country := range topCountries {
		u.printCountryIPsTable(country, data)
	}

	// Bot Analysis
	if data.BotSummary != nil && len(data.BotSummary.BotsByCategory) > 0 {
		u.printTableTitle("Bot Analysis")
		u.printBotAnalysisTable(data.BotSummary)
	}

	// Top Browsers
	if len(data.BrowserStats) > 0 {
		u.printTableTitle("Top Browsers")
		u.printBrowsersTable(data.BrowserStats[:min(10, len(data.BrowserStats))], stats.TotalRequests)
	}

	// Top Operating Systems
	if len(data.OSStats) > 0 {
		u.printTableTitle("Top Operating Systems")
		u.printOSTable(data.OSStats[:min(10, len(data.OSStats))], stats.TotalRequests)
	}

	// Security Analysis
	if data.SecuritySummary != nil && data.SecuritySummary.TotalThreats > 0 {
		u.printSecurityAnalysis(data.SecuritySummary)
	}
}

// DisplaySummary displays a statistics summary (kept for backwards compatibility)
func (u *ConsoleUI) DisplaySummary(stats *models.Statistics) {
	u.printHeader("📊 LOG ANALYSIS SUMMARY")

	// Overall Statistics
	u.printSection("Overall Statistics")
	u.printKeyValue("Total Requests", fmt.Sprintf("%d", stats.TotalRequests))
	u.printKeyValue("Unique IPs", fmt.Sprintf("%d", stats.UniqueIPs))
	u.printKeyValue("Unique Countries", fmt.Sprintf("%d", stats.UniqueCountries))
	u.printKeyValue("Total Bytes", fmt.Sprintf("%.2f MB", float64(stats.TotalBytes)/1024/1024))

	if stats.TotalRequests > 0 {
		botPct := float64(stats.BotTraffic) / float64(stats.TotalRequests) * 100
		humanPct := float64(stats.HumanTraffic) / float64(stats.TotalRequests) * 100
		u.printKeyValue("Bot Traffic", fmt.Sprintf("%d (%.1f%%)", stats.BotTraffic, botPct))
		u.printKeyValue("Human Traffic", fmt.Sprintf("%d (%.1f%%)", stats.HumanTraffic, humanPct))
	}

	// Performance Metrics
	u.printSection("Performance Metrics")
	u.printKeyValue("Avg Response Time", fmt.Sprintf("%.3fs", stats.AvgResponseTime))
	u.printKeyValue("Median Response Time", fmt.Sprintf("%.3fs", stats.MedianResponseTime))
	u.printKeyValue("P95 Response Time", fmt.Sprintf("%.3fs", stats.P95ResponseTime))
	u.printKeyValue("P99 Response Time", fmt.Sprintf("%.3fs", stats.P99ResponseTime))
	u.printKeyValue("Error Rate", fmt.Sprintf("%.2f%%", stats.ErrorRate*100))

	// Top Paths
	if len(stats.TopPaths) > 0 {
		u.printSection("Top Paths")
		u.printPathsTable(stats.TopPaths[:min(10, len(stats.TopPaths))])
	}

	// Top Countries
	if len(stats.TopCountries) > 0 {
		u.printSection("Top Countries")
		u.printCountriesTable(stats.TopCountries[:min(10, len(stats.TopCountries))])
	}
}

// DisplaySecurityReport displays a security analysis report
func (u *ConsoleUI) DisplaySecurityReport(report *models.SecuritySummary) {
	u.printHeader("🔒 SECURITY ANALYSIS REPORT")

	u.printSection("Threat Summary")
	u.printKeyValue("Total Threats", fmt.Sprintf("%d", report.TotalThreats))
	u.printKeyValue("SQL Injection Attempts", fmt.Sprintf("%d", report.SQLInjectionCount))
	u.printKeyValue("XSS Attempts", fmt.Sprintf("%d", report.XSSCount))
	u.printKeyValue("Directory Traversal", fmt.Sprintf("%d", report.DirTraversalCount))
	u.printKeyValue("Command Injection", fmt.Sprintf("%d", report.CmdInjectionCount))
	u.printKeyValue("Brute Force Attempts", fmt.Sprintf("%d", report.BruteForceCount))
	u.printKeyValue("Scanning Detected", fmt.Sprintf("%d", report.ScanningCount))

	// Suspicious IPs
	if len(report.SuspiciousIPs) > 0 {
		u.printSection("Suspicious IPs")
		u.printSuspiciousIPsTable(report.SuspiciousIPs[:min(10, len(report.SuspiciousIPs))])
	}
}

// DisplayPerformanceReport displays a performance analysis report
func (u *ConsoleUI) DisplayPerformanceReport(report *models.PerformanceReport) {
	u.printHeader("⚡ PERFORMANCE ANALYSIS REPORT")

	if report.ResponseTimeStats != nil {
		u.printSection("Response Time Statistics")
		u.printKeyValue("Mean", fmt.Sprintf("%.3fs", report.ResponseTimeStats.Mean))
		u.printKeyValue("Median", fmt.Sprintf("%.3fs", report.ResponseTimeStats.Median))
		u.printKeyValue("Min", fmt.Sprintf("%.3fs", report.ResponseTimeStats.Min))
		u.printKeyValue("Max", fmt.Sprintf("%.3fs", report.ResponseTimeStats.Max))
		u.printKeyValue("P95", fmt.Sprintf("%.3fs", report.ResponseTimeStats.P95))
		u.printKeyValue("P99", fmt.Sprintf("%.3fs", report.ResponseTimeStats.P99))
	}

	if len(report.SlowestEndpoints) > 0 {
		u.printSection("Slowest Endpoints")
		u.printEndpointsTable(report.SlowestEndpoints[:min(10, len(report.SlowestEndpoints))])
	}

	if len(report.Recommendations) > 0 {
		u.printSection("Recommendations")
		for i, rec := range report.Recommendations {
			priority := u.colorize(rec.Priority, u.getPriorityColor(rec.Priority))
			fmt.Fprintf(u.writer, "%d. [%s] %s\n", i+1, priority, rec.Description)
			fmt.Fprintf(u.writer, "   Action: %s\n\n", rec.Action)
		}
	}
}

// DisplayBotReport displays a bot analysis report
func (u *ConsoleUI) DisplayBotReport(report *models.BotSummary) {
	u.printHeader("🤖 BOT ANALYSIS REPORT")

	u.printSection("Bot Summary")
	u.printKeyValue("Total Bot Requests", fmt.Sprintf("%d", report.TotalBotRequests))
	u.printKeyValue("Unique Bots", fmt.Sprintf("%d", report.UniqueBots))
	u.printKeyValue("Bot Traffic %", fmt.Sprintf("%.1f%%", report.BotTrafficPct))

	if len(report.BotsByCategory) > 0 {
		u.printSection("Bots by Category")
		for category, count := range report.BotsByCategory {
			u.printKeyValue(category, fmt.Sprintf("%d", count))
		}
	}

	if len(report.TopBots) > 0 {
		u.printSection("Top Bots")
		u.printBotsTable(report.TopBots[:min(10, len(report.TopBots))])
	}

	if len(report.AIBots) > 0 {
		u.printSection("AI/LLM Bots")
		u.printBotsTable(report.AIBots)
	}
}

// Print helper methods
func (u *ConsoleUI) printHeader(title string) {
	if u.colors {
		color.New(color.FgCyan, color.Bold).Fprintf(u.writer, "\n%s\n", title)
		color.New(color.FgCyan).Fprintf(u.writer, "%s\n\n", strings.Repeat("═", len(title)))
	} else {
		fmt.Fprintf(u.writer, "\n%s\n%s\n\n", title, strings.Repeat("=", len(title)))
	}
}

func (u *ConsoleUI) printSection(title string) {
	if u.colors {
		color.New(color.FgYellow, color.Bold).Fprintf(u.writer, "\n%s\n", title)
		color.New(color.FgYellow).Fprintf(u.writer, "%s\n", strings.Repeat("─", len(title)))
	} else {
		fmt.Fprintf(u.writer, "\n%s\n%s\n", title, strings.Repeat("-", len(title)))
	}
}

func (u *ConsoleUI) printKeyValue(key, value string) {
	if u.colors {
		color.New(color.FgWhite, color.Bold).Fprintf(u.writer, "%-25s", key+":")
		color.New(color.FgGreen).Fprintf(u.writer, "%s\n", value)
	} else {
		fmt.Fprintf(u.writer, "%-25s %s\n", key+":", value)
	}
}

func (u *ConsoleUI) printPathsTable(paths []models.PathStat) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Path", "Requests", "Avg RT", "Errors"})

	for _, path := range paths {
		table.Append([]string{
			truncate(path.Path, 50),
			fmt.Sprintf("%d", path.Count),
			fmt.Sprintf("%.3fs", path.AvgResponseTime),
			fmt.Sprintf("%d", path.ErrorCount),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printCountriesTable(countries []models.CountryStat) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Country", "Requests", "Unique IPs", "Errors"})

	for _, country := range countries {
		table.Append([]string{
			country.Country,
			fmt.Sprintf("%d", country.Count),
			fmt.Sprintf("%d", country.UniqueIPs),
			fmt.Sprintf("%d", country.ErrorCount),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printSuspiciousIPsTable(ips []models.SuspiciousIP) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"IP", "Country", "Threat Score", "Requests", "Recommended"})

	for _, ip := range ips {
		table.Append([]string{
			ip.IP,
			ip.Country,
			fmt.Sprintf("%.1f", ip.ThreatScore),
			fmt.Sprintf("%d", ip.RequestCount),
			truncate(ip.Recommended, 30),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printEndpointsTable(endpoints []models.EndpointStat) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Endpoint", "Requests", "Avg RT", "P95 RT", "Errors"})

	for _, ep := range endpoints {
		table.Append([]string{
			truncate(ep.Endpoint, 40),
			fmt.Sprintf("%d", ep.Count),
			fmt.Sprintf("%.3fs", ep.AvgResponseTime),
			fmt.Sprintf("%.3fs", ep.P95ResponseTime),
			fmt.Sprintf("%d", ep.ErrorCount),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printBotsTable(bots []models.BotStat) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"User Agent", "Category", "Requests", "Legitimacy"})

	for _, bot := range bots {
		table.Append([]string{
			truncate(bot.UserAgent, 50),
			bot.Category,
			fmt.Sprintf("%d", bot.Count),
			fmt.Sprintf("%.0f", bot.LegitimacyScore),
		})
	}

	table.Render()
}

// Helper methods for comprehensive display
func (u *ConsoleUI) printSectionTitle(title string) {
	fmt.Fprintf(u.writer, "\n  %s\n", title)
}

func (u *ConsoleUI) printTableTitle(title string) {
	fmt.Fprintf(u.writer, "\n%s%s\n", strings.Repeat(" ", (63-len(title))/2), title)
}

func (u *ConsoleUI) printKeyValueIndent(key, value string) {
	fmt.Fprintf(u.writer, "    • %s: %s\n", key, value)
}

func (u *ConsoleUI) printCountriesPercentageTable(countries []models.CountryStat, totalRequests int64) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Country", "Hits", "Percentage"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	for _, country := range countries {
		pct := float64(country.Count) / float64(totalRequests) * 100
		table.Append([]string{
			country.Country,
			formatNumber(country.Count),
			fmt.Sprintf("%.1f%%", pct),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printStatusCodesTable(statusCounts map[int]int64, totalRequests int64) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Status", "Count", "Percentage"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	// Sort status codes
	type statusPair struct {
		status int
		count  int64
	}
	var statuses []statusPair
	for status, count := range statusCounts {
		statuses = append(statuses, statusPair{status, count})
	}
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].status < statuses[j].status
	})

	for _, sp := range statuses {
		pct := float64(sp.count) / float64(totalRequests) * 100
		table.Append([]string{
			fmt.Sprintf("%d", sp.status),
			formatNumber(sp.count),
			fmt.Sprintf("%.1f%%", pct),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printUserAgentsTable(userAgents []models.UserAgentStat) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"User Agent", "Hits", "Type"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetColWidth(80)

	for _, ua := range userAgents {
		uaType := "Browser"
		if ua.IsBot {
			uaType = "Bot"
		}
		table.Append([]string{
			truncate(ua.UserAgent, 80),
			formatNumber(ua.Count),
			uaType,
		})
	}

	table.Render()
}

func (u *ConsoleUI) printIPsWithDNSTable(ips []models.IPStat, reverseDNS map[string]string, totalRequests int64) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"IP Address", "Hits", "Percentage", "Reverse DNS"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetColWidth(45)

	for _, ip := range ips {
		pct := float64(ip.Count) / float64(totalRequests) * 100
		dns := reverseDNS[ip.IP]
		if dns == "" || dns == ip.IP {
			dns = "-"
		}
		table.Append([]string{
			ip.IP,
			formatNumber(ip.Count),
			fmt.Sprintf("%.1f%%", pct),
			truncate(dns, 45),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printPathsWithHandlerTable(paths []models.PathStat, handlers map[string]string, totalRequests int64) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Path", "Hits", "Percentage", "Min Time", "Max Time", "Avg Time", "Handler"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetColWidth(60)

	for _, path := range paths {
		pct := float64(path.Count) / float64(totalRequests) * 100
		handler := handlers[path.Path]
		if handler == "" {
			handler = "-"
		}
		table.Append([]string{
			truncate(path.Path, 60),
			formatNumber(path.Count),
			fmt.Sprintf("%.1f%%", pct),
			fmt.Sprintf("%.3fs", path.MinResponseTime),
			fmt.Sprintf("%.3fs", path.MaxResponseTime),
			fmt.Sprintf("%.3fs", path.AvgResponseTime),
			handler,
		})
	}

	table.Render()
}

func (u *ConsoleUI) printCountryIPsTable(country models.CountryStat, data *ComprehensiveData) {
	// Get IPs for this country from stats
	var countryIPs []models.IPStat
	for _, ip := range data.Statistics.TopIPs {
		if ip.Country == country.Country {
			countryIPs = append(countryIPs, ip)
		}
	}

	if len(countryIPs) == 0 {
		return
	}

	// Sort by count
	sort.Slice(countryIPs, func(i, j int) bool {
		return countryIPs[i].Count > countryIPs[j].Count
	})

	fmt.Fprintf(u.writer, "\n%sTop IP Addresses - %s\n", strings.Repeat(" ", (63-len(fmt.Sprintf("Top IP Addresses - %s", country.Country)))/2), country.Country)

	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"IP Address", "Hits", "Percentage"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	for i, ip := range countryIPs {
		if i >= 10 {
			break
		}
		pct := float64(ip.Count) / float64(country.Count) * 100
		table.Append([]string{
			ip.IP,
			formatNumber(ip.Count),
			fmt.Sprintf("%.1f%%", pct),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printBotAnalysisTable(botSummary *models.BotSummary) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Bot Type", "Requests", "Percentage"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	// Sort by count
	type botPair struct {
		category string
		count    int64
	}
	var bots []botPair
	for category, count := range botSummary.BotsByCategory {
		bots = append(bots, botPair{category, count})
	}
	sort.Slice(bots, func(i, j int) bool {
		return bots[i].count > bots[j].count
	})

	for _, bot := range bots {
		pct := float64(bot.count) / float64(botSummary.TotalBotRequests) * 100
		table.Append([]string{
			bot.category,
			formatNumber(bot.count),
			fmt.Sprintf("%.1f%%", pct),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printBrowsersTable(browsers []BrowserStat, totalRequests int64) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Browser", "Hits", "Percentage"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	for _, browser := range browsers {
		pct := float64(browser.Count) / float64(totalRequests) * 100
		table.Append([]string{
			browser.Browser,
			formatNumber(browser.Count),
			fmt.Sprintf("%.1f%%", pct),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printOSTable(oses []OSStat, totalRequests int64) {
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Operating System", "Hits", "Percentage"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	for _, os := range oses {
		pct := float64(os.Count) / float64(totalRequests) * 100
		table.Append([]string{
			os.OS,
			formatNumber(os.Count),
			fmt.Sprintf("%.1f%%", pct),
		})
	}

	table.Render()
}

func (u *ConsoleUI) printSecurityAnalysis(security *models.SecuritySummary) {
	fmt.Fprintf(u.writer, "\n🛡️  SECURITY ANALYSIS - PATTERNS & THREATS\n\n")

	// Attack patterns
	fmt.Fprintf(u.writer, "🔍 Attack Patterns Detected:\n")
	table := tablewriter.NewWriter(u.writer)
	table.SetHeader([]string{"Attack Type", "Attempts"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	if security.DirTraversalCount > 0 {
		table.Append([]string{"Directory Traversal", formatNumber(security.DirTraversalCount)})
	}
	if security.SQLInjectionCount > 0 {
		table.Append([]string{"SQL Injection", formatNumber(security.SQLInjectionCount)})
	}
	if security.XSSCount > 0 {
		table.Append([]string{"XSS", formatNumber(security.XSSCount)})
	}
	if security.CmdInjectionCount > 0 {
		table.Append([]string{"Command Injection", formatNumber(security.CmdInjectionCount)})
	}
	if security.BruteForceCount > 0 {
		table.Append([]string{"Brute Force", formatNumber(security.BruteForceCount)})
	}
	if security.ScanningCount > 0 {
		table.Append([]string{"Web Shell", formatNumber(security.ScanningCount)})
	}

	table.Render()

	// Abusive IPs
	if len(security.SuspiciousIPs) > 0 {
		fmt.Fprintf(u.writer, "\n⚠️  Top 15 Most Abusive IP Addresses:\n")
		table := tablewriter.NewWriter(u.writer)
		table.SetHeader([]string{"IP Address", "Threat Score", "Requests", "Error Rate", "Attack Types", "Failed Logins"})
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetColWidth(30)

		for i, ip := range security.SuspiciousIPs {
			if i >= 15 {
				break
			}
			errorRate := float64(0)
			if ip.RequestCount > 0 {
				errorRate = float64(ip.ErrorCount) / float64(ip.RequestCount) * 100
			}

			attackTypes := strings.Join(ip.Threats, ", ")
			if attackTypes == "" {
				attackTypes = "High Error Rate"
			}

			failedLogins := int64(0)
			if patterns, ok := ip.AttackPatterns["brute_force"]; ok {
				failedLogins = int64(patterns)
			}

			table.Append([]string{
				ip.IP,
				fmt.Sprintf("%.1f", ip.ThreatScore),
				formatNumber(ip.RequestCount),
				fmt.Sprintf("%.1f%%", errorRate),
				truncate(attackTypes, 30),
				formatNumber(failedLogins),
			})
		}

		table.Render()
	}
}

func (u *ConsoleUI) colorize(text string, colorAttr color.Attribute) string {
	if u.colors {
		return color.New(colorAttr).Sprint(text)
	}
	return text
}

func (u *ConsoleUI) getPriorityColor(priority string) color.Attribute {
	switch priority {
	case "critical":
		return color.FgRed
	case "high":
		return color.FgYellow
	case "medium":
		return color.FgBlue
	default:
		return color.FgWhite
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func formatNumber(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	var result []byte
	for i, digit := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(digit))
	}
	return string(result)
}
