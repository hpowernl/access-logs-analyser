package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/olekukonko/tablewriter"
)

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

// DisplaySummary displays a statistics summary
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
