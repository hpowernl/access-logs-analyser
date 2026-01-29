package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hpowernl/hlogcli/internal/ui"
	"github.com/hpowernl/hlogcli/pkg/models"
)

// View represents different views in the TUI
type View int

const (
	ViewOverview View = iota
	ViewSecurity
	ViewPerformance
	ViewBots
	ViewHelp
)

// Model represents the TUI application state
type Model struct {
	data         *ui.ComprehensiveData
	securityData *models.SecuritySummary
	perfData     *models.PerformanceReport
	botData      *models.BotSummary

	currentView View
	loading     bool
	loadingMsg  string
	err         error

	width  int
	height int

	spinnerFrame int

	keys keyMap
}

// keyMap defines keyboard shortcuts
type keyMap struct {
	Up    key.Binding
	Down  key.Binding
	Left  key.Binding
	Right key.Binding
	Tab   key.Binding
	Help  key.Binding
	Quit  key.Binding
	View1 key.Binding
	View2 key.Binding
	View3 key.Binding
	View4 key.Binding
}

var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "scroll up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "scroll down"),
	),
	Left: key.NewBinding(
		key.WithKeys("left", "h"),
		key.WithHelp("←/h", "previous view"),
	),
	Right: key.NewBinding(
		key.WithKeys("right", "l"),
		key.WithHelp("→/l", "next view"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next view"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "esc", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	View1: key.NewBinding(
		key.WithKeys("1"),
		key.WithHelp("1", "overview"),
	),
	View2: key.NewBinding(
		key.WithKeys("2"),
		key.WithHelp("2", "security"),
	),
	View3: key.NewBinding(
		key.WithKeys("3"),
		key.WithHelp("3", "performance"),
	),
	View4: key.NewBinding(
		key.WithKeys("4"),
		key.WithHelp("4", "bots"),
	),
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("6")).
			Padding(0, 1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("8")).
			Padding(1, 2)

	headerStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("6")).
			Foreground(lipgloss.Color("0")).
			Bold(true).
			Padding(0, 1)

	tabStyle = lipgloss.NewStyle().
			Border(lipgloss.Border{Top: " ", Bottom: " ", Left: " ", Right: "│"}, false, true, false, false).
			Padding(0, 2)

	activeTabStyle = lipgloss.NewStyle().
			Border(lipgloss.Border{Top: " ", Bottom: "─", Left: " ", Right: "│"}, false, true, true, false).
			BorderForeground(lipgloss.Color("6")).
			Foreground(lipgloss.Color("6")).
			Bold(true).
			Padding(0, 2)

	keyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("6"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			Padding(0, 1)
)

// NewModel creates a new TUI model
func NewModel() Model {
	return Model{
		currentView: ViewOverview,
		loading:     true,
		loadingMsg:  "Loading logs...",
		keys:        keys,
	}
}

// SetCurrentView sets the current view
func (m *Model) SetCurrentView(view View) {
	m.currentView = view
}

// LoadingMsg is sent when loading starts
type LoadingMsg struct {
	Message string
}

// DataLoadedMsg is sent when data is loaded
type DataLoadedMsg struct {
	Data         *ui.ComprehensiveData
	SecurityData *models.SecuritySummary
	PerfData     *models.PerformanceReport
	BotData      *models.BotSummary
}

// ErrorMsg is sent when an error occurs
type ErrorMsg struct {
	Err error
}

// TickMsg is sent periodically to animate the spinner
type TickMsg struct{}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg {
		return TickMsg{}
	})
}

func (m Model) Init() tea.Cmd {
	return tick()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Tab), key.Matches(msg, m.keys.Right):
			if !m.loading {
				m.currentView = (m.currentView + 1) % 4
			}
		case key.Matches(msg, m.keys.Left):
			if !m.loading {
				m.currentView = (m.currentView - 1 + 4) % 4
			}
		case key.Matches(msg, m.keys.View1):
			if !m.loading {
				m.currentView = ViewOverview
			}
		case key.Matches(msg, m.keys.View2):
			if !m.loading {
				m.currentView = ViewSecurity
			}
		case key.Matches(msg, m.keys.View3):
			if !m.loading {
				m.currentView = ViewPerformance
			}
		case key.Matches(msg, m.keys.View4):
			if !m.loading {
				m.currentView = ViewBots
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case TickMsg:
		m.spinnerFrame++
		if m.loading {
			return m, tick()
		}

	case LoadingMsg:
		m.loading = true
		m.loadingMsg = msg.Message
		return m, tick()

	case DataLoadedMsg:
		m.loading = false
		m.data = msg.Data
		m.securityData = msg.SecurityData
		m.perfData = msg.PerfData
		m.botData = msg.BotData

	case ErrorMsg:
		m.loading = false
		m.err = msg.Err
	}

	return m, nil
}

func (m Model) View() string {
	if m.err != nil {
		return fmt.Sprintf("\nError: %v\n\nPress q to quit.\n", m.err)
	}

	if m.loading {
		return m.renderLoading()
	}

	// Header
	header := m.renderHeader()

	// Tabs
	tabs := m.renderTabs()

	// Content based on current view
	var content string
	switch m.currentView {
	case ViewOverview:
		content = m.renderOverview()
	case ViewSecurity:
		content = m.renderSecurity()
	case ViewPerformance:
		content = m.renderPerformance()
	case ViewBots:
		content = m.renderBots()
	default:
		content = m.renderOverview()
	}

	// Footer
	footer := m.renderFooter()

	// Combine all parts
	availableHeight := m.height - lipgloss.Height(header) - lipgloss.Height(tabs) - lipgloss.Height(footer) - 2

	contentStyle := lipgloss.NewStyle().
		Width(m.width).
		Height(availableHeight)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		tabs,
		contentStyle.Render(content),
		footer,
	)
}

func (m Model) renderLoading() string {
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	frame := spinner[m.spinnerFrame%len(spinner)]

	// Loading animation
	loadingBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("6")).
		Padding(2, 4).
		Align(lipgloss.Center)

	content := fmt.Sprintf("%s %s", frame, m.loadingMsg)

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		loadingBox.Render(content),
	)
}

func (m Model) renderHeader() string {
	title := headerStyle.Render(" HYPERNODE LOG ANALYZER ")
	version := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		Render("v1.0.0")

	line := lipgloss.NewStyle().
		Width(m.width).
		Foreground(lipgloss.Color("8")).
		Render(strings.Repeat("─", m.width))

	headerLine := lipgloss.JoinHorizontal(lipgloss.Top, title, " ", version)

	return lipgloss.JoinVertical(lipgloss.Left, headerLine, line)
}

func (m Model) renderTabs() string {
	tabs := []string{}

	views := []struct {
		name string
		view View
	}{
		{"1 Overview", ViewOverview},
		{"2 Security", ViewSecurity},
		{"3 Performance", ViewPerformance},
		{"4 Bots", ViewBots},
	}

	for _, v := range views {
		if m.currentView == v.view {
			tabs = append(tabs, activeTabStyle.Render(v.name))
		} else {
			tabs = append(tabs, tabStyle.Render(v.name))
		}
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
}

func (m Model) renderFooter() string {
	help := helpStyle.Render("q: quit │ ←/→ or tab: switch view │ 1-4: jump to view")

	line := lipgloss.NewStyle().
		Width(m.width).
		Foreground(lipgloss.Color("8")).
		Render(strings.Repeat("─", m.width))

	return lipgloss.JoinVertical(lipgloss.Left, line, help)
}

func (m Model) renderOverview() string {
	if m.data == nil || m.data.Statistics == nil {
		return "No data available"
	}

	stats := m.data.Statistics

	var sections []string

	// Time Range
	if stats.TimeRange != nil {
		duration := stats.TimeRange.End.Sub(stats.TimeRange.Start)
		content := fmt.Sprintf(
			"%s %s\n%s %s\n%s %s",
			keyStyle.Render("From:"), stats.TimeRange.Start.Format("2006-01-02 15:04:05"),
			keyStyle.Render("To:"), stats.TimeRange.End.Format("2006-01-02 15:04:05"),
			keyStyle.Render("Duration:"), fmt.Sprintf("%.1f hours", duration.Hours()),
		)
		sections = append(sections, m.renderPanel("Time Range", content))
	}

	// Traffic Statistics
	reqPerHour := float64(0)
	if stats.TimeRange != nil && stats.TimeRange.End.Sub(stats.TimeRange.Start).Hours() > 0 {
		reqPerHour = float64(stats.TotalRequests) / stats.TimeRange.End.Sub(stats.TimeRange.Start).Hours()
	}

	traffic := fmt.Sprintf(
		"%s %s\n%s %s\n%s %.1f req/hour\n%s %.1f%%\n%s %.1f%%",
		keyStyle.Render("Total Requests:"), formatNumber(stats.TotalRequests),
		keyStyle.Render("Unique Visitors:"), formatNumber(int64(stats.UniqueIPs)),
		keyStyle.Render("Request Rate:"), reqPerHour,
		keyStyle.Render("Error Rate:"), stats.ErrorRate*100,
		keyStyle.Render("Bot Traffic:"), float64(stats.BotTraffic)/float64(stats.TotalRequests)*100,
	)
	sections = append(sections, m.renderPanel("Traffic Statistics", traffic))

	// Performance
	perf := fmt.Sprintf(
		"%s %.3fs\n%s %.3fs\n%s %.3fs",
		keyStyle.Render("Average:"), stats.AvgResponseTime,
		keyStyle.Render("Maximum:"), m.data.MaxResponseTime,
		keyStyle.Render("95th Percentile:"), stats.P95ResponseTime,
	)
	sections = append(sections, m.renderPanel("Performance Metrics", perf))

	// Bandwidth
	bandwidth := fmt.Sprintf(
		"%s %.2f GB\n%s %s bytes",
		keyStyle.Render("Total:"), float64(stats.TotalBytes)/1024/1024/1024,
		keyStyle.Render("Avg/Request:"), formatNumber(int64(float64(stats.TotalBytes)/float64(stats.TotalRequests))),
	)
	sections = append(sections, m.renderPanel("Bandwidth Usage", bandwidth))

	// Top Countries
	if len(stats.TopCountries) > 0 {
		var countries []string
		for i, c := range stats.TopCountries {
			if i >= 5 {
				break
			}
			pct := float64(c.Count) / float64(stats.TotalRequests) * 100
			countries = append(countries, fmt.Sprintf("%s - %s (%.1f%%)", c.Country, formatNumber(c.Count), pct))
		}
		sections = append(sections, m.renderPanel("Top Countries", strings.Join(countries, "\n")))
	}

	// Top Paths
	if len(stats.TopPaths) > 0 {
		var paths []string
		for i, p := range stats.TopPaths {
			if i >= 5 {
				break
			}
			pct := float64(p.Count) / float64(stats.TotalRequests) * 100
			paths = append(paths, fmt.Sprintf("%s - %s (%.1f%%)", truncate(p.Path, 40), formatNumber(p.Count), pct))
		}
		sections = append(sections, m.renderPanel("Top Requested Paths", strings.Join(paths, "\n")))
	}

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m Model) renderSecurity() string {
	if m.securityData == nil {
		return "No security data available"
	}

	sec := m.securityData

	// Create a 2-column layout
	var leftCol, rightCol []string

	// LEFT COLUMN

	// Overall Statistics
	errorPct := float64(0)
	if sec.TotalRequests > 0 {
		errorPct = float64(sec.TotalErrors) / float64(sec.TotalRequests) * 100
	}

	overall := fmt.Sprintf(
		"%s %s\n%s %s (%.1f%%)\n%s %s\n%s %s\n%s %d",
		keyStyle.Render("Total Requests:"), formatNumber(sec.TotalRequests),
		keyStyle.Render("Total Errors:"), formatNumber(sec.TotalErrors), errorPct,
		keyStyle.Render("Unique IPs:"), formatNumber(int64(sec.UniqueIPs)),
		keyStyle.Render("Attack Attempts:"), formatNumber(sec.AttackAttempts),
		keyStyle.Render("Attack Types:"), sec.UniqueAttackTypes,
	)
	leftCol = append(leftCol, m.renderPanel("Overall Statistics", overall))

	// Threat Analysis
	suspiciousPct := float64(0)
	if sec.UniqueIPs > 0 {
		suspiciousPct = float64(sec.SuspiciousIPsCount) / float64(sec.UniqueIPs) * 100
	}

	threats := fmt.Sprintf(
		"%s %d (%.1f%%)\n%s %d\n%s %d\n%s %d",
		keyStyle.Render("Suspicious IPs:"), sec.SuspiciousIPsCount, suspiciousPct,
		keyStyle.Render("Potential DDoS:"), sec.PotentialDDoSIPs,
		keyStyle.Render("Scanning IPs:"), sec.ScanningIPsCount,
		keyStyle.Render("Admin Access:"), sec.AdminAccessIPs,
	)
	leftCol = append(leftCol, m.renderPanel("Threat Analysis", threats))

	// Attack Patterns
	var attacks []string
	if sec.DirTraversalCount > 0 {
		attacks = append(attacks, fmt.Sprintf("%s %s", keyStyle.Render("Dir Traversal:"), formatNumber(sec.DirTraversalCount)))
	}
	if sec.SQLInjectionCount > 0 {
		attacks = append(attacks, fmt.Sprintf("%s %s", keyStyle.Render("SQL Injection:"), formatNumber(sec.SQLInjectionCount)))
	}
	if sec.XSSCount > 0 {
		attacks = append(attacks, fmt.Sprintf("%s %s", keyStyle.Render("XSS:"), formatNumber(sec.XSSCount)))
	}
	if sec.CmdInjectionCount > 0 {
		attacks = append(attacks, fmt.Sprintf("%s %s", keyStyle.Render("Cmd Injection:"), formatNumber(sec.CmdInjectionCount)))
	}
	if sec.BruteForceCount > 0 {
		attacks = append(attacks, fmt.Sprintf("%s %s", keyStyle.Render("Brute Force:"), formatNumber(sec.BruteForceCount)))
	}
	if sec.ScanningCount > 0 {
		attacks = append(attacks, fmt.Sprintf("%s %s", keyStyle.Render("Web Shell:"), formatNumber(sec.ScanningCount)))
	}
	if sec.SensitiveFileAccessCount > 0 {
		attacks = append(attacks, fmt.Sprintf("%s %s", keyStyle.Render("Sensitive Files:"), formatNumber(sec.SensitiveFileAccessCount)))
	}

	if len(attacks) > 0 {
		leftCol = append(leftCol, m.renderPanel("Attack Patterns", strings.Join(attacks, "\n")))
	}

	// RIGHT COLUMN

	// Top Threat IPs
	if len(sec.SuspiciousIPs) > 0 {
		var ipList []string
		count := 0
		for _, ip := range sec.SuspiciousIPs {
			if ip.ThreatScore >= 10.0 && count < 12 {
				errorRate := float64(0)
				if ip.RequestCount > 0 {
					errorRate = float64(ip.ErrorCount) / float64(ip.RequestCount) * 100
				}

				threatLevel := "LOW"
				if ip.ThreatScore >= 70 {
					threatLevel = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true).Render("CRITICAL")
				} else if ip.ThreatScore >= 50 {
					threatLevel = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render("HIGH")
				} else if ip.ThreatScore >= 30 {
					threatLevel = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render("MEDIUM")
				}

				ipList = append(ipList, fmt.Sprintf(
					"%s [%s]\n  Requests: %s | Error: %.0f%% | Score: %.1f",
					ip.IP, threatLevel, formatNumber(ip.RequestCount), errorRate, ip.ThreatScore,
				))
				count++
			}
		}

		if len(ipList) > 0 {
			rightCol = append(rightCol, m.renderPanel("Top Threat IPs (Score >= 10)", strings.Join(ipList, "\n\n")))
		}
	}

	// Combine columns
	leftColStr := lipgloss.JoinVertical(lipgloss.Left, leftCol...)
	rightColStr := lipgloss.JoinVertical(lipgloss.Left, rightCol...)

	// Create 2-column layout (50/50 split)
	colWidth := (m.width - 6) / 2

	leftStyle := lipgloss.NewStyle().Width(colWidth)
	rightStyle := lipgloss.NewStyle().Width(colWidth)

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		leftStyle.Render(leftColStr),
		rightStyle.Render(rightColStr),
	)
}

func (m Model) renderPerformance() string {
	if m.perfData == nil || m.perfData.ResponseTimeStats == nil {
		return "No performance data available"
	}

	perf := m.perfData

	// LEFT COLUMN
	var leftCol []string

	// Response Time Stats
	rtStats := fmt.Sprintf(
		"%s %.3fs\n%s %.3fs\n%s %.3fs\n%s %.3fs\n%s %.3fs\n%s %.3fs",
		keyStyle.Render("Mean:"), perf.ResponseTimeStats.Mean,
		keyStyle.Render("Median:"), perf.ResponseTimeStats.Median,
		keyStyle.Render("Min:"), perf.ResponseTimeStats.Min,
		keyStyle.Render("Max:"), perf.ResponseTimeStats.Max,
		keyStyle.Render("P95:"), perf.ResponseTimeStats.P95,
		keyStyle.Render("P99:"), perf.ResponseTimeStats.P99,
	)
	leftCol = append(leftCol, m.renderPanel("Response Time Statistics", rtStats))

	// Recommendations
	if len(perf.Recommendations) > 0 {
		var recs []string
		for i, rec := range perf.Recommendations {
			if i >= 5 {
				break
			}
			priority := rec.Priority
			color := "15"
			switch priority {
			case "critical":
				color = "1"
			case "high":
				color = "3"
			case "medium":
				color = "11"
			}
			priorityStyled := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(priority)
			recs = append(recs, fmt.Sprintf(
				"[%s] %s\n  Action: %s",
				priorityStyled, rec.Description, rec.Action,
			))
		}
		leftCol = append(leftCol, m.renderPanel("Recommendations", strings.Join(recs, "\n\n")))
	}

	// RIGHT COLUMN
	var rightCol []string

	// Slowest Endpoints
	if len(perf.SlowestEndpoints) > 0 {
		var endpoints []string
		for i, ep := range perf.SlowestEndpoints {
			if i >= 12 {
				break
			}

			// Color code based on response time
			avgTimeColor := "15"
			if ep.AvgResponseTime > 1.0 {
				avgTimeColor = "1" // Red for > 1s
			} else if ep.AvgResponseTime > 0.5 {
				avgTimeColor = "3" // Yellow for > 0.5s
			}

			avgTimeStyled := lipgloss.NewStyle().Foreground(lipgloss.Color(avgTimeColor)).Render(fmt.Sprintf("%.3fs", ep.AvgResponseTime))

			endpoints = append(endpoints, fmt.Sprintf(
				"%s\n  Avg: %s | Requests: %s | Errors: %s",
				truncate(ep.Endpoint, 55), avgTimeStyled, formatNumber(ep.Count), formatNumber(ep.ErrorCount),
			))
		}
		rightCol = append(rightCol, m.renderPanel("Slowest Endpoints", strings.Join(endpoints, "\n\n")))
	}

	// Combine columns
	leftColStr := lipgloss.JoinVertical(lipgloss.Left, leftCol...)
	rightColStr := lipgloss.JoinVertical(lipgloss.Left, rightCol...)

	colWidth := (m.width - 6) / 2
	leftStyle := lipgloss.NewStyle().Width(colWidth)
	rightStyle := lipgloss.NewStyle().Width(colWidth)

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		leftStyle.Render(leftColStr),
		rightStyle.Render(rightColStr),
	)
}

func (m Model) renderBots() string {
	if m.botData == nil {
		return "No bot data available"
	}

	bot := m.botData
	var sections []string

	// Bot Summary
	summary := fmt.Sprintf(
		"%s %s\n%s %d\n%s %.1f%%",
		keyStyle.Render("Total Bot Requests:"), formatNumber(bot.TotalBotRequests),
		keyStyle.Render("Unique Bots:"), bot.UniqueBots,
		keyStyle.Render("Bot Traffic:"), bot.BotTrafficPct,
	)
	sections = append(sections, m.renderPanel("Bot Summary", summary))

	// Bots by Category
	if len(bot.BotsByCategory) > 0 {
		var categories []string
		for category, count := range bot.BotsByCategory {
			categories = append(categories, fmt.Sprintf("%s %s", keyStyle.Render(category+":"), formatNumber(count)))
		}
		sections = append(sections, m.renderPanel("Bots by Category", strings.Join(categories, "\n")))
	}

	// Top Bots
	if len(bot.TopBots) > 0 {
		var bots []string
		for i, b := range bot.TopBots {
			if i >= 8 {
				break
			}
			bots = append(bots, fmt.Sprintf(
				"%s\n  Category: %s, Requests: %s, Legitimacy: %.0f",
				truncate(b.UserAgent, 60), b.Category, formatNumber(b.Count), b.LegitimacyScore,
			))
		}
		sections = append(sections, m.renderPanel("Top Bots", strings.Join(bots, "\n\n")))
	}

	// AI Bots
	if len(bot.AIBots) > 0 {
		var aiBots []string
		for i, b := range bot.AIBots {
			if i >= 5 {
				break
			}
			aiBots = append(aiBots, fmt.Sprintf(
				"%s - %s requests",
				truncate(b.UserAgent, 50), formatNumber(b.Count),
			))
		}
		sections = append(sections, m.renderPanel("AI/LLM Bots", strings.Join(aiBots, "\n")))
	}

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m Model) renderPanel(title, content string) string {
	titleBar := titleStyle.Render(title)

	panel := panelStyle.
		Width(m.width - 4).
		Render(content)

	return lipgloss.JoinVertical(lipgloss.Left, titleBar, panel)
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
