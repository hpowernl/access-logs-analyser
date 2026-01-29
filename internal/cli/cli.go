package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/hpowernl/hlogcli/internal/aggregators"
	"github.com/hpowernl/hlogcli/internal/analysis"
	"github.com/hpowernl/hlogcli/internal/dns"
	"github.com/hpowernl/hlogcli/internal/export"
	"github.com/hpowernl/hlogcli/internal/hypernode"
	"github.com/hpowernl/hlogcli/internal/logreader"
	"github.com/hpowernl/hlogcli/internal/ui"
	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	daysAgo      int
	useYesterday bool
	logFile      string
	exportFormat string
	exportFile   string
	noColor      bool
)

// RootCmd is the root command
var RootCmd = &cobra.Command{
	Use:   "hlogcli",
	Short: "Hypernode Log Analyzer - Advanced log analysis for Hypernode",
	Long: `Hypernode Log Analyzer provides comprehensive log analysis for Hypernode environments.
	
Features include:
  - Security threat detection
  - Performance analysis
  - Bot classification
  - API endpoint analysis
  - E-commerce platform analysis
  - Anomaly detection`,
	Version: "1.0.0",
}

func init() {
	// Global flags
	RootCmd.PersistentFlags().IntVar(&daysAgo, "days-ago", 0, "Days ago to analyze (0 = today)")
	RootCmd.PersistentFlags().BoolVar(&useYesterday, "yesterday", false, "Analyze yesterday's logs")
	RootCmd.PersistentFlags().StringVarP(&logFile, "file", "f", "", "Log file to analyze (instead of Hypernode command)")
	RootCmd.PersistentFlags().StringVar(&exportFormat, "export", "", "Export format (csv, json, text)")
	RootCmd.PersistentFlags().StringVarP(&exportFile, "output", "o", "", "Output file for export")
	RootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	// Add subcommands
	RootCmd.AddCommand(analyzeCmd)
	RootCmd.AddCommand(securityCmd)
	RootCmd.AddCommand(perfCmd)
	RootCmd.AddCommand(ecommerceCmd)
	RootCmd.AddCommand(botsCmd)
	RootCmd.AddCommand(apiCmd)
	RootCmd.AddCommand(contentCmd)
	RootCmd.AddCommand(anomaliesCmd)
	RootCmd.AddCommand(searchCmd)
	RootCmd.AddCommand(nginxCmd)
}

// Execute runs the CLI
func Execute() error {
	return RootCmd.Execute()
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Comprehensive log analysis",
	Long:  "Analyze logs with traffic insights and statistics",
	RunE:  runAnalyze,
}

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security threat detection and analysis",
	Long:  "Detect and analyze security threats including SQL injection, XSS, brute force",
	RunE:  runSecurity,
}

var perfCmd = &cobra.Command{
	Use:   "perf",
	Short: "Performance analysis",
	Long:  "Analyze response times, cache effectiveness, and performance bottlenecks",
	RunE:  runPerformance,
}

var ecommerceCmd = &cobra.Command{
	Use:   "ecommerce",
	Short: "E-commerce platform analysis",
	Long:  "Analyze e-commerce platforms (Magento, WooCommerce, Shopware)",
	RunE:  runEcommerce,
}

var botsCmd = &cobra.Command{
	Use:   "bots",
	Short: "Bot classification and analysis",
	Long:  "Classify and analyze bot traffic including AI/LLM bots",
	RunE:  runBots,
}

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "API endpoint analysis",
	Long:  "Analyze API endpoints and GraphQL operations",
	RunE:  runAPI,
}

var contentCmd = &cobra.Command{
	Use:   "content",
	Short: "Content type and resource analysis",
	Long:  "Analyze content types, file extensions, and SEO issues",
	RunE:  runContent,
}

var anomaliesCmd = &cobra.Command{
	Use:   "anomalies",
	Short: "Machine learning-based anomaly detection",
	Long:  "Detect anomalies in traffic patterns using statistical analysis",
	RunE:  runAnomalies,
}

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Advanced search and filtering",
	Long:  "Search logs with flexible filtering options",
	RunE:  runSearch,
}

var (
	nginxOption string
)

var nginxCmd = &cobra.Command{
	Use:   "nginx",
	Short: "Generate Nginx block configurations",
	Long:  "Generate Nginx deny rules for suspicious IPs based on threat scores and error rates",
	RunE:  runNginx,
}

func init() {
	nginxCmd.Flags().StringVarP(&nginxOption, "option", "t", "", "Block option: critical (>=70), all, or error100 (100% error rate)")
}

// Command implementations
func runAnalyze(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	entriesChan, err := getLogEntries(ctx)
	if err != nil {
		return err
	}

	// Collect entries into a slice for processing by multiple analyzers
	var entries []*models.LogEntry
	for entry := range entriesChan {
		entries = append(entries, entry)
	}

	// Initialize analyzers
	agg := aggregators.NewStatisticsAggregator()
	secAnalyzer := analysis.NewSecurityAnalyzer()
	botAnalyzer := analysis.NewBotAnalyzer()

	// Process entries through all analyzers
	for _, entry := range entries {
		agg.AddEntry(entry)
		secAnalyzer.AnalyzeEntry(entry)
		botAnalyzer.AnalyzeEntry(entry)
	}

	// Get aggregated statistics
	stats := agg.GetSummary()
	secSummary := secAnalyzer.GetSecuritySummary()
	botSummary := botAnalyzer.GetBotSummary()

	// Get browser and OS statistics
	browserStats := agg.GetTopBrowsers(10)
	osStats := agg.GetTopOS(10)

	// Convert aggregator browser/OS stats to UI types
	uiBrowserStats := make([]ui.BrowserStat, len(browserStats))
	for i, bs := range browserStats {
		uiBrowserStats[i] = ui.BrowserStat{Browser: bs.Browser, Count: bs.Count}
	}
	uiOSStats := make([]ui.OSStat, len(osStats))
	for i, os := range osStats {
		uiOSStats[i] = ui.OSStat{OS: os.OS, Count: os.Count}
	}

	// Get path handlers for top paths
	pathHandlers := make(map[string]string)
	for _, path := range stats.TopPaths {
		handler := agg.GetPathHandler(path.Path)
		if handler != "" {
			pathHandlers[path.Path] = handler
		}
	}

	// Perform reverse DNS lookups for top IPs
	reverseDNS := make(map[string]string)
	if len(stats.TopIPs) > 0 {
		dnsLookup := dns.NewDNSLookup()
		topIPs := stats.TopIPs
		if len(topIPs) > 15 {
			topIPs = topIPs[:15]
		}
		ipList := make([]string, len(topIPs))
		for i, ip := range topIPs {
			ipList[i] = ip.IP
		}
		reverseDNS = dnsLookup.BulkReverseLookup(ipList)
	}

	// Get max response time
	rtStats := agg.GetResponseTimeStats()
	maxResponseTime := rtStats.Max

	// Create comprehensive data
	compData := &ui.ComprehensiveData{
		Statistics:      stats,
		SecuritySummary: secSummary,
		BotSummary:      botSummary,
		BrowserStats:    uiBrowserStats,
		OSStats:         uiOSStats,
		PathHandlers:    pathHandlers,
		ReverseDNS:      reverseDNS,
		MaxResponseTime: maxResponseTime,
	}

	// Display results
	consoleUI := ui.NewConsoleUI(!noColor)
	consoleUI.DisplayComprehensiveSummary(compData)

	// Export if requested
	if exportFormat != "" && exportFile != "" {
		exporter := export.NewDataExporter()
		switch exportFormat {
		case "csv":
			return exporter.ExportToCSV(stats, exportFile)
		case "json":
			return exporter.ExportToJSON(stats, exportFile)
		case "text":
			return export.CreateReportSummary(stats, exportFile)
		}
	}

	return nil
}

func runSecurity(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	entriesChan, err := getLogEntries(ctx)
	if err != nil {
		return err
	}

	// Collect entries into a slice for processing by multiple analyzers
	var entries []*models.LogEntry
	for entry := range entriesChan {
		entries = append(entries, entry)
	}

	// Initialize analyzers
	agg := aggregators.NewStatisticsAggregator()
	secAnalyzer := analysis.NewSecurityAnalyzer()

	// Process entries through both analyzers
	for _, entry := range entries {
		agg.AddEntry(entry)
		secAnalyzer.AnalyzeEntry(entry)
	}

	// Get aggregated statistics
	stats := agg.GetSummary()
	report := secAnalyzer.GetSecuritySummary()

	// Enhance report with aggregator stats
	report.TotalRequests = stats.TotalRequests
	report.UniqueIPs = stats.UniqueIPs

	// Calculate total errors from status codes
	totalErrors := int64(0)
	for status, count := range stats.StatusCounts {
		if status >= 400 {
			totalErrors += count
		}
	}
	report.TotalErrors = totalErrors

	// Display results
	consoleUI := ui.NewConsoleUI(!noColor)
	consoleUI.DisplaySecurityReport(report)

	// Export if requested
	if exportFormat == "json" && exportFile != "" {
		exporter := export.NewDataExporter()
		return exporter.ExportSecurityReport(report, exportFile)
	}

	return nil
}

func runNginx(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	entriesChan, err := getLogEntries(ctx)
	if err != nil {
		return err
	}

	// Collect entries into a slice
	var entries []*models.LogEntry
	for entry := range entriesChan {
		entries = append(entries, entry)
	}

	// Initialize analyzers
	agg := aggregators.NewStatisticsAggregator()
	secAnalyzer := analysis.NewSecurityAnalyzer()

	// Process entries through both analyzers
	for _, entry := range entries {
		agg.AddEntry(entry)
		secAnalyzer.AnalyzeEntry(entry)
	}

	// Get aggregated statistics
	stats := agg.GetSummary()
	report := secAnalyzer.GetSecuritySummary()

	// Enhance report with aggregator stats
	report.TotalRequests = stats.TotalRequests
	report.UniqueIPs = stats.UniqueIPs

	// Calculate total errors from status codes
	totalErrors := int64(0)
	for status, count := range stats.StatusCounts {
		if status >= 400 {
			totalErrors += count
		}
	}
	report.TotalErrors = totalErrors

	// Interactive option selection if not provided via flag
	if nginxOption == "" {
		fmt.Println("\nNGINX BLOCK CONFIGURATION OPTIONS")
		fmt.Println("==================================")
		fmt.Println()
		fmt.Println("Choose which IPs to block:")
		fmt.Println()
		fmt.Println("  1) Critical Threats (Threat Score >= 70)")
		fmt.Println("     - Most conservative, only blocks severe threats")
		fmt.Println("     - Recommended for production environments")
		fmt.Println()
		fmt.Println("  2) All Suspicious IPs (Complete Block List)")
		fmt.Println("     - Most aggressive, blocks all detected threats")
		fmt.Println("     - May include false positives")
		fmt.Println()
		fmt.Println("  3) 100% Error Rate Only (Zero Success)")
		fmt.Println("     - Safest option, only blocks IPs with no successful requests")
		fmt.Println("     - Good balance between security and safety")
		fmt.Println()
		fmt.Print("Enter your choice (1-3): ")

		var choice string
		_, err := fmt.Scanln(&choice)
		if err != nil {
			return fmt.Errorf("failed to read choice: %w", err)
		}

		switch choice {
		case "1":
			nginxOption = "critical"
		case "2":
			nginxOption = "all"
		case "3":
			nginxOption = "error100"
		default:
			return fmt.Errorf("invalid choice: %s (must be 1, 2, or 3)", choice)
		}
	}

	// Display Nginx block configurations with selected option
	consoleUI := ui.NewConsoleUI(!noColor)
	consoleUI.DisplayNginxBlockConfig(report, nginxOption)

	return nil
}

func runPerformance(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	entries, err := getLogEntries(ctx)
	if err != nil {
		return err
	}

	// Performance analysis
	perfAnalyzer := analysis.NewPerformanceAnalyzer(1.0)
	for entry := range entries {
		perfAnalyzer.AnalyzeEntry(entry)
	}

	report := perfAnalyzer.GetPerformanceReport()

	// Display results
	consoleUI := ui.NewConsoleUI(!noColor)
	consoleUI.DisplayPerformanceReport(report)

	// Export if requested
	if exportFormat == "json" && exportFile != "" {
		exporter := export.NewDataExporter()
		return exporter.ExportPerformanceReport(report, exportFile)
	}

	return nil
}

func runEcommerce(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	entries, err := getLogEntries(ctx)
	if err != nil {
		return err
	}

	// E-commerce analysis
	ecommAnalyzer := analysis.NewEcommerceAnalyzer()
	for entry := range entries {
		ecommAnalyzer.AnalyzeEntry(entry)
	}

	summary := ecommAnalyzer.GetEcommerceSummary()

	// Display results
	fmt.Printf("Platform: %s\n", summary.Platform)
	fmt.Printf("Total Requests: %d\n", summary.TotalRequests)
	fmt.Printf("\nFunnel Analysis:\n")
	fmt.Printf("  Product Views: %d\n", summary.FunnelAnalysis.ProductViews)
	fmt.Printf("  Cart Adds: %d\n", summary.FunnelAnalysis.CartAdds)
	fmt.Printf("  Checkouts: %d\n", summary.FunnelAnalysis.Checkouts)
	fmt.Printf("  Orders: %d\n", summary.FunnelAnalysis.Orders)
	fmt.Printf("  Drop-off Rate: %.2f%%\n", summary.FunnelAnalysis.DropOffRate*100)

	return nil
}

func runBots(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	entries, err := getLogEntries(ctx)
	if err != nil {
		return err
	}

	// Bot analysis
	botAnalyzer := analysis.NewBotAnalyzer()
	for entry := range entries {
		botAnalyzer.AnalyzeEntry(entry)
	}

	report := botAnalyzer.GetBotSummary()

	// Display results
	consoleUI := ui.NewConsoleUI(!noColor)
	consoleUI.DisplayBotReport(report)

	// Export if requested
	if exportFormat == "json" && exportFile != "" {
		exporter := export.NewDataExporter()
		return exporter.ExportBotReport(report, exportFile)
	}

	return nil
}

func runAPI(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	entries, err := getLogEntries(ctx)
	if err != nil {
		return err
	}

	// API analysis
	apiAnalyzer := analysis.NewAPIAnalyzer()
	for entry := range entries {
		apiAnalyzer.AnalyzeEntry(entry)
	}

	summary := apiAnalyzer.GetAPISummary()

	fmt.Printf("Platform: %s\n", summary.PlatformDetected)
	fmt.Printf("Total API Requests: %d\n", summary.TotalAPIRequests)
	fmt.Printf("Unique Endpoints: %d\n", summary.UniqueEndpoints)
	fmt.Printf("Average Response Time: %.3fs\n", summary.AvgResponseTime)
	fmt.Printf("Error Rate: %.2f%%\n", summary.ErrorRate*100)

	return nil
}

func runContent(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	entries, err := getLogEntries(ctx)
	if err != nil {
		return err
	}

	// Content analysis
	contentAnalyzer := analysis.NewContentAnalyzer()
	for entry := range entries {
		contentAnalyzer.AnalyzeEntry(entry)
	}

	summary := contentAnalyzer.GetContentSummary()

	fmt.Printf("Total Resources: %d\n", summary.TotalResources)
	fmt.Printf("\nResource Categories:\n")
	for category, count := range summary.ResourceCategories {
		fmt.Printf("  %s: %d\n", category, count)
	}

	if len(summary.SEOIssues) > 0 {
		fmt.Printf("\nSEO Issues:\n")
		for _, issue := range summary.SEOIssues {
			fmt.Printf("  [%s] %s: %d occurrences\n", issue.Severity, issue.Type, issue.Count)
		}
	}

	return nil
}

func runAnomalies(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get historical data for baseline
	hc := hypernode.NewHypernodeCommand()
	if !hc.IsAvailable() && logFile == "" {
		return fmt.Errorf("hypernode-parse-nginx-log command not available")
	}

	fmt.Println("Calculating baseline from historical data...")
	historicalData, err := hc.GetHistoricalData(ctx, 7)
	if err != nil {
		return err
	}

	detector := analysis.NewAnomalyDetector(3.0)
	detector.CalculateBaseline(historicalData)

	// Get current data
	entries, err := getLogEntries(ctx)
	if err != nil {
		return err
	}

	currentData := make([]*models.LogEntry, 0)
	for entry := range entries {
		currentData = append(currentData, entry)
	}

	// Detect anomalies
	anomalies := detector.DetectAnomalies(currentData)

	fmt.Printf("Found %d anomalies\n\n", len(anomalies))
	for _, anomaly := range anomalies {
		fmt.Printf("[%s] %s at %s\n", anomaly.Severity, anomaly.Type, anomaly.Timestamp.Format("2006-01-02 15:04"))
		fmt.Printf("  Value: %.2f, Expected: %.2f, Z-Score: %.2f\n", anomaly.Value, anomaly.Expected, anomaly.ZScore)
		fmt.Printf("  %s\n\n", anomaly.Description)
	}

	return nil
}

func runSearch(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("search command not yet implemented")
}

// Helper function to get log entries
func getLogEntries(ctx context.Context) (<-chan *models.LogEntry, error) {
	if logFile != "" {
		// Read from file
		reader := logreader.NewLogReader()
		entries, errors := reader.ReadFile(ctx, logFile)

		// Handle errors in background
		go func() {
			for err := range errors {
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading log: %v\n", err)
				}
			}
		}()

		return entries, nil
	}

	// Use Hypernode command
	hc := hypernode.NewHypernodeCommand()
	if !hc.IsAvailable() {
		return nil, fmt.Errorf("hypernode-parse-nginx-log command not available, use --file flag")
	}

	days := daysAgo
	if useYesterday {
		days = 1
	}

	entries, errors := hc.GetLogEntries(ctx, []string{}, days)

	// Handle errors in background
	go func() {
		for err := range errors {
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
		}
	}()

	return entries, nil
}
