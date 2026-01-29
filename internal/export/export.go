package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hpowernl/hlogcli/pkg/models"
)

// DataExporter provides data export functionality
type DataExporter struct{}

// NewDataExporter creates a new data exporter
func NewDataExporter() *DataExporter {
	return &DataExporter{}
}

// ExportToCSV exports statistics to CSV format
func (e *DataExporter) ExportToCSV(stats *models.Statistics, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"Metric", "Value"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write statistics
	records := [][]string{
		{"Total Requests", fmt.Sprintf("%d", stats.TotalRequests)},
		{"Unique IPs", fmt.Sprintf("%d", stats.UniqueIPs)},
		{"Unique Countries", fmt.Sprintf("%d", stats.UniqueCountries)},
		{"Total Bytes", fmt.Sprintf("%d", stats.TotalBytes)},
		{"Avg Response Time", fmt.Sprintf("%.3f", stats.AvgResponseTime)},
		{"Median Response Time", fmt.Sprintf("%.3f", stats.MedianResponseTime)},
		{"P95 Response Time", fmt.Sprintf("%.3f", stats.P95ResponseTime)},
		{"P99 Response Time", fmt.Sprintf("%.3f", stats.P99ResponseTime)},
		{"Error Rate", fmt.Sprintf("%.2f%%", stats.ErrorRate*100)},
		{"Bot Traffic", fmt.Sprintf("%d", stats.BotTraffic)},
		{"Human Traffic", fmt.Sprintf("%d", stats.HumanTraffic)},
	}

	for _, record := range records {
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// ExportToJSON exports statistics to JSON format
func (e *DataExporter) ExportToJSON(stats *models.Statistics, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(stats); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

// ExportTimelineCSV exports timeline data to CSV
func (e *DataExporter) ExportTimelineCSV(buckets []models.TimeBucket, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"Timestamp", "Count", "Bytes", "UniqueIPs", "ErrorCount"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write timeline data
	for _, bucket := range buckets {
		record := []string{
			bucket.Timestamp.Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%d", bucket.Count),
			fmt.Sprintf("%d", bucket.Bytes),
			fmt.Sprintf("%d", bucket.UniqueIPs),
			fmt.Sprintf("%d", bucket.ErrorCount),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// CreateReportSummary creates a text report summary
func CreateReportSummary(stats *models.Statistics, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write report header
	fmt.Fprintf(file, "═══════════════════════════════════════════════\n")
	fmt.Fprintf(file, "          LOG ANALYSIS REPORT                 \n")
	fmt.Fprintf(file, "═══════════════════════════════════════════════\n\n")

	// Overall statistics
	fmt.Fprintf(file, "OVERALL STATISTICS\n")
	fmt.Fprintf(file, "─────────────────────────────────────────────\n")
	fmt.Fprintf(file, "Total Requests:      %d\n", stats.TotalRequests)
	fmt.Fprintf(file, "Unique IPs:          %d\n", stats.UniqueIPs)
	fmt.Fprintf(file, "Unique Countries:    %d\n", stats.UniqueCountries)
	fmt.Fprintf(file, "Total Bytes:         %.2f MB\n", float64(stats.TotalBytes)/1024/1024)
	fmt.Fprintf(file, "Bot Traffic:         %d (%.1f%%)\n", stats.BotTraffic, float64(stats.BotTraffic)/float64(stats.TotalRequests)*100)
	fmt.Fprintf(file, "Human Traffic:       %d (%.1f%%)\n\n", stats.HumanTraffic, float64(stats.HumanTraffic)/float64(stats.TotalRequests)*100)

	// Performance statistics
	fmt.Fprintf(file, "PERFORMANCE METRICS\n")
	fmt.Fprintf(file, "─────────────────────────────────────────────\n")
	fmt.Fprintf(file, "Avg Response Time:   %.3fs\n", stats.AvgResponseTime)
	fmt.Fprintf(file, "Median Response Time: %.3fs\n", stats.MedianResponseTime)
	fmt.Fprintf(file, "P95 Response Time:   %.3fs\n", stats.P95ResponseTime)
	fmt.Fprintf(file, "P99 Response Time:   %.3fs\n", stats.P99ResponseTime)
	fmt.Fprintf(file, "Error Rate:          %.2f%%\n\n", stats.ErrorRate*100)

	// Top paths
	if len(stats.TopPaths) > 0 {
		fmt.Fprintf(file, "TOP PATHS\n")
		fmt.Fprintf(file, "─────────────────────────────────────────────\n")
		for i, path := range stats.TopPaths {
			if i >= 10 {
				break
			}
			fmt.Fprintf(file, "%2d. %s (%d requests)\n", i+1, path.Path, path.Count)
		}
		fmt.Fprintf(file, "\n")
	}

	// Top countries
	if len(stats.TopCountries) > 0 {
		fmt.Fprintf(file, "TOP COUNTRIES\n")
		fmt.Fprintf(file, "─────────────────────────────────────────────\n")
		for i, country := range stats.TopCountries {
			if i >= 10 {
				break
			}
			fmt.Fprintf(file, "%2d. %s (%d requests, %d IPs)\n", i+1, country.Country, country.Count, country.UniqueIPs)
		}
		fmt.Fprintf(file, "\n")
	}

	// Status code distribution
	if len(stats.StatusCounts) > 0 {
		fmt.Fprintf(file, "STATUS CODE DISTRIBUTION\n")
		fmt.Fprintf(file, "─────────────────────────────────────────────\n")
		for status, count := range stats.StatusCounts {
			pct := float64(count) / float64(stats.TotalRequests) * 100
			fmt.Fprintf(file, "%d: %d (%.1f%%)\n", status, count, pct)
		}
		fmt.Fprintf(file, "\n")
	}

	return nil
}

// ExportSecurityReport exports security analysis report
func (e *DataExporter) ExportSecurityReport(summary *models.SecuritySummary, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(summary)
}

// ExportBotReport exports bot analysis report
func (e *DataExporter) ExportBotReport(summary *models.BotSummary, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(summary)
}

// ExportPerformanceReport exports performance analysis report
func (e *DataExporter) ExportPerformanceReport(report *models.PerformanceReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(report)
}
