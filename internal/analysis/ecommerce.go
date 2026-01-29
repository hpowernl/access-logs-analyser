package analysis

import (
	"strings"
	"sync"

	"github.com/hpowernl/hlogcli/internal/config"
	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/montanaflynn/stats"
)

// EcommerceAnalyzer provides e-commerce platform analysis
type EcommerceAnalyzer struct {
	mu             sync.RWMutex
	platform       string
	categoryStats  map[string]*categoryData
	funnelData     *funnelData
	checkoutErrors map[string]int64
	graphqlStats   map[string]*graphqlData
}

type categoryData struct {
	category      string
	count         int64
	responseTimes []float64
	errorCount    int64
}

type funnelData struct {
	productViews int64
	cartAdds     int64
	checkouts    int64
	orders       int64
}

type graphqlData struct {
	operation     string
	count         int64
	responseTimes []float64
	errorCount    int64
}

// NewEcommerceAnalyzer creates a new e-commerce analyzer
func NewEcommerceAnalyzer() *EcommerceAnalyzer {
	return &EcommerceAnalyzer{
		categoryStats:  make(map[string]*categoryData),
		funnelData:     &funnelData{},
		checkoutErrors: make(map[string]int64),
		graphqlStats:   make(map[string]*graphqlData),
	}
}

// AnalyzeEntry analyzes a log entry for e-commerce patterns
func (e *EcommerceAnalyzer) AnalyzeEntry(entry *models.LogEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Detect platform if not set
	if e.platform == "" {
		e.platform = e.detectPlatform(entry.Path)
	}

	// Categorize request
	category := e.categorizeRequest(entry.Path, e.platform)
	if category == "" {
		return
	}

	// Update category statistics
	if _, exists := e.categoryStats[category]; !exists {
		e.categoryStats[category] = &categoryData{
			category:      category,
			responseTimes: make([]float64, 0),
		}
	}

	cat := e.categoryStats[category]
	cat.count++
	cat.responseTimes = append(cat.responseTimes, entry.ResponseTime)
	if entry.Status >= 400 {
		cat.errorCount++
	}

	// Update funnel data
	e.updateFunnel(category, entry.Status)

	// Track checkout errors
	if category == "checkout" && entry.Status >= 400 {
		e.checkoutErrors[entry.Path]++
	}

	// Track GraphQL if Magento
	if e.platform == "magento" && strings.Contains(strings.ToLower(entry.Path), "graphql") {
		e.trackGraphQL(entry)
	}
}

// detectPlatform detects the e-commerce platform
func (e *EcommerceAnalyzer) detectPlatform(path string) string {
	lowerPath := strings.ToLower(path)

	for platform, patterns := range config.EcommercePlatforms {
		for _, pattern := range patterns {
			if strings.Contains(lowerPath, strings.ToLower(pattern)) {
				return platform
			}
		}
	}

	return ""
}

// categorizeRequest categorizes an e-commerce request
func (e *EcommerceAnalyzer) categorizeRequest(path, platform string) string {
	lowerPath := strings.ToLower(path)

	// Common categories across platforms
	if strings.Contains(lowerPath, "product") || strings.Contains(lowerPath, "catalog") {
		return "product"
	}
	if strings.Contains(lowerPath, "cart") || strings.Contains(lowerPath, "basket") {
		return "cart"
	}
	if strings.Contains(lowerPath, "checkout") || strings.Contains(lowerPath, "payment") {
		return "checkout"
	}
	if strings.Contains(lowerPath, "account") || strings.Contains(lowerPath, "customer") {
		return "account"
	}
	if strings.Contains(lowerPath, "search") || strings.Contains(lowerPath, "catalogsearch") {
		return "search"
	}
	if strings.Contains(lowerPath, "order") {
		return "order"
	}

	// Platform-specific patterns
	switch platform {
	case "magento":
		if strings.Contains(lowerPath, "/rest/v1/") || strings.Contains(lowerPath, "/graphql") {
			return "api"
		}
		if strings.Contains(lowerPath, "customer/section/load") {
			return "customer_section"
		}
	case "woocommerce":
		if strings.Contains(lowerPath, "wc-ajax") {
			return "ajax"
		}
		if strings.Contains(lowerPath, "wp-json/wc") {
			return "api"
		}
	case "shopware":
		if strings.Contains(lowerPath, "store-api") {
			return "api"
		}
		if strings.Contains(lowerPath, "/account") {
			return "account"
		}
	}

	return ""
}

// updateFunnel updates conversion funnel data
func (e *EcommerceAnalyzer) updateFunnel(category string, status int) {
	if status >= 400 {
		return // Don't count errors in funnel
	}

	switch category {
	case "product":
		e.funnelData.productViews++
	case "cart":
		e.funnelData.cartAdds++
	case "checkout":
		e.funnelData.checkouts++
	case "order":
		e.funnelData.orders++
	}
}

// trackGraphQL tracks GraphQL operations for Magento
func (e *EcommerceAnalyzer) trackGraphQL(entry *models.LogEntry) {
	// Simplified - would need to parse POST body for real operation name
	operation := "graphql_query"

	if _, exists := e.graphqlStats[operation]; !exists {
		e.graphqlStats[operation] = &graphqlData{
			operation:     operation,
			responseTimes: make([]float64, 0),
		}
	}

	gql := e.graphqlStats[operation]
	gql.count++
	gql.responseTimes = append(gql.responseTimes, entry.ResponseTime)
	if entry.Status >= 400 {
		gql.errorCount++
	}
}

// GetEcommerceSummary returns e-commerce analysis summary
func (e *EcommerceAnalyzer) GetEcommerceSummary() *models.EcommerceSummary {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Build category stats
	categoryStats := make(map[string]*models.CategoryStat)
	totalReqs := int64(0)

	for name, cat := range e.categoryStats {
		avgRT := float64(0)
		if len(cat.responseTimes) > 0 {
			avgRT, _ = stats.Mean(cat.responseTimes)
		}

		errorRate := float64(0)
		if cat.count > 0 {
			errorRate = float64(cat.errorCount) / float64(cat.count)
		}

		categoryStats[name] = &models.CategoryStat{
			Category:        name,
			Count:           cat.count,
			AvgResponseTime: avgRT,
			ErrorCount:      cat.errorCount,
			ErrorRate:       errorRate,
		}

		totalReqs += cat.count
	}

	// Build checkout errors
	checkoutErrs := make([]models.CheckoutError, 0)
	for path, count := range e.checkoutErrors {
		checkoutErrs = append(checkoutErrs, models.CheckoutError{
			Path:      path,
			Count:     count,
			ErrorType: "checkout_error",
		})
	}

	// Build GraphQL stats
	graphqlStats := make([]models.GraphQLStat, 0)
	for _, gql := range e.graphqlStats {
		avgRT := float64(0)
		if len(gql.responseTimes) > 0 {
			avgRT, _ = stats.Mean(gql.responseTimes)
		}

		graphqlStats = append(graphqlStats, models.GraphQLStat{
			Operation:       gql.operation,
			Count:           gql.count,
			AvgResponseTime: avgRT,
			ErrorCount:      gql.errorCount,
		})
	}

	// Calculate funnel drop-off
	dropOffRate := float64(0)
	if e.funnelData.productViews > 0 {
		dropOffRate = 1.0 - (float64(e.funnelData.orders) / float64(e.funnelData.productViews))
	}

	summary := &models.EcommerceSummary{
		Platform:      e.platform,
		TotalRequests: totalReqs,
		CategoryStats: categoryStats,
		FunnelAnalysis: &models.FunnelAnalysis{
			ProductViews: e.funnelData.productViews,
			CartAdds:     e.funnelData.cartAdds,
			Checkouts:    e.funnelData.checkouts,
			Orders:       e.funnelData.orders,
			DropOffRate:  dropOffRate,
		},
		CheckoutErrors: checkoutErrs,
		GraphQLStats:   graphqlStats,
	}

	return summary
}

// Reset clears all e-commerce analysis data
func (e *EcommerceAnalyzer) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.platform = ""
	e.categoryStats = make(map[string]*categoryData)
	e.funnelData = &funnelData{}
	e.checkoutErrors = make(map[string]int64)
	e.graphqlStats = make(map[string]*graphqlData)
}
