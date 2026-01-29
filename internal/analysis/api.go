package analysis

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/montanaflynn/stats"
)

// APIAnalyzer provides API endpoint analysis
type APIAnalyzer struct {
	mu           sync.RWMutex
	endpoints    map[string]*apiEndpointData
	graphqlOps   map[string]*graphqlOpData
	platforms    map[string]int64
	totalAPIReqs int64
}

type apiEndpointData struct {
	endpoint      string
	method        string
	count         int64
	responseTimes []float64
	errorCount    int64
	statusCodes   map[int]int64
}

type graphqlOpData struct {
	operation     string
	count         int64
	responseTimes []float64
	errorCount    int64
}

// NewAPIAnalyzer creates a new API analyzer
func NewAPIAnalyzer() *APIAnalyzer {
	return &APIAnalyzer{
		endpoints:  make(map[string]*apiEndpointData),
		graphqlOps: make(map[string]*graphqlOpData),
		platforms:  make(map[string]int64),
	}
}

// AnalyzeEntry analyzes a log entry for API patterns
func (a *APIAnalyzer) AnalyzeEntry(entry *models.LogEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.isAPIRequest(entry.Path) {
		return
	}

	a.totalAPIReqs++

	// Detect platform
	platform := a.detectPlatform(entry.Path)
	if platform != "" {
		a.platforms[platform]++
	}

	// Analyze endpoint
	key := entry.Method + " " + entry.Path
	if _, exists := a.endpoints[key]; !exists {
		a.endpoints[key] = &apiEndpointData{
			endpoint:      entry.Path,
			method:        entry.Method,
			responseTimes: make([]float64, 0),
			statusCodes:   make(map[int]int64),
		}
	}

	ep := a.endpoints[key]
	ep.count++
	ep.responseTimes = append(ep.responseTimes, entry.ResponseTime)
	ep.statusCodes[entry.Status]++
	if entry.Status >= 400 {
		ep.errorCount++
	}

	// Analyze GraphQL if applicable
	if strings.Contains(strings.ToLower(entry.Path), "graphql") {
		a.analyzeGraphQL(entry)
	}
}

// isAPIRequest checks if a request is an API request
func (a *APIAnalyzer) isAPIRequest(path string) bool {
	apiPatterns := []string{
		"/api/", "/rest/", "/graphql", "/wp-json/",
		"/store-api/", "/v1/", "/v2/", "/v3/",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range apiPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	return false
}

// detectPlatform detects the platform from the request path
func (a *APIAnalyzer) detectPlatform(path string) string {
	lowerPath := strings.ToLower(path)

	// WordPress/WooCommerce
	if strings.Contains(lowerPath, "wp-json") || strings.Contains(lowerPath, "wc-api") {
		return "woocommerce"
	}

	// Magento
	if strings.Contains(lowerPath, "/rest/v1") || strings.Contains(lowerPath, "/graphql") {
		if strings.Contains(lowerPath, "magento") || regexp.MustCompile(`/rest/v\d+/`).MatchString(lowerPath) {
			return "magento"
		}
	}

	// Shopware
	if strings.Contains(lowerPath, "store-api") || strings.Contains(lowerPath, "/api/") {
		if strings.Contains(lowerPath, "shopware") {
			return "shopware"
		}
	}

	// PrestaShop
	if strings.Contains(lowerPath, "prestashop") {
		return "prestashop"
	}

	return "generic"
}

// analyzeGraphQL analyzes GraphQL operations
func (a *APIAnalyzer) analyzeGraphQL(entry *models.LogEntry) {
	// Try to extract operation name from path or referer
	// This is a simplified version - real implementation would parse POST body
	operation := "unknown"

	// Common GraphQL operations
	commonOps := []string{
		"IntrospectionQuery", "GetProduct", "AddToCart", "GetCart",
		"GetCustomer", "GetCategories", "GetCmsPage", "Checkout",
	}

	for _, op := range commonOps {
		if strings.Contains(entry.Path, op) || strings.Contains(entry.Referer, op) {
			operation = op
			break
		}
	}

	if _, exists := a.graphqlOps[operation]; !exists {
		a.graphqlOps[operation] = &graphqlOpData{
			operation:     operation,
			responseTimes: make([]float64, 0),
		}
	}

	gql := a.graphqlOps[operation]
	gql.count++
	gql.responseTimes = append(gql.responseTimes, entry.ResponseTime)
	if entry.Status >= 400 {
		gql.errorCount++
	}
}

// GetAPISummary returns API analysis summary
func (a *APIAnalyzer) GetAPISummary() *models.APISummary {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Determine primary platform
	var primaryPlatform string
	var maxCount int64
	for platform, count := range a.platforms {
		if count > maxCount {
			maxCount = count
			primaryPlatform = platform
		}
	}

	// Calculate overall error rate and avg response time
	totalErrors := int64(0)
	var allResponseTimes []float64
	for _, ep := range a.endpoints {
		totalErrors += ep.errorCount
		allResponseTimes = append(allResponseTimes, ep.responseTimes...)
	}

	errorRate := float64(0)
	if a.totalAPIReqs > 0 {
		errorRate = float64(totalErrors) / float64(a.totalAPIReqs)
	}

	avgResponseTime := float64(0)
	if len(allResponseTimes) > 0 {
		avgResponseTime, _ = stats.Mean(allResponseTimes)
	}

	summary := &models.APISummary{
		TotalAPIRequests: a.totalAPIReqs,
		UniqueEndpoints:  len(a.endpoints),
		PlatformDetected: primaryPlatform,
		Endpoints:        a.getTopEndpoints(20),
		GraphQLOps:       a.getGraphQLStats(),
		ErrorRate:        errorRate,
		AvgResponseTime:  avgResponseTime,
	}

	return summary
}

// getTopEndpoints returns top N endpoints
func (a *APIAnalyzer) getTopEndpoints(n int) []models.EndpointStat {
	endpoints := make([]models.EndpointStat, 0, len(a.endpoints))

	for _, ep := range a.endpoints {
		avgRT := float64(0)
		p95RT := float64(0)
		if len(ep.responseTimes) > 0 {
			avgRT, _ = stats.Mean(ep.responseTimes)
			p95RT, _ = stats.Percentile(ep.responseTimes, 95)
		}

		errorRate := float64(0)
		if ep.count > 0 {
			errorRate = float64(ep.errorCount) / float64(ep.count)
		}

		endpoints = append(endpoints, models.EndpointStat{
			Endpoint:        ep.endpoint,
			Method:          ep.method,
			Count:           ep.count,
			AvgResponseTime: avgRT,
			P95ResponseTime: p95RT,
			ErrorCount:      ep.errorCount,
			ErrorRate:       errorRate,
			StatusCodes:     ep.statusCodes,
		})
	}

	// Sort by count
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].Count > endpoints[j].Count
	})

	if n < len(endpoints) {
		return endpoints[:n]
	}
	return endpoints
}

// getGraphQLStats returns GraphQL operation statistics
func (a *APIAnalyzer) getGraphQLStats() []models.GraphQLStat {
	gqlStats := make([]models.GraphQLStat, 0, len(a.graphqlOps))

	for _, gql := range a.graphqlOps {
		avgRT := float64(0)
		if len(gql.responseTimes) > 0 {
			avgRT, _ = stats.Mean(gql.responseTimes)
		}

		gqlStats = append(gqlStats, models.GraphQLStat{
			Operation:       gql.operation,
			Count:           gql.count,
			AvgResponseTime: avgRT,
			ErrorCount:      gql.errorCount,
		})
	}

	// Sort by count
	sort.Slice(gqlStats, func(i, j int) bool {
		return gqlStats[i].Count > gqlStats[j].Count
	})

	return gqlStats
}

// GetEndpointDetails returns detailed statistics for a specific endpoint
func (a *APIAnalyzer) GetEndpointDetails(endpoint string) *models.EndpointStat {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for key, ep := range a.endpoints {
		if strings.Contains(key, endpoint) {
			avgRT := float64(0)
			p95RT := float64(0)
			if len(ep.responseTimes) > 0 {
				avgRT, _ = stats.Mean(ep.responseTimes)
				p95RT, _ = stats.Percentile(ep.responseTimes, 95)
			}

			errorRate := float64(0)
			if ep.count > 0 {
				errorRate = float64(ep.errorCount) / float64(ep.count)
			}

			return &models.EndpointStat{
				Endpoint:        ep.endpoint,
				Method:          ep.method,
				Count:           ep.count,
				AvgResponseTime: avgRT,
				P95ResponseTime: p95RT,
				ErrorCount:      ep.errorCount,
				ErrorRate:       errorRate,
				StatusCodes:     ep.statusCodes,
			}
		}
	}

	return nil
}

// Reset clears all API analysis data
func (a *APIAnalyzer) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.endpoints = make(map[string]*apiEndpointData)
	a.graphqlOps = make(map[string]*graphqlOpData)
	a.platforms = make(map[string]int64)
	a.totalAPIReqs = 0
}
