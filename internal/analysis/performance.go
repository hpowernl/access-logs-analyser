package analysis

import (
	"sort"
	"sync"

	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/montanaflynn/stats"
)

// PerformanceAnalyzer provides performance analysis functionality
type PerformanceAnalyzer struct {
	mu            sync.RWMutex
	endpointStats map[string]*endpointPerf
	handlerStats  map[string]*handlerPerf
	responseTimes []float64
	slowThreshold float64
}

type endpointPerf struct {
	path          string
	count         int64
	responseTimes []float64
	bytes         int64
	errorCount    int64
	methods       map[string]int64
}

type handlerPerf struct {
	handler       string
	count         int64
	responseTimes []float64
	bytes         int64
	errorCount    int64
	cacheHits     int64
	cacheMisses   int64
}

// NewPerformanceAnalyzer creates a new performance analyzer
func NewPerformanceAnalyzer(slowThreshold float64) *PerformanceAnalyzer {
	if slowThreshold == 0 {
		slowThreshold = 1.0 // Default: 1 second
	}
	return &PerformanceAnalyzer{
		endpointStats: make(map[string]*endpointPerf),
		handlerStats:  make(map[string]*handlerPerf),
		responseTimes: make([]float64, 0),
		slowThreshold: slowThreshold,
	}
}

// AnalyzeEntry analyzes a log entry for performance metrics
func (p *PerformanceAnalyzer) AnalyzeEntry(entry *models.LogEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Track overall response times
	p.responseTimes = append(p.responseTimes, entry.ResponseTime)

	// Endpoint statistics
	if _, exists := p.endpointStats[entry.Path]; !exists {
		p.endpointStats[entry.Path] = &endpointPerf{
			path:          entry.Path,
			responseTimes: make([]float64, 0),
			methods:       make(map[string]int64),
		}
	}
	ep := p.endpointStats[entry.Path]
	ep.count++
	ep.responseTimes = append(ep.responseTimes, entry.ResponseTime)
	ep.bytes += entry.BytesSent
	ep.methods[entry.Method]++
	if entry.Status >= 400 {
		ep.errorCount++
	}

	// Handler statistics
	if entry.Handler != "" {
		if _, exists := p.handlerStats[entry.Handler]; !exists {
			p.handlerStats[entry.Handler] = &handlerPerf{
				handler:       entry.Handler,
				responseTimes: make([]float64, 0),
			}
		}
		hp := p.handlerStats[entry.Handler]
		hp.count++
		hp.responseTimes = append(hp.responseTimes, entry.ResponseTime)
		hp.bytes += entry.BytesSent
		if entry.Status >= 400 {
			hp.errorCount++
		}

		// Track cache hits/misses for varnish
		if entry.Handler == "varnish" {
			if entry.Status == 304 || entry.ResponseTime < 0.01 {
				hp.cacheHits++
			} else {
				hp.cacheMisses++
			}
		}
	}
}

// GetResponseTimeStats returns overall response time statistics
func (p *PerformanceAnalyzer) GetResponseTimeStats() *models.ResponseTimeStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.responseTimes) == 0 {
		return &models.ResponseTimeStats{}
	}

	rtStats := &models.ResponseTimeStats{
		Total: int64(len(p.responseTimes)),
	}

	rtStats.Mean, _ = stats.Mean(p.responseTimes)
	rtStats.Median, _ = stats.Median(p.responseTimes)
	rtStats.Min, _ = stats.Min(p.responseTimes)
	rtStats.Max, _ = stats.Max(p.responseTimes)
	rtStats.StdDev, _ = stats.StandardDeviation(p.responseTimes)

	rtStats.P50, _ = stats.Percentile(p.responseTimes, 50)
	rtStats.P75, _ = stats.Percentile(p.responseTimes, 75)
	rtStats.P90, _ = stats.Percentile(p.responseTimes, 90)
	rtStats.P95, _ = stats.Percentile(p.responseTimes, 95)
	rtStats.P99, _ = stats.Percentile(p.responseTimes, 99)

	return rtStats
}

// GetSlowestEndpoints returns the slowest endpoints
func (p *PerformanceAnalyzer) GetSlowestEndpoints(limit int) []models.EndpointStat {
	p.mu.RLock()
	defer p.mu.RUnlock()

	endpoints := make([]models.EndpointStat, 0, len(p.endpointStats))

	for path, ep := range p.endpointStats {
		if len(ep.responseTimes) == 0 {
			continue
		}

		avgRT, _ := stats.Mean(ep.responseTimes)
		p95RT, _ := stats.Percentile(ep.responseTimes, 95)

		errorRate := float64(0)
		if ep.count > 0 {
			errorRate = float64(ep.errorCount) / float64(ep.count)
		}

		endpointStat := models.EndpointStat{
			Endpoint:        path,
			Count:           ep.count,
			AvgResponseTime: avgRT,
			P95ResponseTime: p95RT,
			ErrorCount:      ep.errorCount,
			ErrorRate:       errorRate,
			StatusCodes:     make(map[int]int64),
		}

		endpoints = append(endpoints, endpointStat)
	}

	// Sort by average response time (slowest first)
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].AvgResponseTime > endpoints[j].AvgResponseTime
	})

	if limit < len(endpoints) {
		return endpoints[:limit]
	}
	return endpoints
}

// GetHandlerPerformance returns performance statistics by handler
func (p *PerformanceAnalyzer) GetHandlerPerformance() map[string]*models.HandlerStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	handlerPerf := make(map[string]*models.HandlerStats)

	for handler, hp := range p.handlerStats {
		if len(hp.responseTimes) == 0 {
			continue
		}

		avgRT, _ := stats.Mean(hp.responseTimes)
		p95RT, _ := stats.Percentile(hp.responseTimes, 95)

		errorRate := float64(0)
		if hp.count > 0 {
			errorRate = float64(hp.errorCount) / float64(hp.count)
		}

		handlerPerf[handler] = &models.HandlerStats{
			Handler:         handler,
			Count:           hp.count,
			AvgResponseTime: avgRT,
			P95ResponseTime: p95RT,
			Bytes:           hp.bytes,
			ErrorCount:      hp.errorCount,
			ErrorRate:       errorRate,
		}
	}

	return handlerPerf
}

// GetCacheStats returns cache performance statistics for a specific handler
func (p *PerformanceAnalyzer) GetCacheStats(handler string) *models.CacheStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	hp, exists := p.handlerStats[handler]
	if !exists {
		return nil
	}

	total := hp.cacheHits + hp.cacheMisses
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(hp.cacheHits) / float64(total)
	}

	return &models.CacheStats{
		Handler: handler,
		Hits:    hp.cacheHits,
		Misses:  hp.cacheMisses,
		HitRate: hitRate,
	}
}

// GetOptimizationRecommendations returns performance optimization recommendations
func (p *PerformanceAnalyzer) GetOptimizationRecommendations() []models.Recommendation {
	p.mu.RLock()
	defer p.mu.RUnlock()

	recommendations := make([]models.Recommendation, 0)

	// Check overall response times
	if len(p.responseTimes) > 0 {
		avgRT, _ := stats.Mean(p.responseTimes)
		p95RT, _ := stats.Percentile(p.responseTimes, 95)

		if avgRT > 1.0 {
			recommendations = append(recommendations, models.Recommendation{
				Type:        "response_time",
				Priority:    "high",
				Description: "Average response time is high (>1s)",
				Impact:      "User experience degradation",
				Action:      "Optimize database queries, add caching, or scale resources",
			})
		}

		if p95RT > 3.0 {
			recommendations = append(recommendations, models.Recommendation{
				Type:        "response_time_p95",
				Priority:    "medium",
				Description: "P95 response time is very high (>3s)",
				Impact:      "Poor experience for significant portion of users",
				Action:      "Identify and optimize slowest endpoints",
			})
		}
	}

	// Check for slow endpoints
	slowCount := 0
	for _, ep := range p.endpointStats {
		if len(ep.responseTimes) > 0 {
			avgRT, _ := stats.Mean(ep.responseTimes)
			if avgRT > p.slowThreshold && ep.count > 10 {
				slowCount++
			}
		}
	}

	if slowCount > 0 {
		recommendations = append(recommendations, models.Recommendation{
			Type:        "slow_endpoints",
			Priority:    "high",
			Description: "Multiple slow endpoints detected",
			Impact:      "Performance bottlenecks affecting user experience",
			Action:      "Review and optimize slow endpoints, consider caching",
		})
	}

	// Check cache effectiveness
	for handler, hp := range p.handlerStats {
		if handler == "varnish" {
			total := hp.cacheHits + hp.cacheMisses
			if total > 100 {
				hitRate := float64(hp.cacheHits) / float64(total)
				if hitRate < 0.5 {
					recommendations = append(recommendations, models.Recommendation{
						Type:        "cache_hit_rate",
						Priority:    "high",
						Description: "Low Varnish cache hit rate (<50%)",
						Impact:      "Increased load on backend, slower response times",
						Action:      "Review cache configuration and cache-control headers",
					})
				}
			}
		}
	}

	// Check error rates by handler
	for handler, hp := range p.handlerStats {
		if hp.count > 100 {
			errorRate := float64(hp.errorCount) / float64(hp.count)
			if errorRate > 0.1 {
				recommendations = append(recommendations, models.Recommendation{
					Type:        "handler_errors",
					Priority:    "critical",
					Description: "High error rate for handler: " + handler,
					Impact:      "Service reliability issues",
					Action:      "Investigate and fix errors in " + handler,
				})
			}
		}
	}

	return recommendations
}

// GetPerformanceReport returns a complete performance report
func (p *PerformanceAnalyzer) GetPerformanceReport() *models.PerformanceReport {
	return &models.PerformanceReport{
		ResponseTimeStats: p.GetResponseTimeStats(),
		HandlerStats:      p.GetHandlerPerformance(),
		SlowestEndpoints:  p.GetSlowestEndpoints(10),
		Recommendations:   p.GetOptimizationRecommendations(),
	}
}

// GetSlowRequests returns requests slower than the threshold
func (p *PerformanceAnalyzer) GetSlowRequests() []models.EndpointStat {
	p.mu.RLock()
	defer p.mu.RUnlock()

	slowEndpoints := make([]models.EndpointStat, 0)

	for path, ep := range p.endpointStats {
		if len(ep.responseTimes) == 0 {
			continue
		}

		avgRT, _ := stats.Mean(ep.responseTimes)
		if avgRT > p.slowThreshold {
			slowEndpoints = append(slowEndpoints, models.EndpointStat{
				Endpoint:        path,
				Count:           ep.count,
				AvgResponseTime: avgRT,
			})
		}
	}

	// Sort by average response time
	sort.Slice(slowEndpoints, func(i, j int) bool {
		return slowEndpoints[i].AvgResponseTime > slowEndpoints[j].AvgResponseTime
	})

	return slowEndpoints
}

// Reset clears all performance analysis data
func (p *PerformanceAnalyzer) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.endpointStats = make(map[string]*endpointPerf)
	p.handlerStats = make(map[string]*handlerPerf)
	p.responseTimes = make([]float64, 0)
}
