package aggregators

import (
	"sort"
	"sync"
	"time"

	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/montanaflynn/stats"
)

// StatisticsAggregator aggregates statistics from log entries
type StatisticsAggregator struct {
	mu            sync.RWMutex
	totalRequests int64
	statusCounts  map[int]int64
	methodCounts  map[string]int64
	pathStats     map[string]*pathStats
	ipStats       map[string]*ipStats
	countryCounts map[string]*countryStats
	uaStats       map[string]*uaStats
	browserStats  map[string]int64
	osStats       map[string]int64
	responseTimes []float64
	totalBytes    int64
	botRequests   int64
	humanRequests int64
	errorCount    int64
	minTime       time.Time
	maxTime       time.Time
}

type pathStats struct {
	count         int64
	bytes         int64
	responseTimes []float64
	errorCount    int64
	statusCounts  map[int]int64
	handlers      map[string]int64
}

type ipStats struct {
	count       int64
	bytes       int64
	errorCount  int64
	country     string
	isBot       bool
	paths       map[string]bool
	timestamps  []time.Time
	threats     []string
	threatScore float64
}

type countryStats struct {
	count       int64
	bytes       int64
	ips         map[string]bool
	errorCount  int64
	threatScore float64
}

type uaStats struct {
	count   int64
	isBot   bool
	botType string
}

// NewStatisticsAggregator creates a new statistics aggregator
func NewStatisticsAggregator() *StatisticsAggregator {
	return &StatisticsAggregator{
		statusCounts:  make(map[int]int64),
		methodCounts:  make(map[string]int64),
		pathStats:     make(map[string]*pathStats),
		ipStats:       make(map[string]*ipStats),
		countryCounts: make(map[string]*countryStats),
		uaStats:       make(map[string]*uaStats),
		browserStats:  make(map[string]int64),
		osStats:       make(map[string]int64),
		responseTimes: make([]float64, 0),
	}
}

// AddEntry adds a log entry to the aggregator
func (a *StatisticsAggregator) AddEntry(entry *models.LogEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.totalRequests++
	a.totalBytes += entry.BytesSent
	a.statusCounts[entry.Status]++
	a.methodCounts[entry.Method]++
	a.responseTimes = append(a.responseTimes, entry.ResponseTime)

	// Track time range
	if a.minTime.IsZero() || entry.Timestamp.Before(a.minTime) {
		a.minTime = entry.Timestamp
	}
	if entry.Timestamp.After(a.maxTime) {
		a.maxTime = entry.Timestamp
	}

	// Track bot vs human
	if entry.IsBot {
		a.botRequests++
	} else {
		a.humanRequests++
	}

	// Track errors
	if entry.Status >= 400 {
		a.errorCount++
	}

	// Path statistics
	if _, exists := a.pathStats[entry.Path]; !exists {
		a.pathStats[entry.Path] = &pathStats{
			responseTimes: make([]float64, 0),
			statusCounts:  make(map[int]int64),
			handlers:      make(map[string]int64),
		}
	}
	ps := a.pathStats[entry.Path]
	ps.count++
	ps.bytes += entry.BytesSent
	ps.responseTimes = append(ps.responseTimes, entry.ResponseTime)
	ps.statusCounts[entry.Status]++
	if entry.Handler != "" {
		ps.handlers[entry.Handler]++
	}
	if entry.Status >= 400 {
		ps.errorCount++
	}

	// IP statistics
	ipStr := entry.IP.String()
	if _, exists := a.ipStats[ipStr]; !exists {
		a.ipStats[ipStr] = &ipStats{
			country:    entry.Country,
			isBot:      entry.IsBot,
			paths:      make(map[string]bool),
			timestamps: make([]time.Time, 0),
			threats:    make([]string, 0),
		}
	}
	ips := a.ipStats[ipStr]
	ips.count++
	ips.bytes += entry.BytesSent
	ips.paths[entry.Path] = true
	ips.timestamps = append(ips.timestamps, entry.Timestamp)
	if entry.Status >= 400 {
		ips.errorCount++
	}

	// Country statistics
	if entry.Country != "" {
		if _, exists := a.countryCounts[entry.Country]; !exists {
			a.countryCounts[entry.Country] = &countryStats{
				ips: make(map[string]bool),
			}
		}
		cs := a.countryCounts[entry.Country]
		cs.count++
		cs.bytes += entry.BytesSent
		cs.ips[ipStr] = true
		if entry.Status >= 400 {
			cs.errorCount++
		}
	}

	// User agent statistics
	if entry.UserAgent != "" {
		if _, exists := a.uaStats[entry.UserAgent]; !exists {
			a.uaStats[entry.UserAgent] = &uaStats{
				isBot: entry.IsBot,
			}
		}
		a.uaStats[entry.UserAgent].count++
	}

	// Browser and OS statistics
	if entry.ParsedUA != nil {
		if entry.ParsedUA.Browser != "" {
			a.browserStats[entry.ParsedUA.Browser]++
		}
		if entry.ParsedUA.OS != "" {
			a.osStats[entry.ParsedUA.OS]++
		}
	}
}

// GetSummary returns aggregated statistics
func (a *StatisticsAggregator) GetSummary() *models.Statistics {
	a.mu.RLock()
	defer a.mu.RUnlock()

	summary := &models.Statistics{
		TotalRequests:   a.totalRequests,
		UniqueIPs:       len(a.ipStats),
		UniqueCountries: len(a.countryCounts),
		TotalBytes:      a.totalBytes,
		StatusCounts:    a.statusCounts,
		MethodCounts:    a.methodCounts,
		BotTraffic:      a.botRequests,
		HumanTraffic:    a.humanRequests,
	}

	// Calculate error rate
	if a.totalRequests > 0 {
		summary.ErrorRate = float64(a.errorCount) / float64(a.totalRequests)
	}

	// Calculate response time stats
	if len(a.responseTimes) > 0 {
		summary.AvgResponseTime, _ = stats.Mean(a.responseTimes)
		summary.MedianResponseTime, _ = stats.Median(a.responseTimes)

		if p95, err := stats.Percentile(a.responseTimes, 95); err == nil {
			summary.P95ResponseTime = p95
		}
		if p99, err := stats.Percentile(a.responseTimes, 99); err == nil {
			summary.P99ResponseTime = p99
		}
	}

	// Time range
	if !a.minTime.IsZero() {
		summary.TimeRange = &models.TimeRange{
			Start: a.minTime,
			End:   a.maxTime,
		}
	}

	// Top paths
	summary.TopPaths = a.getTopPaths(10)

	// Top IPs
	summary.TopIPs = a.getTopIPs(10)

	// Top countries
	summary.TopCountries = a.getTopCountries(10)

	// Top user agents
	summary.TopUserAgents = a.getTopUserAgents(10)

	return summary
}

// GetTopPaths returns top N paths by request count
func (a *StatisticsAggregator) GetTopPaths(n int) []models.PathStat {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.getTopPaths(n)
}

func (a *StatisticsAggregator) getTopPaths(n int) []models.PathStat {
	paths := make([]models.PathStat, 0, len(a.pathStats))

	for path, ps := range a.pathStats {
		pathStat := models.PathStat{
			Path:         path,
			Count:        ps.count,
			Bytes:        ps.bytes,
			ErrorCount:   ps.errorCount,
			StatusCounts: ps.statusCounts,
		}

		if ps.count > 0 {
			pathStat.ErrorRate = float64(ps.errorCount) / float64(ps.count)
		}

		if len(ps.responseTimes) > 0 {
			pathStat.AvgResponseTime, _ = stats.Mean(ps.responseTimes)
			if max, err := stats.Max(ps.responseTimes); err == nil {
				pathStat.MaxResponseTime = max
			}
			if min, err := stats.Min(ps.responseTimes); err == nil {
				pathStat.MinResponseTime = min
			}
		}

		paths = append(paths, pathStat)
	}

	// Sort by count
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Count > paths[j].Count
	})

	if n < len(paths) {
		return paths[:n]
	}
	return paths
}

// getMostCommonHandler returns the most common handler for a path
func getMostCommonHandler(handlers map[string]int64) string {
	if len(handlers) == 0 {
		return ""
	}

	var maxHandler string
	var maxCount int64
	for handler, count := range handlers {
		if count > maxCount {
			maxCount = count
			maxHandler = handler
		}
	}
	return maxHandler
}

// GetTopIPs returns top N IPs by request count
func (a *StatisticsAggregator) GetTopIPs(n int) []models.IPStat {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.getTopIPs(n)
}

func (a *StatisticsAggregator) getTopIPs(n int) []models.IPStat {
	ips := make([]models.IPStat, 0, len(a.ipStats))

	for ip, is := range a.ipStats {
		ipStat := models.IPStat{
			IP:          ip,
			Country:     is.country,
			Count:       is.count,
			Bytes:       is.bytes,
			ErrorCount:  is.errorCount,
			IsBot:       is.isBot,
			UniqueURLs:  len(is.paths),
			Threats:     is.threats,
			ThreatScore: is.threatScore,
		}

		// Calculate average interval between requests
		if len(is.timestamps) > 1 {
			var totalInterval float64
			for i := 1; i < len(is.timestamps); i++ {
				totalInterval += is.timestamps[i].Sub(is.timestamps[i-1]).Seconds()
			}
			ipStat.AvgInterval = totalInterval / float64(len(is.timestamps)-1)
		}

		if len(is.timestamps) > 0 {
			ipStat.FirstSeen = is.timestamps[0]
			ipStat.LastSeen = is.timestamps[len(is.timestamps)-1]
		}

		ips = append(ips, ipStat)
	}

	// Sort by count
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].Count > ips[j].Count
	})

	if n < len(ips) {
		return ips[:n]
	}
	return ips
}

// GetTopCountries returns top N countries by request count
func (a *StatisticsAggregator) GetTopCountries(n int) []models.CountryStat {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.getTopCountries(n)
}

func (a *StatisticsAggregator) getTopCountries(n int) []models.CountryStat {
	countries := make([]models.CountryStat, 0, len(a.countryCounts))

	for country, cs := range a.countryCounts {
		countryStat := models.CountryStat{
			Country:     country,
			Count:       cs.count,
			Bytes:       cs.bytes,
			UniqueIPs:   len(cs.ips),
			ErrorCount:  cs.errorCount,
			ThreatScore: cs.threatScore,
		}

		countries = append(countries, countryStat)
	}

	// Sort by count
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Count > countries[j].Count
	})

	if n < len(countries) {
		return countries[:n]
	}
	return countries
}

// GetTopUserAgents returns top N user agents by request count
func (a *StatisticsAggregator) getTopUserAgents(n int) []models.UserAgentStat {
	uas := make([]models.UserAgentStat, 0, len(a.uaStats))

	for ua, us := range a.uaStats {
		uaStat := models.UserAgentStat{
			UserAgent: ua,
			Count:     us.count,
			IsBot:     us.isBot,
			BotType:   us.botType,
		}
		uas = append(uas, uaStat)
	}

	// Sort by count
	sort.Slice(uas, func(i, j int) bool {
		return uas[i].Count > uas[j].Count
	})

	if n < len(uas) {
		return uas[:n]
	}
	return uas
}

// GetResponseTimeStats returns detailed response time statistics
func (a *StatisticsAggregator) GetResponseTimeStats() *models.ResponseTimeStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.responseTimes) == 0 {
		return &models.ResponseTimeStats{}
	}

	rtStats := &models.ResponseTimeStats{
		Total: int64(len(a.responseTimes)),
	}

	rtStats.Mean, _ = stats.Mean(a.responseTimes)
	rtStats.Median, _ = stats.Median(a.responseTimes)
	rtStats.Min, _ = stats.Min(a.responseTimes)
	rtStats.Max, _ = stats.Max(a.responseTimes)
	rtStats.StdDev, _ = stats.StandardDeviation(a.responseTimes)

	rtStats.P50, _ = stats.Percentile(a.responseTimes, 50)
	rtStats.P75, _ = stats.Percentile(a.responseTimes, 75)
	rtStats.P90, _ = stats.Percentile(a.responseTimes, 90)
	rtStats.P95, _ = stats.Percentile(a.responseTimes, 95)
	rtStats.P99, _ = stats.Percentile(a.responseTimes, 99)

	return rtStats
}

// GetBandwidthStats returns bandwidth statistics
func (a *StatisticsAggregator) GetBandwidthStats() *models.BandwidthStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	bwStats := &models.BandwidthStats{
		TotalBytes: a.totalBytes,
		TotalMB:    float64(a.totalBytes) / 1024 / 1024,
		TotalGB:    float64(a.totalBytes) / 1024 / 1024 / 1024,
	}

	if a.totalRequests > 0 {
		bwStats.AvgBytesPerReq = float64(a.totalBytes) / float64(a.totalRequests)
	}

	// Find max and min bytes per request
	if len(a.pathStats) > 0 {
		first := true
		for _, ps := range a.pathStats {
			avgBytes := ps.bytes / ps.count
			if first || avgBytes > bwStats.MaxBytesPerReq {
				bwStats.MaxBytesPerReq = avgBytes
				first = false
			}
			if avgBytes < bwStats.MinBytesPerReq || bwStats.MinBytesPerReq == 0 {
				bwStats.MinBytesPerReq = avgBytes
			}
		}
	}

	return bwStats
}

// TimelineAggregator aggregates statistics over time
type TimelineAggregator struct {
	mu          sync.RWMutex
	buckets     map[time.Time]*models.TimeBucket
	granularity time.Duration
}

// NewTimelineAggregator creates a new timeline aggregator
func NewTimelineAggregator(granularity time.Duration) *TimelineAggregator {
	return &TimelineAggregator{
		buckets:     make(map[time.Time]*models.TimeBucket),
		granularity: granularity,
	}
}

// AddEntry adds a log entry to the timeline
func (t *TimelineAggregator) AddEntry(entry *models.LogEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Round timestamp to granularity
	bucketTime := entry.Timestamp.Truncate(t.granularity)

	if _, exists := t.buckets[bucketTime]; !exists {
		t.buckets[bucketTime] = &models.TimeBucket{
			Timestamp:    bucketTime,
			StatusCounts: make(map[int]int64),
		}
	}

	bucket := t.buckets[bucketTime]
	bucket.Count++
	bucket.Bytes += entry.BytesSent
	bucket.StatusCounts[entry.Status]++

	if entry.Status >= 400 {
		bucket.ErrorCount++
	}

	// Update average response time
	oldAvg := bucket.AvgResponseTime
	bucket.AvgResponseTime = (oldAvg*float64(bucket.Count-1) + entry.ResponseTime) / float64(bucket.Count)
}

// GetTimeline returns timeline buckets sorted by time
func (t *TimelineAggregator) GetTimeline() []models.TimeBucket {
	t.mu.RLock()
	defer t.mu.RUnlock()

	timeline := make([]models.TimeBucket, 0, len(t.buckets))
	for _, bucket := range t.buckets {
		timeline = append(timeline, *bucket)
	}

	// Sort by timestamp
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Timestamp.Before(timeline[j].Timestamp)
	})

	return timeline
}

// RealTimeAggregator maintains a sliding window of recent entries
type RealTimeAggregator struct {
	mu         sync.RWMutex
	window     time.Duration
	entries    []*models.LogEntry
	aggregator *StatisticsAggregator
}

// NewRealTimeAggregator creates a new real-time aggregator
func NewRealTimeAggregator(window time.Duration) *RealTimeAggregator {
	return &RealTimeAggregator{
		window:     window,
		entries:    make([]*models.LogEntry, 0),
		aggregator: NewStatisticsAggregator(),
	}
}

// AddEntry adds an entry and maintains the sliding window
func (r *RealTimeAggregator) AddEntry(entry *models.LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Add entry
	r.entries = append(r.entries, entry)

	// Remove old entries outside the window
	cutoff := time.Now().Add(-r.window)
	newStart := 0
	for i, e := range r.entries {
		if e.Timestamp.After(cutoff) {
			newStart = i
			break
		}
	}
	r.entries = r.entries[newStart:]

	// Rebuild aggregator with current window
	r.aggregator = NewStatisticsAggregator()
	for _, e := range r.entries {
		r.aggregator.AddEntry(e)
	}
}

// GetCurrentStats returns statistics for the current window
func (r *RealTimeAggregator) GetCurrentStats() *models.Statistics {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.aggregator.GetSummary()
}

// BrowserStat represents browser statistics
type BrowserStat struct {
	Browser string
	Count   int64
}

// OSStat represents operating system statistics
type OSStat struct {
	OS    string
	Count int64
}

// GetTopBrowsers returns top N browsers by request count
func (a *StatisticsAggregator) GetTopBrowsers(n int) []BrowserStat {
	a.mu.RLock()
	defer a.mu.RUnlock()

	browsers := make([]BrowserStat, 0, len(a.browserStats))
	for browser, count := range a.browserStats {
		browsers = append(browsers, BrowserStat{
			Browser: browser,
			Count:   count,
		})
	}

	// Sort by count
	sort.Slice(browsers, func(i, j int) bool {
		return browsers[i].Count > browsers[j].Count
	})

	if n < len(browsers) {
		return browsers[:n]
	}
	return browsers
}

// GetTopOS returns top N operating systems by request count
func (a *StatisticsAggregator) GetTopOS(n int) []OSStat {
	a.mu.RLock()
	defer a.mu.RUnlock()

	oses := make([]OSStat, 0, len(a.osStats))
	for os, count := range a.osStats {
		oses = append(oses, OSStat{
			OS:    os,
			Count: count,
		})
	}

	// Sort by count
	sort.Slice(oses, func(i, j int) bool {
		return oses[i].Count > oses[j].Count
	})

	if n < len(oses) {
		return oses[:n]
	}
	return oses
}

// GetIPsByCountry returns IPs grouped by country
func (a *StatisticsAggregator) GetIPsByCountry(country string, n int) []models.IPStat {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ips := make([]models.IPStat, 0)
	for ip, is := range a.ipStats {
		if is.country == country {
			ipStat := models.IPStat{
				IP:         ip,
				Country:    is.country,
				Count:      is.count,
				Bytes:      is.bytes,
				ErrorCount: is.errorCount,
				IsBot:      is.isBot,
				UniqueURLs: len(is.paths),
			}
			ips = append(ips, ipStat)
		}
	}

	// Sort by count
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].Count > ips[j].Count
	})

	if n < len(ips) {
		return ips[:n]
	}
	return ips
}

// GetPathHandler returns the most common handler for a path
func (a *StatisticsAggregator) GetPathHandler(path string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if ps, exists := a.pathStats[path]; exists {
		return getMostCommonHandler(ps.handlers)
	}
	return ""
}
