package filters

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/hpowernl/hlogcli/pkg/models"
)

// LogFilter provides filtering functionality for log entries
type LogFilter struct {
	countries       map[string]bool
	statusCodes     map[int]bool
	excludeBots     bool
	ipRanges        []*net.IPNet
	timeRange       *models.TimeRange
	methods         map[string]bool
	pathPatterns    []*regexp.Regexp
	ignoreBlocked   bool
	blockedStatuses map[int]bool
}

// NewLogFilter creates a new log filter with default settings
func NewLogFilter() *LogFilter {
	return &LogFilter{
		countries:       make(map[string]bool),
		statusCodes:     make(map[int]bool),
		excludeBots:     false,
		ipRanges:        make([]*net.IPNet, 0),
		methods:         make(map[string]bool),
		pathPatterns:    make([]*regexp.Regexp, 0),
		ignoreBlocked:   false,
		blockedStatuses: make(map[int]bool),
	}
}

// ShouldInclude checks if a log entry should be included based on filters
func (f *LogFilter) ShouldInclude(entry *models.LogEntry) bool {
	// Check blocked status
	if f.ignoreBlocked && f.IsBlocked(entry) {
		return false
	}

	// Check bot filter
	if f.excludeBots && entry.IsBot {
		return false
	}

	// Check country filter
	if len(f.countries) > 0 {
		if !f.countries[entry.Country] {
			return false
		}
	}

	// Check status code filter
	if len(f.statusCodes) > 0 {
		if !f.statusCodes[entry.Status] {
			return false
		}
	}

	// Check method filter
	if len(f.methods) > 0 {
		if !f.methods[entry.Method] {
			return false
		}
	}

	// Check IP range filter
	if len(f.ipRanges) > 0 {
		inRange := false
		for _, ipRange := range f.ipRanges {
			if ipRange.Contains(entry.IP) {
				inRange = true
				break
			}
		}
		if !inRange {
			return false
		}
	}

	// Check time range filter
	if f.timeRange != nil {
		if entry.Timestamp.Before(f.timeRange.Start) || entry.Timestamp.After(f.timeRange.End) {
			return false
		}
	}

	// Check path pattern filter
	if len(f.pathPatterns) > 0 {
		matched := false
		for _, pattern := range f.pathPatterns {
			if pattern.MatchString(entry.Path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// AddCountryFilter adds a country filter
func (f *LogFilter) AddCountryFilter(countries []string) {
	for _, country := range countries {
		f.countries[strings.ToUpper(country)] = true
	}
}

// AddStatusFilter adds a status code filter
func (f *LogFilter) AddStatusFilter(codes []int) {
	for _, code := range codes {
		f.statusCodes[code] = true
	}
}

// AddMethodFilter adds an HTTP method filter
func (f *LogFilter) AddMethodFilter(methods []string) {
	for _, method := range methods {
		f.methods[strings.ToUpper(method)] = true
	}
}

// AddIPRangeFilter adds an IP range filter (CIDR notation)
func (f *LogFilter) AddIPRangeFilter(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	f.ipRanges = append(f.ipRanges, ipNet)
	return nil
}

// AddPathPattern adds a path pattern filter (regex)
func (f *LogFilter) AddPathPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	f.pathPatterns = append(f.pathPatterns, re)
	return nil
}

// SetTimeRange sets the time range filter
func (f *LogFilter) SetTimeRange(start, end time.Time) {
	f.timeRange = &models.TimeRange{
		Start: start,
		End:   end,
	}
}

// SetExcludeBots sets whether to exclude bot traffic
func (f *LogFilter) SetExcludeBots(exclude bool) {
	f.excludeBots = exclude
}

// SetIgnoreBlocked sets whether to ignore blocked requests
func (f *LogFilter) SetIgnoreBlocked(ignore bool) {
	f.ignoreBlocked = ignore
}

// SetBlockedStatusCodes sets the status codes to consider as blocked
func (f *LogFilter) SetBlockedStatusCodes(codes []int) {
	f.blockedStatuses = make(map[int]bool)
	for _, code := range codes {
		f.blockedStatuses[code] = true
	}
}

// IsBlocked checks if a log entry is blocked
func (f *LogFilter) IsBlocked(entry *models.LogEntry) bool {
	if len(f.blockedStatuses) == 0 {
		// Default blocked status codes
		return entry.Status == 403 || entry.Status == 429
	}
	return f.blockedStatuses[entry.Status]
}

// Clear resets all filters
func (f *LogFilter) Clear() {
	f.countries = make(map[string]bool)
	f.statusCodes = make(map[int]bool)
	f.excludeBots = false
	f.ipRanges = make([]*net.IPNet, 0)
	f.timeRange = nil
	f.methods = make(map[string]bool)
	f.pathPatterns = make([]*regexp.Regexp, 0)
	f.ignoreBlocked = false
	f.blockedStatuses = make(map[int]bool)
}

// FilterPresets provides common filter presets

// ErrorsOnly creates a filter for error responses only (4xx, 5xx)
func ErrorsOnly() *LogFilter {
	filter := NewLogFilter()
	for i := 400; i < 600; i++ {
		filter.AddStatusFilter([]int{i})
	}
	return filter
}

// SuccessOnly creates a filter for successful responses only (2xx)
func SuccessOnly() *LogFilter {
	filter := NewLogFilter()
	for i := 200; i < 300; i++ {
		filter.AddStatusFilter([]int{i})
	}
	return filter
}

// NoBots creates a filter that excludes bot traffic
func NoBots() *LogFilter {
	filter := NewLogFilter()
	filter.SetExcludeBots(true)
	return filter
}

// APIOnly creates a filter for API endpoints
func APIOnly() *LogFilter {
	filter := NewLogFilter()
	_ = filter.AddPathPattern(`(?i)/(api|graphql|rest|wp-json)`)
	return filter
}

// RecentActivity creates a filter for recent activity within specified hours
func RecentActivity(hours int) *LogFilter {
	filter := NewLogFilter()
	end := time.Now()
	start := end.Add(-time.Duration(hours) * time.Hour)
	filter.SetTimeRange(start, end)
	return filter
}

// ClientErrorsOnly creates a filter for client errors (4xx)
func ClientErrorsOnly() *LogFilter {
	filter := NewLogFilter()
	for i := 400; i < 500; i++ {
		filter.AddStatusFilter([]int{i})
	}
	return filter
}

// ServerErrorsOnly creates a filter for server errors (5xx)
func ServerErrorsOnly() *LogFilter {
	filter := NewLogFilter()
	for i := 500; i < 600; i++ {
		filter.AddStatusFilter([]int{i})
	}
	return filter
}

// SlowRequests creates a filter for requests slower than threshold (seconds)
func SlowRequests(thresholdSeconds float64) func(*models.LogEntry) bool {
	return func(entry *models.LogEntry) bool {
		return entry.ResponseTime >= thresholdSeconds
	}
}

// LargeResponses creates a filter for responses larger than threshold (bytes)
func LargeResponses(thresholdBytes int64) func(*models.LogEntry) bool {
	return func(entry *models.LogEntry) bool {
		return entry.BytesSent >= thresholdBytes
	}
}

// ByCountries creates a filter for specific countries
func ByCountries(countries []string) *LogFilter {
	filter := NewLogFilter()
	filter.AddCountryFilter(countries)
	return filter
}

// ByStatus creates a filter for specific status codes
func ByStatus(codes []int) *LogFilter {
	filter := NewLogFilter()
	filter.AddStatusFilter(codes)
	return filter
}

// ByMethod creates a filter for specific HTTP methods
func ByMethod(methods []string) *LogFilter {
	filter := NewLogFilter()
	filter.AddMethodFilter(methods)
	return filter
}
