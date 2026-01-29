package models

import (
	"net"
	"regexp"
	"time"
)

// LogEntry represents a normalized log entry from Nginx JSON format
type LogEntry struct {
	Timestamp    time.Time
	IP           net.IP
	Method       string
	Path         string
	Status       int
	BytesSent    int64
	ResponseTime float64
	UserAgent    string
	ParsedUA     *UserAgentInfo
	IsBot        bool
	Country      string
	Host         string
	ServerName   string
	Handler      string
	Port         string
	SSLProtocol  string
	SSLCipher    string
	Referer      string
	RemoteUser   string
	Raw          map[string]interface{}
}

// UserAgentInfo contains parsed user agent information
type UserAgentInfo struct {
	Browser string
	OS      string
	Device  string
}

// TimeRange represents a time range filter
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// FilterConfig holds filter configuration
type FilterConfig struct {
	Countries       []string
	StatusCodes     []int
	ExcludeBots     bool
	IPRanges        []*net.IPNet
	TimeRange       *TimeRange
	Methods         []string
	PathPatterns    []*regexp.Regexp
	IgnoreBlocked   bool
	BlockedStatuses []int
}

// Statistics contains aggregated statistics
type Statistics struct {
	TotalRequests      int64
	UniqueIPs          int
	UniqueCountries    int
	TotalBytes         int64
	AvgResponseTime    float64
	MedianResponseTime float64
	P95ResponseTime    float64
	P99ResponseTime    float64
	StatusCounts       map[int]int64
	MethodCounts       map[string]int64
	TopPaths           []PathStat
	TopIPs             []IPStat
	TopCountries       []CountryStat
	TopUserAgents      []UserAgentStat
	BotTraffic         int64
	HumanTraffic       int64
	ErrorRate          float64
	TimeRange          *TimeRange
}

// PathStat contains statistics for a specific path
type PathStat struct {
	Path            string
	Count           int64
	Bytes           int64
	AvgResponseTime float64
	MaxResponseTime float64
	MinResponseTime float64
	ErrorCount      int64
	ErrorRate       float64
	StatusCounts    map[int]int64
}

// IPStat contains statistics for a specific IP address
type IPStat struct {
	IP          string
	Country     string
	Count       int64
	Bytes       int64
	ErrorCount  int64
	IsBot       bool
	UniqueURLs  int
	AvgInterval float64
	ThreatScore float64
	Threats     []string
	FirstSeen   time.Time
	LastSeen    time.Time
	DNSHostname string
}

// CountryStat contains statistics for a specific country
type CountryStat struct {
	Country     string
	CountryName string
	Count       int64
	Bytes       int64
	UniqueIPs   int
	ErrorCount  int64
	ThreatScore float64
}

// UserAgentStat contains statistics for a specific user agent
type UserAgentStat struct {
	UserAgent string
	Count     int64
	IsBot     bool
	BotType   string
}

// ResponseTimeStats contains response time statistics
type ResponseTimeStats struct {
	Mean   float64
	Median float64
	Min    float64
	Max    float64
	P50    float64
	P75    float64
	P90    float64
	P95    float64
	P99    float64
	StdDev float64
	Total  int64
}

// BandwidthStats contains bandwidth statistics
type BandwidthStats struct {
	TotalBytes     int64
	AvgBytesPerReq float64
	MaxBytesPerReq int64
	MinBytesPerReq int64
	TotalMB        float64
	TotalGB        float64
}

// HandlerStats contains statistics for a backend handler
type HandlerStats struct {
	Handler         string
	Count           int64
	AvgResponseTime float64
	P95ResponseTime float64
	Bytes           int64
	ErrorCount      int64
	ErrorRate       float64
}

// TimeBucket represents statistics for a time bucket
type TimeBucket struct {
	Timestamp       time.Time
	Count           int64
	Bytes           int64
	UniqueIPs       int
	AvgResponseTime float64
	ErrorCount      int64
	StatusCounts    map[int]int64
}

// SecuritySummary contains security analysis results
type SecuritySummary struct {
	TotalThreats      int64
	SQLInjectionCount int64
	XSSCount          int64
	DirTraversalCount int64
	CmdInjectionCount int64
	BruteForceCount   int64
	ScanningCount     int64
	SuspiciousIPs     []SuspiciousIP
	ThreatTimeline    []ThreatEvent
	PlatformThreats   map[string]int64
}

// SuspiciousIP represents an IP with suspicious activity
type SuspiciousIP struct {
	IP             string
	Country        string
	ThreatScore    float64
	Threats        []string
	RequestCount   int64
	ErrorCount     int64
	AttackPatterns map[string]int
	FirstSeen      time.Time
	LastSeen       time.Time
	Recommended    string
}

// ThreatEvent represents a security threat event
type ThreatEvent struct {
	Timestamp   time.Time
	IP          string
	ThreatType  string
	Path        string
	Severity    string
	Description string
}

// BotSummary contains bot analysis results
type BotSummary struct {
	TotalBotRequests int64
	UniqueBots       int
	BotTrafficPct    float64
	BotsByCategory   map[string]int64
	TopBots          []BotStat
	AIBots           []BotStat
	LegitimacyScores map[string]float64
}

// BotStat contains statistics for a specific bot
type BotStat struct {
	UserAgent       string
	Category        string
	Count           int64
	Bytes           int64
	AvgInterval     float64
	UniquePaths     int
	LegitimacyScore float64
	IsAIBot         bool
}

// APISummary contains API analysis results
type APISummary struct {
	TotalAPIRequests int64
	UniqueEndpoints  int
	PlatformDetected string
	Endpoints        []EndpointStat
	GraphQLOps       []GraphQLStat
	ErrorRate        float64
	AvgResponseTime  float64
}

// EndpointStat contains statistics for an API endpoint
type EndpointStat struct {
	Endpoint        string
	Method          string
	Count           int64
	AvgResponseTime float64
	P95ResponseTime float64
	ErrorCount      int64
	ErrorRate       float64
	StatusCodes     map[int]int64
}

// GraphQLStat contains GraphQL operation statistics
type GraphQLStat struct {
	Operation       string
	Count           int64
	AvgResponseTime float64
	ErrorCount      int64
}

// EcommerceSummary contains e-commerce analysis results
type EcommerceSummary struct {
	Platform       string
	TotalRequests  int64
	CategoryStats  map[string]*CategoryStat
	FunnelAnalysis *FunnelAnalysis
	CheckoutErrors []CheckoutError
	GraphQLStats   []GraphQLStat
}

// CategoryStat contains statistics for an e-commerce category
type CategoryStat struct {
	Category        string
	Count           int64
	AvgResponseTime float64
	ErrorCount      int64
	ErrorRate       float64
}

// FunnelAnalysis contains conversion funnel analysis
type FunnelAnalysis struct {
	ProductViews int64
	CartAdds     int64
	Checkouts    int64
	Orders       int64
	DropOffRate  float64
}

// CheckoutError represents a checkout error
type CheckoutError struct {
	Path      string
	Count     int64
	ErrorType string
}

// AnomalySummary contains anomaly detection results
type AnomalySummary struct {
	TotalAnomalies int
	Anomalies      []Anomaly
	Baseline       *Baseline
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	Timestamp   time.Time
	Type        string
	Severity    string
	Description string
	Value       float64
	Expected    float64
	ZScore      float64
}

// Baseline contains baseline statistics for anomaly detection
type Baseline struct {
	AvgRequestsPerMinute float64
	StdDevRequests       float64
	AvgErrorRate         float64
	StdDevErrorRate      float64
	AvgResponseTime      float64
	StdDevResponseTime   float64
}

// GeographicSummary contains geographic analysis results
type GeographicSummary struct {
	TotalCountries int
	TopCountries   []CountryStat
	ThreatMap      map[string]*ThreatData
}

// ThreatData contains threat data for a country
type ThreatData struct {
	Country      string
	ThreatScore  float64
	ThreatCount  int64
	RequestCount int64
}

// TimelineSummary contains timeline analysis results
type TimelineSummary struct {
	Buckets         []TimeBucket
	Granularity     time.Duration
	TotalBuckets    int
	PeakTraffic     *TimeBucket
	SecurityEvents  []SecurityEvent
	TrafficPatterns *TrafficPatterns
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	Timestamp time.Time
	EventType string
	IP        string
	Count     int
	Severity  string
}

// TrafficPatterns contains traffic pattern analysis
type TrafficPatterns struct {
	PeakHours        []int
	LowTrafficHours  []int
	WeekendVsWeekday float64
	AverageRPS       float64
	PeakRPS          float64
}

// ContentSummary contains content analysis results
type ContentSummary struct {
	TotalResources     int64
	ContentTypes       map[string]int64
	Extensions         map[string]*ExtensionStat
	ResourceCategories map[string]int64
	SEOIssues          []SEOIssue
}

// ExtensionStat contains statistics for a file extension
type ExtensionStat struct {
	Extension       string
	Count           int64
	Bytes           int64
	AvgResponseTime float64
}

// SEOIssue represents an SEO optimization issue
type SEOIssue struct {
	Type        string
	Description string
	Count       int64
	Severity    string
}

// PerformanceReport contains performance analysis results
type PerformanceReport struct {
	ResponseTimeStats *ResponseTimeStats
	BandwidthStats    *BandwidthStats
	HandlerStats      map[string]*HandlerStats
	SlowestEndpoints  []EndpointStat
	CacheStats        *CacheStats
	Recommendations   []Recommendation
}

// CacheStats contains cache performance statistics
type CacheStats struct {
	Handler     string
	Hits        int64
	Misses      int64
	HitRate     float64
	AvgHitTime  float64
	AvgMissTime float64
}

// Recommendation represents a performance recommendation
type Recommendation struct {
	Type        string
	Priority    string
	Description string
	Impact      string
	Action      string
}
