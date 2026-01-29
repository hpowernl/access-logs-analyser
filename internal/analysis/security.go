package analysis

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hpowernl/hlogcli/internal/config"
	"github.com/hpowernl/hlogcli/pkg/models"
)

// SecurityAnalyzer provides security analysis functionality
type SecurityAnalyzer struct {
	mu                sync.RWMutex
	attackPatterns    map[string]*regexp.Regexp
	suspiciousIPs     map[string]*ipThreatData
	totalThreats      int64
	sqlInjectionCount int64
	xssCount          int64
	dirTraversalCount int64
	cmdInjectionCount int64
	bruteForceCount   int64
	scanningCount     int64
	threatTimeline    []models.ThreatEvent
	platformThreats   map[string]int64
}

type ipThreatData struct {
	ip           string
	country      string
	threats      []string
	requestCount int64
	errorCount   int64
	attackTypes  map[string]int
	firstSeen    time.Time
	lastSeen     time.Time
	threatScore  float64
}

// NewSecurityAnalyzer creates a new security analyzer
func NewSecurityAnalyzer() *SecurityAnalyzer {
	sa := &SecurityAnalyzer{
		suspiciousIPs:   make(map[string]*ipThreatData),
		attackPatterns:  make(map[string]*regexp.Regexp),
		threatTimeline:  make([]models.ThreatEvent, 0),
		platformThreats: make(map[string]int64),
	}

	// Compile attack patterns
	for name, pattern := range config.AttackPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			sa.attackPatterns[name] = re
		}
	}

	return sa
}

// AnalyzeEntry analyzes a log entry for security threats
func (s *SecurityAnalyzer) AnalyzeEntry(entry *models.LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ipStr := entry.IP.String()

	// Initialize IP threat data if not exists
	if _, exists := s.suspiciousIPs[ipStr]; !exists {
		s.suspiciousIPs[ipStr] = &ipThreatData{
			ip:          ipStr,
			country:     entry.Country,
			threats:     make([]string, 0),
			attackTypes: make(map[string]int),
			firstSeen:   entry.Timestamp,
		}
	}

	ipData := s.suspiciousIPs[ipStr]
	ipData.requestCount++
	ipData.lastSeen = entry.Timestamp

	if entry.Status >= 400 {
		ipData.errorCount++
	}

	// Check for attack patterns
	threats := s.checkAttackPatterns(ipStr, entry.Path, entry.UserAgent)
	if len(threats) > 0 {
		s.totalThreats++
		for _, threat := range threats {
			ipData.threats = append(ipData.threats, threat)
			ipData.attackTypes[threat]++

			// Track threat event
			s.threatTimeline = append(s.threatTimeline, models.ThreatEvent{
				Timestamp:   entry.Timestamp,
				IP:          ipStr,
				ThreatType:  threat,
				Path:        entry.Path,
				Severity:    s.getThreatSeverity(threat),
				Description: s.getThreatDescription(threat, entry.Path),
			})
		}
	}

	// Check platform-specific threats
	s.checkPlatformThreats(entry)

	// Check for brute force attempts
	if s.isBruteForceAttempt(entry) {
		s.bruteForceCount++
		ipData.attackTypes["brute_force"]++
	}

	// Check for scanning behavior
	if s.isScanningBehavior(ipData) {
		s.scanningCount++
		ipData.attackTypes["scanning"]++
	}

	// Update threat score
	ipData.threatScore = s.calculateThreatScore(ipData)
}

// checkAttackPatterns checks for various attack patterns
func (s *SecurityAnalyzer) checkAttackPatterns(ip, path, userAgent string) []string {
	threats := make([]string, 0)
	combined := path + " " + userAgent

	for attackType, pattern := range s.attackPatterns {
		if pattern.MatchString(combined) {
			threats = append(threats, attackType)

			// Update attack counters
			switch attackType {
			case "sql_injection":
				s.sqlInjectionCount++
			case "xss":
				s.xssCount++
			case "directory_traversal":
				s.dirTraversalCount++
			case "command_injection":
				s.cmdInjectionCount++
			}
		}
	}

	return threats
}

// checkPlatformThreats checks for platform-specific security threats
func (s *SecurityAnalyzer) checkPlatformThreats(entry *models.LogEntry) {
	path := strings.ToLower(entry.Path)

	// WordPress threats
	if strings.Contains(path, "wp-") || strings.Contains(path, "wordpress") {
		if strings.Contains(path, "wp-login") && entry.Status == 401 {
			s.platformThreats["wordpress_brute_force"]++
		}
		if strings.Contains(path, "wp-admin") && entry.Status == 403 {
			s.platformThreats["wordpress_unauthorized"]++
		}
		if strings.Contains(path, "xmlrpc.php") {
			s.platformThreats["wordpress_xmlrpc_abuse"]++
		}
	}

	// Magento threats
	if strings.Contains(path, "/admin") || strings.Contains(path, "/magento") {
		if strings.Contains(path, "/admin") && entry.Status == 401 {
			s.platformThreats["magento_admin_brute_force"]++
		}
	}

	// Shopware threats
	if strings.Contains(path, "shopware") || strings.Contains(path, "/backend") {
		if strings.Contains(path, "/backend") && entry.Status == 401 {
			s.platformThreats["shopware_admin_brute_force"]++
		}
	}

	// Generic admin path attacks
	for _, adminPath := range config.AdminPaths {
		if strings.Contains(path, adminPath) && entry.Status >= 400 {
			s.platformThreats["admin_path_probe"]++
		}
	}
}

// isBruteForceAttempt checks if an entry indicates a brute force attempt
func (s *SecurityAnalyzer) isBruteForceAttempt(entry *models.LogEntry) bool {
	path := strings.ToLower(entry.Path)

	// Check for login endpoints with failed auth
	loginPaths := []string{
		"login", "signin", "auth", "wp-login", "admin",
		"administrator", "user/login", "account/login",
	}

	for _, loginPath := range loginPaths {
		if strings.Contains(path, loginPath) && (entry.Status == 401 || entry.Status == 403) {
			return true
		}
	}

	return false
}

// isScanningBehavior checks if IP shows scanning behavior
func (s *SecurityAnalyzer) isScanningBehavior(ipData *ipThreatData) bool {
	// High error rate indicates scanning
	if ipData.requestCount > 10 && float64(ipData.errorCount)/float64(ipData.requestCount) > 0.8 {
		return true
	}

	// Many different attack types indicate scanning
	if len(ipData.attackTypes) >= 3 {
		return true
	}

	return false
}

// calculateThreatScore calculates a threat score for an IP (0-100)
func (s *SecurityAnalyzer) calculateThreatScore(ipData *ipThreatData) float64 {
	score := 0.0

	// Base score from attack types
	score += float64(len(ipData.attackTypes)) * 10

	// Add score for each attack type count
	for _, count := range ipData.attackTypes {
		score += float64(count) * 5
	}

	// High error rate increases score
	if ipData.requestCount > 0 {
		errorRate := float64(ipData.errorCount) / float64(ipData.requestCount)
		score += errorRate * 20
	}

	// Many requests in short time increases score
	if !ipData.firstSeen.IsZero() && !ipData.lastSeen.IsZero() {
		duration := ipData.lastSeen.Sub(ipData.firstSeen).Seconds()
		if duration > 0 {
			requestsPerSecond := float64(ipData.requestCount) / duration
			if requestsPerSecond > 10 {
				score += 15
			}
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// getThreatSeverity returns the severity level for a threat type
func (s *SecurityAnalyzer) getThreatSeverity(threatType string) string {
	severityMap := map[string]string{
		"sql_injection":       config.SeverityCritical,
		"command_injection":   config.SeverityCritical,
		"xss":                 config.SeverityHigh,
		"directory_traversal": config.SeverityHigh,
		"file_inclusion":      config.SeverityCritical,
		"brute_force":         config.SeverityMedium,
		"scanning":            config.SeverityLow,
	}

	if severity, ok := severityMap[threatType]; ok {
		return severity
	}
	return config.SeverityLow
}

// getThreatDescription returns a description for a threat
func (s *SecurityAnalyzer) getThreatDescription(threatType, path string) string {
	descriptions := map[string]string{
		"sql_injection":       "SQL injection attempt detected in request",
		"xss":                 "Cross-site scripting (XSS) attempt detected",
		"directory_traversal": "Directory traversal attempt detected",
		"command_injection":   "Command injection attempt detected",
		"file_inclusion":      "File inclusion attempt detected",
		"brute_force":         "Brute force login attempt detected",
		"scanning":            "Security scanning behavior detected",
	}

	if desc, ok := descriptions[threatType]; ok {
		return desc + ": " + path
	}
	return "Security threat detected: " + path
}

// GetSecuritySummary returns a summary of security analysis
func (s *SecurityAnalyzer) GetSecuritySummary() *models.SecuritySummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	summary := &models.SecuritySummary{
		TotalThreats:      s.totalThreats,
		SQLInjectionCount: s.sqlInjectionCount,
		XSSCount:          s.xssCount,
		DirTraversalCount: s.dirTraversalCount,
		CmdInjectionCount: s.cmdInjectionCount,
		BruteForceCount:   s.bruteForceCount,
		ScanningCount:     s.scanningCount,
		SuspiciousIPs:     s.getSuspiciousIPs(20),
		ThreatTimeline:    s.threatTimeline,
		PlatformThreats:   s.platformThreats,
	}

	return summary
}

// GetSuspiciousIPs returns a list of suspicious IPs sorted by threat score
func (s *SecurityAnalyzer) GetSuspiciousIPs(limit int) []models.SuspiciousIP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getSuspiciousIPs(limit)
}

func (s *SecurityAnalyzer) getSuspiciousIPs(limit int) []models.SuspiciousIP {
	// Filter IPs with threats
	suspicious := make([]models.SuspiciousIP, 0)

	for _, ipData := range s.suspiciousIPs {
		if len(ipData.threats) > 0 || ipData.threatScore > 30 {
			ip := models.SuspiciousIP{
				IP:             ipData.ip,
				Country:        ipData.country,
				ThreatScore:    ipData.threatScore,
				Threats:        ipData.threats,
				RequestCount:   ipData.requestCount,
				ErrorCount:     ipData.errorCount,
				AttackPatterns: ipData.attackTypes,
				FirstSeen:      ipData.firstSeen,
				LastSeen:       ipData.lastSeen,
				Recommended:    s.getRecommendation(ipData.threatScore),
			}
			suspicious = append(suspicious, ip)
		}
	}

	// Sort by threat score (highest first)
	for i := 0; i < len(suspicious)-1; i++ {
		for j := i + 1; j < len(suspicious); j++ {
			if suspicious[j].ThreatScore > suspicious[i].ThreatScore {
				suspicious[i], suspicious[j] = suspicious[j], suspicious[i]
			}
		}
	}

	if limit < len(suspicious) {
		return suspicious[:limit]
	}
	return suspicious
}

// getRecommendation returns a recommendation based on threat score
func (s *SecurityAnalyzer) getRecommendation(score float64) string {
	switch {
	case score >= 80:
		return "BLOCK IMMEDIATELY - Critical threat detected"
	case score >= 60:
		return "Consider blocking - High threat level"
	case score >= 40:
		return "Monitor closely - Moderate threat level"
	case score >= 20:
		return "Watch for patterns - Low threat level"
	default:
		return "Continue monitoring"
	}
}

// DetectSQLInjection checks if a path contains SQL injection patterns
func (s *SecurityAnalyzer) DetectSQLInjection(path string) bool {
	if pattern, ok := s.attackPatterns["sql_injection"]; ok {
		return pattern.MatchString(path)
	}
	return false
}

// DetectXSS checks if a path contains XSS patterns
func (s *SecurityAnalyzer) DetectXSS(path string) bool {
	if pattern, ok := s.attackPatterns["xss"]; ok {
		return pattern.MatchString(path)
	}
	return false
}

// DetectDirectoryTraversal checks if a path contains directory traversal patterns
func (s *SecurityAnalyzer) DetectDirectoryTraversal(path string) bool {
	if pattern, ok := s.attackPatterns["directory_traversal"]; ok {
		return pattern.MatchString(path)
	}
	return false
}

// DetectCommandInjection checks if a path contains command injection patterns
func (s *SecurityAnalyzer) DetectCommandInjection(path string) bool {
	if pattern, ok := s.attackPatterns["command_injection"]; ok {
		return pattern.MatchString(path)
	}
	return false
}

// GetThreatTimeline returns security events over time
func (s *SecurityAnalyzer) GetThreatTimeline() []models.ThreatEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.threatTimeline
}

// GetPlatformThreats returns platform-specific threat counts
func (s *SecurityAnalyzer) GetPlatformThreats() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	threats := make(map[string]int64)
	for k, v := range s.platformThreats {
		threats[k] = v
	}
	return threats
}

// Reset clears all security analysis data
func (s *SecurityAnalyzer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.suspiciousIPs = make(map[string]*ipThreatData)
	s.totalThreats = 0
	s.sqlInjectionCount = 0
	s.xssCount = 0
	s.dirTraversalCount = 0
	s.cmdInjectionCount = 0
	s.bruteForceCount = 0
	s.scanningCount = 0
	s.threatTimeline = make([]models.ThreatEvent, 0)
	s.platformThreats = make(map[string]int64)
}
