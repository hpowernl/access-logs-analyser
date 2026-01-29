package analysis

import (
	"fmt"
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

	// Extended threat counters
	sensitiveFileCount      int64
	webShellCount           int64
	log4ShellCount          int64
	ssrfCount               int64
	openRedirectCount       int64
	xxeCount                int64
	crlfInjectionCount      int64
	credentialStuffingCount int64
	apiAbuseCount           int64
	pathTraversalExtCount   int64
	templateInjectionCount  int64
	nosqlInjectionCount     int64
	prototypePollutionCount int64
	httpMethodAnomalyCount  int64
	maliciousUACount        int64
	emptyUACount            int64

	// Detailed tracking maps
	sensitiveFilesAccessed map[string]int64
	webShellsDetected      map[string]int64
	anomalousHTTPMethods   map[string]int64

	// Credential stuffing tracking
	ipLoginAttempts map[string]map[string]bool // IP -> set of usernames
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
		suspiciousIPs:          make(map[string]*ipThreatData),
		attackPatterns:         make(map[string]*regexp.Regexp),
		threatTimeline:         make([]models.ThreatEvent, 0),
		platformThreats:        make(map[string]int64),
		sensitiveFilesAccessed: make(map[string]int64),
		webShellsDetected:      make(map[string]int64),
		anomalousHTTPMethods:   make(map[string]int64),
		ipLoginAttempts:        make(map[string]map[string]bool),
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

	// Phase 1: Core Security Checks
	if s.checkSensitiveFileAccess(entry) {
		s.sensitiveFileCount++
		s.totalThreats++
		ipData.attackTypes["sensitive_files"]++
	}

	if s.checkWebShell(entry) {
		s.webShellCount++
		s.totalThreats++
		ipData.attackTypes["web_shell"]++
	}

	if s.checkLog4Shell(entry) {
		s.log4ShellCount++
		s.totalThreats++
		ipData.attackTypes["log4shell"]++
	}

	if s.checkMaliciousUserAgent(entry) {
		s.maliciousUACount++
		s.totalThreats++
		ipData.attackTypes["malicious_ua"]++
	}

	// Phase 2: Advanced Security Checks
	if s.checkHTTPMethodAnomaly(entry) {
		s.httpMethodAnomalyCount++
		s.totalThreats++
		ipData.attackTypes["http_method_anomaly"]++
	}

	if s.checkSSRF(entry) {
		s.ssrfCount++
		s.totalThreats++
		ipData.attackTypes["ssrf"]++
	}

	if s.checkPathTraversalExtended(entry) {
		s.pathTraversalExtCount++
		s.totalThreats++
		ipData.attackTypes["path_traversal_ext"]++
	}

	if s.checkCredentialStuffing(ipData, entry) {
		s.credentialStuffingCount++
		s.totalThreats++
		ipData.attackTypes["credential_stuffing"]++
	}

	// Phase 3: Medium Impact Security Checks
	if s.checkOpenRedirect(entry) {
		s.openRedirectCount++
		s.totalThreats++
		ipData.attackTypes["open_redirect"]++
	}

	if s.checkXXE(entry) {
		s.xxeCount++
		s.totalThreats++
		ipData.attackTypes["xxe"]++
	}

	if s.checkCRLFInjection(entry) {
		s.crlfInjectionCount++
		s.totalThreats++
		ipData.attackTypes["crlf_injection"]++
	}

	if s.checkAPIAbuse(ipData, entry) {
		s.apiAbuseCount++
		s.totalThreats++
		ipData.attackTypes["api_abuse"]++
	}

	// Phase 4: Additional Coverage Security Checks
	if s.checkTemplateInjection(entry) {
		s.templateInjectionCount++
		s.totalThreats++
		ipData.attackTypes["template_injection"]++
	}

	if s.checkNoSQLInjection(entry) {
		s.nosqlInjectionCount++
		s.totalThreats++
		ipData.attackTypes["nosql_injection"]++
	}

	if s.checkPrototypePollution(entry) {
		s.prototypePollutionCount++
		s.totalThreats++
		ipData.attackTypes["prototype_pollution"]++
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

// calculateThreatScore calculates a threat score for an IP (0-100) with weighted risk levels
func (s *SecurityAnalyzer) calculateThreatScore(ipData *ipThreatData) float64 {
	score := 0.0

	// Critical threats (weight: 25 points each)
	criticalThreats := []string{"web_shell", "log4shell", "xxe", "ssrf", "command_injection", "sql_injection"}
	for _, threat := range criticalThreats {
		if count, ok := ipData.attackTypes[threat]; ok {
			score += float64(count) * 25
		}
	}

	// High threats (weight: 15 points each)
	highThreats := []string{"sensitive_files", "credential_stuffing", "template_injection", "nosql_injection"}
	for _, threat := range highThreats {
		if count, ok := ipData.attackTypes[threat]; ok {
			score += float64(count) * 15
		}
	}

	// Medium threats (weight: 10 points each)
	mediumThreats := []string{"xss", "directory_traversal", "path_traversal_ext", "crlf_injection",
		"open_redirect", "prototype_pollution", "brute_force"}
	for _, threat := range mediumThreats {
		if count, ok := ipData.attackTypes[threat]; ok {
			score += float64(count) * 10
		}
	}

	// Low threats (weight: 5 points each)
	lowThreats := []string{"scanning", "http_method_anomaly", "malicious_ua", "api_abuse"}
	for _, threat := range lowThreats {
		if count, ok := ipData.attackTypes[threat]; ok {
			score += float64(count) * 5
		}
	}

	// High error rate increases score
	if ipData.requestCount > 0 {
		errorRate := float64(ipData.errorCount) / float64(ipData.requestCount)
		score += errorRate * 20
	}

	// Many requests in short time increases score (DDoS indicator)
	if !ipData.firstSeen.IsZero() && !ipData.lastSeen.IsZero() {
		duration := ipData.lastSeen.Sub(ipData.firstSeen).Seconds()
		if duration > 0 {
			requestsPerSecond := float64(ipData.requestCount) / duration
			if requestsPerSecond > 10 {
				score += 15
			}
		}
	}

	// Bonus for variety of attacks (indicates sophisticated attacker)
	if len(ipData.attackTypes) >= 5 {
		score += 10
	} else if len(ipData.attackTypes) >= 3 {
		score += 5
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

	// Calculate categorized IP counts
	suspiciousCount := 0
	ddosCount := 0
	scanningCount := 0
	adminAccessCount := 0

	// Suspicious UA count is the sum of malicious and empty user agents
	suspiciousUACount := int(s.maliciousUACount + s.emptyUACount)

	// Track unique IPs per attack type
	attackTypeIPs := make(map[string]map[string]bool)
	attackTypeIPs["sql_injection"] = make(map[string]bool)
	attackTypeIPs["xss"] = make(map[string]bool)
	attackTypeIPs["directory_traversal"] = make(map[string]bool)
	attackTypeIPs["command_injection"] = make(map[string]bool)
	attackTypeIPs["brute_force"] = make(map[string]bool)
	attackTypeIPs["web_shell"] = make(map[string]bool)
	attackTypeIPs["scanning"] = make(map[string]bool)

	for ip, ipData := range s.suspiciousIPs {
		// Categorize IPs
		if ipData.threatScore >= 30 {
			suspiciousCount++
		}

		// DDoS detection: high request count or high request rate
		if ipData.requestCount > 500 {
			ddosCount++
		} else if !ipData.firstSeen.IsZero() && !ipData.lastSeen.IsZero() {
			duration := ipData.lastSeen.Sub(ipData.firstSeen).Seconds()
			if duration > 0 {
				requestsPerSecond := float64(ipData.requestCount) / duration
				if requestsPerSecond > 10 {
					ddosCount++
				}
			}
		}

		// Scanning detection: high error rate or many attack types
		if ipData.requestCount > 0 {
			errorRate := float64(ipData.errorCount) / float64(ipData.requestCount)
			if errorRate > 0.8 || len(ipData.attackTypes) >= 3 {
				scanningCount++
			}
		}

		// Admin access attempts
		if count, ok := ipData.attackTypes["brute_force"]; ok && count > 0 {
			adminAccessCount++
		}

		// Track unique IPs per attack type
		for attackType := range ipData.attackTypes {
			if attackType == "sql_injection" {
				attackTypeIPs["sql_injection"][ip] = true
			} else if attackType == "xss" {
				attackTypeIPs["xss"][ip] = true
			} else if attackType == "directory_traversal" {
				attackTypeIPs["directory_traversal"][ip] = true
			} else if attackType == "command_injection" {
				attackTypeIPs["command_injection"][ip] = true
			} else if attackType == "brute_force" {
				attackTypeIPs["brute_force"][ip] = true
			} else if attackType == "web_shell" {
				attackTypeIPs["web_shell"][ip] = true
			} else if attackType == "scanning" {
				attackTypeIPs["scanning"][ip] = true
			}
		}
	}

	// Build attack categories with IP counts
	attackCategoriesIPCount := make(map[string]int)
	attackCategoriesIPCount["Brute Force"] = len(attackTypeIPs["brute_force"])
	attackCategoriesIPCount["SQL Injection"] = len(attackTypeIPs["sql_injection"])
	attackCategoriesIPCount["XSS"] = len(attackTypeIPs["xss"])
	attackCategoriesIPCount["Directory Traversal"] = len(attackTypeIPs["directory_traversal"])
	attackCategoriesIPCount["Command Injection"] = len(attackTypeIPs["command_injection"])

	// Build top attack types
	topAttackTypes := []models.AttackTypeStat{}

	if s.dirTraversalCount > 0 {
		topAttackTypes = append(topAttackTypes, models.AttackTypeStat{
			AttackType: "Directory Traversal",
			Attempts:   s.dirTraversalCount,
			UniqueIPs:  len(attackTypeIPs["directory_traversal"]),
		})
	}
	if s.bruteForceCount > 0 {
		topAttackTypes = append(topAttackTypes, models.AttackTypeStat{
			AttackType: "Brute Force",
			Attempts:   s.bruteForceCount,
			UniqueIPs:  len(attackTypeIPs["brute_force"]),
		})
	}
	if s.sqlInjectionCount > 0 {
		topAttackTypes = append(topAttackTypes, models.AttackTypeStat{
			AttackType: "SQL Injection",
			Attempts:   s.sqlInjectionCount,
			UniqueIPs:  len(attackTypeIPs["sql_injection"]),
		})
	}
	if s.xssCount > 0 {
		topAttackTypes = append(topAttackTypes, models.AttackTypeStat{
			AttackType: "XSS",
			Attempts:   s.xssCount,
			UniqueIPs:  len(attackTypeIPs["xss"]),
		})
	}
	if s.cmdInjectionCount > 0 {
		topAttackTypes = append(topAttackTypes, models.AttackTypeStat{
			AttackType: "Command Injection",
			Attempts:   s.cmdInjectionCount,
			UniqueIPs:  len(attackTypeIPs["command_injection"]),
		})
	}
	if s.webShellCount > 0 {
		topAttackTypes = append(topAttackTypes, models.AttackTypeStat{
			AttackType: "Web Shell",
			Attempts:   s.webShellCount,
			UniqueIPs:  len(attackTypeIPs["web_shell"]),
		})
	}
	if s.scanningCount > 0 {
		topAttackTypes = append(topAttackTypes, models.AttackTypeStat{
			AttackType: "Scanning",
			Attempts:   s.scanningCount,
			UniqueIPs:  len(attackTypeIPs["scanning"]),
		})
	}

	// Sort top attack types by attempts (descending)
	for i := 0; i < len(topAttackTypes)-1; i++ {
		for j := i + 1; j < len(topAttackTypes); j++ {
			if topAttackTypes[j].Attempts > topAttackTypes[i].Attempts {
				topAttackTypes[i], topAttackTypes[j] = topAttackTypes[j], topAttackTypes[i]
			}
		}
	}

	// Count unique attack types
	uniqueAttackTypes := 0
	if s.sqlInjectionCount > 0 {
		uniqueAttackTypes++
	}
	if s.xssCount > 0 {
		uniqueAttackTypes++
	}
	if s.dirTraversalCount > 0 {
		uniqueAttackTypes++
	}
	if s.cmdInjectionCount > 0 {
		uniqueAttackTypes++
	}
	if s.bruteForceCount > 0 {
		uniqueAttackTypes++
	}
	if s.scanningCount > 0 {
		uniqueAttackTypes++
	}

	summary := &models.SecuritySummary{
		TotalThreats:      s.totalThreats,
		SQLInjectionCount: s.sqlInjectionCount,
		XSSCount:          s.xssCount,
		DirTraversalCount: s.dirTraversalCount,
		CmdInjectionCount: s.cmdInjectionCount,
		BruteForceCount:   s.bruteForceCount,
		ScanningCount:     s.scanningCount,
		SuspiciousIPs:     s.getSuspiciousIPs(100),
		ThreatTimeline:    s.threatTimeline,
		PlatformThreats:   s.platformThreats,

		// New fields
		AttackAttempts:          s.totalThreats,
		UniqueAttackTypes:       uniqueAttackTypes,
		SuspiciousIPsCount:      suspiciousCount,
		PotentialDDoSIPs:        ddosCount,
		ScanningIPsCount:        scanningCount,
		AdminAccessIPs:          adminAccessCount,
		AttackCategoriesIPCount: attackCategoriesIPCount,
		TopAttackTypes:          topAttackTypes,
		SuspiciousUserAgents:    suspiciousUACount,

		// Extended threat counts
		SensitiveFileAccessCount: s.sensitiveFileCount,
		WebShellCount:            s.webShellCount,
		Log4ShellCount:           s.log4ShellCount,
		SSRFCount:                s.ssrfCount,
		OpenRedirectCount:        s.openRedirectCount,
		XXECount:                 s.xxeCount,
		CRLFInjectionCount:       s.crlfInjectionCount,
		CredentialStuffingCount:  s.credentialStuffingCount,
		APIAbuseCount:            s.apiAbuseCount,
		PathTraversalExtCount:    s.pathTraversalExtCount,
		TemplateInjectionCount:   s.templateInjectionCount,
		NoSQLInjectionCount:      s.nosqlInjectionCount,
		PrototypePollutionCount:  s.prototypePollutionCount,
		HTTPMethodAnomalyCount:   s.httpMethodAnomalyCount,

		// User agent analysis (expanded)
		MaliciousUserAgentCount: s.maliciousUACount,
		EmptyUserAgentCount:     s.emptyUACount,

		// Detailed breakdowns
		SensitiveFilesAccessed: s.sensitiveFilesAccessed,
		WebShellsDetected:      s.webShellsDetected,
		AnomalousHTTPMethods:   s.anomalousHTTPMethods,
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

// Phase 1: Core Security Checks

// checkSensitiveFileAccess detects attempts to access sensitive files
func (s *SecurityAnalyzer) checkSensitiveFileAccess(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["sensitive_files"]; ok {
		if pattern.MatchString(entry.Path) {
			// Extract filename for tracking
			pathLower := strings.ToLower(entry.Path)
			if strings.Contains(pathLower, ".git") {
				s.sensitiveFilesAccessed[".git/"]++
			} else if strings.Contains(pathLower, ".env") {
				s.sensitiveFilesAccessed[".env"]++
			} else if strings.Contains(pathLower, "wp-config") {
				s.sensitiveFilesAccessed["wp-config.php"]++
			} else if strings.Contains(pathLower, "backup.sql") || strings.Contains(pathLower, "dump.sql") {
				s.sensitiveFilesAccessed["database_backups"]++
			} else if strings.Contains(pathLower, ".bak") || strings.Contains(pathLower, ".old") {
				s.sensitiveFilesAccessed["backup_files"]++
			} else {
				s.sensitiveFilesAccessed["other_sensitive"]++
			}
			return true
		}
	}
	return false
}

// checkWebShell detects web shell patterns
func (s *SecurityAnalyzer) checkWebShell(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["web_shell"]; ok {
		combined := entry.Path + " " + entry.UserAgent
		if pattern.MatchString(combined) {
			// Identify shell type
			pathLower := strings.ToLower(combined)
			if strings.Contains(pathLower, "c99") {
				s.webShellsDetected["c99"]++
			} else if strings.Contains(pathLower, "r57") {
				s.webShellsDetected["r57"]++
			} else if strings.Contains(pathLower, "wso") {
				s.webShellsDetected["wso"]++
			} else if strings.Contains(pathLower, "b374k") {
				s.webShellsDetected["b374k"]++
			} else if strings.Contains(pathLower, "eval(") || strings.Contains(pathLower, "base64_decode(") {
				s.webShellsDetected["php_backdoor"]++
			} else {
				s.webShellsDetected["generic"]++
			}
			return true
		}
	}
	return false
}

// checkLog4Shell detects Log4j JNDI injection attempts
func (s *SecurityAnalyzer) checkLog4Shell(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["log4shell"]; ok {
		combined := entry.Path + " " + entry.UserAgent + " " + entry.Referer
		return pattern.MatchString(combined)
	}
	return false
}

// checkMaliciousUserAgent detects known malicious user agents
func (s *SecurityAnalyzer) checkMaliciousUserAgent(entry *models.LogEntry) bool {
	ua := strings.ToLower(entry.UserAgent)

	// Check for empty user agent
	if ua == "" || ua == "-" {
		s.emptyUACount++
		return true
	}

	// Check against known malicious tools
	for _, malicious := range config.MaliciousUserAgents {
		if strings.Contains(ua, strings.ToLower(malicious)) {
			s.maliciousUACount++
			return true
		}
	}

	return false
}

// Phase 2: Advanced Security Checks

// checkHTTPMethodAnomaly detects suspicious HTTP methods
func (s *SecurityAnalyzer) checkHTTPMethodAnomaly(entry *models.LogEntry) bool {
	for _, suspiciousMethod := range config.SuspiciousHTTPMethods {
		if entry.Method == suspiciousMethod {
			s.anomalousHTTPMethods[entry.Method]++
			return true
		}
	}
	return false
}

// checkSSRF detects Server-Side Request Forgery attempts
func (s *SecurityAnalyzer) checkSSRF(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["ssrf"]; ok {
		combined := entry.Path + " " + entry.Referer
		return pattern.MatchString(combined)
	}
	return false
}

// checkPathTraversalExtended detects advanced path traversal patterns
func (s *SecurityAnalyzer) checkPathTraversalExtended(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["path_traversal_extended"]; ok {
		return pattern.MatchString(entry.Path)
	}
	return false
}

// checkCredentialStuffing detects credential stuffing patterns
func (s *SecurityAnalyzer) checkCredentialStuffing(ipData *ipThreatData, entry *models.LogEntry) bool {
	path := strings.ToLower(entry.Path)

	// Check if this is a login endpoint
	isLoginEndpoint := false
	loginPaths := []string{"login", "signin", "auth", "authenticate"}
	for _, loginPath := range loginPaths {
		if strings.Contains(path, loginPath) {
			isLoginEndpoint = true
			break
		}
	}

	if !isLoginEndpoint {
		return false
	}

	// Track login attempts per IP
	if _, exists := s.ipLoginAttempts[ipData.ip]; !exists {
		s.ipLoginAttempts[ipData.ip] = make(map[string]bool)
	}

	// Track failed login attempts with timestamp-based unique keys
	// This allows us to count multiple failed attempts instead of just one
	if entry.Status == 401 || entry.Status == 403 {
		// Create a unique key for each failed attempt using nanosecond precision
		// UnixNano() ensures each attempt gets a truly unique key
		attemptKey := fmt.Sprintf("%d", entry.Timestamp.UnixNano())
		s.ipLoginAttempts[ipData.ip][attemptKey] = true

		// If this IP has many failed login attempts, it's likely credential stuffing
		if len(s.ipLoginAttempts[ipData.ip]) > 5 {
			return true
		}
	}

	return false
}

// Phase 3: Medium Impact Security Checks

// checkOpenRedirect detects open redirect attempts
func (s *SecurityAnalyzer) checkOpenRedirect(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["open_redirect"]; ok {
		return pattern.MatchString(entry.Path)
	}
	return false
}

// checkXXE detects XML External Entity attacks
func (s *SecurityAnalyzer) checkXXE(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["xxe"]; ok {
		combined := entry.Path + " " + entry.UserAgent
		return pattern.MatchString(combined)
	}
	return false
}

// checkCRLFInjection detects CRLF/Header injection attempts
func (s *SecurityAnalyzer) checkCRLFInjection(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["crlf_injection"]; ok {
		return pattern.MatchString(entry.Path)
	}
	return false
}

// checkAPIAbuse detects API abuse patterns
func (s *SecurityAnalyzer) checkAPIAbuse(ipData *ipThreatData, entry *models.LogEntry) bool {
	path := strings.ToLower(entry.Path)

	// Check for GraphQL introspection
	if strings.Contains(path, "/graphql") && strings.Contains(path, "introspection") {
		return true
	}

	// Check for API enumeration (many requests to different API endpoints)
	if strings.Contains(path, "/api/") || strings.Contains(path, "/rest/") {
		// High request rate to API endpoints
		if ipData.requestCount > 100 {
			duration := ipData.lastSeen.Sub(ipData.firstSeen).Seconds()
			if duration > 0 {
				requestsPerSecond := float64(ipData.requestCount) / duration
				if requestsPerSecond > 5 {
					return true
				}
			}
		}
	}

	return false
}

// Phase 4: Additional Coverage Security Checks

// checkTemplateInjection detects Server-Side Template Injection
func (s *SecurityAnalyzer) checkTemplateInjection(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["template_injection"]; ok {
		return pattern.MatchString(entry.Path)
	}
	return false
}

// checkNoSQLInjection detects NoSQL injection patterns
func (s *SecurityAnalyzer) checkNoSQLInjection(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["nosql_injection"]; ok {
		return pattern.MatchString(entry.Path)
	}
	return false
}

// checkPrototypePollution detects JavaScript prototype pollution
func (s *SecurityAnalyzer) checkPrototypePollution(entry *models.LogEntry) bool {
	if pattern, ok := s.attackPatterns["prototype_pollution"]; ok {
		return pattern.MatchString(entry.Path)
	}
	return false
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

	// Reset extended counters
	s.sensitiveFileCount = 0
	s.webShellCount = 0
	s.log4ShellCount = 0
	s.ssrfCount = 0
	s.openRedirectCount = 0
	s.xxeCount = 0
	s.crlfInjectionCount = 0
	s.credentialStuffingCount = 0
	s.apiAbuseCount = 0
	s.pathTraversalExtCount = 0
	s.templateInjectionCount = 0
	s.nosqlInjectionCount = 0
	s.prototypePollutionCount = 0
	s.httpMethodAnomalyCount = 0
	s.maliciousUACount = 0
	s.emptyUACount = 0

	s.sensitiveFilesAccessed = make(map[string]int64)
	s.webShellsDetected = make(map[string]int64)
	s.anomalousHTTPMethods = make(map[string]int64)
	s.ipLoginAttempts = make(map[string]map[string]bool)
}
