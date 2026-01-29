package analysis

import (
	"path/filepath"
	"strings"
	"sync"

	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/montanaflynn/stats"
)

// ContentAnalyzer provides content analysis
type ContentAnalyzer struct {
	mu           sync.RWMutex
	contentTypes map[string]int64
	extensions   map[string]*extensionData
	categories   map[string]int64
	seoIssues    map[string]int64
}

type extensionData struct {
	extension     string
	count         int64
	bytes         int64
	responseTimes []float64
}

// NewContentAnalyzer creates a new content analyzer
func NewContentAnalyzer() *ContentAnalyzer {
	return &ContentAnalyzer{
		contentTypes: make(map[string]int64),
		extensions:   make(map[string]*extensionData),
		categories:   make(map[string]int64),
		seoIssues:    make(map[string]int64),
	}
}

// AnalyzeEntry analyzes a log entry for content patterns
func (c *ContentAnalyzer) AnalyzeEntry(entry *models.LogEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Extract file extension
	ext := filepath.Ext(entry.Path)
	if ext != "" {
		ext = strings.ToLower(ext)

		if _, exists := c.extensions[ext]; !exists {
			c.extensions[ext] = &extensionData{
				extension:     ext,
				responseTimes: make([]float64, 0),
			}
		}

		extData := c.extensions[ext]
		extData.count++
		extData.bytes += entry.BytesSent
		extData.responseTimes = append(extData.responseTimes, entry.ResponseTime)

		// Categorize by content type
		category := c.categorizeByExtension(ext)
		c.categories[category]++

		// Detect content type
		contentType := c.detectContentType(ext)
		c.contentTypes[contentType]++

		// Check for SEO issues
		c.checkSEOIssues(entry, ext)
	}
}

// categorizeByExtension categorizes files by extension
func (c *ContentAnalyzer) categorizeByExtension(ext string) string {
	imageExts := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico"}
	scriptExts := []string{".js", ".jsx", ".ts", ".tsx"}
	styleExts := []string{".css", ".scss", ".sass", ".less"}
	mediaExts := []string{".mp4", ".webm", ".mp3", ".ogg", ".wav"}
	documentExts := []string{".pdf", ".doc", ".docx", ".xls", ".xlsx"}

	for _, imgExt := range imageExts {
		if ext == imgExt {
			return "image"
		}
	}
	for _, scriptExt := range scriptExts {
		if ext == scriptExt {
			return "script"
		}
	}
	for _, styleExt := range styleExts {
		if ext == styleExt {
			return "style"
		}
	}
	for _, mediaExt := range mediaExts {
		if ext == mediaExt {
			return "media"
		}
	}
	for _, docExt := range documentExts {
		if ext == docExt {
			return "document"
		}
	}

	return "other"
}

// detectContentType detects content type from extension
func (c *ContentAnalyzer) detectContentType(ext string) string {
	contentTypeMap := map[string]string{
		".html": "text/html",
		".css":  "text/css",
		".js":   "application/javascript",
		".json": "application/json",
		".xml":  "application/xml",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".svg":  "image/svg+xml",
		".pdf":  "application/pdf",
		".zip":  "application/zip",
	}

	if ct, ok := contentTypeMap[ext]; ok {
		return ct
	}
	return "application/octet-stream"
}

// checkSEOIssues checks for SEO-related issues
func (c *ContentAnalyzer) checkSEOIssues(entry *models.LogEntry, ext string) {
	// Large images
	if c.categorizeByExtension(ext) == "image" && entry.BytesSent > 500*1024 {
		c.seoIssues["large_images"]++
	}

	// Broken links
	if entry.Status == 404 {
		c.seoIssues["broken_links"]++
	}

	// Slow resources
	if entry.ResponseTime > 2.0 {
		c.seoIssues["slow_resources"]++
	}
}

// GetContentSummary returns content analysis summary
func (c *ContentAnalyzer) GetContentSummary() *models.ContentSummary {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalResources := int64(0)
	extensionStats := make(map[string]*models.ExtensionStat)

	for ext, extData := range c.extensions {
		totalResources += extData.count

		avgRT := float64(0)
		if len(extData.responseTimes) > 0 {
			avgRT, _ = stats.Mean(extData.responseTimes)
		}

		extensionStats[ext] = &models.ExtensionStat{
			Extension:       ext,
			Count:           extData.count,
			Bytes:           extData.bytes,
			AvgResponseTime: avgRT,
		}
	}

	seoIssues := make([]models.SEOIssue, 0)
	for issueType, count := range c.seoIssues {
		issue := models.SEOIssue{
			Type:     issueType,
			Count:    count,
			Severity: c.getSEOSeverity(issueType),
		}
		issue.Description = c.getSEODescription(issueType)
		seoIssues = append(seoIssues, issue)
	}

	return &models.ContentSummary{
		TotalResources:     totalResources,
		ContentTypes:       c.contentTypes,
		Extensions:         extensionStats,
		ResourceCategories: c.categories,
		SEOIssues:          seoIssues,
	}
}

func (c *ContentAnalyzer) getSEOSeverity(issueType string) string {
	switch issueType {
	case "broken_links":
		return "high"
	case "large_images":
		return "medium"
	case "slow_resources":
		return "medium"
	default:
		return "low"
	}
}

func (c *ContentAnalyzer) getSEODescription(issueType string) string {
	descriptions := map[string]string{
		"large_images":   "Images larger than 500KB detected - consider optimization",
		"broken_links":   "404 errors detected - broken links affect SEO",
		"slow_resources": "Slow loading resources detected - impacts page speed",
	}

	if desc, ok := descriptions[issueType]; ok {
		return desc
	}
	return "SEO issue detected"
}
