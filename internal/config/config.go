package config

import "time"

// BotSignatures contains user agent signatures for bot detection
var BotSignatures = map[string]bool{
	// Traditional bots
	"googlebot": true, "bingbot": true, "slurp": true, "duckduckbot": true, "baiduspider": true,
	"yandexbot": true, "facebookexternalhit": true, "twitterbot": true, "linkedinbot": true,
	"whatsapp": true, "telegrambot": true, "applebot": true, "amazonbot": true, "crawl": true,
	"spider": true, "bot": true, "scraper": true, "curl": true, "wget": true, "python-requests": true,
	"postman": true, "insomnia": true, "httpie": true,

	// AI and LLM bots
	"chatgpt": true, "gpt-bot": true, "openai": true, "gpt-4": true, "gpt-3.5": true,
	"claude": true, "anthropic": true, "claude-bot": true, "bard": true, "google-bard": true, "palm-bot": true,
	"copilot": true, "github-copilot": true, "microsoft-copilot": true, "perplexity": true, "perplexitybot": true,
	"ccbot": true, "common-crawl": true, "commoncrawl": true, "ai2bot": true, "allen-institute": true,
	"anthropic-ai": true, "claude-web": true, "research-bot": true, "academic-crawler": true, "university-bot": true,
	"huggingface": true, "hf-bot": true, "jasper": true, "copy.ai": true, "writesonic": true, "contentbot": true,
	"midjourney": true, "dall-e": true, "stable-diffusion": true, "imagen": true, "ai-seo": true, "rank-math-ai": true,
	"yoast-ai": true, "surfer-ai": true, "marketo-ai": true, "hubspot-ai": true, "salesforce-ai": true,
	"chatbot": true, "virtual-assistant": true, "dialogflow": true, "rasa": true, "alexa": true, "siri": true,
	"google-assistant": true, "cortana": true, "ai-api": true, "ml-service": true, "neural-bot": true,
	"tensorflow-bot": true, "automated-ai": true, "ai-automation": true, "ml-automation": true,
}

// StatusGroups defines HTTP status code groups
var StatusGroups = map[string][]int{
	"success":      {200, 201, 202, 204, 206},
	"redirect":     {301, 302, 303, 304, 307, 308},
	"client_error": {400, 401, 403, 404, 405, 406, 409, 410, 422, 429},
	"server_error": {500, 501, 502, 503, 504, 505},
}

// DefaultFilters contains default filter settings
type DefaultFilters struct {
	Countries   []string
	StatusCodes []int
	ExcludeBots bool
	IPRanges    []string
	Methods     []string
	Paths       []string
}

var DefaultFilterSettings = DefaultFilters{
	Countries:   []string{},
	StatusCodes: []int{},
	ExcludeBots: false,
	IPRanges:    []string{},
	Methods:     []string{},
	Paths:       []string{},
}

// AlertThresholds defines thresholds for alerts
type AlertThresholds struct {
	ErrorRate          float64
	RequestsPerMinute  int64
	UniqueIPsPerMinute int64
}

var DefaultAlertThresholds = AlertThresholds{
	ErrorRate:          0.5,  // 50% error rate
	RequestsPerMinute:  1000, // High traffic threshold
	UniqueIPsPerMinute: 100,  // Potential attack threshold
}

// TimelineSettings defines timeline configuration
type TimelineSettings struct {
	Granularity     string
	WindowSize      int
	RefreshInterval time.Duration
}

var DefaultTimelineSettings = TimelineSettings{
	Granularity:     "minute", // minute, hour, day
	WindowSize:      60,       // Number of time units to keep in sliding window
	RefreshInterval: 1 * time.Second,
}

// ExportSettings defines export configuration
type ExportSettings struct {
	CSVDelimiter    string
	TimestampFormat string
	ChartWidth      int
	ChartHeight     int
}

var DefaultExportSettings = ExportSettings{
	CSVDelimiter:    ",",
	TimestampFormat: "2006-01-02 15:04:05",
	ChartWidth:      1200,
	ChartHeight:     600,
}

// HypernodeSettings defines Hypernode-specific configuration
type HypernodeSettings struct {
	CommonLogPaths      []string
	AutoDiscoverEnabled bool
}

var DefaultHypernodeSettings = HypernodeSettings{
	CommonLogPaths: []string{
		"/var/log/nginx/access.log",
		"/var/log/nginx/access.log.1",
		"/data/log/nginx/access.log",
		"/data/log/nginx/access.log.1",
	},
	AutoDiscoverEnabled: true,
}

// PlatformSecurity defines platform-specific security settings
type PlatformSecurity struct {
	EnableWordPress   bool
	EnableWooCommerce bool
	EnableShopware    bool
	EnableMagento     bool
	MagentoAdminPath  string
}

var DefaultPlatformSecurity = PlatformSecurity{
	EnableWordPress:   true,
	EnableWooCommerce: true,
	EnableShopware:    true,
	EnableMagento:     true,
	MagentoAdminPath:  "",
}

// BotCategories defines bot category mappings
var BotCategories = map[string]string{
	// Search engines
	"googlebot":   "search_engine",
	"bingbot":     "search_engine",
	"slurp":       "search_engine",
	"duckduckbot": "search_engine",
	"baiduspider": "search_engine",
	"yandexbot":   "search_engine",
	"applebot":    "search_engine",

	// Social media
	"facebookexternalhit": "social_media",
	"twitterbot":          "social_media",
	"linkedinbot":         "social_media",
	"whatsapp":            "social_media",
	"telegrambot":         "social_media",

	// AI/LLM bots
	"chatgpt":    "ai_llm",
	"gpt-bot":    "ai_llm",
	"openai":     "ai_llm",
	"claude":     "ai_llm",
	"anthropic":  "ai_llm",
	"bard":       "ai_llm",
	"copilot":    "ai_llm",
	"perplexity": "ai_llm",
	"ccbot":      "ai_llm",

	// Monitoring
	"uptimerobot": "monitoring",
	"pingdom":     "monitoring",
	"newrelic":    "monitoring",

	// Security scanners
	"nessus":   "security_scanner",
	"qualys":   "security_scanner",
	"acunetix": "security_scanner",

	// Generic
	"curl":            "generic",
	"wget":            "generic",
	"python-requests": "generic",
}

// E-commerce platform patterns
var EcommercePlatforms = map[string][]string{
	"magento": {
		"/graphql",
		"/rest/V1/",
		"/customer/section/load",
		"/checkout/",
		"/catalogsearch/",
		"/api/rest/",
		"Magento_",
	},
	"woocommerce": {
		"/?wc-ajax=",
		"/wp-json/wc/",
		"/cart/",
		"/checkout/",
		"/my-account/",
		"wc-api",
	},
	"shopware": {
		"/store-api/",
		"/api/",
		"/admin/api/",
		"/checkout/",
		"/account/",
	},
}

// Attack patterns for security analysis
var AttackPatterns = map[string]string{
	"sql_injection":       `(?i)(union|select|insert|update|delete|drop|alter|exec|script|javascript|<script)`,
	"xss":                 `(?i)(<script|javascript:|on\w+=|<iframe|<object|<embed)`,
	"directory_traversal": `\.\./|\.\.\%2[fF]|\.\.\\`,
	"command_injection":   `(?i)(;|\||&&|\$\(|` + "`" + `)`,
	"file_inclusion":      `(?i)(file://|php://|expect://|data:)`,
}

// Security threat severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Common admin paths
var AdminPaths = []string{
	"/admin",
	"/administrator",
	"/wp-admin",
	"/wp-login.php",
	"/admin.php",
	"/backend",
	"/adminpanel",
	"/control",
	"/cpanel",
	"/manager",
}

// HTTP methods
var HTTPMethods = []string{
	"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT",
}
