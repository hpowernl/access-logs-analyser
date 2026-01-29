package analysis

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hpowernl/hlogcli/internal/config"
	"github.com/hpowernl/hlogcli/pkg/models"
)

// BotAnalyzer provides bot analysis functionality
type BotAnalyzer struct {
	mu               sync.RWMutex
	botStats         map[string]*botData
	totalBotRequests int64
	totalRequests    int64
}

type botData struct {
	userAgent       string
	category        string
	count           int64
	bytes           int64
	paths           map[string]bool
	timestamps      []time.Time
	legitimacyScore float64
	isAIBot         bool
}

// NewBotAnalyzer creates a new bot analyzer
func NewBotAnalyzer() *BotAnalyzer {
	return &BotAnalyzer{
		botStats: make(map[string]*botData),
	}
}

// AnalyzeEntry analyzes a log entry for bot patterns
func (b *BotAnalyzer) AnalyzeEntry(entry *models.LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.totalRequests++

	if !entry.IsBot {
		return
	}

	b.totalBotRequests++

	ua := entry.UserAgent
	if _, exists := b.botStats[ua]; !exists {
		category := b.classifyBot(ua)
		b.botStats[ua] = &botData{
			userAgent:       ua,
			category:        category,
			paths:           make(map[string]bool),
			timestamps:      make([]time.Time, 0),
			isAIBot:         b.isAIBot(ua),
			legitimacyScore: b.calculateLegitimacyScore(ua, category),
		}
	}

	bd := b.botStats[ua]
	bd.count++
	bd.bytes += entry.BytesSent
	bd.paths[entry.Path] = true
	bd.timestamps = append(bd.timestamps, entry.Timestamp)
}

// classifyBot classifies a bot based on its user agent
func (b *BotAnalyzer) classifyBot(userAgent string) string {
	ua := strings.ToLower(userAgent)

	// Check against known bot categories
	for signature, category := range config.BotCategories {
		if strings.Contains(ua, signature) {
			return category
		}
	}

	// Default classification based on patterns
	if strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") || strings.Contains(ua, "spider") {
		return "generic"
	}

	return "unknown"
}

// isAIBot checks if the bot is an AI/LLM bot
func (b *BotAnalyzer) isAIBot(userAgent string) bool {
	ua := strings.ToLower(userAgent)

	aiSignatures := []string{
		"chatgpt", "gpt-bot", "openai", "gpt-4", "gpt-3.5",
		"claude", "anthropic", "bard", "google-bard",
		"copilot", "perplexity", "ccbot", "common-crawl",
	}

	for _, sig := range aiSignatures {
		if strings.Contains(ua, sig) {
			return true
		}
	}

	return false
}

// calculateLegitimacyScore calculates a legitimacy score for a bot (0-100)
func (b *BotAnalyzer) calculateLegitimacyScore(userAgent, category string) float64 {
	var score float64

	// Known legitimate bots get higher scores
	switch category {
	case "search_engine":
		score = 95.0
	case "social_media":
		score = 90.0
	case "monitoring":
		score = 85.0
	case "ai_llm":
		score = 70.0 // Somewhat legitimate but data collection concerns
	case "security_scanner":
		score = 60.0 // Can be legitimate but also concerning
	case "generic":
		score = 40.0
	default:
		score = 30.0
	}

	// Adjust based on user agent string quality
	ua := strings.ToLower(userAgent)
	if strings.Contains(ua, "http://") || strings.Contains(ua, "https://") {
		score += 10 // Contains URL, likely legitimate
	}
	if len(userAgent) > 100 {
		score += 5 // Detailed user agent, likely legitimate
	}
	if strings.Contains(ua, "compatible") {
		score += 5 // Standards compliant
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// GetBotSummary returns a summary of bot analysis
func (b *BotAnalyzer) GetBotSummary() *models.BotSummary {
	b.mu.RLock()
	defer b.mu.RUnlock()

	botTrafficPct := float64(0)
	if b.totalRequests > 0 {
		botTrafficPct = float64(b.totalBotRequests) / float64(b.totalRequests) * 100
	}

	// Count bots by category
	botsByCategory := make(map[string]int64)
	for _, bd := range b.botStats {
		botsByCategory[bd.category]++
	}

	// Get legitimacy scores
	legitimacyScores := make(map[string]float64)
	for ua, bd := range b.botStats {
		legitimacyScores[ua] = bd.legitimacyScore
	}

	summary := &models.BotSummary{
		TotalBotRequests: b.totalBotRequests,
		UniqueBots:       len(b.botStats),
		BotTrafficPct:    botTrafficPct,
		BotsByCategory:   botsByCategory,
		TopBots:          b.getTopBots(10),
		AIBots:           b.getAIBots(),
		LegitimacyScores: legitimacyScores,
	}

	return summary
}

// GetTopBots returns the top N bots by request count
func (b *BotAnalyzer) GetTopBots(n int) []models.BotStat {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.getTopBots(n)
}

func (b *BotAnalyzer) getTopBots(n int) []models.BotStat {
	bots := make([]models.BotStat, 0, len(b.botStats))

	for _, bd := range b.botStats {
		avgInterval := float64(0)
		if len(bd.timestamps) > 1 {
			var totalInterval float64
			for i := 1; i < len(bd.timestamps); i++ {
				totalInterval += bd.timestamps[i].Sub(bd.timestamps[i-1]).Seconds()
			}
			avgInterval = totalInterval / float64(len(bd.timestamps)-1)
		}

		bot := models.BotStat{
			UserAgent:       bd.userAgent,
			Category:        bd.category,
			Count:           bd.count,
			Bytes:           bd.bytes,
			AvgInterval:     avgInterval,
			UniquePaths:     len(bd.paths),
			LegitimacyScore: bd.legitimacyScore,
			IsAIBot:         bd.isAIBot,
		}
		bots = append(bots, bot)
	}

	// Sort by count
	sort.Slice(bots, func(i, j int) bool {
		return bots[i].Count > bots[j].Count
	})

	if n < len(bots) {
		return bots[:n]
	}
	return bots
}

// GetAIBots returns AI/LLM bots
func (b *BotAnalyzer) GetAIBots() []models.BotStat {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.getAIBots()
}

func (b *BotAnalyzer) getAIBots() []models.BotStat {
	aiBots := make([]models.BotStat, 0)

	for _, bd := range b.botStats {
		if bd.isAIBot {
			avgInterval := float64(0)
			if len(bd.timestamps) > 1 {
				var totalInterval float64
				for i := 1; i < len(bd.timestamps); i++ {
					totalInterval += bd.timestamps[i].Sub(bd.timestamps[i-1]).Seconds()
				}
				avgInterval = totalInterval / float64(len(bd.timestamps)-1)
			}

			bot := models.BotStat{
				UserAgent:       bd.userAgent,
				Category:        bd.category,
				Count:           bd.count,
				Bytes:           bd.bytes,
				AvgInterval:     avgInterval,
				UniquePaths:     len(bd.paths),
				LegitimacyScore: bd.legitimacyScore,
				IsAIBot:         true,
			}
			aiBots = append(aiBots, bot)
		}
	}

	// Sort by count
	sort.Slice(aiBots, func(i, j int) bool {
		return aiBots[i].Count > aiBots[j].Count
	})

	return aiBots
}

// GetBehaviorPatterns returns behavior patterns for bots
func (b *BotAnalyzer) GetBehaviorPatterns() map[string]*BehaviorPattern {
	b.mu.RLock()
	defer b.mu.RUnlock()

	patterns := make(map[string]*BehaviorPattern)

	for ua, bd := range b.botStats {
		pattern := &BehaviorPattern{
			UserAgent:    ua,
			Category:     bd.category,
			RequestCount: bd.count,
			UniquePaths:  len(bd.paths),
		}

		// Calculate request rate
		if len(bd.timestamps) > 1 {
			duration := bd.timestamps[len(bd.timestamps)-1].Sub(bd.timestamps[0]).Seconds()
			if duration > 0 {
				pattern.RequestsPerSecond = float64(bd.count) / duration
			}
		}

		// Analyze access patterns
		pattern.BehaviorType = b.analyzeBehaviorType(bd)

		patterns[ua] = pattern
	}

	return patterns
}

// BehaviorPattern represents bot behavior patterns
type BehaviorPattern struct {
	UserAgent         string
	Category          string
	RequestCount      int64
	UniquePaths       int
	RequestsPerSecond float64
	BehaviorType      string
}

// analyzeBehaviorType analyzes the behavior type of a bot
func (b *BotAnalyzer) analyzeBehaviorType(bd *botData) string {
	// High request rate suggests aggressive crawling
	if len(bd.timestamps) > 1 {
		duration := bd.timestamps[len(bd.timestamps)-1].Sub(bd.timestamps[0]).Seconds()
		if duration > 0 {
			rps := float64(bd.count) / duration
			if rps > 10 {
				return "aggressive"
			} else if rps > 1 {
				return "moderate"
			}
		}
	}

	// Many unique paths suggests comprehensive crawling
	if len(bd.paths) > 100 {
		return "comprehensive"
	} else if len(bd.paths) > 10 {
		return "targeted"
	}

	return "light"
}

// GetLegitimacyScores returns legitimacy scores for all bots
func (b *BotAnalyzer) GetLegitimacyScores() map[string]float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	scores := make(map[string]float64)
	for ua, bd := range b.botStats {
		scores[ua] = bd.legitimacyScore
	}
	return scores
}

// GetBotsByCategory returns bots grouped by category
func (b *BotAnalyzer) GetBotsByCategory() map[string][]models.BotStat {
	b.mu.RLock()
	defer b.mu.RUnlock()

	categories := make(map[string][]models.BotStat)

	for _, bd := range b.botStats {
		bot := models.BotStat{
			UserAgent:       bd.userAgent,
			Category:        bd.category,
			Count:           bd.count,
			Bytes:           bd.bytes,
			UniquePaths:     len(bd.paths),
			LegitimacyScore: bd.legitimacyScore,
			IsAIBot:         bd.isAIBot,
		}

		categories[bd.category] = append(categories[bd.category], bot)
	}

	// Sort each category by count
	for category := range categories {
		sort.Slice(categories[category], func(i, j int) bool {
			return categories[category][i].Count > categories[category][j].Count
		})
	}

	return categories
}

// Reset clears all bot analysis data
func (b *BotAnalyzer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.botStats = make(map[string]*botData)
	b.totalBotRequests = 0
	b.totalRequests = 0
}
