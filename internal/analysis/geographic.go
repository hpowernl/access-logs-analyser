package analysis

import (
	"sort"
	"sync"

	"github.com/hpowernl/hlogcli/pkg/models"
)

// GeographicAnalyzer provides geographic analysis
type GeographicAnalyzer struct {
	mu           sync.RWMutex
	countryStats map[string]*geoCountryData
}

type geoCountryData struct {
	country     string
	count       int64
	bytes       int64
	ips         map[string]bool
	errorCount  int64
	threatCount int64
}

// NewGeographicAnalyzer creates a new geographic analyzer
func NewGeographicAnalyzer() *GeographicAnalyzer {
	return &GeographicAnalyzer{
		countryStats: make(map[string]*geoCountryData),
	}
}

// AnalyzeEntry analyzes a log entry for geographic patterns
func (g *GeographicAnalyzer) AnalyzeEntry(entry *models.LogEntry) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if entry.Country == "" {
		return
	}

	country := entry.Country
	if _, exists := g.countryStats[country]; !exists {
		g.countryStats[country] = &geoCountryData{
			country: country,
			ips:     make(map[string]bool),
		}
	}

	cs := g.countryStats[country]
	cs.count++
	cs.bytes += entry.BytesSent
	cs.ips[entry.IP.String()] = true

	if entry.Status >= 400 {
		cs.errorCount++
	}
}

// AddThreat adds a threat for a specific country
func (g *GeographicAnalyzer) AddThreat(country string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if cs, exists := g.countryStats[country]; exists {
		cs.threatCount++
	}
}

// GetGeographicSummary returns geographic analysis summary
func (g *GeographicAnalyzer) GetGeographicSummary() *models.GeographicSummary {
	g.mu.RLock()
	defer g.mu.RUnlock()

	topCountries := g.getTopCountries(20)
	threatMap := g.getThreatMapData()

	return &models.GeographicSummary{
		TotalCountries: len(g.countryStats),
		TopCountries:   topCountries,
		ThreatMap:      threatMap,
	}
}

func (g *GeographicAnalyzer) getTopCountries(n int) []models.CountryStat {
	countries := make([]models.CountryStat, 0, len(g.countryStats))

	for _, cs := range g.countryStats {
		threatScore := float64(0)
		if cs.count > 0 {
			threatScore = (float64(cs.errorCount) + float64(cs.threatCount)*10) / float64(cs.count) * 100
		}

		countries = append(countries, models.CountryStat{
			Country:     cs.country,
			Count:       cs.count,
			Bytes:       cs.bytes,
			UniqueIPs:   len(cs.ips),
			ErrorCount:  cs.errorCount,
			ThreatScore: threatScore,
		})
	}

	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Count > countries[j].Count
	})

	if n < len(countries) {
		return countries[:n]
	}
	return countries
}

func (g *GeographicAnalyzer) getThreatMapData() map[string]*models.ThreatData {
	threatMap := make(map[string]*models.ThreatData)

	for country, cs := range g.countryStats {
		threatScore := float64(0)
		if cs.count > 0 {
			threatScore = (float64(cs.errorCount) + float64(cs.threatCount)*10) / float64(cs.count) * 100
		}

		threatMap[country] = &models.ThreatData{
			Country:      country,
			ThreatScore:  threatScore,
			ThreatCount:  cs.threatCount,
			RequestCount: cs.count,
		}
	}

	return threatMap
}
