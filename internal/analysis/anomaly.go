package analysis

import (
	"math"
	"sync"
	"time"

	"github.com/hpowernl/hlogcli/pkg/models"
	"github.com/montanaflynn/stats"
)

// AnomalyDetector provides anomaly detection functionality
type AnomalyDetector struct {
	mu              sync.RWMutex
	baseline        *models.Baseline
	zScoreThreshold float64
	anomalies       []models.Anomaly
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(zScoreThreshold float64) *AnomalyDetector {
	if zScoreThreshold == 0 {
		zScoreThreshold = 3.0 // Default: 3 standard deviations
	}
	return &AnomalyDetector{
		zScoreThreshold: zScoreThreshold,
		anomalies:       make([]models.Anomaly, 0),
	}
}

// CalculateBaseline calculates baseline statistics from historical data
func (a *AnomalyDetector) CalculateBaseline(entries []*models.LogEntry) *models.Baseline {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(entries) == 0 {
		return &models.Baseline{}
	}

	// Group entries by minute
	buckets := make(map[time.Time]bucketData)
	for _, entry := range entries {
		minute := entry.Timestamp.Truncate(time.Minute)

		if _, exists := buckets[minute]; !exists {
			buckets[minute] = bucketData{
				count:         0,
				errors:        0,
				responseTimes: make([]float64, 0),
			}
		}

		bucket := buckets[minute]
		bucket.count++
		if entry.Status >= 400 {
			bucket.errors++
		}
		bucket.responseTimes = append(bucket.responseTimes, entry.ResponseTime)
		buckets[minute] = bucket
	}

	// Calculate statistics
	requestsPerMinute := make([]float64, 0)
	errorRates := make([]float64, 0)
	avgResponseTimes := make([]float64, 0)

	for _, bucket := range buckets {
		requestsPerMinute = append(requestsPerMinute, float64(bucket.count))

		errorRate := float64(0)
		if bucket.count > 0 {
			errorRate = float64(bucket.errors) / float64(bucket.count)
		}
		errorRates = append(errorRates, errorRate)

		if len(bucket.responseTimes) > 0 {
			avgRT, _ := stats.Mean(bucket.responseTimes)
			avgResponseTimes = append(avgResponseTimes, avgRT)
		}
	}

	baseline := &models.Baseline{}

	if len(requestsPerMinute) > 0 {
		baseline.AvgRequestsPerMinute, _ = stats.Mean(requestsPerMinute)
		baseline.StdDevRequests, _ = stats.StandardDeviation(requestsPerMinute)
	}

	if len(errorRates) > 0 {
		baseline.AvgErrorRate, _ = stats.Mean(errorRates)
		baseline.StdDevErrorRate, _ = stats.StandardDeviation(errorRates)
	}

	if len(avgResponseTimes) > 0 {
		baseline.AvgResponseTime, _ = stats.Mean(avgResponseTimes)
		baseline.StdDevResponseTime, _ = stats.StandardDeviation(avgResponseTimes)
	}

	a.baseline = baseline
	return baseline
}

type bucketData struct {
	count         int
	errors        int
	responseTimes []float64
}

// DetectAnomalies detects anomalies in current data compared to baseline
func (a *AnomalyDetector) DetectAnomalies(entries []*models.LogEntry) []models.Anomaly {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.baseline == nil {
		return []models.Anomaly{}
	}

	anomalies := make([]models.Anomaly, 0)

	// Group entries by minute
	buckets := make(map[time.Time]bucketData)
	for _, entry := range entries {
		minute := entry.Timestamp.Truncate(time.Minute)

		if _, exists := buckets[minute]; !exists {
			buckets[minute] = bucketData{
				count:         0,
				errors:        0,
				responseTimes: make([]float64, 0),
			}
		}

		bucket := buckets[minute]
		bucket.count++
		if entry.Status >= 400 {
			bucket.errors++
		}
		bucket.responseTimes = append(bucket.responseTimes, entry.ResponseTime)
		buckets[minute] = bucket
	}

	// Check each bucket for anomalies
	for timestamp, bucket := range buckets {
		// Check traffic spike
		if spike := a.detectTrafficSpike(timestamp, float64(bucket.count)); spike != nil {
			anomalies = append(anomalies, *spike)
		}

		// Check error rate anomaly
		errorRate := float64(0)
		if bucket.count > 0 {
			errorRate = float64(bucket.errors) / float64(bucket.count)
		}
		if errorAnomaly := a.detectErrorRateAnomaly(timestamp, errorRate); errorAnomaly != nil {
			anomalies = append(anomalies, *errorAnomaly)
		}

		// Check response time anomaly
		if len(bucket.responseTimes) > 0 {
			avgRT, _ := stats.Mean(bucket.responseTimes)
			if rtAnomaly := a.detectResponseTimeAnomaly(timestamp, avgRT); rtAnomaly != nil {
				anomalies = append(anomalies, *rtAnomaly)
			}
		}
	}

	a.anomalies = append(a.anomalies, anomalies...)
	return anomalies
}

// detectTrafficSpike detects traffic spike anomalies
func (a *AnomalyDetector) detectTrafficSpike(timestamp time.Time, requests float64) *models.Anomaly {
	if a.baseline.StdDevRequests == 0 {
		return nil
	}

	zScore := a.calculateZScore(requests, a.baseline.AvgRequestsPerMinute, a.baseline.StdDevRequests)

	if math.Abs(zScore) > a.zScoreThreshold {
		severity := a.getSeverity(zScore)
		return &models.Anomaly{
			Timestamp:   timestamp,
			Type:        "traffic_spike",
			Severity:    severity,
			Description: "Unusual traffic volume detected",
			Value:       requests,
			Expected:    a.baseline.AvgRequestsPerMinute,
			ZScore:      zScore,
		}
	}

	return nil
}

// detectErrorRateAnomaly detects error rate anomalies
func (a *AnomalyDetector) detectErrorRateAnomaly(timestamp time.Time, errorRate float64) *models.Anomaly {
	if a.baseline.StdDevErrorRate == 0 {
		return nil
	}

	zScore := a.calculateZScore(errorRate, a.baseline.AvgErrorRate, a.baseline.StdDevErrorRate)

	if zScore > a.zScoreThreshold { // Only check for increases
		severity := a.getSeverity(zScore)
		return &models.Anomaly{
			Timestamp:   timestamp,
			Type:        "error_rate",
			Severity:    severity,
			Description: "Unusual error rate detected",
			Value:       errorRate,
			Expected:    a.baseline.AvgErrorRate,
			ZScore:      zScore,
		}
	}

	return nil
}

// detectResponseTimeAnomaly detects response time anomalies
func (a *AnomalyDetector) detectResponseTimeAnomaly(timestamp time.Time, avgRT float64) *models.Anomaly {
	if a.baseline.StdDevResponseTime == 0 {
		return nil
	}

	zScore := a.calculateZScore(avgRT, a.baseline.AvgResponseTime, a.baseline.StdDevResponseTime)

	if zScore > a.zScoreThreshold { // Only check for increases
		severity := a.getSeverity(zScore)
		return &models.Anomaly{
			Timestamp:   timestamp,
			Type:        "response_time",
			Severity:    severity,
			Description: "Unusual response time detected",
			Value:       avgRT,
			Expected:    a.baseline.AvgResponseTime,
			ZScore:      zScore,
		}
	}

	return nil
}

// calculateZScore calculates the Z-score for a value
func (a *AnomalyDetector) calculateZScore(value, mean, stddev float64) float64 {
	if stddev == 0 {
		return 0
	}
	return (value - mean) / stddev
}

// getSeverity returns severity based on Z-score
func (a *AnomalyDetector) getSeverity(zScore float64) string {
	absZ := math.Abs(zScore)
	switch {
	case absZ >= 5:
		return "critical"
	case absZ >= 4:
		return "high"
	case absZ >= 3:
		return "medium"
	default:
		return "low"
	}
}

// GetAnomalySummary returns anomaly detection summary
func (a *AnomalyDetector) GetAnomalySummary() *models.AnomalySummary {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return &models.AnomalySummary{
		TotalAnomalies: len(a.anomalies),
		Anomalies:      a.anomalies,
		Baseline:       a.baseline,
	}
}

// GetBaseline returns the current baseline
func (a *AnomalyDetector) GetBaseline() *models.Baseline {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.baseline
}

// SetBaseline sets a new baseline
func (a *AnomalyDetector) SetBaseline(baseline *models.Baseline) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.baseline = baseline
}

// Reset clears all anomaly detection data
func (a *AnomalyDetector) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.baseline = nil
	a.anomalies = make([]models.Anomaly, 0)
}
