package analysis

import (
	"sort"
	"sync"
	"time"

	"github.com/hpowernl/hlogcli/pkg/models"
)

// TimelineAnalyzer provides timeline analysis
type TimelineAnalyzer struct {
	mu             sync.RWMutex
	buckets        map[time.Time]*timelineBucket
	granularity    time.Duration
	securityEvents []models.SecurityEvent
}

type timelineBucket struct {
	timestamp    time.Time
	count        int64
	bytes        int64
	uniqueIPs    map[string]bool
	errorCount   int64
	statusCounts map[int]int64
}

// NewTimelineAnalyzer creates a new timeline analyzer
func NewTimelineAnalyzer(granularity time.Duration) *TimelineAnalyzer {
	if granularity == 0 {
		granularity = time.Minute
	}
	return &TimelineAnalyzer{
		buckets:        make(map[time.Time]*timelineBucket),
		granularity:    granularity,
		securityEvents: make([]models.SecurityEvent, 0),
	}
}

// AnalyzeEntry analyzes a log entry for timeline patterns
func (t *TimelineAnalyzer) AnalyzeEntry(entry *models.LogEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	bucketTime := entry.Timestamp.Truncate(t.granularity)

	if _, exists := t.buckets[bucketTime]; !exists {
		t.buckets[bucketTime] = &timelineBucket{
			timestamp:    bucketTime,
			uniqueIPs:    make(map[string]bool),
			statusCounts: make(map[int]int64),
		}
	}

	bucket := t.buckets[bucketTime]
	bucket.count++
	bucket.bytes += entry.BytesSent
	bucket.uniqueIPs[entry.IP.String()] = true
	bucket.statusCounts[entry.Status]++

	if entry.Status >= 400 {
		bucket.errorCount++
	}
}

// AddSecurityEvent adds a security event to the timeline
func (t *TimelineAnalyzer) AddSecurityEvent(event models.SecurityEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.securityEvents = append(t.securityEvents, event)
}

// GetTimelineSummary returns timeline analysis summary
func (t *TimelineAnalyzer) GetTimelineSummary() *models.TimelineSummary {
	t.mu.RLock()
	defer t.mu.RUnlock()

	buckets := t.getTimeline()

	var peakBucket *models.TimeBucket
	for i := range buckets {
		if peakBucket == nil || buckets[i].Count > peakBucket.Count {
			peakBucket = &buckets[i]
		}
	}

	return &models.TimelineSummary{
		Buckets:        buckets,
		Granularity:    t.granularity,
		TotalBuckets:   len(buckets),
		PeakTraffic:    peakBucket,
		SecurityEvents: t.securityEvents,
	}
}

func (t *TimelineAnalyzer) getTimeline() []models.TimeBucket {
	timeline := make([]models.TimeBucket, 0, len(t.buckets))

	for _, bucket := range t.buckets {
		timeline = append(timeline, models.TimeBucket{
			Timestamp:    bucket.timestamp,
			Count:        bucket.count,
			Bytes:        bucket.bytes,
			UniqueIPs:    len(bucket.uniqueIPs),
			ErrorCount:   bucket.errorCount,
			StatusCounts: bucket.statusCounts,
		})
	}

	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Timestamp.Before(timeline[j].Timestamp)
	})

	return timeline
}
