package dns

import (
	"net"
	"sync"
	"time"
)

// DNSLookup provides DNS lookup functionality with caching
type DNSLookup struct {
	mu          sync.RWMutex
	cache       map[string]*cacheEntry
	timeout     time.Duration
	maxCacheAge time.Duration
}

type cacheEntry struct {
	hostname  string
	timestamp time.Time
}

// NewDNSLookup creates a new DNS lookup instance
func NewDNSLookup() *DNSLookup {
	return &DNSLookup{
		cache:       make(map[string]*cacheEntry),
		timeout:     2 * time.Second,
		maxCacheAge: 24 * time.Hour,
	}
}

// ReverseLookup performs a reverse DNS lookup with caching
func (d *DNSLookup) ReverseLookup(ip string) string {
	d.mu.RLock()
	if entry, exists := d.cache[ip]; exists {
		// Check if cache entry is still valid
		if time.Since(entry.timestamp) < d.maxCacheAge {
			d.mu.RUnlock()
			return entry.hostname
		}
	}
	d.mu.RUnlock()

	// Perform lookup with timeout
	hostname := d.lookupWithTimeout(ip)

	// Cache the result
	d.mu.Lock()
	d.cache[ip] = &cacheEntry{
		hostname:  hostname,
		timestamp: time.Now(),
	}
	d.mu.Unlock()

	return hostname
}

// lookupWithTimeout performs DNS lookup with timeout
func (d *DNSLookup) lookupWithTimeout(ip string) string {
	type result struct {
		names []string
		err   error
	}

	ch := make(chan result, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		ch <- result{names, err}
	}()

	select {
	case res := <-ch:
		if res.err == nil && len(res.names) > 0 {
			return res.names[0]
		}
		return ip
	case <-time.After(d.timeout):
		return ip // Return IP if lookup times out
	}
}

// BulkReverseLookup performs bulk reverse DNS lookups
func (d *DNSLookup) BulkReverseLookup(ips []string) map[string]string {
	results := make(map[string]string)
	var wg sync.WaitGroup
	mu := sync.Mutex{}

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			hostname := d.ReverseLookup(ip)
			mu.Lock()
			results[ip] = hostname
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

// ClearCache clears the DNS cache
func (d *DNSLookup) ClearCache() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache = make(map[string]*cacheEntry)
}

// GetCacheSize returns the current cache size
func (d *DNSLookup) GetCacheSize() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.cache)
}

// PurgeExpiredEntries removes expired cache entries
func (d *DNSLookup) PurgeExpiredEntries() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for ip, entry := range d.cache {
		if time.Since(entry.timestamp) >= d.maxCacheAge {
			delete(d.cache, ip)
		}
	}
}
