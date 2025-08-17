package etw

import (
	"sync"
	"sync/atomic"
)

// globalUtf16Cache is a cache for UTF-16 string conversions.
// It uses a concurrent-safe, low-overhead clock cache to approximate LRU.
// 512 is the sweet spot, in benchmarks on etl file kernel data, it performs best with this size.
var globalUtf16Cache = newClockCache(512)

const (
	// FNV-1a hash constants for 64-bit hash computation
	// These are the standard FNV-1a constants as defined in the FNV specification
	fnvOffset64 = 14695981039346656037 // FNV-1a 64-bit offset basis
	fnvPrime64  = 1099511628211        // FNV-1a 64-bit prime multiplier
)

// clockCacheEntry is the value stored in the cache.
type clockCacheEntry struct {
	key        uint64
	value      string
	referenced atomic.Bool // Used by the clock algorithm
}

// clockCache is a concurrent-safe, fixed-size cache using the second-chance algorithm.
type clockCache struct {
	mu       sync.RWMutex
	data     map[uint64]*clockCacheEntry
	buffer   []*clockCacheEntry
	capacity int
	hand     int
}

// newClockCache creates a new cache with the given capacity.
func newClockCache(capacity int) *clockCache {
	return &clockCache{
		data:     make(map[uint64]*clockCacheEntry, capacity),
		buffer:   make([]*clockCacheEntry, 0, capacity),
		capacity: capacity,
	}
}

// lookupOrConvert contains the core clock cache logic.
func (c *clockCache) lookupOrConvert(hash uint64, converter func() string) string {
	// Use a read lock for the common cache-hit case.
	c.mu.RLock()
	if entry, ok := c.data[hash]; ok {
		entry.referenced.Store(true)
		c.mu.RUnlock()
		return entry.value
	}
	c.mu.RUnlock()

	// Item not in cache, convert it before taking the full lock.
	str := converter()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check if another goroutine inserted it while we were unlocked.
	if entry, ok := c.data[hash]; ok {
		entry.referenced.Store(true)
		return entry.value
	}

	entry := &clockCacheEntry{key: hash, value: str}
	entry.referenced.Store(true)

	// If the cache is not yet full, just add the new entry.
	if len(c.buffer) < c.capacity {
		c.buffer = append(c.buffer, entry)
		c.data[hash] = entry
		return str
	}

	// The cache is full. Evict an entry using the clock algorithm.
	for {
		victim := c.buffer[c.hand]
		if victim.referenced.CompareAndSwap(true, false) {
			// Give it a second chance.
			c.hand = (c.hand + 1) % c.capacity
		} else {
			// Evict this entry.
			delete(c.data, victim.key)
			c.buffer[c.hand] = entry
			c.data[hash] = entry
			c.hand = (c.hand + 1) % c.capacity
			return str
		}
	}
}
