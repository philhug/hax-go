package server

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// rateLimiter implements a simple per-IP sliding-window rate limiter.
type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	hits    map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:  limit,
		window: window,
		hits:   make(map[string][]time.Time),
	}
}

// allow checks if the IP is within the rate limit. Returns (allowed, remaining, resetAt).
func (rl *rateLimiter) allow(ip string) (bool, int, time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Filter to recent hits.
	var recent []time.Time
	for _, t := range rl.hits[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= rl.limit {
		// Reset time = oldest hit + window.
		resetAt := recent[0].Add(rl.window)
		rl.hits[ip] = recent
		return false, 0, resetAt
	}

	recent = append(recent, now)
	rl.hits[ip] = recent
	remaining := rl.limit - len(recent)
	resetAt := now.Add(rl.window)
	return true, remaining, resetAt
}

// rateLimit is middleware that enforces per-IP rate limiting.
func (s *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	if s.limiter == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = forwarded
		}
		// Strip port from RemoteAddr (e.g. "127.0.0.1:12345" → "127.0.0.1").
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		allowed, remaining, resetAt := s.limiter.allow(ip)
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(resetAt).Seconds())+1))
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(s.limiter.limit))
			w.Header().Set("X-RateLimit-Remaining", "0")
			writeErrorWithDetails(w, http.StatusTooManyRequests, "rate limit exceeded", map[string]any{
				"limit":     s.limiter.limit,
				"used":      s.limiter.limit,
				"remaining": 0,
				"resetsAt":  resetAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			})
			return
		}
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(s.limiter.limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		next(w, r)
	}
}
