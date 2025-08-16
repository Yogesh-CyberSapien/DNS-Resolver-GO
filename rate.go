package main

import (
        "context"

        "golang.org/x/time/rate"
)

// RateLimiter controls the rate of DNS queries
type RateLimiter struct {
        limiter *rate.Limiter
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(qps int) *RateLimiter {
        if qps <= 0 {
                qps = defaultQPS
        }
        
        // Allow some burst capacity
        burst := qps / 10
        if burst < 1 {
                burst = 1
        }
        
        return &RateLimiter{
                limiter: rate.NewLimiter(rate.Limit(qps), burst),
        }
}

// Wait blocks until the rate limiter allows another request
func (r *RateLimiter) Wait(ctx context.Context) error {
        return r.limiter.Wait(ctx)
}

// Allow checks if a request is allowed without blocking
func (r *RateLimiter) Allow() bool {
        return r.limiter.Allow()
}

// SetLimit updates the rate limit
func (r *RateLimiter) SetLimit(qps int) {
        if qps <= 0 {
                qps = defaultQPS
        }
        
        burst := qps / 10
        if burst < 1 {
                burst = 1
        }
        
        r.limiter.SetLimit(rate.Limit(qps))
        r.limiter.SetBurst(burst)
}

// GetLimit returns the current rate limit
func (r *RateLimiter) GetLimit() float64 {
        return float64(r.limiter.Limit())
}
