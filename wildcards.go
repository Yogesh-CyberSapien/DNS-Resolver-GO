package main

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// WildcardDetector detects DNS wildcard responses
type WildcardDetector struct {
	resolverPool *ResolverPool
	cache        map[string]bool
	cacheMutex   sync.RWMutex
	logger       *log.Logger
}

// WildcardInfo contains information about a wildcard domain
type WildcardInfo struct {
	Domain    string
	Responses []string
	IsWildcard bool
}

// NewWildcardDetector creates a new wildcard detector
func NewWildcardDetector(resolverPool *ResolverPool, logger *log.Logger) *WildcardDetector {
	return &WildcardDetector{
		resolverPool: resolverPool,
		cache:        make(map[string]bool),
		logger:       logger,
	}
}

// IsWildcard checks if a DNS result is from a wildcard domain
func (w *WildcardDetector) IsWildcard(result *DNSResult) bool {
	if result.Response == nil || len(result.Response.Answer) == 0 {
		return false
	}
	
	// Extract the domain from the result
	domain := strings.TrimSuffix(result.Domain, ".")
	
	// Get the effective TLD+1 (e.g., example.com from subdomain.example.com)
	baseDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// If we can't parse the domain, assume it's not a wildcard
		return false
	}
	
	// Check cache first
	w.cacheMutex.RLock()
	if isWildcard, exists := w.cache[baseDomain]; exists {
		w.cacheMutex.RUnlock()
		return isWildcard
	}
	w.cacheMutex.RUnlock()
	
	// Perform wildcard detection
	isWildcard := w.detectWildcard(baseDomain, result.Type)
	
	// Cache the result
	w.cacheMutex.Lock()
	w.cache[baseDomain] = isWildcard
	w.cacheMutex.Unlock()
	
	if isWildcard && w.logger != nil {
		w.logger.Printf("Wildcard detected for domain: %s", baseDomain)
	}
	
	return isWildcard
}

// detectWildcard performs the actual wildcard detection
func (w *WildcardDetector) detectWildcard(baseDomain string, qtype uint16) bool {
	// Generate random subdomains for testing
	testSubdomains := w.generateRandomSubdomains(baseDomain, 3)
	
	var responses [][]string
	consistentResponses := true
	
	for _, testDomain := range testSubdomains {
		answers := w.queryDomain(testDomain, qtype)
		responses = append(responses, answers)
		
		// If any query returns no results, it's likely not a wildcard
		if len(answers) == 0 {
			return false
		}
	}
	
	// Check if all test queries returned the same results
	if len(responses) < 2 {
		return false
	}
	
	firstResponse := responses[0]
	for i := 1; i < len(responses); i++ {
		if !sliceEqual(firstResponse, responses[i]) {
			consistentResponses = false
			break
		}
	}
	
	return consistentResponses && len(firstResponse) > 0
}

// generateRandomSubdomains creates random subdomain names for testing
func (w *WildcardDetector) generateRandomSubdomains(baseDomain string, count int) []string {
	var subdomains []string
	
	for i := 0; i < count; i++ {
		randomString := w.generateRandomString(12)
		subdomain := fmt.Sprintf("%s.%s", randomString, baseDomain)
		subdomains = append(subdomains, subdomain)
	}
	
	return subdomains
}

// generateRandomString creates a random string of specified length
func (w *WildcardDetector) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	
	rand.Seed(time.Now().UnixNano())
	result := make([]byte, length)
	
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	
	return string(result)
}

// queryDomain performs a DNS query and returns the answer records
func (w *WildcardDetector) queryDomain(domain string, qtype uint16) []string {
	resolver := w.resolverPool.GetRandomResolver()
	if resolver == nil {
		return nil
	}
	
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true
	
	response, _, err := resolver.Client.Exchange(msg, resolver.Address)
	if err != nil || response == nil {
		return nil
	}
	
	var answers []string
	for _, rr := range response.Answer {
		switch qtype {
		case dns.TypeA:
			if a, ok := rr.(*dns.A); ok {
				answers = append(answers, a.A.String())
			}
		case dns.TypeAAAA:
			if aaaa, ok := rr.(*dns.AAAA); ok {
				answers = append(answers, aaaa.AAAA.String())
			}
		case dns.TypeCNAME:
			if cname, ok := rr.(*dns.CNAME); ok {
				answers = append(answers, cname.Target)
			}
		default:
			answers = append(answers, rr.String())
		}
	}
	
	return answers
}

// sliceEqual compares two string slices for equality
func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	
	return true
}

// ClearCache clears the wildcard detection cache
func (w *WildcardDetector) ClearCache() {
	w.cacheMutex.Lock()
	defer w.cacheMutex.Unlock()
	
	w.cache = make(map[string]bool)
}

// GetCacheSize returns the number of cached wildcard results
func (w *WildcardDetector) GetCacheSize() int {
	w.cacheMutex.RLock()
	defer w.cacheMutex.RUnlock()
	
	return len(w.cache)
}
