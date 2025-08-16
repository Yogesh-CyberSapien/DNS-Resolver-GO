package main

import (
        "bufio"
        "context"
        "fmt"
        "log"
        "math/rand"
        "net"
        "os"
        "strings"
        "sync"
        "time"

        "github.com/miekg/dns"
)

// DNSResolver represents a single DNS resolver
type DNSResolver struct {
        Address string
        Client  *dns.Client
}

// ResolverPool manages a pool of DNS resolvers
type ResolverPool struct {
        resolvers []*DNSResolver
        mutex     sync.RWMutex
        index     int
        logger    *log.Logger
}

// NewResolverPool creates a new resolver pool
func NewResolverPool(config *Config, logger *log.Logger) *ResolverPool {
        pool := &ResolverPool{
                resolvers: make([]*DNSResolver, 0),
                logger:    logger,
        }
        
        // Load resolvers from various sources
        var resolverAddresses []string
        
        // Load from command line
        if config.Resolvers != "" {
                addresses := strings.Split(config.Resolvers, ",")
                for _, addr := range addresses {
                        addr = strings.TrimSpace(addr)
                        if addr != "" {
                                resolverAddresses = append(resolverAddresses, addr)
                        }
                }
        }
        
        // Load from file
        if config.ResolversFile != "" {
                fileAddresses, err := loadResolversFromFile(config.ResolversFile)
                if err != nil {
                        logger.Printf("Error loading resolvers from file: %v", err)
                } else {
                        resolverAddresses = append(resolverAddresses, fileAddresses...)
                }
        }
        
        // Use defaults if no resolvers specified
        if len(resolverAddresses) == 0 {
                resolverAddresses = GetDefaultResolvers()
                logger.Println("Using default DNS resolvers")
        }
        
        // Create resolver instances
        for _, addr := range resolverAddresses {
                if resolver := pool.createResolver(addr, config.Timeout); resolver != nil {
                        pool.resolvers = append(pool.resolvers, resolver)
                }
        }
        
        logger.Printf("Initialized resolver pool with %d resolvers", len(pool.resolvers))
        return pool
}

// createResolver creates a new DNS resolver with proper address formatting
func (p *ResolverPool) createResolver(address string, timeout int) *DNSResolver {
        // Ensure address has port
        if !strings.Contains(address, ":") {
                address = address + ":53"
        }
        
        // Validate address
        if _, _, err := net.SplitHostPort(address); err != nil {
                p.logger.Printf("Invalid resolver address: %s", address)
                return nil
        }
        
        client := &dns.Client{
                Timeout: time.Duration(timeout) * time.Second,
                Net:     "udp",
        }
        
        // Test the resolver
        if !p.testResolver(address, client) {
                p.logger.Printf("Resolver test failed: %s", address)
                return nil
        }
        
        return &DNSResolver{
                Address: address,
                Client:  client,
        }
}

// testResolver performs a basic connectivity test
func (p *ResolverPool) testResolver(address string, client *dns.Client) bool {
        msg := &dns.Msg{}
        msg.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
        
        _, _, err := client.Exchange(msg, address)
        return err == nil
}

// GetResolver returns the next available resolver using round-robin
func (p *ResolverPool) GetResolver() *DNSResolver {
        p.mutex.Lock()
        defer p.mutex.Unlock()
        
        if len(p.resolvers) == 0 {
                return nil
        }
        
        resolver := p.resolvers[p.index]
        p.index = (p.index + 1) % len(p.resolvers)
        
        return resolver
}

// GetRandomResolver returns a random resolver from the pool
func (p *ResolverPool) GetRandomResolver() *DNSResolver {
        p.mutex.RLock()
        defer p.mutex.RUnlock()
        
        if len(p.resolvers) == 0 {
                return nil
        }
        
        index := rand.Intn(len(p.resolvers))
        return p.resolvers[index]
}

// GetResolverCount returns the number of available resolvers
func (p *ResolverPool) GetResolverCount() int {
        p.mutex.RLock()
        defer p.mutex.RUnlock()
        
        return len(p.resolvers)
}

// Close cleans up the resolver pool
func (p *ResolverPool) Close() {
        p.mutex.Lock()
        defer p.mutex.Unlock()
        
        p.resolvers = nil
        p.logger.Println("Resolver pool closed")
}

// ExchangeContext performs a DNS query with context support
func (r *DNSResolver) ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
        return r.Client.ExchangeContext(ctx, msg, address)
}

// loadResolversFromFile loads resolver addresses from a file
func loadResolversFromFile(filename string) ([]string, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, fmt.Errorf("failed to open resolvers file: %v", err)
        }
        defer file.Close()
        
        var resolvers []string
        scanner := bufio.NewScanner(file)
        
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" && !strings.HasPrefix(line, "#") {
                        resolvers = append(resolvers, line)
                }
        }
        
        if err := scanner.Err(); err != nil {
                return nil, fmt.Errorf("error reading resolvers file: %v", err)
        }
        
        return resolvers, nil
}
