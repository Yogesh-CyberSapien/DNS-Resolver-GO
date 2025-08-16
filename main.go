// High-performance DNS resolver command-line tool
// Supports concurrent DNS queries and brute-forcing
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultQPS      = 100
	defaultTimeout  = 5
	defaultRetries  = 3
	defaultWorkers  = 50
)

func main() {
	config := parseFlags()
	
	if config.Help {
		printUsage()
		return
	}

	if config.Version {
		fmt.Println("DNS Resolver v1.0.0")
		return
	}

	// Initialize logger
	logger := setupLogger(config.LogFile, config.Verbose)
	
	// Initialize resolver pool
	resolverPool := NewResolverPool(config, logger)
	defer resolverPool.Close()

	// Initialize rate limiter
	rateLimiter := NewRateLimiter(config.QPS)

	// Initialize wildcard detector if enabled
	var wildcardDetector *WildcardDetector
	if config.WildcardDetection {
		wildcardDetector = NewWildcardDetector(resolverPool, logger)
	}

	// Initialize output handler
	outputHandler := NewOutputHandler(config.OutputFile, config.OutputFormat, logger)
	defer outputHandler.Close()

	// Initialize statistics tracker
	stats := NewStats()

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		logger.Println("Received shutdown signal, stopping...")
		cancel()
	}()

	// Start the DNS resolution process
	err := processDNSQueries(ctx, config, resolverPool, rateLimiter, wildcardDetector, outputHandler, stats, logger)
	if err != nil {
		logger.Fatalf("Error processing DNS queries: %v", err)
	}

	// Print final statistics
	stats.PrintFinalStats(logger)
}

func parseFlags() *Config {
	config := &Config{}
	
	flag.StringVar(&config.InputFile, "i", "", "Input file containing DNS names (default: stdin)")
	flag.StringVar(&config.OutputFile, "o", "", "Output file for results (default: stdout)")
	flag.StringVar(&config.LogFile, "l", "", "Log file for errors and debug info (default: stderr)")
	flag.StringVar(&config.ResolversFile, "rf", "", "File containing DNS resolver IP addresses")
	flag.StringVar(&config.Resolvers, "r", "", "Comma-separated list of DNS resolver IP addresses")
	flag.StringVar(&config.QueryTypes, "t", "A", "Comma-separated list of DNS record types (A,AAAA,CNAME,MX,NS,TXT,SOA,PTR)")
	flag.StringVar(&config.OutputFormat, "f", "simple", "Output format: simple, json, csv")
	flag.IntVar(&config.QPS, "qps", defaultQPS, "Queries per second per resolver")
	flag.IntVar(&config.Timeout, "timeout", defaultTimeout, "Query timeout in seconds")
	flag.IntVar(&config.Retries, "retries", defaultRetries, "Number of retries for failed queries")
	flag.IntVar(&config.Workers, "workers", defaultWorkers, "Number of worker goroutines")
	flag.BoolVar(&config.WildcardDetection, "w", false, "Enable DNS wildcard detection")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose logging")
	flag.BoolVar(&config.Help, "h", false, "Show help message")
	flag.BoolVar(&config.Version, "version", false, "Show version information")
	flag.BoolVar(&config.Quiet, "q", false, "Quiet mode (suppress non-essential output)")

	flag.Parse()
	
	// Validate and set defaults
	if config.QPS <= 0 {
		config.QPS = defaultQPS
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultTimeout
	}
	if config.Retries < 0 {
		config.Retries = defaultRetries
	}
	if config.Workers <= 0 {
		config.Workers = defaultWorkers
	}

	return config
}

func printUsage() {
	fmt.Println("DNS Resolver - High-performance DNS resolution tool")
	fmt.Println()
	fmt.Println("Usage: dns-resolver [options]")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  echo 'google.com' | dns-resolver")
	fmt.Println("  dns-resolver -i domains.txt -o results.txt -t A,AAAA -qps 50")
	fmt.Println("  dns-resolver -r 8.8.8.8,1.1.1.1 -w -v")
	fmt.Println("  dns-resolver -rf resolvers.txt -f json -timeout 10")
}

func setupLogger(logFile string, verbose bool) *log.Logger {
	var logOutput *os.File = os.Stderr
	
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		logOutput = file
	}
	
	flags := log.LstdFlags
	if verbose {
		flags |= log.Lshortfile
	}
	
	return log.New(logOutput, "[DNS-RESOLVER] ", flags)
}

func processDNSQueries(ctx context.Context, config *Config, resolverPool *ResolverPool, 
	rateLimiter *RateLimiter, wildcardDetector *WildcardDetector, 
	outputHandler *OutputHandler, stats *Stats, logger *log.Logger) error {

	// Parse query types
	queryTypes, err := parseQueryTypes(config.QueryTypes)
	if err != nil {
		return fmt.Errorf("invalid query types: %v", err)
	}

	// Setup input reader
	inputReader, err := setupInputReader(config.InputFile)
	if err != nil {
		return fmt.Errorf("failed to setup input reader: %v", err)
	}
	defer inputReader.Close()

	// Create channels for communication
	domainChan := make(chan string, config.Workers)
	resultChan := make(chan *DNSResult, config.Workers*2)
	
	// Start worker goroutines
	for i := 0; i < config.Workers; i++ {
		go dnsWorker(ctx, domainChan, resultChan, queryTypes, resolverPool, 
			rateLimiter, config, stats, logger)
	}

	// Start result processor
	go resultProcessor(ctx, resultChan, outputHandler, wildcardDetector, stats, logger)

	// Start statistics reporter if verbose
	if config.Verbose && !config.Quiet {
		go stats.StartReporter(ctx, logger, 10*time.Second)
	}

	// Read domains and send to workers
	scanner := bufio.NewScanner(inputReader)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}
		
		select {
		case domainChan <- domain:
			stats.IncrementTotal()
		case <-ctx.Done():
			close(domainChan)
			return ctx.Err()
		}
	}
	
	close(domainChan)
	
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input: %v", err)
	}

	// Wait for all workers to finish
	logger.Println("Waiting for workers to complete...")
	for stats.GetProcessed() < stats.GetTotal() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			// Continue waiting
		}
	}

	close(resultChan)
	return nil
}

func parseQueryTypes(queryTypesStr string) ([]uint16, error) {
	typeMap := map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"CNAME": dns.TypeCNAME,
		"MX":    dns.TypeMX,
		"NS":    dns.TypeNS,
		"TXT":   dns.TypeTXT,
		"SOA":   dns.TypeSOA,
		"PTR":   dns.TypePTR,
		"SRV":   dns.TypeSRV,
	}
	
	types := strings.Split(strings.ToUpper(queryTypesStr), ",")
	var result []uint16
	
	for _, t := range types {
		t = strings.TrimSpace(t)
		if qtype, exists := typeMap[t]; exists {
			result = append(result, qtype)
		} else {
			// Try parsing as numeric type
			if num, err := strconv.Atoi(t); err == nil && num > 0 && num < 65536 {
				result = append(result, uint16(num))
			} else {
				return nil, fmt.Errorf("unknown query type: %s", t)
			}
		}
	}
	
	if len(result) == 0 {
		return []uint16{dns.TypeA}, nil
	}
	
	return result, nil
}

func setupInputReader(inputFile string) (*os.File, error) {
	if inputFile == "" {
		return os.Stdin, nil
	}
	
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file: %v", err)
	}
	
	return file, nil
}

func dnsWorker(ctx context.Context, domainChan <-chan string, resultChan chan<- *DNSResult,
	queryTypes []uint16, resolverPool *ResolverPool, rateLimiter *RateLimiter,
	config *Config, stats *Stats, logger *log.Logger) {
	
	for {
		select {
		case domain, ok := <-domainChan:
			if !ok {
				return
			}
			
			for _, qtype := range queryTypes {
				// Apply rate limiting
				rateLimiter.Wait(ctx)
				
				// Perform DNS query with retries
				result := performDNSQuery(ctx, domain, qtype, resolverPool, config, logger)
				
				select {
				case resultChan <- result:
				case <-ctx.Done():
					return
				}
			}
			
		case <-ctx.Done():
			return
		}
	}
}

func performDNSQuery(ctx context.Context, domain string, qtype uint16, 
	resolverPool *ResolverPool, config *Config, logger *log.Logger) *DNSResult {
	
	var lastErr error
	
	for attempt := 0; attempt <= config.Retries; attempt++ {
		resolver := resolverPool.GetResolver()
		if resolver == nil {
			lastErr = fmt.Errorf("no resolvers available")
			continue
		}
		
		msg := &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(domain), qtype)
		msg.RecursionDesired = true
		
		ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
		response, _, err := resolver.ExchangeContext(ctx, msg, resolver.Address)
		cancel()
		
		if err != nil {
			lastErr = err
			if config.Verbose {
				logger.Printf("Query failed for %s (type %d, attempt %d): %v", 
					domain, qtype, attempt+1, err)
			}
			continue
		}
		
		return &DNSResult{
			Domain:   domain,
			Type:     qtype,
			Response: response,
			Error:    nil,
			Resolver: resolver.Address,
		}
	}
	
	return &DNSResult{
		Domain: domain,
		Type:   qtype,
		Error:  lastErr,
	}
}

func resultProcessor(ctx context.Context, resultChan <-chan *DNSResult, 
	outputHandler *OutputHandler, wildcardDetector *WildcardDetector, 
	stats *Stats, logger *log.Logger) {
	
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				return
			}
			
			stats.IncrementProcessed()
			
			if result.Error != nil {
				stats.IncrementErrors()
				if logger != nil {
					logger.Printf("DNS query error for %s: %v", result.Domain, result.Error)
				}
				continue
			}
			
			// Check for wildcard if detector is enabled
			if wildcardDetector != nil && wildcardDetector.IsWildcard(result) {
				stats.IncrementWildcards()
				continue
			}
			
			// Process successful result
			if result.Response != nil && len(result.Response.Answer) > 0 {
				stats.IncrementSuccessful()
				outputHandler.WriteResult(result)
			} else {
				stats.IncrementNoAnswer()
			}
			
		case <-ctx.Done():
			return
		}
	}
}
