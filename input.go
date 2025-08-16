package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
)

// InputReader handles reading and validating domain names from input
type InputReader struct {
	reader   io.Reader
	scanner  *bufio.Scanner
	validator *DomainValidator
}

// DomainValidator validates domain names
type DomainValidator struct {
	domainRegex *regexp.Regexp
	ipv4Regex   *regexp.Regexp
	ipv6Regex   *regexp.Regexp
}

// NewInputReader creates a new input reader
func NewInputReader(reader io.Reader) *InputReader {
	validator := &DomainValidator{
		domainRegex: regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`),
		ipv4Regex:   regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`),
		ipv6Regex:   regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$`),
	}
	
	return &InputReader{
		reader:    reader,
		scanner:   bufio.NewScanner(reader),
		validator: validator,
	}
}

// ReadDomains reads and validates domain names from input
func (r *InputReader) ReadDomains() ([]string, error) {
	var domains []string
	lineNum := 0
	
	for r.scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(r.scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Validate the domain/IP
		if r.validator.IsValid(line) {
			domains = append(domains, line)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Invalid domain/IP on line %d: %s\n", lineNum, line)
		}
	}
	
	if err := r.scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input: %v", err)
	}
	
	return domains, nil
}

// IsValid checks if a string is a valid domain name or IP address
func (v *DomainValidator) IsValid(input string) bool {
	// Remove any protocol prefix
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")
	
	// Remove any path
	if idx := strings.Index(input, "/"); idx != -1 {
		input = input[:idx]
	}
	
	// Remove any port
	if host, _, err := net.SplitHostPort(input); err == nil {
		input = host
	}
	
	// Check if it's an IPv4 address
	if v.ipv4Regex.MatchString(input) {
		return true
	}
	
	// Check if it's an IPv6 address
	if v.ipv6Regex.MatchString(input) {
		return true
	}
	
	// Check if it's a valid domain name
	if len(input) > 253 {
		return false
	}
	
	// Domain name validation
	if v.domainRegex.MatchString(input) {
		// Additional checks
		parts := strings.Split(input, ".")
		for _, part := range parts {
			if len(part) > 63 {
				return false
			}
		}
		return true
	}
	
	return false
}

// ReadDomainsFromFile reads domains from a file
func ReadDomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()
	
	reader := NewInputReader(file)
	return reader.ReadDomains()
}

// ReadDomainsFromStdin reads domains from standard input
func ReadDomainsFromStdin() ([]string, error) {
	reader := NewInputReader(os.Stdin)
	return reader.ReadDomains()
}

// generateSubdomains generates common subdomains for a given domain
func generateSubdomains(domain string) []string {
	commonSubdomains := []string{
		"www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
		"blog", "shop", "store", "support", "help", "docs", "cdn",
		"static", "media", "images", "img", "assets", "download",
		"secure", "vpn", "remote", "portal", "dashboard", "panel",
		"forum", "community", "social", "chat", "wiki", "news",
		"mobile", "m", "app", "apps", "beta", "alpha", "demo",
	}
	
	var subdomains []string
	for _, sub := range commonSubdomains {
		subdomains = append(subdomains, fmt.Sprintf("%s.%s", sub, domain))
	}
	
	return subdomains
}

// FilterDomains filters out invalid or unwanted domains
func FilterDomains(domains []string, validator *DomainValidator) []string {
	var filtered []string
	seen := make(map[string]bool)
	
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		
		// Skip if already seen
		if seen[domain] {
			continue
		}
		
		// Validate domain
		if validator.IsValid(domain) {
			filtered = append(filtered, domain)
			seen[domain] = true
		}
	}
	
	return filtered
}
