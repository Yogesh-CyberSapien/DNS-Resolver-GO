package main

import "github.com/miekg/dns"

// Config holds all configuration options for the DNS resolver
type Config struct {
        // Input/Output options
        InputFile    string
        OutputFile   string
        LogFile      string
        OutputFormat string
        
        // DNS resolver options
        Resolvers     string
        ResolversFile string
        QueryTypes    string
        
        // Performance options
        QPS      int
        Timeout  int
        Retries  int
        Workers  int
        
        // Feature flags
        WildcardDetection bool
        Verbose           bool
        Help              bool
        Version           bool
        Quiet             bool
}

// DNSResult represents the result of a DNS query
type DNSResult struct {
        Domain   string
        Type     uint16
        Response *dns.Msg
        Error    error
        Resolver string
}

// GetDefaultResolvers returns a list of popular public DNS resolvers
func GetDefaultResolvers() []string {
        return []string{
                "8.8.8.8:53",        // Google DNS
                "8.8.4.4:53",        // Google DNS
                "1.1.1.1:53",        // Cloudflare DNS
                "1.0.0.1:53",        // Cloudflare DNS
                "9.9.9.9:53",        // Quad9 DNS
                "149.112.112.112:53", // Quad9 DNS
                "208.67.222.222:53", // OpenDNS
                "208.67.220.220:53", // OpenDNS
                "84.200.69.80:53",   // DNS.WATCH
                "84.200.70.40:53",   // DNS.WATCH
                "76.76.19.19:53",    // Alternate DNS
                "76.76.2.0:53",      // Alternate DNS
                "94.140.14.14:53",   // AdGuard DNS
                "94.140.15.15:53",   // AdGuard DNS
        }
}
