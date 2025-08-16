package main

import (
        "encoding/csv"
        "encoding/json"
        "fmt"
        "log"
        "os"
        "strings"
        "sync"

        "github.com/miekg/dns"
)

// OutputHandler manages output formatting and writing
type OutputHandler struct {
        file   *os.File
        format string
        writer interface{}
        mutex  sync.Mutex
        logger *log.Logger
}

// OutputRecord represents a single DNS resolution result for output
type OutputRecord struct {
        Domain   string `json:"domain"`
        Type     string `json:"type"`
        Record   string `json:"record"`
        Value    string `json:"value"`
        TTL      uint32 `json:"ttl"`
        Resolver string `json:"resolver"`
}

// NewOutputHandler creates a new output handler
func NewOutputHandler(filename, format string, logger *log.Logger) *OutputHandler {
        var file *os.File = os.Stdout
        
        if filename != "" {
                var err error
                file, err = os.Create(filename)
                if err != nil {
                        logger.Fatalf("Failed to create output file: %v", err)
                }
        }
        
        handler := &OutputHandler{
                file:   file,
                format: format,
                logger: logger,
        }
        
        // Initialize writer based on format
        switch format {
        case "csv":
                csvWriter := csv.NewWriter(file)
                csvWriter.Write([]string{"Domain", "Type", "Record", "Value", "TTL", "Resolver"})
                csvWriter.Flush()
                handler.writer = csvWriter
        case "json":
                // JSON array will be handled manually
        default:
                // Simple format, no special writer needed
        }
        
        return handler
}

// WriteResult writes a DNS result to the output
func (o *OutputHandler) WriteResult(result *DNSResult) {
        o.mutex.Lock()
        defer o.mutex.Unlock()
        
        if result.Response == nil || len(result.Response.Answer) == 0 {
                return
        }
        
        records := o.extractRecords(result)
        
        switch o.format {
        case "json":
                o.writeJSON(records)
        case "csv":
                o.writeCSV(records)
        default:
                o.writeSimple(records)
        }
}

// extractRecords extracts DNS records from a response
func (o *OutputHandler) extractRecords(result *DNSResult) []OutputRecord {
        var records []OutputRecord
        
        for _, rr := range result.Response.Answer {
                record := OutputRecord{
                        Domain:   result.Domain,
                        Type:     dns.TypeToString[result.Type],
                        Record:   rr.Header().Name,
                        TTL:      rr.Header().Ttl,
                        Resolver: result.Resolver,
                }
                
                // Extract the value based on record type
                switch r := rr.(type) {
                case *dns.A:
                        record.Value = r.A.String()
                case *dns.AAAA:
                        record.Value = r.AAAA.String()
                case *dns.CNAME:
                        record.Value = r.Target
                case *dns.MX:
                        record.Value = fmt.Sprintf("%d %s", r.Preference, r.Mx)
                case *dns.NS:
                        record.Value = r.Ns
                case *dns.TXT:
                        record.Value = strings.Join(r.Txt, " ")
                case *dns.SOA:
                        record.Value = fmt.Sprintf("%s %s %d %d %d %d %d", 
                                r.Ns, r.Mbox, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl)
                case *dns.PTR:
                        record.Value = r.Ptr
                case *dns.SRV:
                        record.Value = fmt.Sprintf("%d %d %d %s", 
                                r.Priority, r.Weight, r.Port, r.Target)
                default:
                        record.Value = rr.String()
                }
                
                records = append(records, record)
        }
        
        return records
}

// writeSimple writes records in simple text format
func (o *OutputHandler) writeSimple(records []OutputRecord) {
        for _, record := range records {
                fmt.Fprintf(o.file, "%s\t%s\t%s\t%d\n", 
                        record.Domain, record.Type, record.Value, record.TTL)
        }
}

// writeJSON writes records in JSON format
func (o *OutputHandler) writeJSON(records []OutputRecord) {
        for _, record := range records {
                data, err := json.Marshal(record)
                if err != nil {
                        if o.logger != nil {
                                o.logger.Printf("Error marshaling JSON: %v", err)
                        }
                        continue
                }
                fmt.Fprintf(o.file, "%s\n", data)
        }
}

// writeCSV writes records in CSV format
func (o *OutputHandler) writeCSV(records []OutputRecord) {
        if csvWriter, ok := o.writer.(*csv.Writer); ok {
                for _, record := range records {
                        row := []string{
                                record.Domain,
                                record.Type,
                                record.Record,
                                record.Value,
                                fmt.Sprintf("%d", record.TTL),
                                record.Resolver,
                        }
                        csvWriter.Write(row)
                }
                csvWriter.Flush()
        }
}

// Close closes the output handler and flushes any pending data
func (o *OutputHandler) Close() {
        o.mutex.Lock()
        defer o.mutex.Unlock()
        
        if csvWriter, ok := o.writer.(*csv.Writer); ok {
                csvWriter.Flush()
        }
        
        if o.file != os.Stdout {
                o.file.Close()
        }
}

// Flush flushes any buffered output
func (o *OutputHandler) Flush() {
        o.mutex.Lock()
        defer o.mutex.Unlock()
        
        if csvWriter, ok := o.writer.(*csv.Writer); ok {
                csvWriter.Flush()
        }
        
        o.file.Sync()
}
