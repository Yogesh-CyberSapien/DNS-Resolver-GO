package main

import (
        "context"
        "fmt"
        "log"
        "strings"
        "sync/atomic"
        "time"
)

// Stats tracks statistics for DNS resolution
type Stats struct {
        totalDomains    int64
        processedQueries int64
        successfulQueries int64
        errorQueries     int64
        noAnswerQueries  int64
        wildcardQueries  int64
        startTime       time.Time
}

// NewStats creates a new statistics tracker
func NewStats() *Stats {
        return &Stats{
                startTime: time.Now(),
        }
}

// IncrementTotal increments the total domain count
func (s *Stats) IncrementTotal() {
        atomic.AddInt64(&s.totalDomains, 1)
}

// IncrementProcessed increments the processed query count
func (s *Stats) IncrementProcessed() {
        atomic.AddInt64(&s.processedQueries, 1)
}

// IncrementSuccessful increments the successful query count
func (s *Stats) IncrementSuccessful() {
        atomic.AddInt64(&s.successfulQueries, 1)
}

// IncrementErrors increments the error query count
func (s *Stats) IncrementErrors() {
        atomic.AddInt64(&s.errorQueries, 1)
}

// IncrementNoAnswer increments the no-answer query count
func (s *Stats) IncrementNoAnswer() {
        atomic.AddInt64(&s.noAnswerQueries, 1)
}

// IncrementWildcards increments the wildcard query count
func (s *Stats) IncrementWildcards() {
        atomic.AddInt64(&s.wildcardQueries, 1)
}

// GetTotal returns the total domain count
func (s *Stats) GetTotal() int64 {
        return atomic.LoadInt64(&s.totalDomains)
}

// GetProcessed returns the processed query count
func (s *Stats) GetProcessed() int64 {
        return atomic.LoadInt64(&s.processedQueries)
}

// GetSuccessful returns the successful query count
func (s *Stats) GetSuccessful() int64 {
        return atomic.LoadInt64(&s.successfulQueries)
}

// GetErrors returns the error query count
func (s *Stats) GetErrors() int64 {
        return atomic.LoadInt64(&s.errorQueries)
}

// GetNoAnswer returns the no-answer query count
func (s *Stats) GetNoAnswer() int64 {
        return atomic.LoadInt64(&s.noAnswerQueries)
}

// GetWildcards returns the wildcard query count
func (s *Stats) GetWildcards() int64 {
        return atomic.LoadInt64(&s.wildcardQueries)
}

// GetElapsedTime returns the elapsed time since start
func (s *Stats) GetElapsedTime() time.Duration {
        return time.Since(s.startTime)
}

// GetQueriesPerSecond calculates the current queries per second rate
func (s *Stats) GetQueriesPerSecond() float64 {
        elapsed := s.GetElapsedTime().Seconds()
        if elapsed == 0 {
                return 0
        }
        return float64(s.GetProcessed()) / elapsed
}

// PrintCurrentStats prints current statistics
func (s *Stats) PrintCurrentStats(logger *log.Logger) {
        total := s.GetTotal()
        processed := s.GetProcessed()
        successful := s.GetSuccessful()
        errors := s.GetErrors()
        noAnswer := s.GetNoAnswer()
        wildcards := s.GetWildcards()
        elapsed := s.GetElapsedTime()
        qps := s.GetQueriesPerSecond()
        
        logger.Printf("Stats: Total=%d, Processed=%d, Successful=%d, Errors=%d, NoAnswer=%d, Wildcards=%d, Elapsed=%v, QPS=%.2f",
                total, processed, successful, errors, noAnswer, wildcards, elapsed.Truncate(time.Second), qps)
}

// PrintFinalStats prints final statistics summary
func (s *Stats) PrintFinalStats(logger *log.Logger) {
        total := s.GetTotal()
        processed := s.GetProcessed()
        successful := s.GetSuccessful()
        errors := s.GetErrors()
        noAnswer := s.GetNoAnswer()
        wildcards := s.GetWildcards()
        elapsed := s.GetElapsedTime()
        qps := s.GetQueriesPerSecond()
        
        logger.Println("=== Final Statistics ===")
        logger.Printf("Total domains processed: %d", total)
        logger.Printf("Total queries sent: %d", processed)
        logger.Printf("Successful queries: %d (%.2f%%)", successful, percentage(successful, processed))
        logger.Printf("Failed queries: %d (%.2f%%)", errors, percentage(errors, processed))
        logger.Printf("No answer queries: %d (%.2f%%)", noAnswer, percentage(noAnswer, processed))
        logger.Printf("Wildcard queries: %d (%.2f%%)", wildcards, percentage(wildcards, processed))
        logger.Printf("Total elapsed time: %v", elapsed.Truncate(time.Second))
        logger.Printf("Average queries per second: %.2f", qps)
        
        if processed > 0 {
                successRate := float64(successful) / float64(processed) * 100
                logger.Printf("Success rate: %.2f%%", successRate)
        }
}

// StartReporter starts a goroutine that periodically reports statistics
func (s *Stats) StartReporter(ctx context.Context, logger *log.Logger, interval time.Duration) {
        ticker := time.NewTicker(interval)
        defer ticker.Stop()
        
        for {
                select {
                case <-ticker.C:
                        s.PrintCurrentStats(logger)
                case <-ctx.Done():
                        return
                }
        }
}

// GetSummary returns a summary of statistics as a map
func (s *Stats) GetSummary() map[string]interface{} {
        return map[string]interface{}{
                "total_domains":      s.GetTotal(),
                "processed_queries":  s.GetProcessed(),
                "successful_queries": s.GetSuccessful(),
                "error_queries":      s.GetErrors(),
                "no_answer_queries":  s.GetNoAnswer(),
                "wildcard_queries":   s.GetWildcards(),
                "elapsed_time":       s.GetElapsedTime().Seconds(),
                "queries_per_second": s.GetQueriesPerSecond(),
        }
}

// Reset resets all statistics counters
func (s *Stats) Reset() {
        atomic.StoreInt64(&s.totalDomains, 0)
        atomic.StoreInt64(&s.processedQueries, 0)
        atomic.StoreInt64(&s.successfulQueries, 0)
        atomic.StoreInt64(&s.errorQueries, 0)
        atomic.StoreInt64(&s.noAnswerQueries, 0)
        atomic.StoreInt64(&s.wildcardQueries, 0)
        s.startTime = time.Now()
}

// percentage calculates percentage with zero division protection
func percentage(part, total int64) float64 {
        if total == 0 {
                return 0
        }
        return float64(part) / float64(total) * 100
}

// FormatDuration formats a duration in a human-readable format
func FormatDuration(d time.Duration) string {
        if d < time.Minute {
                return fmt.Sprintf("%.1fs", d.Seconds())
        }
        if d < time.Hour {
                return fmt.Sprintf("%.1fm", d.Minutes())
        }
        return fmt.Sprintf("%.1fh", d.Hours())
}

// ProgressBar represents a simple progress bar
type ProgressBar struct {
        total   int64
        current int64
        width   int
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int64, width int) *ProgressBar {
        return &ProgressBar{
                total: total,
                width: width,
        }
}

// Update updates the progress bar
func (p *ProgressBar) Update(current int64) {
        p.current = current
}

// String returns the progress bar as a string
func (p *ProgressBar) String() string {
        if p.total == 0 {
                return "[" + strings.Repeat("=", p.width) + "]"
        }
        
        progress := float64(p.current) / float64(p.total)
        filled := int(progress * float64(p.width))
        
        bar := "["
        bar += strings.Repeat("=", filled)
        if filled < p.width {
                bar += ">"
                bar += strings.Repeat(" ", p.width-filled-1)
        }
        bar += "]"
        
        return fmt.Sprintf("%s %.1f%% (%d/%d)", bar, progress*100, p.current, p.total)
}
