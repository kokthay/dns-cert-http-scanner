// Direct-IP HTTPS collection. No DNS, certificate validation, or redirects.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	Input, Output, FailuresOutput, UserAgent                          string
	Workers, Port, Limit                                              int
	Rate                                                              float64
	Timeout, ConnectTimeout, TLSTimeout, HeaderTimeout, ProgressEvery time.Duration
	MaxHeaderBytes                                                    int64
	Resume, RetryFailed                                               bool
}

func parseConfig() Config {
	c := Config{}
	flag.StringVar(&c.Input, "input", "/work/results/websites_ipv4.jsonl", "JSONL input: rank, domain, ips (or legacy ip)")
	flag.StringVar(&c.Output, "output", "/work/results/cert_http", "Result root")
	flag.StringVar(&c.FailuresOutput, "failures-output", "", "Failure root; default: failures_certHTTP beside output")
	flag.IntVar(&c.Workers, "workers", 100, "Concurrent domain tasks")
	flag.Float64Var(&c.Rate, "rate", 50, "Global connection starts/second, including HTTP/2 retries; 0 unlimited")
	flag.DurationVar(&c.Timeout, "timeout", 20*time.Second, "Network timeout for EACH protocol attempt")
	flag.DurationVar(&c.ConnectTimeout, "connect-timeout", 5*time.Second, "TCP timeout")
	flag.DurationVar(&c.TLSTimeout, "tls-timeout", 5*time.Second, "TLS timeout")
	flag.DurationVar(&c.HeaderTimeout, "header-timeout", 10*time.Second, "HTTP write/header timeout")
	flag.DurationVar(&c.ProgressEvery, "progress-every", 10*time.Second, "Progress interval")
	flag.Int64Var(&c.MaxHeaderBytes, "max-header-bytes", 1<<20, "Response-header limit per protocol attempt")
	flag.IntVar(&c.Port, "port", 443, "HTTPS destination port")
	flag.IntVar(&c.Limit, "limit", 0, "Read at most this many nonblank input rows; 0 all")
	flag.BoolVar(&c.Resume, "resume", true, "Reuse completed domain results and import old HTTP/1 successes")
	flag.BoolVar(&c.RetryFailed, "retry-failed", false, "Re-probe completed failures; keep successes")
	flag.StringVar(&c.UserAgent, "user-agent", "ResearchHTTPSScanner/1.0", "HTTP User-Agent")
	flag.Parse()
	return c
}

func (c Config) validate() error {
	if c.Workers < 1 || c.Port < 1 || c.Port > 65535 || c.Limit < 0 || c.MaxHeaderBytes < 1024 || math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) || c.Rate < 0 || c.Rate > 1e9 || c.Rate > 0 && c.Rate < 1e-6 {
		return errors.New("invalid workers, port, limit, header limit, or rate")
	}
	if c.Timeout <= 0 || c.ConnectTimeout <= 0 || c.TLSTimeout <= 0 || c.HeaderTimeout <= 0 || c.ProgressEvery <= 0 {
		return errors.New("timeouts must be positive")
	}
	if strings.ContainsAny(c.UserAgent, "\r\n") {
		return errors.New("invalid User-Agent")
	}
	return nil
}

type Counters struct{ Rows, Queued, Done, Skipped, Migrated, Succeeded, Failed, Invalid, Deduplicated, WriteErrors atomic.Int64 }

func (s *Counters) snapshot() map[string]int64 {
	return map[string]int64{"rows_read": s.Rows.Load(), "domains_queued": s.Queued.Load(), "probed": s.Done.Load(), "resume_skipped": s.Skipped.Load(), "legacy_imported": s.Migrated.Load(), "collected": s.Succeeded.Load(), "collection_failed": s.Failed.Load(), "invalid_input": s.Invalid.Load(), "duplicate_ips_skipped": s.Deduplicated.Load(), "write_errors": s.WriteErrors.Load()}
}

type JSONLog struct {
	mu   sync.Mutex
	file *os.File
}

func (l *JSONLog) write(v any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return json.NewEncoder(l.file).Encode(v)
}
func openLog(path string) (*JSONLog, error) {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	return &JSONLog{file: f}, e
}

type statusStats struct {
	mu                  sync.Mutex
	Endpoints, Attempts map[string]int64
}

func (s *statusStats) add(e Endpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Endpoints[e.HTTP.Status]++
	for _, a := range e.HTTP.Attempts {
		s.Attempts[a.Protocol+":"+a.Status]++
	}
}

func run(parent context.Context, c Config) error {
	if c.FailuresOutput == "" {
		c.FailuresOutput = filepath.Join(filepath.Dir(filepath.Clean(c.Output)), "failures_certHTTP")
	}
	if err := c.validate(); err != nil {
		return err
	}
	started := time.Now().UTC()
	runID := started.Format("20060102T150405.000000000Z")
	runDir := filepath.Join(c.Output, "_runs", runID)
	failureRunDir := filepath.Join(c.FailuresOutput, "_runs", runID)
	for _, p := range []string{runDir, failureRunDir} {
		if err := os.MkdirAll(p, 0755); err != nil {
			return err
		}
	}
	errorLog, err := openLog(filepath.Join(failureRunDir, "errors.jsonl"))
	if err != nil {
		return err
	}
	defer errorLog.file.Close()
	invalid, err := openLog(filepath.Join(runDir, "input_errors.jsonl"))
	if err != nil {
		return err
	}
	defer invalid.file.Close()
	f, err := os.Open(c.Input)
	if err != nil {
		_ = errorLog.write(map[string]any{"status": "LOCAL_IO_ERROR", "error": err.Error()})
		return err
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var counts Counters
	stats := statusStats{Endpoints: map[string]int64{}, Attempts: map[string]int64{}}
	var fatalMu sync.Mutex
	var fatalErr error
	fail := func(e error) {
		fatalMu.Lock()
		if fatalErr == nil {
			fatalErr = e
			_ = errorLog.write(map[string]any{"status": "LOCAL_IO_ERROR", "error": e.Error(), "observed_at": time.Now().UTC()})
		}
		fatalMu.Unlock()
		cancel()
	}
	var ticks <-chan time.Time
	if c.Rate > 0 {
		ticker := time.NewTicker(time.Duration(float64(time.Second) / c.Rate))
		defer ticker.Stop()
		ticks = ticker.C
	}
	gate := func(ctx context.Context) error {
		if ticks == nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			return nil
		}
	}
	progressDone := make(chan struct{})
	defer close(progressDone)
	go func() {
		ticker := time.NewTicker(c.ProgressEvery)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				log.Printf("probed=%d collected=%d failed=%d skipped=%d imported=%d invalid=%d queued=%d elapsed=%s", counts.Done.Load(), counts.Succeeded.Load(), counts.Failed.Load(), counts.Skipped.Load(), counts.Migrated.Load(), counts.Invalid.Load(), counts.Queued.Load(), time.Since(started).Round(time.Second))
			}
		}
	}()
	index := func(dir string, e Endpoint) error {
		record, err := syncFailure(c.FailuresOutput, dir, e)
		if err != nil {
			return err
		}
		if record != nil {
			return errorLog.write(record)
		}
		return nil
	}
	log.Printf("output=%s failures_output=%s run_log=%s workers=%d rate=%.1f/s protocols=HTTP/1.1,HTTP/2_fallback", c.Output, c.FailuresOutput, runDir, c.Workers, c.Rate)
	jobs := make(chan DomainTask, c.Workers)
	var wg sync.WaitGroup
	for n := 0; n < c.Workers; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					return
				}
				dir := targetDir(c.Output, Target{Rank: t.Rank, Domain: t.Domain})
				e, ok := loadCompleted(dir, t, c)
				if !ok && c.Resume {
					if imported, found := importLegacy(c.Output, t, c); found {
						e = imported
						ok = true
						if err := saveEndpoint(dir, e); err != nil {
							counts.WriteErrors.Add(1)
							fail(err)
							return
						}
						counts.Migrated.Add(1)
					}
				}
				if ok {
					if err := index(dir, e); err != nil {
						counts.WriteErrors.Add(1)
						fail(err)
						return
					}
					stats.add(e)
					counts.Skipped.Add(1)
					continue
				}
				e = probeEndpoint(ctx, t, c, gate)
				if err := saveEndpoint(dir, e); err != nil {
					counts.WriteErrors.Add(1)
					fail(fmt.Errorf("save rank %d domain %s: %w", t.Rank, t.Domain, err))
					return
				}
				if err := index(dir, e); err != nil {
					counts.WriteErrors.Add(1)
					fail(err)
					return
				}
				stats.add(e)
				counts.Done.Add(1)
				if e.HTTP.Success {
					counts.Succeeded.Add(1)
				} else {
					counts.Failed.Add(1)
				}
			}
		}()
	}
	inputError := func(line int, raw, status string, e error) {
		counts.Invalid.Add(1)
		v := map[string]any{"line": line, "status": status, "error": e.Error(), "input": raw}
		if err := invalid.write(v); err != nil {
			fail(err)
			return
		}
		if err := errorLog.write(v); err != nil {
			fail(err)
		}
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	tasks := []DomainTask{}
	rankIndexes := map[int]int{}
	line := 0
	// Merge repeated domain rows before scheduling, preserving IP appearance order.
	for scanner.Scan() {
		line++
		if ctx.Err() != nil {
			break
		}
		raw := scanner.Text()
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if c.Limit > 0 && counts.Rows.Load() >= int64(c.Limit) {
			break
		}
		counts.Rows.Add(1)
		var row InputRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			inputError(line, raw, "INVALID_INPUT", err)
			continue
		}
		identity := Target{Rank: row.Rank, Domain: row.Domain, IP: "127.0.0.1"}
		if err := normalize(&identity); err != nil {
			inputError(line, raw, "INVALID_INPUT", err)
			continue
		}
		idx, exists := rankIndexes[row.Rank]
		if exists && tasks[idx].Domain != identity.Domain {
			inputError(line, raw, "INVALID_INPUT", errors.New("same rank assigned to different domains"))
			continue
		}
		ips := append([]string{}, row.IPs...)
		if row.IP != "" {
			ips = append([]string{row.IP}, ips...)
		}
		if len(ips) == 0 {
			inputError(line, raw, "INVALID_INPUT", errors.New("missing ip or nonempty ips list"))
			continue
		}
		if !exists {
			idx = len(tasks)
			rankIndexes[row.Rank] = idx
			tasks = append(tasks, DomainTask{Rank: row.Rank, Domain: identity.Domain})
		}
		for _, ip := range ips {
			t := Target{row.Rank, ip, identity.Domain}
			if err := normalize(&t); err != nil {
				inputError(line, raw, "INVALID_IP", fmt.Errorf("IP %q: %w", ip, err))
				continue
			}
			if contains(tasks[idx].IPs, t.IP) {
				counts.Deduplicated.Add(1)
				continue
			}
			tasks[idx].IPs = append(tasks[idx].IPs, t.IP)
		}
	}
	if err := scanner.Err(); err != nil {
		fail(err)
	}
	log.Printf("input read: rows=%d unique_domains=%d invalid=%d; starting domain tasks", counts.Rows.Load(), len(tasks), counts.Invalid.Load())
enqueueLoop:
	for _, task := range tasks {
		if len(task.IPs) == 0 {
			continue
		}
		select {
		case jobs <- task:
			counts.Queued.Add(1)
		case <-ctx.Done():
			break enqueueLoop
		}
	}
	close(jobs)
	wg.Wait()
	if fatalErr == nil && parent.Err() != nil {
		fatalErr = parent.Err()
	}
	summary := map[string]any{"schema": profile, "started_at": started, "finished_at": time.Now().UTC(), "elapsed_seconds": time.Since(started).Seconds(), "counters": counts.snapshot(), "domain_status_counts": stats.Endpoints, "attempt_status_counts": stats.Attempts, "input": c.Input, "output": c.Output, "failures_output": c.FailuresOutput, "config": c, "go_version": runtime.Version(), "run_directory": runDir, "interrupted": parent.Err() != nil}
	if fatalErr != nil {
		summary["error"] = fatalErr.Error()
	}
	for _, path := range []string{filepath.Join(runDir, "summary.json"), filepath.Join(failureRunDir, "summary.json")} {
		if err := writeJSON(path, summary); err != nil {
			_ = errorLog.write(map[string]any{"status": "LOCAL_IO_ERROR", "error": err.Error()})
			return err
		}
	}
	log.Printf("finished counters=%v status_counts=%v summary=%s", counts.snapshot(), stats.Endpoints, filepath.Join(runDir, "summary.json"))
	if fatalErr != nil {
		return fatalErr
	}
	if counts.Invalid.Load() > 0 {
		return fmt.Errorf("%d invalid input entries; see %s", counts.Invalid.Load(), filepath.Join(runDir, "input_errors.jsonl"))
	}
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	c := parseConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, c); err != nil {
		log.Print(err)
		if ctx.Err() != nil {
			os.Exit(130)
		}
		os.Exit(1)
	}
}
