package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// This file demonstrates Go best practices using patterns from your EOS codebase

// 1. INTERFACE DESIGN - Make your code testable and flexible
type StorageMonitor interface {
	CheckUsage(ctx context.Context, path string) (*UsageInfo, error)
	TrackGrowth(ctx context.Context, path string) (*GrowthInfo, error)
}

type UsageInfo struct {
	Path        string
	UsedPercent float64
	TotalBytes  int64
}

type GrowthInfo struct {
	Path          string
	GrowthRate    float64
	DaysUntilFull float64
}

// 2. STRUCT EMBEDDING - Compose behavior instead of inheritance
type BaseMonitor struct {
	name    string
	timeout time.Duration
}

func (b *BaseMonitor) GetName() string           { return b.name }
func (b *BaseMonitor) GetTimeout() time.Duration { return b.timeout }

type DiskMonitor struct {
	BaseMonitor    // Embedded struct
	alertThreshold float64
}

// 3. FUNCTIONAL OPTIONS PATTERN - Flexible configuration
type MonitorOption func(*DiskMonitor)

func WithAlertThreshold(threshold float64) MonitorOption {
	return func(m *DiskMonitor) {
		m.alertThreshold = threshold
	}
}

func WithTimeout(timeout time.Duration) MonitorOption {
	return func(m *DiskMonitor) {
		m.timeout = timeout
	}
}

func NewDiskMonitor(name string, opts ...MonitorOption) *DiskMonitor {
	m := &DiskMonitor{
		BaseMonitor: BaseMonitor{
			name:    name,
			timeout: 30 * time.Second, // default
		},
		alertThreshold: 80.0, // default
	}

	// Apply options
	for _, opt := range opts {
		opt(m)
	}

	return m
}

// 4. CONTEXT HANDLING - Always pass context for cancellation
func (d *DiskMonitor) CheckUsage(ctx context.Context, path string) (*UsageInfo, error) {
	// Create a timeout context
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Simulate work with context checking
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
		// Simulated disk check
		return &UsageInfo{
			Path:        path,
			UsedPercent: 75.5,
			TotalBytes:  1000000000,
		}, nil
	}
}

// 5. ERROR WRAPPING - Use fmt.Errorf with %w for error chains
func (d *DiskMonitor) TrackGrowth(ctx context.Context, path string) (*GrowthInfo, error) {
	usage, err := d.CheckUsage(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to check usage for growth tracking: %w", err)
	}

	// Simulate growth calculation
	return &GrowthInfo{
		Path:          usage.Path,
		GrowthRate:    1.5, // GB per day
		DaysUntilFull: 30.0,
	}, nil
}

// 6. WORKER POOL PATTERN - Efficient concurrency
type MonitorJob struct {
	Path   string
	Result chan<- *UsageInfo
	Error  chan<- error
}

type MonitorPool struct {
	monitor  StorageMonitor
	workers  int
	jobQueue chan MonitorJob
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func NewMonitorPool(monitor StorageMonitor, workers int) *MonitorPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &MonitorPool{
		monitor:  monitor,
		workers:  workers,
		jobQueue: make(chan MonitorJob, workers*2), // Buffered channel
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (p *MonitorPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
}

func (p *MonitorPool) worker(id int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case job := <-p.jobQueue:
			result, err := p.monitor.CheckUsage(p.ctx, job.Path)
			if err != nil {
				job.Error <- err
			} else {
				job.Result <- result
			}
		}
	}
}

func (p *MonitorPool) Submit(path string) (<-chan *UsageInfo, <-chan error) {
	resultChan := make(chan *UsageInfo, 1)
	errorChan := make(chan error, 1)

	job := MonitorJob{
		Path:   path,
		Result: resultChan,
		Error:  errorChan,
	}

	select {
	case p.jobQueue <- job:
		// Job submitted successfully
	case <-p.ctx.Done():
		errorChan <- p.ctx.Err()
	}

	return resultChan, errorChan
}

func (p *MonitorPool) Stop() {
	p.cancel()
	p.wg.Wait()
	close(p.jobQueue)
}

// 7. RESOURCE MANAGEMENT - Always use defer for cleanup
func MonitorMultiplePaths(monitor StorageMonitor, paths []string) error {
	pool := NewMonitorPool(monitor, 3)
	defer pool.Stop() // Ensure cleanup happens

	pool.Start()

	// Collect results
	var wg sync.WaitGroup
	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			resultChan, errorChan := pool.Submit(p)
			select {
			case result := <-resultChan:
				fmt.Printf("Path: %s, Usage: %.1f%%\n", result.Path, result.UsedPercent)
			case err := <-errorChan:
				fmt.Printf("Error monitoring %s: %v\n", p, err)
			case <-time.After(5 * time.Second):
				fmt.Printf("Timeout monitoring %s\n", p)
			}
		}(path)
	}

	wg.Wait()
	return nil
}

// 8. BUILDER PATTERN - Complex object construction
type AlertConfigBuilder struct {
	config *AlertConfig
}

type AlertConfig struct {
	Thresholds map[string]float64
	Recipients []string
	Enabled    bool
	Cooldown   time.Duration
}

func NewAlertConfigBuilder() *AlertConfigBuilder {
	return &AlertConfigBuilder{
		config: &AlertConfig{
			Thresholds: make(map[string]float64),
			Recipients: make([]string, 0),
			Enabled:    true,
			Cooldown:   5 * time.Minute,
		},
	}
}

func (b *AlertConfigBuilder) WithThreshold(metric string, value float64) *AlertConfigBuilder {
	b.config.Thresholds[metric] = value
	return b
}

func (b *AlertConfigBuilder) AddRecipient(email string) *AlertConfigBuilder {
	b.config.Recipients = append(b.config.Recipients, email)
	return b
}

func (b *AlertConfigBuilder) SetCooldown(duration time.Duration) *AlertConfigBuilder {
	b.config.Cooldown = duration
	return b
}

func (b *AlertConfigBuilder) Build() *AlertConfig {
	// Return a copy to prevent mutation
	config := &AlertConfig{
		Thresholds: make(map[string]float64),
		Recipients: make([]string, len(b.config.Recipients)),
		Enabled:    b.config.Enabled,
		Cooldown:   b.config.Cooldown,
	}

	for k, v := range b.config.Thresholds {
		config.Thresholds[k] = v
	}
	copy(config.Recipients, b.config.Recipients)

	return config
}

// 9. DEMONSTRATION FUNCTION
func demonstratePatterns() {
	fmt.Println("=== Go Best Practices Demo ===")

	// Functional options pattern
	monitor := NewDiskMonitor("production",
		WithAlertThreshold(85.0),
		WithTimeout(10*time.Second),
	)

	// Builder pattern
	alertConfig := NewAlertConfigBuilder().
		WithThreshold("disk_usage", 80.0).
		WithThreshold("growth_rate", 5.0).
		AddRecipient("admin@example.com").
		SetCooldown(10 * time.Minute).
		Build()

	fmt.Printf("Monitor: %s, Threshold: %.1f%%\n",
		monitor.GetName(), monitor.alertThreshold)
	fmt.Printf("Alert config has %d thresholds and %d recipients\n",
		len(alertConfig.Thresholds), len(alertConfig.Recipients))

	// Context and error handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	usage, err := monitor.CheckUsage(ctx, "/")
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Usage for %s: %.1f%%\n", usage.Path, usage.UsedPercent)

	// Worker pool pattern
	paths := []string{"/", "/home", "/var", "/tmp"}
	if err := MonitorMultiplePaths(monitor, paths); err != nil {
		log.Printf("Error monitoring paths: %v", err)
	}
}

func main() {
	demonstratePatterns()
}
