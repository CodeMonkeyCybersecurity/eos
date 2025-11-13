package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Run performance benchmarks and generate reports",
	Long: `Runs Go benchmarks and generates performance reports.

This command:
1. Runs benchmarks for specified packages
2. Optionally compares with baseline results
3. Generates benchmark reports
4. Detects performance regressions

Benchmarking best practices:
- Run multiple times (-count=5) for statistical significance
- Use -benchmem to measure allocations
- Compare against baseline for regression detection
- Benchmark on representative hardware

Examples:
  # Run all benchmarks
  eos self test benchmark

  # Run benchmarks for specific package
  eos self test benchmark --package=./pkg/crypto/...

  # Run with memory profiling
  eos self test benchmark --mem

  # Compare with baseline
  eos self test benchmark --compare=baseline.txt

  # Save results for future comparison
  eos self test benchmark --save=baseline.txt

  # Run CPU profiling
  eos self test benchmark --cpuprofile=cpu.prof
`,
	RunE: eos_cli.Wrap(runBenchmark),
}

func init() {
	benchmarkCmd.Flags().String("package", "./...", "Package pattern to benchmark")
	benchmarkCmd.Flags().String("run", "", "Run only benchmarks matching regexp")
	benchmarkCmd.Flags().Int("count", 5, "Number of times to run each benchmark")
	benchmarkCmd.Flags().Duration("time", 1*time.Second, "Benchmark run time per operation")
	benchmarkCmd.Flags().Bool("mem", false, "Include memory allocation statistics")
	benchmarkCmd.Flags().String("compare", "", "Compare with baseline results file")
	benchmarkCmd.Flags().String("save", "", "Save results to file for future comparison")
	benchmarkCmd.Flags().String("cpuprofile", "", "Write CPU profile to file")
	benchmarkCmd.Flags().String("memprofile", "", "Write memory profile to file")
	benchmarkCmd.Flags().Bool("verbose", false, "Show verbose output")
}

func runBenchmark(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	packagePattern, _ := cmd.Flags().GetString("package")
	runPattern, _ := cmd.Flags().GetString("run")
	count, _ := cmd.Flags().GetInt("count")
	benchTime, _ := cmd.Flags().GetDuration("time")
	includeMem, _ := cmd.Flags().GetBool("mem")
	compareTo, _ := cmd.Flags().GetString("compare")
	saveFile, _ := cmd.Flags().GetString("save")
	cpuProfile, _ := cmd.Flags().GetString("cpuprofile")
	memProfile, _ := cmd.Flags().GetString("memprofile")
	verbose, _ := cmd.Flags().GetBool("verbose")

	logger.Info("Running benchmarks",
		zap.String("package", packagePattern),
		zap.Int("count", count),
		zap.Duration("bench_time", benchTime))

	// ASSESS: Check if go is available
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go command not found: %w", err)
	}

	// INTERVENE: Run benchmarks
	result, err := runBenchmarks(rc, benchmarkConfig{
		PackagePattern: packagePattern,
		RunPattern:     runPattern,
		Count:          count,
		BenchTime:      benchTime,
		IncludeMem:     includeMem,
		CPUProfile:     cpuProfile,
		MemProfile:     memProfile,
		Verbose:        verbose,
	})

	if err != nil {
		return err
	}

	// Save results if requested
	if saveFile != "" {
		if err := saveBenchmarkResults(rc, result.Output, saveFile); err != nil {
			logger.Warn("Failed to save benchmark results", zap.Error(err))
		}
	}

	// Compare with baseline if requested
	if compareTo != "" {
		if err := compareWithBaseline(rc, result.Output, compareTo); err != nil {
			logger.Warn("Failed to compare with baseline", zap.Error(err))
		}
	}

	// EVALUATE: Report results
	return reportBenchmarkResults(rc, result)
}

type benchmarkConfig struct {
	PackagePattern string
	RunPattern     string
	Count          int
	BenchTime      time.Duration
	IncludeMem     bool
	CPUProfile     string
	MemProfile     string
	Verbose        bool
}

type benchmarkResult struct {
	Output        string
	HasBenchmarks bool
}

func runBenchmarks(rc *eos_io.RuntimeContext, config benchmarkConfig) (*benchmarkResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Performance Benchmarks")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Build benchmark arguments
	args := []string{"test", "-bench=."}

	// Add run pattern if specified
	if config.RunPattern != "" {
		args = append(args, fmt.Sprintf("-run=^$")) // Don't run regular tests
		args = append(args, fmt.Sprintf("-bench=%s", config.RunPattern))
	}

	// Add count
	args = append(args, fmt.Sprintf("-count=%d", config.Count))

	// Add bench time
	args = append(args, fmt.Sprintf("-benchtime=%s", config.BenchTime))

	// Add memory stats
	if config.IncludeMem {
		args = append(args, "-benchmem")
	}

	// Add CPU profiling
	if config.CPUProfile != "" {
		args = append(args, fmt.Sprintf("-cpuprofile=%s", config.CPUProfile))
		logger.Info("CPU profiling enabled", zap.String("output", config.CPUProfile))
	}

	// Add memory profiling
	if config.MemProfile != "" {
		args = append(args, fmt.Sprintf("-memprofile=%s", config.MemProfile))
		logger.Info("Memory profiling enabled", zap.String("output", config.MemProfile))
	}

	// Add verbose
	if config.Verbose {
		args = append(args, "-v")
	}

	// Add package pattern
	args = append(args, config.PackagePattern)

	logger.Info("Running benchmarks",
		zap.String("command", "go "+strings.Join(args, " ")))

	// Run benchmarks
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "go",
		Args:    args,
		Capture: true,
	})

	result := &benchmarkResult{
		Output:        output,
		HasBenchmarks: strings.Contains(output, "Benchmark"),
	}

	if err != nil {
		logger.Error("Benchmarks failed", zap.Error(err))
		return result, fmt.Errorf("benchmark execution failed: %w", err)
	}

	return result, nil
}

func saveBenchmarkResults(rc *eos_io.RuntimeContext, output, saveFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create directory if needed
	dir := filepath.Dir(saveFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write results
	if err := os.WriteFile(saveFile, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to save results: %w", err)
	}

	logger.Info("Benchmark results saved",
		zap.String("file", saveFile))

	fmt.Printf("\n✓ Benchmark results saved to: %s\n", saveFile)

	return nil
}

func compareWithBaseline(rc *eos_io.RuntimeContext, currentOutput, baselineFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if benchstat is available
	if _, err := exec.LookPath("benchstat"); err != nil {
		fmt.Println("\n⚠ benchstat not installed - comparison not available")
		fmt.Println("Install with: go install golang.org/x/perf/cmd/benchstat@latest")
		return nil
	}

	// Check if baseline file exists
	if _, err := os.Stat(baselineFile); os.IsNotExist(err) {
		return fmt.Errorf("baseline file not found: %s", baselineFile)
	}

	// Write current output to temp file
	tmpFile := "benchmark-current.txt"
	if err := os.WriteFile(tmpFile, []byte(currentOutput), 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Comparison with Baseline")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	logger.Info("Comparing with baseline",
		zap.String("baseline", baselineFile),
		zap.String("current", tmpFile))

	// Run benchstat
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "benchstat",
		Args:    []string{baselineFile, tmpFile},
		Capture: true,
	})

	fmt.Print(output)

	if err != nil {
		logger.Warn("benchstat comparison failed", zap.Error(err))
	}

	return nil
}

func reportBenchmarkResults(rc *eos_io.RuntimeContext, result *benchmarkResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Benchmark Results")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	if !result.HasBenchmarks {
		fmt.Println("ℹ No benchmarks found")
		fmt.Println()
		fmt.Println("To add benchmarks, create functions like:")
		fmt.Println()
		fmt.Println("  func BenchmarkMyOperation(b *testing.B) {")
		fmt.Println("      for b.Loop() {  // Modern Go 1.24+ pattern")
		fmt.Println("          myOperation()")
		fmt.Println("      }")
		fmt.Println("  }")
		fmt.Println()
		logger.Info("No benchmarks found")
		return nil
	}

	// Print the output
	fmt.Print(result.Output)

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	fmt.Println("Interpreting results:")
	fmt.Println("  - ns/op:  Nanoseconds per operation (lower is better)")
	fmt.Println("  - B/op:   Bytes allocated per operation (lower is better)")
	fmt.Println("  - allocs/op: Number of allocations per operation (lower is better)")
	fmt.Println()

	fmt.Println("Next steps:")
	fmt.Println("  - Save baseline: eos self test benchmark --save=baseline.txt")
	fmt.Println("  - Compare later: eos self test benchmark --compare=baseline.txt")
	fmt.Println("  - Profile CPU:   eos self test benchmark --cpuprofile=cpu.prof")
	fmt.Println("  - Profile mem:   eos self test benchmark --memprofile=mem.prof")
	fmt.Println()

	logger.Info("Benchmark execution complete")
	return nil
}
