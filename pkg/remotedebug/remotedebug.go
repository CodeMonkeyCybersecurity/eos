package remotedebug

import (
	"encoding/json"
	"fmt"
	"time"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoteDebugger is the main structure for remote debugging operations
type RemoteDebugger struct {
	rc           *eos_io.RuntimeContext
	config       *Config
	outputFormat OutputFormat
	client       *SSHClient
}

// New creates a new RemoteDebugger instance
func New(rc *eos_io.RuntimeContext, config *Config) *RemoteDebugger {
	if config.Timeout == 0 {
		config.Timeout = DefaultSSHTimeout
	}
	
	return &RemoteDebugger{
		rc:           rc,
		config:       config,
		outputFormat: OutputHuman,
	}
}

// SetOutputFormat sets the output format for results
func (rd *RemoteDebugger) SetOutputFormat(format OutputFormat) {
	rd.outputFormat = format
}

// RunDiagnostics performs system diagnostics based on options
func (rd *RemoteDebugger) RunDiagnostics(opts DiagnosticOptions) error {
	logger := otelzap.Ctx(rd.rc.Ctx)
	
	// ASSESS - Check if we can connect
	logger.Info("Assessing SSH connectivity",
		zap.String("host", rd.config.Host),
		zap.String("phase", "assess"))
	
	if err := rd.connect(); err != nil {
		return fmt.Errorf("failed to establish SSH connection: %w", err)
	}
	defer rd.disconnect()
	
	// INTERVENE - Collect diagnostics
	logger.Info("Collecting system diagnostics",
		zap.String("check_type", opts.CheckType),
		zap.String("phase", "intervene"))
	
	collector := NewDiagnosticCollector(rd.client, rd.config.SudoPass)
	report, err := collector.CollectDiagnostics(opts)
	if err != nil {
		return fmt.Errorf("failed to collect diagnostics: %w", err)
	}
	
	// Add kernel logs if requested
	if opts.KernelLogs {
		logger.Info("Retrieving kernel logs")
		kernelLogs, err := rd.collectKernelLogs(opts.Since)
		if err != nil {
			logger.Warn("Failed to retrieve kernel logs",
				zap.Error(err))
		} else {
			report.KernelLogs = kernelLogs
		}
	}
	
	// Analyze results
	analyzer := NewAnalyzer(report)
	report.Issues = analyzer.AnalyzeIssues()
	report.Warnings = analyzer.AnalyzeWarnings()
	report.Summary = analyzer.GenerateSummary()
	
	// EVALUATE - Output results
	logger.Info("Diagnostic collection completed",
		zap.Int("issues", len(report.Issues)),
		zap.Int("warnings", len(report.Warnings)),
		zap.String("phase", "evaluate"))
	
	return rd.outputReport(report)
}

// DiagnoseAndFix runs diagnostics and attempts to fix issues
func (rd *RemoteDebugger) DiagnoseAndFix(dryRun bool) error {
	logger := otelzap.Ctx(rd.rc.Ctx)
	
	// First run diagnostics
	logger.Info("Running initial diagnostics")
	
	if err := rd.connect(); err != nil {
		return fmt.Errorf("failed to establish SSH connection: %w", err)
	}
	defer rd.disconnect()
	
	collector := NewDiagnosticCollector(rd.client, rd.config.SudoPass)
	report, err := collector.CollectDiagnostics(DiagnosticOptions{CheckType: "all"})
	if err != nil {
		return fmt.Errorf("failed to collect diagnostics: %w", err)
	}
	
	// Analyze and prioritize issues
	analyzer := NewAnalyzer(report)
	report.Issues = analyzer.AnalyzeIssues()
	
	if len(report.Issues) == 0 {
		logger.Info("No issues detected, system appears healthy")
		return rd.outputReport(report)
	}
	
	// Apply fixes
	logger.Info("Attempting to fix detected issues",
		zap.Bool("dry_run", dryRun),
		zap.Int("issue_count", len(report.Issues)))
	
	fixer := NewAutomatedFixer(rd.client, rd.config.SudoPass, dryRun)
	fixReport, err := fixer.FixIssues(report)
	if err != nil {
		return fmt.Errorf("fix process failed: %w", err)
	}
	
	// Re-run diagnostics to verify fixes
	if !dryRun && fixReport.Success {
		logger.Info("Verifying fixes by re-running diagnostics")
		newReport, err := collector.CollectDiagnostics(DiagnosticOptions{CheckType: "all"})
		if err == nil {
			fixReport.VerificationReport = newReport
		}
	}
	
	return rd.outputFixReport(fixReport)
}

// RunInteractive starts interactive troubleshooting mode
func (rd *RemoteDebugger) RunInteractive() error {
	logger := otelzap.Ctx(rd.rc.Ctx)
	
	logger.Info("Starting interactive troubleshooting mode")
	
	if err := rd.connect(); err != nil {
		return fmt.Errorf("failed to establish SSH connection: %w", err)
	}
	defer rd.disconnect()
	
	troubleshooter := NewInteractiveTroubleshooter(rd.rc, rd.client, rd.config.SudoPass)
	return troubleshooter.Start()
}

// connect establishes SSH connection
func (rd *RemoteDebugger) connect() error {
	logger := otelzap.Ctx(rd.rc.Ctx)
	
	logger.Info("Establishing SSH connection",
		zap.String("host", rd.config.Host),
		zap.String("port", rd.config.Port),
		zap.String("user", rd.config.User))
	
	client, err := NewSSHClient(rd.config)
	if err != nil {
		// Try emergency connection strategies
		logger.Warn("Standard connection failed, trying emergency strategies")
		client, err = NewEmergencySSHClient(rd.config)
		if err != nil {
			return fmt.Errorf("all connection attempts failed: %w", err)
		}
		logger.Info("Connected using emergency mode")
	} else {
		logger.Info("Connected successfully")
	}
	
	rd.client = client
	return nil
}

// disconnect closes SSH connection
func (rd *RemoteDebugger) disconnect() {
	if rd.client != nil {
		rd.client.Close()
		rd.client = nil
	}
}

// collectKernelLogs retrieves kernel logs
func (rd *RemoteDebugger) collectKernelLogs(since string) (*KernelLogs, error) {
	// Parse duration
	duration, err := time.ParseDuration(since)
	if err != nil {
		duration = time.Hour // default
	}
	
	retriever := NewKernelLogRetriever(rd.client, rd.config.SudoPass)
	return retriever.RetrieveKernelLogs(duration)
}

// outputReport outputs the diagnostic report in the configured format
func (rd *RemoteDebugger) outputReport(report *SystemReport) error {
	switch rd.outputFormat {
	case OutputJSON:
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal report: %w", err)
		}
		fmt.Println(string(data))
		
	case OutputHuman:
		printer := NewReportPrinter()
		printer.PrintDiagnosticReport(report)
	}
	
	return nil
}

// outputFixReport outputs the fix report in the configured format
func (rd *RemoteDebugger) outputFixReport(report *FixReport) error {
	switch rd.outputFormat {
	case OutputJSON:
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal report: %w", err)
		}
		fmt.Println(string(data))
		
	case OutputHuman:
		printer := NewReportPrinter()
		printer.PrintFixReport(report)
		
		// Also print verification results if available
		if report.VerificationReport != nil {
			fmt.Println("\n=== Post-Fix Verification ===")
			printer.PrintDiagnosticReport(report.VerificationReport)
		}
	}
	
	return nil
}