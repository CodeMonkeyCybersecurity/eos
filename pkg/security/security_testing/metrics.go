// pkg/security_testing/metrics.go
package security_testing

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SecurityMetrics tracks security-related metrics and improvements
type SecurityMetrics struct {
	Timestamp                time.Time                `json:"timestamp"`
	VulnerabilitiesFound     int                      `json:"vulnerabilities_found"`
	VulnerabilitiesFixed     int                      `json:"vulnerabilities_fixed"`
	TestCoverage             float64                  `json:"test_coverage_percent"`
	SecurityTestsPassed      int                      `json:"security_tests_passed"`
	SecurityTestsFailed      int                      `json:"security_tests_failed"`
	FuzzingCrashesFound      int                      `json:"fuzzing_crashes_found"`
	PropertyViolationsFound  int                      `json:"property_violations_found"`
	SecurityFunctionsBenched map[string]time.Duration `json:"security_functions_benchmarked"`
	RiskScore                float64                  `json:"risk_score"` // 0-100, lower is better
	ComplianceLevel          string                   `json:"compliance_level"`
}

// VulnerabilityRecord represents a specific vulnerability
type VulnerabilityRecord struct {
	ID          string     `json:"id"`
	Severity    string     `json:"severity"` // Critical, High, Medium, Low
	Type        string     `json:"type"`     // SQL Injection, XSS, Path Traversal, etc.
	Location    string     `json:"location"` // File and line
	Description string     `json:"description"`
	Status      string     `json:"status"` // Found, Fixed, Verified
	FoundAt     time.Time  `json:"found_at"`
	FixedAt     *time.Time `json:"fixed_at,omitempty"`
}

// SecurityReport contains comprehensive security assessment data
type SecurityReport struct {
	GeneratedAt      time.Time             `json:"generated_at"`
	ProjectVersion   string                `json:"project_version"`
	TestingDuration  time.Duration         `json:"testing_duration"`
	Metrics          SecurityMetrics       `json:"metrics"`
	Vulnerabilities  []VulnerabilityRecord `json:"vulnerabilities"`
	Recommendations  []string              `json:"recommendations"`
	ImprovementTrend []SecurityMetrics     `json:"improvement_trend"`
}

// CalculateRiskScore computes an overall security risk score
func (sm *SecurityMetrics) CalculateRiskScore() float64 {
	// Base risk starts at 50
	risk := 50.0

	// Vulnerabilities increase risk
	criticalVulns := sm.VulnerabilitiesFound - sm.VulnerabilitiesFixed
	risk += float64(criticalVulns) * 10.0

	// Good test coverage decreases risk
	if sm.TestCoverage > 80 {
		risk -= 15.0
	} else if sm.TestCoverage > 60 {
		risk -= 10.0
	} else if sm.TestCoverage > 40 {
		risk -= 5.0
	}

	// Failed tests increase risk
	if sm.SecurityTestsFailed > 0 {
		failureRate := float64(sm.SecurityTestsFailed) / float64(sm.SecurityTestsPassed+sm.SecurityTestsFailed)
		risk += failureRate * 20.0
	} else {
		risk -= 5.0 // Bonus for all tests passing
	}

	// Fuzzing crashes are concerning
	risk += float64(sm.FuzzingCrashesFound) * 5.0

	// Property violations indicate design issues
	risk += float64(sm.PropertyViolationsFound) * 3.0

	// Performance issues can indicate poor implementation
	slowFunctions := 0
	for _, duration := range sm.SecurityFunctionsBenched {
		if duration > time.Millisecond {
			slowFunctions++
		}
	}
	risk += float64(slowFunctions) * 2.0

	// Clamp risk score between 0 and 100
	if risk < 0 {
		risk = 0
	} else if risk > 100 {
		risk = 100
	}

	sm.RiskScore = risk
	return risk
}

// DetermineComplianceLevel sets compliance level based on metrics
func (sm *SecurityMetrics) DetermineComplianceLevel() string {
	riskScore := sm.CalculateRiskScore()

	switch {
	case riskScore <= 20 && sm.TestCoverage >= 90:
		sm.ComplianceLevel = "Excellent"
	case riskScore <= 35 && sm.TestCoverage >= 80:
		sm.ComplianceLevel = "Good"
	case riskScore <= 50 && sm.TestCoverage >= 70:
		sm.ComplianceLevel = "Satisfactory"
	case riskScore <= 70:
		sm.ComplianceLevel = "Needs Improvement"
	default:
		sm.ComplianceLevel = "Critical Issues"
	}

	return sm.ComplianceLevel
}

// SaveMetrics saves security metrics to a JSON file
func (sm *SecurityMetrics) SaveMetrics(filepath string) error {
	// Calculate derived metrics
	sm.CalculateRiskScore()
	sm.DetermineComplianceLevel()

	data, err := json.MarshalIndent(sm, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	return os.WriteFile(filepath, data, 0644)
}

// LoadMetrics loads security metrics from a JSON file
func LoadMetrics(filepath string) (*SecurityMetrics, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metrics file: %w", err)
	}

	var metrics SecurityMetrics
	if err := json.Unmarshal(data, &metrics); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metrics: %w", err)
	}

	return &metrics, nil
}

// GenerateRecommendations creates actionable security recommendations
func (sm *SecurityMetrics) GenerateRecommendations() []string {
	var recommendations []string

	// Test coverage recommendations
	if sm.TestCoverage < 80 {
		recommendations = append(recommendations,
			fmt.Sprintf("Increase security test coverage from %.1f%% to at least 80%%", sm.TestCoverage))
	}

	// Vulnerability recommendations
	unfixedVulns := sm.VulnerabilitiesFound - sm.VulnerabilitiesFixed
	if unfixedVulns > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Fix %d remaining security vulnerabilities", unfixedVulns))
	}

	// Test failure recommendations
	if sm.SecurityTestsFailed > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Address %d failing security tests", sm.SecurityTestsFailed))
	}

	// Fuzzing recommendations
	if sm.FuzzingCrashesFound > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Investigate %d crashes found during fuzzing", sm.FuzzingCrashesFound))
	}

	// Property violation recommendations
	if sm.PropertyViolationsFound > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Fix %d security property violations", sm.PropertyViolationsFound))
	}

	// Performance recommendations
	slowFunctions := make([]string, 0)
	for funcName, duration := range sm.SecurityFunctionsBenched {
		if duration > time.Millisecond {
			slowFunctions = append(slowFunctions, fmt.Sprintf("%s (%.2fms)", funcName, float64(duration.Nanoseconds())/1e6))
		}
	}
	if len(slowFunctions) > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Optimize slow security functions: %v", slowFunctions))
	}

	// Risk-based recommendations
	riskScore := sm.RiskScore
	switch {
	case riskScore > 70:
		recommendations = append(recommendations, "URGENT: Implement immediate security measures - risk score is critical")
	case riskScore > 50:
		recommendations = append(recommendations, "HIGH PRIORITY: Address security issues within 2 weeks")
	case riskScore > 30:
		recommendations = append(recommendations, "MEDIUM PRIORITY: Plan security improvements for next sprint")
	}

	// General recommendations
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Security posture is good - maintain current practices")
		recommendations = append(recommendations, "Consider regular security audits and penetration testing")
	}

	return recommendations
}

// CompareMetrics compares current metrics with previous metrics to show trends
func (sm *SecurityMetrics) CompareMetrics(previous *SecurityMetrics) map[string]interface{} {
	if previous == nil {
		return map[string]interface{}{
			"status":  "baseline",
			"message": "This is the first metrics collection",
		}
	}

	comparison := make(map[string]interface{})

	// Risk score trend
	riskDelta := sm.RiskScore - previous.RiskScore
	if riskDelta < -5 {
		comparison["risk_trend"] = "significantly_improved"
	} else if riskDelta < 0 {
		comparison["risk_trend"] = "improved"
	} else if riskDelta > 5 {
		comparison["risk_trend"] = "worsened"
	} else {
		comparison["risk_trend"] = "stable"
	}
	comparison["risk_delta"] = riskDelta

	// Coverage trend
	coverageDelta := sm.TestCoverage - previous.TestCoverage
	comparison["coverage_delta"] = coverageDelta

	// Vulnerability trend
	vulnDelta := (sm.VulnerabilitiesFound - sm.VulnerabilitiesFixed) -
		(previous.VulnerabilitiesFound - previous.VulnerabilitiesFixed)
	comparison["vulnerability_delta"] = vulnDelta

	// Test results trend
	currentFailureRate := float64(sm.SecurityTestsFailed) / float64(sm.SecurityTestsPassed+sm.SecurityTestsFailed)
	previousFailureRate := float64(previous.SecurityTestsFailed) / float64(previous.SecurityTestsPassed+previous.SecurityTestsFailed)
	comparison["failure_rate_delta"] = currentFailureRate - previousFailureRate

	// Overall assessment
	improvementScore := 0
	if riskDelta < 0 {
		improvementScore++
	}
	if coverageDelta > 0 {
		improvementScore++
	}
	if vulnDelta <= 0 {
		improvementScore++
	}
	if currentFailureRate <= previousFailureRate {
		improvementScore++
	}

	switch improvementScore {
	case 4:
		comparison["overall_trend"] = "excellent_improvement"
	case 3:
		comparison["overall_trend"] = "good_improvement"
	case 2:
		comparison["overall_trend"] = "moderate_improvement"
	case 1:
		comparison["overall_trend"] = "slight_improvement"
	default:
		comparison["overall_trend"] = "needs_attention"
	}

	return comparison
}

// PrintSummary prints a human-readable summary of security metrics
func (sm *SecurityMetrics) PrintSummary() {
	fmt.Println("=== Security Metrics Summary ===")
	fmt.Printf("Timestamp: %s\n", sm.Timestamp.Format(time.RFC3339))
	fmt.Printf("Risk Score: %.1f/100 (%s)\n", sm.RiskScore, sm.ComplianceLevel)
	fmt.Printf("Test Coverage: %.1f%%\n", sm.TestCoverage)
	fmt.Printf("Vulnerabilities: %d found, %d fixed, %d remaining\n",
		sm.VulnerabilitiesFound, sm.VulnerabilitiesFixed,
		sm.VulnerabilitiesFound-sm.VulnerabilitiesFixed)
	fmt.Printf("Security Tests: %d passed, %d failed\n",
		sm.SecurityTestsPassed, sm.SecurityTestsFailed)

	if sm.FuzzingCrashesFound > 0 {
		fmt.Printf("Fuzzing Crashes: %d found\n", sm.FuzzingCrashesFound)
	}

	if sm.PropertyViolationsFound > 0 {
		fmt.Printf("Property Violations: %d found\n", sm.PropertyViolationsFound)
	}

	fmt.Println("\n=== Recommendations ===")
	recommendations := sm.GenerateRecommendations()
	for i, rec := range recommendations {
		fmt.Printf("%d. %s\n", i+1, rec)
	}

	fmt.Println("\n=== Performance Benchmarks ===")
	for funcName, duration := range sm.SecurityFunctionsBenched {
		status := "✓"
		if duration > time.Millisecond {
			status = "⚠"
		}
		fmt.Printf("%s %s: %.3fms\n", status, funcName, float64(duration.Nanoseconds())/1e6)
	}
}
