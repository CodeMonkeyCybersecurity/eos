package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatchesPattern(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path    string
		pattern string
		want    bool
	}{
		{"pkg/vault/install.go", "pkg/vault/**", true},
		{"test/integration_test.go", "test/integration*", true},
		{"pkg/backup/job.go", "pkg/vault/**", false},
	}
	for _, tc := range cases {
		got := matchesPattern(tc.path, tc.pattern)
		if got != tc.want {
			t.Fatalf("matchesPattern(%q,%q)=%v want %v", tc.path, tc.pattern, got, tc.want)
		}
	}
}

func TestParseJSONL(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "sample.jsonl")
	content := "" +
		`{"Action":"pass","Package":"p/a","Test":"T1","Elapsed":0.1}` + "\n" +
		`{"Action":"fail","Package":"p/a","Test":"T2","Elapsed":0.2}` + "\n" +
		`{"Action":"skip","Package":"p/b","Test":"T3","Elapsed":0.0}` + "\n"
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	r := report{Packages: map[string]float64{}}
	failures := map[string]struct{}{}
	failedPackages := map[string]int{}
	window := &timeWindow{}
	if err := parseJSONL(file, &r, failures, failedPackages, window); err != nil {
		t.Fatal(err)
	}
	if r.Pass != 1 || r.Fail != 1 || r.Skip != 1 {
		t.Fatalf("unexpected counts: pass=%d fail=%d skip=%d", r.Pass, r.Fail, r.Skip)
	}
	if _, ok := failures["p/a::T2"]; !ok {
		t.Fatalf("expected failed test key")
	}
	if got := failedPackages["p/a"]; got != 1 {
		t.Fatalf("expected failed package count to be 1, got %d", got)
	}
}

func TestApprovedAllowlist(t *testing.T) {
	t.Parallel()
	issue := gosecIssue{RuleID: "G402", File: "pkg/httpclient/tls_helper.go", Line: "12", Details: "x"}
	entries := []gosecAllowlistItem{{
		RuleID:    "G402",
		FileRegex: `pkg/httpclient/.*`,
		ExpiresOn: "2099-01-01",
		IssueID:   24,
		Owner:     "platform-security",
	}}
	if !approved(issue, entries, time.Now().UTC()) {
		t.Fatalf("expected allowlist approval")
	}
}

func TestIsBroadAllowlistEntry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		entry  gosecAllowlistItem
		broad  bool
		reason string
	}{
		{
			name: "exact file is allowed",
			entry: gosecAllowlistItem{
				RuleID:    "G402",
				FileRegex: `^pkg/httpclient/tls_helper\.go$`,
			},
			broad: false,
		},
		{
			name: "wildcard rule denied",
			entry: gosecAllowlistItem{
				RuleID:    "*",
				FileRegex: `^pkg/httpclient/tls_helper\.go$`,
			},
			broad:  true,
			reason: "rule_id wildcard",
		},
		{
			name: "repo wide regex denied",
			entry: gosecAllowlistItem{
				RuleID:    "G402",
				FileRegex: `^.*$`,
			},
			broad:  true,
			reason: "entire repository",
		},
		{
			name: "all go files denied",
			entry: gosecAllowlistItem{
				RuleID:    "G402",
				FileRegex: `^.*\.go$`,
			},
			broad:  true,
			reason: "every Go file",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			broad, reason := isBroadAllowlistEntry(tc.entry)
			if broad != tc.broad {
				t.Fatalf("isBroadAllowlistEntry() broad=%v want %v", broad, tc.broad)
			}
			if tc.reason != "" && !strings.Contains(reason, tc.reason) {
				t.Fatalf("isBroadAllowlistEntry() reason=%q want substring %q", reason, tc.reason)
			}
		})
	}
}

func TestPolicyValidateRules(t *testing.T) {
	t.Parallel()

	valid := suitesConfig{
		Version: 3,
		Policy: policyConfig{
			Weights:       policyWeights{Unit: 70, Integration: 20, E2E: 10},
			RequiredLanes: []string{"unit", "integration", "e2e-smoke"},
		},
		Suites: []suiteConfig{
			{Name: "unit", Weight: 70, Gate: gateConfig{RequiredOnPR: true, CoverageThreshold: 70}},
			{Name: "integration", Weight: 20, Gate: gateConfig{RequiredOnPR: true}},
			{Name: "e2e-smoke", Weight: 10, Gate: gateConfig{RequiredOnPR: true}},
		},
	}
	if valid.Policy.Weights.Unit+valid.Policy.Weights.Integration+valid.Policy.Weights.E2E != 100 {
		t.Fatalf("weights should sum to 100")
	}
	unit := findLane(valid, "unit")
	if unit == nil || !unit.Gate.RequiredOnPR || unit.Gate.CoverageThreshold <= 0 {
		t.Fatalf("unit lane policy invariant broken")
	}
	integ := findLane(valid, "integration")
	if integ == nil || !integ.Gate.RequiredOnPR {
		t.Fatalf("integration lane policy invariant broken")
	}
	e2e := findLane(valid, "e2e-smoke")
	if e2e == nil || !e2e.Gate.RequiredOnPR {
		t.Fatalf("e2e-smoke lane policy invariant broken")
	}
}

func TestSummaryDoesNotUseCoverageWhenDisabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	jsonl := filepath.Join(dir, "lane.jsonl")
	reportPath := filepath.Join(dir, "report.json")
	mdPath := filepath.Join(dir, "summary.md")
	content := `{"Action":"pass","Package":"p/a","Test":"T1","Elapsed":0.1}` + "\n"
	if err := os.WriteFile(jsonl, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cmdSummary([]string{"unit", "success", dir, "-", reportPath, mdPath})

	b, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var r report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.Coverage != "N/A" {
		t.Fatalf("expected coverage to remain N/A when disabled, got %q", r.Coverage)
	}
}

func TestHasDependencyFileChange(t *testing.T) {
	t.Parallel()

	if !hasDependencyFileChange([]string{"go.mod", "pkg/x.go"}) {
		t.Fatalf("expected go.mod change to be detected")
	}
	if !hasDependencyFileChange([]string{"cmd/a/main.go", "internal/go.sum"}) {
		t.Fatalf("expected go.sum change to be detected")
	}
	if hasDependencyFileChange([]string{"README.md", "pkg/x.go"}) {
		t.Fatalf("did not expect non-dependency file changes to be detected")
	}
}
