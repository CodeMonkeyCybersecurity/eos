package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type suitesConfig struct {
	Version int           `yaml:"version"`
	Policy  policyConfig  `yaml:"policy"`
	Suites  []suiteConfig `yaml:"suites"`
}

type policyConfig struct {
	Description   string         `yaml:"description"`
	Weights       policyWeights  `yaml:"weights"`
	RequiredLanes []string       `yaml:"required_lanes"`
	Defaults      policyDefaults `yaml:"defaults"`
}

type policyWeights struct {
	Unit        int `yaml:"unit"`
	Integration int `yaml:"integration"`
	E2E         int `yaml:"e2e"`
}

type policyDefaults struct {
	RequiredOnPR bool `yaml:"required_on_pr"`
}

type suiteConfig struct {
	Name   string     `yaml:"name"`
	Weight int        `yaml:"weight"`
	Owner  string     `yaml:"owner"`
	Gate   gateConfig `yaml:"gate"`
}

type gateConfig struct {
	RequiredOnPR            bool     `yaml:"required_on_pr"`
	RequiredOnPRWhenChanged []string `yaml:"required_on_pr_when_changed"`
	CoverageThreshold       float64  `yaml:"coverage_threshold"`
	RequiredOnSchedule      bool     `yaml:"required_on_schedule"`
	InformationalOnPR       bool     `yaml:"informational_on_pr"`
	ScheduledOrManualOnly   bool     `yaml:"scheduled_or_manual_only"`
}

type goTestEvent struct {
	Time    string  `json:"Time"`
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Elapsed float64 `json:"Elapsed"`
}

type report struct {
	Lane                  string             `json:"lane"`
	Status                string             `json:"status"`
	Pass                  int                `json:"pass"`
	Fail                  int                `json:"fail"`
	Skip                  int                `json:"skip"`
	Coverage              string             `json:"coverage"`
	FlakeCount            int                `json:"flake_count"`
	Packages              map[string]float64 `json:"packages"`
	TopFailures           []string           `json:"top_failures"`
	FailedPackagesTopN    []string           `json:"failed_packages_top_n"`
	LaneDurationSeconds   float64            `json:"lane_duration_seconds"`
	DependencyChange      bool               `json:"dependency_change_detected"`
	ChangedFilesCount     int                `json:"changed_files_count"`
	PolicyWeights         map[string]int     `json:"policy_weights,omitempty"`
	RequiredLaneStatus    map[string]string  `json:"required_lane_status,omitempty"`
	RequiredLanes         []string           `json:"required_lanes,omitempty"`
	TestPyramidCompliance string             `json:"test_pyramid_compliance,omitempty"`
	GeneratedUTC          string             `json:"generated_utc"`
}

type gosecResult struct {
	Issues []gosecIssue `json:"Issues"`
}

type gosecIssue struct {
	RuleID  string `json:"rule_id"`
	Details string `json:"details"`
	File    string `json:"file"`
	Line    string `json:"line"`
}

type gosecAllowlist struct {
	Version int                  `yaml:"version"`
	Entries []gosecAllowlistItem `yaml:"entries"`
}

type gosecAllowlistItem struct {
	RuleID    string `yaml:"rule_id"`
	FileRegex string `yaml:"file_regex"`
	Line      int    `yaml:"line"`
	IssueID   int    `yaml:"issue_id"`
	Owner     string `yaml:"owner"`
	ExpiresOn string `yaml:"expires_on"`
	Reason    string `yaml:"reason"`
}

func main() {
	if len(os.Args) < 2 {
		die("usage: go run ./test/ci/tool <policy-validate|policy-threshold|policy-should-run|summary|gosec-check|allowlist-validate> ...")
	}
	switch os.Args[1] {
	case "policy-validate":
		cmdPolicyValidate(os.Args[2:])
	case "policy-threshold":
		cmdPolicyThreshold(os.Args[2:])
	case "policy-should-run":
		cmdPolicyShouldRun(os.Args[2:])
	case "summary":
		cmdSummary(os.Args[2:])
	case "gosec-check":
		cmdGosecCheck(os.Args[2:])
	case "allowlist-validate":
		cmdAllowlistValidate(os.Args[2:])
	default:
		die("unknown command: %s", os.Args[1])
	}
}

func cmdPolicyValidate(args []string) {
	if len(args) != 1 {
		die("usage: ... policy-validate <suite.yaml>")
	}
	cfg := mustLoadSuites(args[0])

	if cfg.Version <= 0 {
		die("policy validation failed: version must be > 0")
	}

	total := cfg.Policy.Weights.Unit + cfg.Policy.Weights.Integration + cfg.Policy.Weights.E2E
	if total != 100 {
		die("policy validation failed: policy.weights must sum to 100 (got %d)", total)
	}

	if cfg.Policy.Weights.Unit != 70 || cfg.Policy.Weights.Integration != 20 || cfg.Policy.Weights.E2E != 10 {
		die("policy validation failed: policy.weights must be unit=70 integration=20 e2e=10")
	}

	if len(cfg.Policy.RequiredLanes) == 0 {
		die("policy validation failed: policy.required_lanes must not be empty")
	}

	suitesByName := map[string]suiteConfig{}
	for _, s := range cfg.Suites {
		suitesByName[s.Name] = s
	}

	for _, lane := range cfg.Policy.RequiredLanes {
		if _, ok := suitesByName[lane]; !ok {
			die("policy validation failed: required lane %q is missing in suites", lane)
		}
	}

	unit := findLane(cfg, "unit")
	if unit == nil {
		die("policy validation failed: missing suite unit")
	}
	if unit.Weight != cfg.Policy.Weights.Unit {
		die("policy validation failed: unit suite weight=%d does not match policy weight=%d", unit.Weight, cfg.Policy.Weights.Unit)
	}
	if !unit.Gate.RequiredOnPR {
		die("policy validation failed: unit.gate.required_on_pr must be true")
	}
	if unit.Gate.CoverageThreshold <= 0 {
		die("policy validation failed: unit.gate.coverage_threshold must be > 0")
	}

	integration := findLane(cfg, "integration")
	if integration == nil {
		die("policy validation failed: missing suite integration")
	}
	if integration.Weight != cfg.Policy.Weights.Integration {
		die("policy validation failed: integration suite weight=%d does not match policy weight=%d", integration.Weight, cfg.Policy.Weights.Integration)
	}
	if !integration.Gate.RequiredOnPR {
		die("policy validation failed: integration.gate.required_on_pr must be true")
	}

	e2eSmoke := findLane(cfg, "e2e-smoke")
	if e2eSmoke == nil {
		die("policy validation failed: missing suite e2e-smoke")
	}
	if e2eSmoke.Weight != cfg.Policy.Weights.E2E {
		die("policy validation failed: e2e-smoke suite weight=%d does not match policy weight=%d", e2eSmoke.Weight, cfg.Policy.Weights.E2E)
	}
	if !e2eSmoke.Gate.RequiredOnPR {
		die("policy validation failed: e2e-smoke.gate.required_on_pr must be true")
	}

	fmt.Println("policy valid")
}

func cmdPolicyThreshold(args []string) {
	if len(args) != 3 {
		die("usage: ... policy-threshold <suite.yaml> <lane> <default>")
	}
	cfg := mustLoadSuites(args[0])
	lane := findLane(cfg, args[1])
	if lane == nil || lane.Gate.CoverageThreshold <= 0 {
		fmt.Println(args[2])
		return
	}
	fmt.Printf("%.2f\n", lane.Gate.CoverageThreshold)
}

func cmdPolicyShouldRun(args []string) {
	if len(args) != 5 {
		die("usage: ... policy-should-run <suite.yaml> <lane> <event> <changed-files.txt|-> <default-true|default-false>")
	}
	cfg := mustLoadSuites(args[0])
	lane := findLane(cfg, args[1])
	if lane == nil {
		fmt.Println(parseDefault(args[4]))
		return
	}
	event := args[2]
	if event != "pull_request" {
		fmt.Println("true")
		return
	}
	if lane.Gate.RequiredOnPR {
		fmt.Println("true")
		return
	}
	if len(lane.Gate.RequiredOnPRWhenChanged) == 0 {
		fmt.Println(parseDefault(args[4]))
		return
	}
	changed := readChangedFiles(args[3])
	for _, f := range changed {
		for _, p := range lane.Gate.RequiredOnPRWhenChanged {
			if matchesPattern(f, p) {
				fmt.Println("true")
				return
			}
		}
	}
	fmt.Println("false")
}

func cmdSummary(args []string) {
	if len(args) != 6 {
		die("usage: ... summary <lane> <status> <lane-log-dir> <coverage-file|-> <report-out> <md-out|- for stdout>")
	}
	r := report{Lane: args[0], Status: args[1], Coverage: "N/A", Packages: map[string]float64{}, GeneratedUTC: time.Now().UTC().Format(time.RFC3339)}
	logDir := args[2]
	coverageFile := args[3]
	reportOut := args[4]
	mdOut := args[5]

	jsonlFiles, _ := filepath.Glob(filepath.Join(logDir, "*.jsonl"))
	failureSet := map[string]struct{}{}
	failedPackages := map[string]int{}
	window := &timeWindow{}
	for _, file := range jsonlFiles {
		_ = parseJSONL(file, &r, failureSet, failedPackages, window)
	}
	for f := range failureSet {
		r.TopFailures = append(r.TopFailures, f)
	}
	sort.Strings(r.TopFailures)
	if len(r.TopFailures) > 10 {
		r.TopFailures = r.TopFailures[:10]
	}
	r.FailedPackagesTopN = topFailedPackages(failedPackages, 5)
	r.FlakeCount = countFlakes(logDir)
	r.LaneDurationSeconds = window.DurationSeconds()

	changedFilesPath := filepath.Join(logDir, "changed-files.txt")
	changedFiles := readChangedFiles(changedFilesPath)
	r.ChangedFilesCount = len(changedFiles)
	r.DependencyChange = hasDependencyFileChange(changedFiles)

	if cfg := loadSuitesForSummary(); cfg != nil {
		r.PolicyWeights = map[string]int{
			"unit":        cfg.Policy.Weights.Unit,
			"integration": cfg.Policy.Weights.Integration,
			"e2e":         cfg.Policy.Weights.E2E,
		}
		r.RequiredLanes = append([]string(nil), cfg.Policy.RequiredLanes...)
		r.RequiredLaneStatus = collectRequiredLaneStatus(*cfg, r.Lane, r.Status, logDir)
		r.TestPyramidCompliance = fmt.Sprintf("unit %d / integration %d / e2e %d",
			cfg.Policy.Weights.Unit, cfg.Policy.Weights.Integration, cfg.Policy.Weights.E2E)
	}

	if coverageFile != "-" {
		if cov, err := parseCoverage(coverageFile); err == nil {
			r.Coverage = cov
		}
	}
	writeJSON(reportOut, r)
	md := renderSummaryMarkdown(r)
	if mdOut == "-" {
		fmt.Print(md)
		return
	}
	// 0644: CI report output readable by runner and artifact upload.
	if err := os.WriteFile(mdOut, []byte(md), 0644); err != nil { //nolint:gosec
		die("write markdown: %v", err)
	}
}

func cmdGosecCheck(args []string) {
	if len(args) != 2 {
		die("usage: ... gosec-check <gosec.json> <allowlist.yaml>")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		die("read gosec json: %v", err)
	}
	var findings gosecResult
	if err := json.Unmarshal(b, &findings); err != nil {
		die("parse gosec json: %v", err)
	}
	allow := mustLoadAllowlist(args[1])
	validateAllowlistOrDie(allow)
	now := time.Now().UTC()
	var unapproved []string
	for _, issue := range findings.Issues {
		if approved(issue, allow.Entries, now) {
			continue
		}
		unapproved = append(unapproved, fmt.Sprintf("%s %s:%s %s", issue.RuleID, issue.File, issue.Line, oneLine(issue.Details)))
	}
	if len(unapproved) > 0 {
		fmt.Println("Unapproved gosec findings:")
		for _, u := range unapproved {
			fmt.Printf("- %s\n", u)
		}
		os.Exit(1)
	}
	fmt.Printf("All gosec findings are allowlisted (%d findings).\n", len(findings.Issues))
}

func cmdAllowlistValidate(args []string) {
	if len(args) != 1 {
		die("usage: ... allowlist-validate <allowlist.yaml>")
	}
	allow := mustLoadAllowlist(args[0])
	validateAllowlistOrDie(allow)
	fmt.Println("allowlist valid")
}

func mustLoadSuites(path string) suitesConfig {
	b, err := os.ReadFile(path)
	if err != nil {
		die("read suites: %v", err)
	}
	var cfg suitesConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		die("parse suites: %v", err)
	}
	return cfg
}

func mustLoadAllowlist(path string) gosecAllowlist {
	b, err := os.ReadFile(path)
	if err != nil {
		die("read allowlist: %v", err)
	}
	var a gosecAllowlist
	if err := yaml.Unmarshal(b, &a); err != nil {
		die("parse allowlist: %v", err)
	}
	return a
}

func validateAllowlistOrDie(allow gosecAllowlist) {
	if len(allow.Entries) == 0 {
		return
	}

	for i, entry := range allow.Entries {
		if broad, reason := isBroadAllowlistEntry(entry); broad {
			die("allowlist validation failed: entry %d is too broad: %s (rule_id=%q file_regex=%q)", i+1, reason, entry.RuleID, entry.FileRegex)
		}
	}
}

func findLane(cfg suitesConfig, name string) *suiteConfig {
	for i := range cfg.Suites {
		if cfg.Suites[i].Name == name {
			return &cfg.Suites[i]
		}
	}
	return nil
}

func readChangedFiles(path string) []string {
	if path == "-" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(b), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func matchesPattern(path, pattern string) bool {
	path = strings.TrimPrefix(filepath.ToSlash(path), "./")
	pattern = strings.TrimPrefix(filepath.ToSlash(pattern), "./")
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}
	if strings.Contains(pattern, "**") {
		re := regexp.QuoteMeta(pattern)
		re = strings.ReplaceAll(re, "\\*\\*", ".*")
		re = strings.ReplaceAll(re, "\\*", "[^/]*")
		ok, _ := regexp.MatchString("^"+re+"$", path)
		return ok
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	if strings.Contains(pattern, "*") {
		ok, _ := filepath.Match(pattern, path)
		return ok
	}
	return path == pattern
}

func isBroadAllowlistEntry(entry gosecAllowlistItem) (bool, string) {
	ruleID := strings.TrimSpace(entry.RuleID)
	fileRegex := strings.TrimSpace(entry.FileRegex)
	if ruleID == "" || fileRegex == "" {
		return true, "rule_id and file_regex must be set"
	}
	if ruleID == "*" {
		return true, "rule_id wildcard is not allowed"
	}

	normalized := strings.ReplaceAll(fileRegex, " ", "")
	normalized = strings.TrimPrefix(normalized, "^")
	normalized = strings.TrimSuffix(normalized, "$")
	switch normalized {
	case ".*", ".+", ".*\\.go", ".+\\.go", "(.+)", "(.*)", "(.+)\\.go", "(.*)\\.go":
		return true, "file_regex matches the entire repository or every Go file"
	}

	re, err := regexp.Compile(fileRegex)
	if err != nil {
		return true, fmt.Sprintf("file_regex does not compile: %v", err)
	}

	broadSamples := []string{
		"pkg/httpclient/tls_helper.go",
		"cmd/root.go",
		"internal/service/executor.go",
		"test/ci/tool/main.go",
	}
	matchesAll := true
	for _, sample := range broadSamples {
		if !re.MatchString(sample) {
			matchesAll = false
			break
		}
	}
	if matchesAll {
		return true, "file_regex matches representative files across the repository"
	}

	return false, ""
}

type timeWindow struct {
	Start time.Time
	End   time.Time
}

func (w *timeWindow) Add(ts time.Time) {
	if ts.IsZero() {
		return
	}
	if w.Start.IsZero() || ts.Before(w.Start) {
		w.Start = ts
	}
	if w.End.IsZero() || ts.After(w.End) {
		w.End = ts
	}
}

func (w *timeWindow) DurationSeconds() float64 {
	if w.Start.IsZero() || w.End.IsZero() || w.End.Before(w.Start) {
		return 0
	}
	return w.End.Sub(w.Start).Seconds()
}

func parseJSONL(path string, out *report, failureSet map[string]struct{}, failedPackages map[string]int, window *timeWindow) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var e goTestEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if e.Time != "" {
			if ts, err := time.Parse(time.RFC3339Nano, e.Time); err == nil {
				window.Add(ts)
			}
		}
		switch e.Action {
		case "pass":
			out.Pass++
		case "fail":
			out.Fail++
			if e.Package != "" {
				failedPackages[e.Package]++
			}
			name := strings.TrimSpace(e.Package)
			if e.Test != "" {
				name = fmt.Sprintf("%s::%s", e.Package, e.Test)
			}
			if name != "" {
				failureSet[name] = struct{}{}
			}
		case "skip":
			out.Skip++
		}
		if e.Package != "" && e.Elapsed > 0 {
			out.Packages[e.Package] += e.Elapsed
		}
	}
	return s.Err()
}

func countFlakes(logDir string) int {
	files, _ := filepath.Glob(filepath.Join(logDir, "*"))
	count := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(b))
		count += strings.Count(lower, "flaky")
		count += strings.Count(lower, "flake")
	}
	return count
}

func parseCoverage(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	cmd := exec.Command("go", "tool", "cover", "-func="+path)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "total:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[2], nil
			}
		}
	}
	return "", fmt.Errorf("total coverage not found")
}

func approved(issue gosecIssue, entries []gosecAllowlistItem, now time.Time) bool {
	line, _ := strconv.Atoi(strings.TrimSpace(issue.Line))
	for _, e := range entries {
		if e.RuleID != "*" && e.RuleID != issue.RuleID {
			continue
		}
		if e.ExpiresOn != "" {
			exp, err := time.Parse("2006-01-02", e.ExpiresOn)
			if err != nil || now.After(exp.Add(24*time.Hour)) {
				continue
			}
		}
		if e.FileRegex != "" {
			re, err := regexp.Compile(e.FileRegex)
			if err != nil || !re.MatchString(issue.File) {
				continue
			}
		}
		if e.Line > 0 && line != e.Line {
			continue
		}
		return true
	}
	return false
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		die("marshal report: %v", err)
	}
	// 0644: CI report JSON readable by runner and artifact upload.
	if err := os.WriteFile(path, b, 0644); err != nil { //nolint:gosec
		die("write report: %v", err)
	}
}

func renderSummaryMarkdown(r report) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "### CI Lane Summary: %s\n\n", r.Lane)
	fmt.Fprintf(b, "- Status: %s\n", r.Status)
	fmt.Fprintf(b, "- Test events: pass=%d, fail=%d, skip=%d\n", r.Pass, r.Fail, r.Skip)
	fmt.Fprintf(b, "- Coverage: %s\n", r.Coverage)
	fmt.Fprintf(b, "- Lane duration (seconds): %.2f\n", r.LaneDurationSeconds)
	fmt.Fprintf(b, "- Dependency change detected: %t\n", r.DependencyChange)
	fmt.Fprintf(b, "- Changed files counted: %d\n", r.ChangedFilesCount)
	fmt.Fprintf(b, "- Flake signatures: %d\n", r.FlakeCount)
	if len(r.FailedPackagesTopN) > 0 {
		fmt.Fprintf(b, "- Failed packages (top): %s\n", strings.Join(r.FailedPackagesTopN, ", "))
	}
	if len(r.PolicyWeights) > 0 {
		fmt.Fprintf(b, "- Test Pyramid Compliance: unit %d / integration %d / e2e %d\n",
			r.PolicyWeights["unit"], r.PolicyWeights["integration"], r.PolicyWeights["e2e"])
	}
	if len(r.RequiredLaneStatus) > 0 {
		fmt.Fprintf(b, "- Required lane status:\n")
		lanes := make([]string, 0, len(r.RequiredLaneStatus))
		for lane := range r.RequiredLaneStatus {
			lanes = append(lanes, lane)
		}
		sort.Strings(lanes)
		for _, lane := range lanes {
			fmt.Fprintf(b, "  - `%s`: %s\n", lane, r.RequiredLaneStatus[lane])
		}
	}
	if len(r.TopFailures) > 0 {
		fmt.Fprintf(b, "- Top failures:\n")
		for _, f := range r.TopFailures {
			fmt.Fprintf(b, "  - `%s`\n", f)
		}
		fmt.Fprintf(b, "- Next action: re-run the lane locally and start with the first failing test above.\n")
	} else if r.Status == "success" {
		fmt.Fprintf(b, "- Next action: no action required.\n")
	}
	return b.String()
}

func parseDefault(v string) string {
	if strings.EqualFold(v, "default-true") {
		return "true"
	}
	return "false"
}

func topFailedPackages(counts map[string]int, limit int) []string {
	type item struct {
		name  string
		count int
	}

	items := make([]item, 0, len(counts))
	for name, count := range counts {
		items = append(items, item{name: name, count: count})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})

	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}

	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, fmt.Sprintf("%s (%d fails)", it.name, it.count))
	}
	return out
}

func hasDependencyFileChange(files []string) bool {
	for _, file := range files {
		base := filepath.Base(file)
		if base == "go.mod" || base == "go.sum" {
			return true
		}
	}
	return false
}

func loadSuitesForSummary() *suitesConfig {
	candidates := []string{
		os.Getenv("CI_SUITE_FILE"),
		"test/ci/suites.yaml",
	}
	for _, path := range candidates {
		if strings.TrimSpace(path) == "" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg suitesConfig
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			continue
		}
		return &cfg
	}
	return nil
}

func collectRequiredLaneStatus(cfg suitesConfig, currentLane, currentStatus, logDir string) map[string]string {
	status := map[string]string{}
	outputsDir := filepath.Dir(logDir)

	for _, lane := range cfg.Policy.RequiredLanes {
		laneStatus := "unknown"
		if lane == currentLane {
			laneStatus = currentStatus
		}

		reportPath := filepath.Join(outputsDir, lane, "report.json")
		if b, err := os.ReadFile(reportPath); err == nil {
			var laneReport report
			if err := json.Unmarshal(b, &laneReport); err == nil && laneReport.Status != "" {
				laneStatus = laneReport.Status
			}
		}

		statusPath := filepath.Join(outputsDir, lane, lane+".status")
		if b, err := os.ReadFile(statusPath); err == nil {
			trimmed := strings.TrimSpace(string(b))
			if strings.HasPrefix(trimmed, "skipped:") {
				laneStatus = trimmed
			}
		}

		status[lane] = laneStatus
	}

	return status
}

func oneLine(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
