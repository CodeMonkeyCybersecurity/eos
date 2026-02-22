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
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Elapsed float64 `json:"Elapsed"`
}

type report struct {
	Lane         string             `json:"lane"`
	Status       string             `json:"status"`
	Pass         int                `json:"pass"`
	Fail         int                `json:"fail"`
	Skip         int                `json:"skip"`
	Coverage     string             `json:"coverage"`
	FlakeCount   int                `json:"flake_count"`
	Packages     map[string]float64 `json:"packages"`
	TopFailures  []string           `json:"top_failures"`
	GeneratedUTC string             `json:"generated_utc"`
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
		die("usage: go run ./test/ci/tool <policy-validate|policy-threshold|policy-should-run|summary|gosec-check> ...")
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
	for _, file := range jsonlFiles {
		_ = parseJSONL(file, &r, failureSet)
	}
	for f := range failureSet {
		r.TopFailures = append(r.TopFailures, f)
	}
	sort.Strings(r.TopFailures)
	if len(r.TopFailures) > 10 {
		r.TopFailures = r.TopFailures[:10]
	}
	r.FlakeCount = countFlakes(logDir)
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

func parseJSONL(path string, out *report, failureSet map[string]struct{}) error {
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
		switch e.Action {
		case "pass":
			out.Pass++
		case "fail":
			out.Fail++
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
	fmt.Fprintf(b, "- Flake signatures: %d\n", r.FlakeCount)
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
