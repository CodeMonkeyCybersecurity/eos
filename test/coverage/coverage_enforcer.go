// test/coverage/coverage_enforcer.go
package coverage

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// EnforceCoverage checks if package meets minimum coverage requirements
func EnforceCoverage(coverageFile string, minCoverage float64) error {
	file, err := os.Open(coverageFile)
	if err != nil {
		return fmt.Errorf("opening coverage file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "total:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				coverageStr := strings.TrimSuffix(parts[2], "%")
				coverage, err := strconv.ParseFloat(coverageStr, 64)
				if err != nil {
					return fmt.Errorf("parsing coverage: %w", err)
				}

				if coverage < minCoverage {
					return fmt.Errorf("coverage %.1f%% is below minimum %.1f%%",
						coverage, minCoverage)
				}

				return nil
			}
		}
	}

	return fmt.Errorf("coverage data not found")
}

// Makefile additions for test coverage enforcement
const makefileAdditions = `
# Test coverage targets
.PHONY: test-coverage test-coverage-html coverage-check

COVERAGE_THRESHOLD := 70

test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out -covermode=atomic ./pkg/...
	@go tool cover -func=coverage.out

test-coverage-html: test-coverage
	@echo "Generating HTML coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

coverage-check: test-coverage
	@echo "Checking coverage threshold..."
	@go run test/coverage/coverage_enforcer.go coverage.out $(COVERAGE_THRESHOLD)

# Run before commits
pre-commit: lint test-coverage-check
	@echo "Pre-commit checks passed!"

# Package-specific coverage targets
test-vault-coverage:
	@go test -v -coverprofile=vault.coverage.out ./pkg/vault/...
	@go tool cover -func=vault.coverage.out | grep total

test-crypto-coverage:
	@go test -v -coverprofile=crypto.coverage.out ./pkg/crypto/...
	@go tool cover -func=crypto.coverage.out | grep total

# Critical packages must have 90% coverage
test-critical-coverage:
	@go test -v -coverprofile=critical.coverage.out \
		./pkg/vault/... ./pkg/crypto/... ./pkg/eos_io/... ./pkg/eos_err/...
	@go run test/coverage/coverage_enforcer.go critical.coverage.out 90
`
