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
	defer func() { _ = file.Close() }()

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
