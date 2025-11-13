// pkg/storage/analyzer/classifier.go

package analyzer

import (
	"path/filepath"
	"strings"
)

// DataClassifier classifies files and directories by importance
type DataClassifier struct {
	criticalPaths   []string
	importantPaths  []string
	standardPaths   []string
	expendablePaths []string
}

// DataClass represents the classification of data
type DataClass string

const (
	ClassCritical   DataClass = "critical"
	ClassImportant  DataClass = "important"
	ClassStandard   DataClass = "standard"
	ClassExpendable DataClass = "expendable"
)

// NewDataClassifier creates a new data classifier with default rules
func NewDataClassifier() *DataClassifier {
	return &DataClassifier{
		criticalPaths: []string{
			"/etc",
			"/var/lib/mysql",
			"/var/lib/postgresql",
			"/var/lib/vault",
			"/home",
			"*.key",
			"*.crt",
			"*.pem",
		},
		importantPaths: []string{
			"/var/log",
			"/var/backups",
			"/opt",
			"/usr/local",
			"*.conf",
			"*.config",
		},
		standardPaths: []string{
			"/var/cache",
			"/var/spool",
			"/usr/share",
		},
		expendablePaths: []string{
			"/tmp",
			"/var/tmp",
			"*.tmp",
			"*.cache",
			"*.swp",
			"*~",
			".trash",
			".Trash",
		},
	}
}

// ClassifyPath determines the classification of a given path
func (c *DataClassifier) ClassifyPath(path string) DataClass {
	// Check expendable first (most likely to be deleted)
	if c.matchesPatterns(path, c.expendablePaths) {
		return ClassExpendable
	}

	// Check critical paths
	if c.matchesPatterns(path, c.criticalPaths) {
		return ClassCritical
	}

	// Check important paths
	if c.matchesPatterns(path, c.importantPaths) {
		return ClassImportant
	}

	// Check standard paths
	if c.matchesPatterns(path, c.standardPaths) {
		return ClassStandard
	}

	// Default to standard if no match
	return ClassStandard
}

// matchesPatterns checks if a path matches any of the given patterns
func (c *DataClassifier) matchesPatterns(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(pattern, "*") {
			// Simple glob matching
			if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
				return true
			}
		} else {
			// Direct path matching
			if strings.HasPrefix(path, pattern) {
				return true
			}
		}
	}
	return false
}

// GetCleanupCandidates returns paths that can be cleaned up based on class
func (c *DataClassifier) GetCleanupCandidates(basePath string, aggressive bool) []string {
	candidates := []string{}

	// Always include expendable paths
	for _, path := range c.expendablePaths {
		if !strings.Contains(path, "*") {
			candidates = append(candidates, filepath.Join(basePath, path))
		}
	}

	// In aggressive mode, include some standard paths
	if aggressive {
		candidates = append(candidates,
			filepath.Join(basePath, "/var/cache/apt/archives/*.deb"),
			filepath.Join(basePath, "/var/log/*.gz"),
			filepath.Join(basePath, "/var/log/*.old"),
		)
	}

	return candidates
}

// GetCompressionCandidates returns paths suitable for compression
func (c *DataClassifier) GetCompressionCandidates(basePath string) []string {
	return []string{
		filepath.Join(basePath, "/var/log/*.log"),
		filepath.Join(basePath, "/var/log/*/*.log"),
		filepath.Join(basePath, "/home/*/.bash_history"),
		filepath.Join(basePath, "/root/.bash_history"),
	}
}

// GetClassDescription returns a description of a data class
func GetClassDescription(class DataClass) string {
	descriptions := map[DataClass]string{
		ClassCritical:   "Critical system and security files",
		ClassImportant:  "Important application and configuration data",
		ClassStandard:   "Standard operational data",
		ClassExpendable: "Temporary and cache files that can be deleted",
	}

	if desc, ok := descriptions[class]; ok {
		return desc
	}
	return "Unknown classification"
}
