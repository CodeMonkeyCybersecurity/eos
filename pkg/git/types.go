// Package git provides Git repository management utilities
package git

// GitStatus represents the current status of a Git repository
type GitStatus struct {
	IsClean      bool
	Branch       string
	Staged       []string
	Modified     []string
	Untracked    []string
	HasConflicts bool
}

// ChangeAnalysis represents an analysis of Git changes for commit message generation
type ChangeAnalysis struct {
	PrimaryAction string
	FileTypes     map[string]int
	Packages      []string
	HasTests      bool
	HasDocs       bool
	HasConfig     bool
	TotalFiles    int
	LinesAdded    int
	LinesRemoved  int
}
