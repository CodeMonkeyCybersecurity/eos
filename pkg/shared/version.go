// pkg/shared/version.go

package shared

// Version is the semantic version of eos
// Injected at build time via -ldflags "-X github.com/CodeMonkeyCybersecurity/eos/pkg/shared.Version=x.y.z"
var Version = "0.1.0"

// BuildCommit is the git commit hash the binary was built from
// Injected at build time via -ldflags "-X github.com/CodeMonkeyCybersecurity/eos/pkg/shared.BuildCommit=abc123"
// If empty, the binary was built without commit tracking (development build)
var BuildCommit = ""

// BuildTime is the timestamp when the binary was built
// Injected at build time via -ldflags "-X github.com/CodeMonkeyCybersecurity/eos/pkg/shared.BuildTime=2024-01-01T00:00:00Z"
var BuildTime = ""

// IsDevelopmentBuild returns true if the binary was built without commit tracking
func IsDevelopmentBuild() bool {
	return BuildCommit == ""
}
