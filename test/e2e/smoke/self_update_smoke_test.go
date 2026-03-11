//go:build e2e_smoke

package smoke

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/test/e2e"
)

func TestSmoke_SelfUpdateHelp(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "self-update-help-smoke")

	result := suite.RunCommand("self", "update", "--help")
	result.AssertSuccess(t)
	result.AssertContains(t, "--system-packages")
	result.AssertContains(t, "--go-version")
	result.AssertContains(t, "--force-clean")
}
