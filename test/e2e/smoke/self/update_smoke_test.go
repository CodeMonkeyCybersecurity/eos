//go:build e2e_smoke

package self

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSelfUpdateHelpSmoke(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "self", "update", "--help")
	cmd.Dir = "../../../../"

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("self update help failed: %v\n%s", err, string(out))
	}

	output := string(out)
	if !strings.Contains(output, "Update Eos to the latest version") {
		t.Fatalf("unexpected help output:\n%s", output)
	}
}

func TestSelfUpdateFlagsSmoke(t *testing.T) {
	// Verify key flags are wired into the self update command.
	cmd := exec.Command("go", "run", ".", "self", "update", "--help")
	cmd.Dir = "../../../../"

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("self update --help failed: %v\n%s", err, string(out))
	}

	output := string(out)
	expectedFlags := []string{"force-clean", "system-packages", "go-version"}
	for _, flag := range expectedFlags {
		if !strings.Contains(output, flag) {
			t.Fatalf("help should mention --%s flag:\n%s", flag, output)
		}
	}
}

func TestSelfCommandStructureSmoke(t *testing.T) {
	// Verify the self subcommand exists and lists its children
	cmd := exec.Command("go", "run", ".", "self", "--help")
	cmd.Dir = "../../../../"

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("self --help failed: %v\n%s", err, string(out))
	}

	output := string(out)
	// "update" should appear as a subcommand of "self"
	if !strings.Contains(output, "update") {
		t.Fatalf("self --help should list 'update' subcommand:\n%s", output)
	}
}
