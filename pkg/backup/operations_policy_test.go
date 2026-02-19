package backup

import (
	"context"
	"testing"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func boolPtr(v bool) *bool {
	return &v
}

func TestBuildAllowedHookCommands_DefaultPlusConfig(t *testing.T) {
	settings := Settings{
		HooksPolicy: HooksPolicy{
			Enabled:         boolPtr(true),
			AllowedCommands: []string{"/bin/echo", "relative/ignored"},
		},
	}

	allowed := buildAllowedHookCommands(settings)
	if _, ok := allowed["/bin/echo"]; !ok {
		t.Fatalf("expected /bin/echo to be allowlisted")
	}
	for _, cmd := range DefaultAllowedHookCommands {
		if _, ok := allowed[cmd]; !ok {
			t.Fatalf("expected default command %s to be allowlisted", cmd)
		}
	}
	if _, ok := allowed["relative/ignored"]; ok {
		t.Fatal("relative commands must not be allowlisted")
	}
}

func TestRunHookWithSettings_Disabled(t *testing.T) {
	logger := otelzap.New(zap.NewNop()).Ctx(context.Background())
	settings := Settings{
		HooksPolicy: HooksPolicy{
			Enabled: boolPtr(false),
		},
	}

	err := RunHookWithSettings(context.Background(), logger, "/usr/bin/tar --version", settings)
	if err == nil {
		t.Fatal("expected hook execution to fail when hooks are disabled")
	}
}
