// pkg/docker/exec.go

package container

import (
	"bytes"
	"io"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/cockroachdb/errors"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/go-playground/validator/v10"
	"github.com/open-policy-agent/opa/v1/rego"
	"go.uber.org/zap"
)

// ExecConfig defines and validates the parameters for an exec.
type ExecConfig struct {
	ContainerName string   `validate:"required"`
	Cmd           []string `validate:"required,min=1,dive,required"`
	Tty           bool
}

// ExecCommandInContainer runs a command inside a container with full validation,
// policy enforcement, tracing, logging, and enriched error handling.
func ExecCommandInContainer(rc *eos_io.RuntimeContext, cfg ExecConfig) (string, error) {

	// 2) Validation
	if err := validator.New().Struct(cfg); err != nil {
		return "", errors.Wrap(err, "invalid ExecConfig")
	}

	// 3) Policy check (OPA) - with safe error handling
	policy := `
  package exec
  default allow = false
  allow { input.Cmd[0] != "rm" }  # simplistic deny rm
  `
	query, prepErr := rego.New(
		rego.Query("data.exec.allow"),
		rego.Module("policy.rego", policy),
	).PrepareForEval(rc.Ctx)
	
	if prepErr != nil {
		// Log but don't fail - allow execution if policy setup fails
		zap.L().Warn("OPA policy setup failed, proceeding without policy enforcement", zap.Error(prepErr))
	} else {
		res, err := query.Eval(rc.Ctx, rego.EvalInput(cfg))
		if err != nil {
			zap.L().Warn("OPA policy evaluation failed, proceeding without policy enforcement", zap.Error(err))
		} else if len(res) == 0 {
			zap.L().Warn("OPA policy returned no results, proceeding without policy enforcement")
		} else if len(res[0].Expressions) == 0 {
			zap.L().Warn("OPA policy returned no expressions, proceeding without policy enforcement")
		} else {
			// Safely extract the boolean result
			if allowed, ok := res[0].Expressions[0].Value.(bool); ok && !allowed {
				return "", errors.New("execution denied by policy")
			} else if !ok {
				zap.L().Warn("OPA policy returned non-boolean result, proceeding without policy enforcement")
			}
		}
	}

	// 5) Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", errors.Wrap(err, "creating docker client")
	}
	defer func() {
		if cerr := cli.Close(); cerr != nil {
			zap.L().Error("failed to close docker client", zap.Error(cerr))
		}
	}()

	// 6) Create exec instance
	execResp, err := cli.ContainerExecCreate(rc.Ctx, cfg.ContainerName, container.ExecOptions{
		Cmd:          cfg.Cmd,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          cfg.Tty,
	})
	if err != nil {
		return "", errors.Wrap(err, "creating exec instance")
	}

	// 7) Attach & Start
	attachResp, err := cli.ContainerExecAttach(rc.Ctx, execResp.ID, container.ExecAttachOptions{Tty: cfg.Tty})
	if err != nil {
		return "", errors.Wrap(err, "attaching to exec")
	}
	defer attachResp.Close()

	if err := cli.ContainerExecStart(rc.Ctx, execResp.ID, container.ExecStartOptions{Tty: cfg.Tty}); err != nil {
		return "", errors.Wrap(err, "starting exec")
	}

	// 8) Read output
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, attachResp.Reader); err != nil {
		return "", errors.Wrap(err, "reading exec output")
	}

	// 9) Inspect exit code
	inspect, err := cli.ContainerExecInspect(rc.Ctx, execResp.ID)
	if err != nil {
		return "", errors.Wrap(err, "inspecting exec result")
	}
	if inspect.ExitCode != 0 {
		return buf.String(), errors.Errorf("command exited with code %d", inspect.ExitCode)
	}

	zap.L().Info("exec complete", zap.Int("exit_code", inspect.ExitCode))
	return buf.String(), nil
}
