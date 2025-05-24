// pkg/docker/exec.go

package docker

import (
	"bytes"
	"context"
	"io"

	"github.com/cockroachdb/errors"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/go-playground/validator/v10"
	"github.com/open-policy-agent/opa/rego"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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
func ExecCommandInContainer(ctx context.Context, cfg ExecConfig) (string, error) {
	// 1) Tracing
	tracer := otel.Tracer("docker.exec")
	ctx, span := tracer.Start(ctx, "ExecCommandInContainer",
		trace.WithAttributes(
			attribute.String("container", cfg.ContainerName),
			attribute.StringSlice("cmd", cfg.Cmd),
		),
	)
	defer span.End()

	// 2) Validation
	if err := validator.New().Struct(cfg); err != nil {
		return "", errors.Wrap(err, "invalid ExecConfig")
	}

	// 3) Policy check (OPA)
	policy := `
  package exec
  default allow = false
  allow { input.Cmd[0] != "rm" }  # simplistic deny rm
  `
	query, _ := rego.New(
		rego.Query("data.exec.allow"),
		rego.Module("policy.rego", policy),
	).PrepareForEval(ctx)
	res, err := query.Eval(ctx, rego.EvalInput(cfg))
	if err != nil || len(res) == 0 || !res[0].Expressions[0].Value.(bool) {
		return "", errors.New("execution denied by policy")
	}

	// 4) Logging
	logger := zap.L().With(
		zap.String("container", cfg.ContainerName),
		zap.Strings("cmd", cfg.Cmd),
	)
	logger.Info("starting exec")

	// 5) Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", errors.Wrap(err, "creating docker client")
	}
	defer cli.Close()

	// 6) Create exec instance
	execResp, err := cli.ContainerExecCreate(ctx, cfg.ContainerName, container.ExecOptions{
		Cmd:          cfg.Cmd,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          cfg.Tty,
	})
	if err != nil {
		return "", errors.Wrap(err, "creating exec instance")
	}

	// 7) Attach & Start
	attachResp, err := cli.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{Tty: cfg.Tty})
	if err != nil {
		return "", errors.Wrap(err, "attaching to exec")
	}
	defer attachResp.Close()

	if err := cli.ContainerExecStart(ctx, execResp.ID, container.ExecStartOptions{Tty: cfg.Tty}); err != nil {
		return "", errors.Wrap(err, "starting exec")
	}

	// 8) Read output
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, attachResp.Reader); err != nil {
		return "", errors.Wrap(err, "reading exec output")
	}

	// 9) Inspect exit code
	inspect, err := cli.ContainerExecInspect(ctx, execResp.ID)
	if err != nil {
		return "", errors.Wrap(err, "inspecting exec result")
	}
	if inspect.ExitCode != 0 {
		return buf.String(), errors.Errorf("command exited with code %d", inspect.ExitCode)
	}

	logger.Info("exec complete", zap.Int("exit_code", inspect.ExitCode))
	return buf.String(), nil
}
