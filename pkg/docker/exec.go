// pkg/docker/exec.go

package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// ExecCommandInContainer runs a command inside a running container and returns its combined stdout/stderr output.
func ExecCommandInContainer(containerName string, cmd []string) (string, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	execConfig := container.ExecOptions{
		Cmd:          cmd,
		AttachStderr: true,
		AttachStdout: true,
		Tty:          false,
	}

	execResp, err := cli.ContainerExecCreate(ctx, containerName, execConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create exec instance: %w", err)
	}

	// 2) Attach for I/O:
	attachResp, err := cli.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{
		Tty: false,
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach to exec instance: %w", err)
	}
	defer attachResp.Close()

	if err := cli.ContainerExecStart(ctx, execResp.ID, container.ExecStartOptions{
		Tty: false,
	}); err != nil {
		return "", fmt.Errorf("failed to start exec: %w", err)
	}

	var outputBuf bytes.Buffer
	if _, err := io.Copy(&outputBuf, attachResp.Reader); err != nil {
		return "", fmt.Errorf("failed to read exec output: %w", err)
	}

	inspect, err := cli.ContainerExecInspect(ctx, execResp.ID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect exec: %w", err)
	}
	if inspect.ExitCode != 0 {
		return outputBuf.String(), fmt.Errorf("command exited with code %d", inspect.ExitCode)
	}

	return outputBuf.String(), nil
}
