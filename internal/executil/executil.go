package executil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

var ErrOutputLimit = errors.New("subprocess output exceeded configured limit")

type Result struct {
	Stdout []byte
	Stderr []byte
}

type limitedBuffer struct {
	buffer  bytes.Buffer
	limit   int64
	n       int64
	over    bool
	onLimit func()
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		b.markLimit()
		return len(p), nil
	}
	remaining := b.limit - b.n
	if remaining <= 0 {
		b.markLimit()
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		_, _ = b.buffer.Write(p[:remaining])
		b.n += remaining
		b.markLimit()
		return len(p), nil
	}
	_, _ = b.buffer.Write(p)
	b.n += int64(len(p))
	return len(p), nil
}

func (b *limitedBuffer) markLimit() {
	if b.over {
		return
	}
	b.over = true
	if b.onLimit != nil {
		b.onLimit()
	}
}

func Run(ctx context.Context, path string, args []string, stdin io.Reader, maxOutput int64) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("subprocess context is required")
	}
	if path == "" {
		return Result{}, errors.New("subprocess path is required")
	}
	if maxOutput < 1 {
		return Result{}, errors.New("subprocess output limit must be positive")
	}
	command := exec.CommandContext(ctx, path, args...)
	command.Stdin = stdin
	stdout, err := command.StdoutPipe()
	if err != nil {
		return Result{}, fmt.Errorf("create subprocess stdout pipe: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return Result{}, fmt.Errorf("create subprocess stderr pipe: %w", err)
	}
	if err := command.Start(); err != nil {
		return Result{}, fmt.Errorf("start subprocess: %w", err)
	}

	var killOnce sync.Once
	kill := func() { killOnce.Do(func() { _ = command.Process.Kill() }) }
	var output limitedBuffer
	output.limit = maxOutput
	output.onLimit = kill
	var diagnostics limitedBuffer
	diagnostics.limit = maxOutput
	diagnostics.onLimit = kill
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		_, _ = io.Copy(&output, stdout)
	}()
	go func() {
		defer waitGroup.Done()
		_, _ = io.Copy(&diagnostics, stderr)
	}()
	waitErr := command.Wait()
	waitGroup.Wait()
	result := Result{Stdout: output.buffer.Bytes(), Stderr: diagnostics.buffer.Bytes()}
	if output.over || diagnostics.over {
		return result, ErrOutputLimit
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if waitErr != nil {
		return result, fmt.Errorf("subprocess exited: %w", waitErr)
	}
	return result, nil
}
