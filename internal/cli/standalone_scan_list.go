package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/scan"
)

// RunStandaloneScanCommand dispatches the native scanner and adds Nmap-style
// input-list support without complicating the single-target parser.
func RunStandaloneScanCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if hasStandaloneInputList(args) {
		return RunStandaloneScanList(ctx, args, stdout, stderr)
	}
	return RunStandaloneScan(ctx, args, stdout, stderr)
}

// RunStandaloneScanList reads a bounded local target list and reuses the
// validated standalone scanner for each canonical target. The list itself
// performs no network I/O and may expand CIDRs only up to scan.MaxTargets.
func RunStandaloneScanList(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if ctx == nil || len(args) < 2 || args[0] != "scan" {
		return errors.New("usage: wraith scan -iL FILE [scan options]")
	}

	cleanArgs, path, err := stripStandaloneInputList(args)
	if err != nil {
		return err
	}
	targets, err := loadStandaloneTargetList(path)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("input list contains no valid targets")
	}

	jsonOutput := hasStandaloneExactFlag(cleanArgs[1:], "--json")
	if jsonOutput {
		values := make([]any, 0, len(targets))
		for _, target := range targets {
			if err := ctx.Err(); err != nil {
				return err
			}
			callArgs := append(append([]string(nil), cleanArgs...), target)
			var buffer bytes.Buffer
			if err := RunStandaloneScan(ctx, callArgs, &buffer, stderr); err != nil {
				return err
			}
			var value any
			if err := json.Unmarshal(buffer.Bytes(), &value); err != nil {
				return fmt.Errorf("decode standalone scan result for %s: %w", target, err)
			}
			values = append(values, value)
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(values)
	}

	for index, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if index > 0 {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
		}
		callArgs := append(append([]string(nil), cleanArgs...), target)
		if err := RunStandaloneScan(ctx, callArgs, stdout, stderr); err != nil {
			return err
		}
	}
	return nil
}

func hasStandaloneInputList(args []string) bool {
	for _, raw := range args[1:] {
		if raw == "-iL" || raw == "--input-list" || strings.HasPrefix(raw, "-iL=") || strings.HasPrefix(raw, "--input-list=") {
			return true
		}
	}
	return false
}

func stripStandaloneInputList(args []string) ([]string, string, error) {
	clean := make([]string, 0, len(args))
	clean = append(clean, args[0])
	path := ""

	for index := 1; index < len(args); index++ {
		raw := strings.TrimSpace(args[index])
		switch {
		case raw == "-iL" || raw == "--input-list":
			if path != "" || index+1 >= len(args) {
				return nil, "", errors.New("scan accepts exactly one -iL/--input-list file")
			}
			path = strings.TrimSpace(args[index+1])
			index++
		case strings.HasPrefix(raw, "-iL="):
			if path != "" {
				return nil, "", errors.New("scan accepts exactly one -iL/--input-list file")
			}
			path = strings.TrimSpace(strings.TrimPrefix(raw, "-iL="))
		case strings.HasPrefix(raw, "--input-list="):
			if path != "" {
				return nil, "", errors.New("scan accepts exactly one -iL/--input-list file")
			}
			path = strings.TrimSpace(strings.TrimPrefix(raw, "--input-list="))
		default:
			clean = append(clean, args[index])
		}
	}
	if path == "" {
		return nil, "", errors.New("-iL/--input-list requires a local file path")
	}
	if path == "-" {
		return nil, "", errors.New("stdin target lists are not supported; provide a bounded local file")
	}
	return clean, path, nil
}

func loadStandaloneTargetList(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input list: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	seen := make(map[string]struct{})
	targets := make([]string, 0)
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		expanded, err := standaloneTargets(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid input-list target %q: %w", raw, err)
		}
		for _, target := range expanded {
			if _, exists := seen[target]; exists {
				continue
			}
			if len(targets) >= scan.MaxTargets {
				return nil, fmt.Errorf("input list expands beyond the %d-target bound", scan.MaxTargets)
			}
			seen[target] = struct{}{}
			targets = append(targets, target)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read input list: %w", err)
	}
	return targets, nil
}

func hasStandaloneExactFlag(args []string, name string) bool {
	for _, raw := range args {
		if strings.TrimSpace(raw) == name {
			return true
		}
	}
	return false
}
