package vulncheck

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/executil"
)

const (
	DefaultTimeout    = 10 * time.Minute
	DefaultRateLimit  = 5
	DefaultMaxOutput  = 8 << 20
	DefaultMaxTargets = 100
	ToolName          = "nuclei"
)

var lookupBinary = exec.LookPath

type Finding struct {
	Subdomain   string `json:"subdomain"`
	TemplateID  string `json:"template_id"`
	Severity    string `json:"severity"`
	MatchedURL  string `json:"matched_url"`
	Description string `json:"description"`
}

type Config struct {
	Timeout        time.Duration
	RateLimit      int
	MaxTargets     int
	MaxOutputBytes int64
}

func (c Config) Validate() error {
	if c.Timeout <= 0 || c.Timeout > DefaultTimeout {
		return fmt.Errorf("nuclei timeout must be between 1 and %s", DefaultTimeout)
	}
	if c.RateLimit < 1 || c.RateLimit > DefaultRateLimit {
		return fmt.Errorf("nuclei rate limit must be between 1 and %d requests per second", DefaultRateLimit)
	}
	if c.MaxTargets < 1 || c.MaxTargets > DefaultMaxTargets {
		return fmt.Errorf("nuclei target limit must be between 1 and %d", DefaultMaxTargets)
	}
	if c.MaxOutputBytes < 0 || c.MaxOutputBytes > DefaultMaxOutput {
		return fmt.Errorf("nuclei output limit must be between 1 and %d bytes", DefaultMaxOutput)
	}
	return nil
}

func (c Config) withDefaults() Config {
	if c.MaxTargets == 0 {
		c.MaxTargets = DefaultMaxTargets
	}
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = DefaultMaxOutput
	}
	return c
}

type ScanResult struct {
	Findings []Finding
	Errors   []string
	Skipped  bool
	Reason   string
}

func BuildArgs(rateLimit int) []string {
	return []string{
		"-l", "-",
		"-tags", "cves,exposures,misconfiguration",
		"-exclude-tags", "fuzz,dast,headless,code,workflow,interactsh,dos,ddos,brute-force,default-login",
		"-rate-limit", strconv.Itoa(rateLimit),
		"-jsonl",
		"-no-color",
		"-silent",
		"-no-meta",
		"-omit-raw",
		"-restrict-local-network-access",
		"-dr",
		"-ni",
		"-duc",
	}
}

func Scan(ctx context.Context, targets []string, config Config) (ScanResult, error) {
	if ctx == nil {
		return ScanResult{}, errors.New("nuclei context is required")
	}
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return ScanResult{}, err
	}
	path, err := lookupBinary(ToolName)
	if err != nil {
		return ScanResult{Skipped: true, Reason: "nuclei binary not found"}, nil
	}
	validatedTargets, targetHosts, err := validateTargets(targets, config.MaxTargets)
	if err != nil {
		return ScanResult{}, err
	}
	if len(validatedTargets) == 0 {
		return ScanResult{Skipped: true, Reason: "no same-scan live HTTP targets"}, nil
	}
	input := strings.NewReader(strings.Join(validatedTargets, "\n") + "\n")
	targetCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	commandResult, runErr := executil.Run(targetCtx, path, BuildArgs(config.RateLimit), input, config.MaxOutputBytes)
	cancel()
	if runErr != nil {
		return ScanResult{Errors: []string{runErr.Error()}}, nil
	}
	findings, parseErr := ParseJSONL(commandResult.Stdout)
	if parseErr != nil {
		return ScanResult{Errors: []string{parseErr.Error()}}, nil
	}
	result := ScanResult{Findings: make([]Finding, 0, len(findings))}
	for _, finding := range findings {
		matched, err := url.Parse(finding.MatchedURL)
		if err != nil || matched.Hostname() == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("ignore nuclei finding with invalid matched URL %q", finding.MatchedURL))
			continue
		}
		subdomain, ok := targetHosts[strings.ToLower(matched.Hostname())]
		if !ok {
			result.Errors = append(result.Errors, fmt.Sprintf("ignore nuclei finding outside same-scan hosts: %q", finding.MatchedURL))
			continue
		}
		finding.Subdomain = subdomain
		result.Findings = append(result.Findings, finding)
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		left, right := result.Findings[i], result.Findings[j]
		if left.Subdomain != right.Subdomain {
			return left.Subdomain < right.Subdomain
		}
		if left.TemplateID != right.TemplateID {
			return left.TemplateID < right.TemplateID
		}
		return left.MatchedURL < right.MatchedURL
	})
	return result, nil
}

func ParseJSONL(data []byte) ([]Finding, error) {
	if int64(len(data)) > DefaultMaxOutput {
		return nil, errors.New("nuclei JSONL exceeds configured output limit")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	findings := make([]Finding, 0)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var output nucleiOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			return nil, fmt.Errorf("parse nuclei JSONL line %d: %w", lineNumber, err)
		}
		if output.TemplateID == "" || output.MatchedURL == "" {
			continue
		}
		findings = append(findings, Finding{
			TemplateID:  output.TemplateID,
			Severity:    output.Info.Severity,
			MatchedURL:  output.MatchedURL,
			Description: output.Info.Description,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read nuclei JSONL: %w", err)
	}
	return findings, nil
}

type nucleiOutput struct {
	TemplateID string `json:"template-id"`
	MatchedURL string `json:"matched-at"`
	Info       struct {
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
}

func validateTargets(targets []string, maxTargets int) ([]string, map[string]string, error) {
	validated := make([]string, 0, len(targets))
	hosts := make(map[string]string, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, rawTarget := range targets {
		parsed, err := url.Parse(rawTarget)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Path == "" {
			return nil, nil, fmt.Errorf("nuclei target must be an HTTP(S) URL without userinfo: %q", rawTarget)
		}
		key := parsed.Scheme + "://" + strings.ToLower(parsed.Hostname()) + parsed.EscapedPath()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		validated = append(validated, rawTarget)
		hosts[strings.ToLower(parsed.Hostname())] = parsed.Hostname()
		if len(validated) > maxTargets {
			return nil, nil, fmt.Errorf("nuclei target count exceeds bounded limit of %d", maxTargets)
		}
	}
	return validated, hosts, nil
}
