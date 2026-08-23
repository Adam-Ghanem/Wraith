// Package scanner provides the top-level Wraith scan orchestration layer.
// Active network I/O remains below the scanner: TCP uses NPD/R3 and optional
// HTTP service detection uses the shared policy-aware HTTP engine.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
)

type Profile string

const (
	ProfileSafe     Profile = "safe"
	ProfileStandard Profile = "standard"
	ProfileDeep     Profile = "deep"
	ProfileCustom   Profile = "custom"
)

type Request struct {
	ProjectID      string
	ScopeVersion   string
	Target         string
	Profile        Profile
	Ports          []uint16
	AllPorts       bool
	Timeout        time.Duration
	Concurrency    int
	DetectServices bool
}

type Result struct {
	ProjectID    string            `json:"project_id"`
	ScopeVersion string            `json:"scope_version"`
	Target       string            `json:"target"`
	Profile      Profile           `json:"profile"`
	StartedAt    time.Time         `json:"started_at"`
	CompletedAt  time.Time         `json:"completed_at"`
	Ports        []PortObservation `json:"ports"`
}

type PortObservation struct {
	Port       uint16     `json:"port"`
	Protocol   string     `json:"protocol"`
	State      npd.State  `json:"state"`
	Duration   time.Duration `json:"duration"`
	ObservedAt time.Time  `json:"observed_at"`
	Error      string     `json:"error,omitempty"`
	Service    string     `json:"service,omitempty"`
	Version    string     `json:"version,omitempty"`
	Evidence   []Evidence `json:"evidence,omitempty"`
}

type Evidence struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type Engine struct {
	TCP  httpengine.TCPClient
	HTTP httpengine.Client
	Now  func() time.Time
}

func (e Engine) Run(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("nil scan context")
	}
	if e.TCP == nil {
		return Result{}, errors.New("scan engine TCP transport is unavailable")
	}
	if strings.TrimSpace(req.ProjectID) == "" || strings.TrimSpace(req.ScopeVersion) == "" || strings.TrimSpace(req.Target) == "" {
		return Result{}, errors.New("scan request identity is incomplete")
	}
	if req.Timeout < 0 {
		return Result{}, errors.New("scan timeout cannot be negative")
	}
	profile, err := normalizeProfile(req.Profile)
	if err != nil {
		return Result{}, err
	}
	ports, err := selectPorts(profile, req.Ports, req.AllPorts)
	if err != nil {
		return Result{}, err
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	started := now().UTC()
	npdScanner := npd.Scanner{TCP: e.TCP, Now: now}
	plan, err := npdScanner.Plan(req.Target, ports)
	if err != nil {
		return Result{}, err
	}
	plan.ProjectID, plan.ScopeVersion, plan.Profile, plan.Timeout, plan.Concurrency = req.ProjectID, req.ScopeVersion, npd.Profile(profile), req.Timeout, req.Concurrency
	npdResult, scanErr := npdScanner.Scan(ctx, plan)
	result := Result{ProjectID: req.ProjectID, ScopeVersion: req.ScopeVersion, Target: npdResult.Target, Profile: profile, StartedAt: started, CompletedAt: now().UTC(), Ports: make([]PortObservation, 0, len(npdResult.Ports))}
	for _, port := range npdResult.Ports {
		obs := PortObservation{Port: port.Port, Protocol: port.Protocol, State: port.State, Duration: port.Duration, ObservedAt: port.ObservedAt, Error: port.Error}
		if port.State == npd.StateOpen {
			obs.Service, obs.Evidence = identifyService(port.Port)
		}
		if scanErr == nil && req.DetectServices && port.State == npd.StateOpen && e.HTTP != nil && isHTTPPort(port.Port) {
			service, version, evidence := e.detectHTTP(ctx, req, port.Port)
			if service != "" {
				obs.Service = service
			}
			if version != "" {
				obs.Version = version
			}
			obs.Evidence = append(obs.Evidence, evidence...)
		}
		result.Ports = append(result.Ports, obs)
	}
	sort.Slice(result.Ports, func(i, j int) bool {
		if result.Ports[i].Port != result.Ports[j].Port {
			return result.Ports[i].Port < result.Ports[j].Port
		}
		return result.Ports[i].Protocol < result.Ports[j].Protocol
	})
	if scanErr != nil {
		result.CompletedAt = npdResult.CompletedAt
		return result, scanErr
	}
	result.CompletedAt = npdResult.CompletedAt
	return result, nil
}

func identifyService(port uint16) (string, []Evidence) {
	services := map[uint16]string{
		20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "domain", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
		111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
		161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
		587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
		1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
		5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
	}
	service := services[port]
	if service == "" {
		return "", nil
	}
	return service, []Evidence{{Kind: "service.port-hint", Value: service}}
}

func isHTTPPort(port uint16) bool {
	switch port {
	case 80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888:
		return true
	default:
		return false
	}
}

func (e Engine) detectHTTP(ctx context.Context, req Request, port uint16) (string, string, []Evidence) {
	host := strings.TrimSuffix(strings.TrimPrefix(req.Target, "tcp://"), "/")
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	urlHost := host
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		urlHost = "[" + host + "]"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, urlHost, port)
	response, err := e.HTTP.Do(ctx, httpengine.Request{ProjectID: req.ProjectID, Method: "HEAD", URL: url, Timeout: req.Timeout, MaxResponseBytes: 1 << 20, Source: "wraith-scan-service-detection"})
	if err != nil {
		return "", "", nil
	}
	service := "http"
	if scheme == "https" {
		service = "https"
	}
	version := ""
	evidence := make([]Evidence, 0, 3)
	if server := strings.TrimSpace(response.Headers.Get("Server")); server != "" {
		version = server
		evidence = append(evidence, Evidence{Kind: "http.server", Value: server})
	}
	if powered := strings.TrimSpace(response.Headers.Get("X-Powered-By")); powered != "" {
		evidence = append(evidence, Evidence{Kind: "http.powered_by", Value: powered})
	}
	evidence = append(evidence, Evidence{Kind: "http.status", Value: fmt.Sprintf("%d", response.StatusCode)})
	return service, version, evidence
}

func normalizeProfile(profile Profile) (Profile, error) {
	profile = Profile(strings.ToLower(strings.TrimSpace(string(profile))))
	switch profile {
	case ProfileSafe, ProfileStandard, ProfileDeep, ProfileCustom:
		return profile, nil
	default:
		return "", errors.New("invalid scan profile")
	}
}

func selectPorts(profile Profile, requested []uint16, allPorts bool) ([]uint16, error) {
	if allPorts {
		if profile == ProfileCustom && len(requested) != 0 {
			return nil, errors.New("all-port selection cannot be combined with explicit ports")
		}
		return npd.FullPorts(), nil
	}
	if profile == ProfileCustom {
		if len(requested) == 0 {
			return nil, errors.New("custom scan profile requires ports")
		}
		ports := append([]uint16(nil), requested...)
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		for i, p := range ports {
			if p == 0 || (i > 0 && ports[i-1] == p) {
				return nil, npd.ErrInvalidSpec
			}
		}
		if len(ports) > npd.MaxPorts {
			return nil, npd.ErrPortLimit
		}
		return ports, nil
	}
	if len(requested) != 0 {
		return nil, errors.New("ports are only valid with custom profile")
	}
	return npd.DefaultPorts(npd.Profile(profile)), nil
}
