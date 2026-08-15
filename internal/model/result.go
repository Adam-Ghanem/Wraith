package model

import "net/netip"

// Result is the machine-readable Phase 1 run envelope.
type Result struct {
	SchemaVersion string     `json:"schema_version"`
	Scope         Scope      `json:"scope"`
	PortList      PortList   `json:"port_list"`
	Run           Run        `json:"run"`
	Targets       []Target   `json:"targets"`
	Limitations   []string   `json:"limitations,omitempty"`
	Errors        []RunError `json:"errors,omitempty"`
}

type Scope struct {
	Interface              string `json:"interface"`
	CIDR                   string `json:"cidr"`
	AuthorizationConfirmed bool   `json:"authorization_confirmed"`
}

type PortList struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Run struct {
	StartedAt   string `json:"started_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
	Status      string `json:"status"`
}

type Target struct {
	IP        netip.Addr   `json:"ip"`
	MAC       string       `json:"mac,omitempty"`
	Discovery string       `json:"discovery,omitempty"`
	Ports     []PortResult `json:"ports,omitempty"`
}

type PortResult struct {
	Port     uint16 `json:"port"`
	Status   string `json:"status"`
	Service  string `json:"service,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Error    string `json:"error,omitempty"`
}

type RunError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
