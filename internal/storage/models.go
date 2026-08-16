package storage

type ScanRecord struct {
	ID          int64  `json:"id"`
	Target      string `json:"target"`
	ScanType    string `json:"scan_type"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

type DeviceRecord struct {
	ID            int64  `json:"id"`
	ScanID        int64  `json:"scan_id"`
	IP            string `json:"ip"`
	MAC           string `json:"mac"`
	OpenPortsJSON string `json:"open_ports"`
	OSGuess       string `json:"os_guess"`
	Confidence    string `json:"confidence"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
}

type SubdomainRecord struct {
	ID           int64  `json:"id"`
	ScanID       int64  `json:"scan_id"`
	Domain       string `json:"domain"`
	Subdomain    string `json:"subdomain"`
	IP           string `json:"ip"`
	StatusCode   int    `json:"status_code"`
	Title        string `json:"title"`
	ServerHeader string `json:"server_header"`
	TechGuess    string `json:"tech_guess"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
}

type DeviceSnapshot struct {
	IP            string `json:"ip"`
	MAC           string `json:"mac"`
	OpenPortsJSON string `json:"open_ports"`
	OSGuess       string `json:"os_guess"`
	Confidence    string `json:"confidence"`
}

type SubdomainSnapshot struct {
	Subdomain  string `json:"subdomain"`
	IP         string `json:"ip"`
	StatusCode int    `json:"status_code"`
	TechGuess  string `json:"tech_guess"`
}

type ChangeKind string

const (
	ChangeNew     ChangeKind = "NEW"
	ChangeRemoved ChangeKind = "REMOVED"
	ChangeChanged ChangeKind = "CHANGED"
)

type DeviceChange struct {
	Kind     ChangeKind      `json:"kind"`
	IP       string          `json:"ip"`
	Previous *DeviceSnapshot `json:"previous,omitempty"`
	Current  *DeviceSnapshot `json:"current,omitempty"`
}

type SubdomainChange struct {
	Kind      ChangeKind         `json:"kind"`
	Subdomain string             `json:"subdomain"`
	Previous  *SubdomainSnapshot `json:"previous,omitempty"`
	Current   *SubdomainSnapshot `json:"current,omitempty"`
}

type ContentFindingRecord struct {
	ID             int64  `json:"id"`
	ScanID         int64  `json:"scan_id"`
	Subdomain      string `json:"subdomain"`
	Path           string `json:"path"`
	StatusCode     int    `json:"status_code"`
	ResponseLength int64  `json:"response_length"`
	DiscoveredAt   string `json:"discovered_at"`
}

type JSFindingRecord struct {
	ID           int64  `json:"id"`
	ScanID       int64  `json:"scan_id"`
	Subdomain    string `json:"subdomain"`
	SourceFile   string `json:"source_file"`
	FindingType  string `json:"finding_type"`
	Value        string `json:"value"`
	Confidence   string `json:"confidence"`
	DiscoveredAt string `json:"discovered_at"`
}

type ContentFindingSnapshot struct {
	Subdomain      string `json:"subdomain"`
	Path           string `json:"path"`
	StatusCode     int    `json:"status_code"`
	ResponseLength int64  `json:"response_length"`
}

type JSFindingSnapshot struct {
	Subdomain   string `json:"subdomain"`
	SourceFile  string `json:"source_file"`
	FindingType string `json:"finding_type"`
	Value       string `json:"value"`
	Confidence  string `json:"confidence"`
}

type ContentFindingChange struct {
	Kind    ChangeKind             `json:"kind"`
	Current ContentFindingSnapshot `json:"current"`
}

type JSFindingChange struct {
	Kind    ChangeKind        `json:"kind"`
	Current JSFindingSnapshot `json:"current"`
}
