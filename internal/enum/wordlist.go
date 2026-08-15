package enum

// DefaultDNSPrefixes is a conservative built-in list for authorized DNS enumeration.
// It is deliberately finite and is consumed through DNSBruteForcer's concurrency and rate limits.
var DefaultDNSPrefixes = []string{
	"www", "api", "app", "web", "dev", "development", "stage", "staging", "test", "testing", "qa", "uat", "prod", "production", "beta", "alpha", "demo", "preview", "sandbox", "lab",
	"portal", "admin", "administrator", "dashboard", "console", "manage", "management", "login", "auth", "oauth", "sso", "account", "accounts", "user", "users", "support", "help", "docs", "documentation", "wiki",
	"blog", "news", "status", "health", "monitor", "monitoring", "metrics", "alerts", "grafana", "kibana", "elastic", "search", "analytics", "reports", "reporting", "events", "tracking", "telemetry", "logs",
	"mail", "smtp", "imap", "pop", "pop3", "webmail", "mx", "email", "exchange", "autodiscover", "owa", "calendar", "contacts", "newsletter", "relay", "mailgun", "send", "receive", "inbox",
	"vpn", "remote", "gateway", "gw", "router", "firewall", "proxy", "forward", "bastion", "jump", "ssh", "rdp", "citrix", "terminal", "access", "secure", "internal", "intranet", "extranet", "office",
	"ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "dhcp", "ntp", "time", "directory", "ldap", "ad", "dc", "domain", "host", "server", "server1", "server2", "node",
	"cdn", "static", "assets", "asset", "img", "images", "image", "media", "video", "videos", "audio", "files", "file", "download", "downloads", "upload", "uploads", "storage", "object", "bucket",
	"store", "shop", "commerce", "ecommerce", "checkout", "cart", "payment", "payments", "pay", "billing", "invoice", "invoices", "orders", "order", "catalog", "products", "product", "customer", "customers", "sales",
	"crm", "erp", "hr", "finance", "financial", "accounting", "inventory", "warehouse", "operations", "ops", "project", "projects", "jira", "confluence", "redmine", "service", "servicedesk", "ticket", "tickets",
	"git", "gitlab", "github", "bitbucket", "svn", "repo", "repository", "code", "ci", "cd", "build", "builder", "artifact", "artifacts", "deploy", "deployment", "release", "jenkins", "runner", "agent",
	"registry", "docker", "container", "containers", "k8s", "kubernetes", "cluster", "master", "worker", "control", "controlplane", "vault", "consul", "nomad", "terraform", "ansible", "salt", "puppet", "chef", "config",
	"db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb", "redis", "cache", "memcached", "queue", "rabbit", "rabbitmq", "kafka", "broker", "message", "stream", "warehouse", "data", "dwh",
	"graphql", "grpc", "rest", "service1", "service2", "microservice", "backend", "frontend", "origin", "edge", "api1", "api2", "v1", "v2", "legacy", "old", "new", "mobile", "m", "mobileapi",
}
