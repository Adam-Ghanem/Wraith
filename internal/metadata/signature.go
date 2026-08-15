package metadata

import "strings"

func GuessServiceFromBanner(port uint16, banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ssh-"):
		return "ssh"
	case strings.Contains(lower, "http/") || strings.Contains(lower, "server:"):
		return "http"
	case strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.Contains(lower, "smtp") || strings.Contains(lower, "mail service ready"):
		return "smtp"
	case strings.Contains(lower, "mysql"):
		return "mysql"
	case strings.Contains(lower, "redis"):
		return "redis"
	default:
		return GuessService(port)
	}
}
