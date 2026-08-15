package metadata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
)

var ErrInvalidBounds = errors.New("metadata byte limit and timeout must be positive")

func ReadBanner(ctx context.Context, conn net.Conn, maxBytes int, timeout time.Duration) (string, error) {
	if conn == nil {
		return "", errors.New("metadata connection is nil")
	}
	if maxBytes <= 0 || timeout <= 0 {
		return "", ErrInvalidBounds
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return "", fmt.Errorf("set metadata deadline: %w", err)
	}

	buffer := make([]byte, maxBytes)
	n, err := conn.Read(buffer)
	if err != nil && n == 0 {
		return "", fmt.Errorf("read metadata: %w", err)
	}
	return sanitize(string(buffer[:n])), nil
}

func GuessService(port uint16) string {
	switch port {
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 25, 465, 587:
		return "smtp"
	case 53:
		return "dns"
	case 80, 81, 8000, 8008, 8080, 8081, 8888, 9000:
		return "http"
	case 110:
		return "pop3"
	case 143, 993:
		return "imap"
	case 443, 8443:
		return "https"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 3389:
		return "rdp"
	case 5900:
		return "vnc"
	default:
		return "unknown"
	}
}

func sanitize(value string) string {
	value = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return '�'
		default:
			return r
		}
	}, value)
	return strings.Join(strings.Fields(value), " ")
}
