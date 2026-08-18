package authsecurity

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
)

const (
	MaxCredentialFileBytes = 32 << 10
	maxCredentialLines     = 256
	maxCredentialValueLen  = 256
)

type CredentialInput struct {
	UsersPath       string
	PasswordsPath   string
	CredentialsPath string
}

type CredentialPair struct {
	ID       string
	username string
	password string
}

func (pair CredentialPair) FormBody(usernameField, passwordField string) ([]byte, error) {
	if !validCredentialValue(pair.username) || !validCredentialValue(pair.password) || strings.TrimSpace(usernameField) == "" || strings.TrimSpace(passwordField) == "" || len(usernameField) > 64 || len(passwordField) > 64 || strings.ContainsAny(usernameField+passwordField, "&=\r\n") {
		return nil, errors.New("invalid authentication form fields")
	}
	form := url.Values{}
	form.Set(usernameField, pair.username)
	form.Set(passwordField, pair.password)
	return []byte(form.Encode()), nil
}

func LoadCredentialInput(input CredentialInput, maxPairs int) ([]CredentialPair, error) {
	if maxPairs < 1 || maxPairs > maxCredentialLines || (input.CredentialsPath == "" && (input.UsersPath == "" || input.PasswordsPath == "")) || (input.CredentialsPath != "" && (input.UsersPath != "" || input.PasswordsPath != "")) {
		return nil, errors.New("invalid bounded credential input")
	}
	pairs := make([]CredentialPair, 0, maxPairs)
	seen := map[string]struct{}{}
	add := func(username, password string) error {
		if !validCredentialValue(username) || !validCredentialValue(password) {
			return errors.New("invalid local credential input")
		}
		sum := sha256.Sum256([]byte(username + "\x00" + password))
		id := hex.EncodeToString(sum[:])
		if _, exists := seen[id]; exists {
			return nil
		}
		if len(pairs) >= maxPairs {
			return errors.New("credential input exceeds attempt budget")
		}
		seen[id] = struct{}{}
		pairs = append(pairs, CredentialPair{ID: id, username: username, password: password})
		return nil
	}
	if input.CredentialsPath != "" {
		lines, err := readCredentialLines(input.CredentialsPath)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			username, password, ok := strings.Cut(line, ":")
			if !ok {
				return nil, errors.New("invalid credential pair input")
			}
			if err := add(username, password); err != nil {
				return nil, err
			}
		}
		return pairs, nil
	}
	users, err := readCredentialLines(input.UsersPath)
	if err != nil {
		return nil, err
	}
	passwords, err := readCredentialLines(input.PasswordsPath)
	if err != nil {
		return nil, err
	}
	for _, username := range users {
		for _, password := range passwords {
			if err := add(username, password); err != nil {
				return nil, err
			}
		}
	}
	return pairs, nil
}

func readCredentialLines(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxCredentialFileBytes {
		return nil, errors.New("invalid or oversized local credential source")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("invalid local credential source")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), maxCredentialValueLen+1)
	lines := []string{}
	for scanner.Scan() {
		if len(lines) >= maxCredentialLines {
			return nil, errors.New("credential source has too many lines")
		}
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil || len(lines) == 0 {
		return nil, errors.New("invalid local credential source")
	}
	return lines, nil
}

func validCredentialValue(value string) bool {
	return value != "" && len(value) <= maxCredentialValueLen && !strings.ContainsAny(value, "\r\n")
}
