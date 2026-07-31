// Package users creates and validates panel accounts.
//
// Identifier strategy: every user gets exactly one UUID, which is registered on
// all 50 location inbounds. That is what keeps the server config small -- adding
// an account adds one client entry per inbound, not fifty new identities.
package users

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jack22Jqck211/panel/internal/store"
)

// NewUUID returns a RFC 4122 version 4 UUID sourced from crypto/rand.
func NewUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// NewToken returns a URL-safe random token. Subscription links are served
// without a login by design, so the token is the only thing protecting them --
// 32 bytes of entropy makes guessing infeasible.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// NewID returns a short random identifier for a user record.
func NewID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Options describes a user to create.
type Options struct {
	Name       string
	CleanIP    string
	Note       string
	QuotaBytes int64
	// ExpiresInDays is 0 for an account that never expires.
	ExpiresInDays int
}

// New builds a user from options, generating all identifiers.
func New(opt Options) (*store.User, error) {
	name := strings.TrimSpace(opt.Name)
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	clean := strings.TrimSpace(opt.CleanIP)
	if clean != "" {
		if err := ValidateCleanIP(clean); err != nil {
			return nil, err
		}
	}
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	uuid, err := NewUUID()
	if err != nil {
		return nil, err
	}
	token, err := NewToken()
	if err != nil {
		return nil, err
	}
	u := &store.User{
		ID:         id,
		Name:       name,
		UUID:       uuid,
		SubToken:   token,
		CleanIP:    clean,
		Enabled:    true,
		Note:       strings.TrimSpace(opt.Note),
		CreatedAt:  time.Now().UTC(),
		QuotaBytes: opt.QuotaBytes,
	}
	if opt.ExpiresInDays > 0 {
		u.ExpiresAt = time.Now().UTC().AddDate(0, 0, opt.ExpiresInDays)
	}
	return u, nil
}

// ValidateName rejects names that would be awkward in config remarks or emails.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > 48 {
		return fmt.Errorf("name must be 48 characters or fewer")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("name may only contain letters, digits, dot, dash and underscore")
		}
	}
	return nil
}

// ValidateCleanIP accepts either a literal IP address or a hostname.
//
// A "clean IP" is a CDN edge address that is reachable from the client's network
// when the origin hostname is not. The client dials this address but still
// presents the real hostname in SNI and the Host header, so the CDN can route
// the connection. That only works when the origin domain is actually proxied
// through a CDN -- pointing a clean IP at a domain served directly by the VPS
// sends the connection to an unrelated machine.
func ValidateCleanIP(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if strings.ContainsAny(v, " \t\r\n/?#@") {
		return fmt.Errorf("clean IP must be a bare address or hostname, without scheme or path")
	}
	if net.ParseIP(v) != nil {
		return nil
	}
	if isHostname(v) {
		return nil
	}
	return fmt.Errorf("%q is not a valid IP address or hostname", v)
}

// isHostname performs a conservative DNS name check.
func isHostname(v string) bool {
	if len(v) == 0 || len(v) > 253 {
		return false
	}
	if strings.HasPrefix(v, ".") || strings.HasSuffix(v, ".") {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z',
				r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9',
				r == '-':
			default:
				return false
			}
		}
	}
	// A bare single label like "localhost" is allowed; anything else needs a dot.
	return true
}
