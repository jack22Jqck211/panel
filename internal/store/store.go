// Package store provides the panel's persistence layer: a single JSON file
// guarded by a RWMutex and written atomically.
//
// Why a JSON file and not a database: the panel's entire dataset is a settings
// object plus a list of users. Even a few thousand users is well under a
// megabyte, and the read path is dominated by subscription fetches that are
// served from memory. Adding a database would multiply the deployment surface
// for no measurable benefit.
//
// IMPORTANT deployment note: container filesystems on most PaaS platforms
// (Railway included) are ephemeral -- they are wiped on every redeploy. Point
// DATA_DIR at a mounted persistent volume in production, otherwise users are
// lost whenever the service is rebuilt.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Settings holds panel-wide configuration that applies to every generated config.
type Settings struct {
	// ServerAddress is the hostname (or IP) of the machine running nginx + Xray
	// + Tor-ML. This is what lands in the TLS SNI and the WebSocket Host header,
	// and it is the connect address whenever no clean IP is set.
	ServerAddress string `json:"serverAddress"`
	// ServerPort is the public port clients connect to. 443 when fronted by TLS.
	ServerPort int `json:"serverPort"`
	// TLS reports whether the public endpoint terminates TLS.
	TLS bool `json:"tls"`
	// PathPrefix is prepended to every location path, e.g. "/ws" -> "/ws/de".
	PathPrefix string `json:"pathPrefix"`
	// DefaultCleanIP, when set, is the fallback connect address for users that
	// do not define their own clean IP.
	DefaultCleanIP string `json:"defaultCleanIp"`
	// SubIntervalHours is advertised to clients as the subscription refresh period.
	SubIntervalHours int `json:"subIntervalHours"`
	// PanelBaseURL is the panel's own public origin, used to render copyable
	// subscription links. Auto-detected from the request when empty.
	PanelBaseURL string `json:"panelBaseUrl"`
	// Protocol is "vless" or "vmess". It drives both the client URIs and the
	// generated server inbounds, so the two can never disagree.
	Protocol string `json:"protocol"`
}

// DefaultSettings returns a usable baseline configuration.
func DefaultSettings() Settings {
	return Settings{
		ServerAddress:    "",
		ServerPort:       443,
		TLS:              true,
		PathPrefix:       "/ws",
		DefaultCleanIP:   "",
		SubIntervalHours: 12,
		PanelBaseURL:     "",
		Protocol:         "vless",
	}
}

// User is one panel account. A user holds a single UUID that is valid on all 50
// location inbounds; the 50 configs differ only by path and label.
type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	UUID      string    `json:"uuid"`
	SubToken  string    `json:"subToken"`
	CleanIP   string    `json:"cleanIp"`
	Enabled   bool      `json:"enabled"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"createdAt"`
	// ExpiresAt is the zero value when the account never expires.
	ExpiresAt time.Time `json:"expiresAt"`
	// QuotaBytes is 0 for unlimited. Advertised to clients in the
	// Subscription-Userinfo header; the panel does not meter traffic itself.
	QuotaBytes int64 `json:"quotaBytes"`
}

// Expired reports whether the user's expiry date has passed.
func (u *User) Expired() bool {
	return !u.ExpiresAt.IsZero() && time.Now().After(u.ExpiresAt)
}

// Active reports whether the user should be served and included in Xray configs.
func (u *User) Active() bool { return u.Enabled && !u.Expired() }

// Email is the identifier Xray uses for this user inside inbound client lists.
func (u *User) Email() string { return u.ID + "@panel" }

// data is the on-disk document.
type data struct {
	Settings Settings `json:"settings"`
	Users    []*User  `json:"users"`
}

// Store is a concurrency-safe handle to the panel's persisted state.
type Store struct {
	mu   sync.RWMutex
	path string
	d    data
}

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("not found")

// Open loads the store from dir, creating the directory and an empty document
// if they do not exist yet.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w", dir, err)
	}
	s := &Store{
		path: filepath.Join(dir, "panel.json"),
		d:    data{Settings: DefaultSettings(), Users: []*User{}},
	}
	raw, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// First boot: persist the defaults so the file always exists.
		if err := s.save(); err != nil {
			return nil, err
		}
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", s.path, err)
	}
	if err := json.Unmarshal(raw, &s.d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	if s.d.Users == nil {
		s.d.Users = []*User{}
	}
	// Backfill fields that may be absent in older files.
	if s.d.Settings.ServerPort == 0 {
		s.d.Settings.ServerPort = 443
	}
	if s.d.Settings.PathPrefix == "" {
		s.d.Settings.PathPrefix = "/ws"
	}
	if s.d.Settings.SubIntervalHours == 0 {
		s.d.Settings.SubIntervalHours = 12
	}
	if s.d.Settings.Protocol == "" {
		s.d.Settings.Protocol = "vless"
	}
	return s, nil
}

// Path reports where the store persists to. Useful for startup logging.
func (s *Store) Path() string { return s.path }

// save writes the document atomically: a temp file in the same directory
// followed by a rename, so a crash mid-write cannot truncate the real file.
// Callers must already hold the write lock.
func (s *Store) save() error {
	raw, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return fmt.Errorf("encode store: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".panel-*.json")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// Settings returns a copy of the current settings.
func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.d.Settings
}

// SetSettings replaces the settings and persists.
func (s *Store) SetSettings(next Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Settings = next
	return s.save()
}

// Users returns a copy of the user list.
func (s *Store) Users() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, len(s.d.Users))
	for i, u := range s.d.Users {
		cp := *u
		out[i] = &cp
	}
	return out
}

// ActiveUsers returns only users that are enabled and unexpired.
func (s *Store) ActiveUsers() []*User {
	all := s.Users()
	out := make([]*User, 0, len(all))
	for _, u := range all {
		if u.Active() {
			out = append(out, u)
		}
	}
	return out
}

// UserByID looks a user up by primary key.
func (s *Store) UserByID(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.d.Users {
		if u.ID == id {
			cp := *u
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// UserBySubToken resolves a subscription token to its owner.
func (s *Store) UserBySubToken(token string) (*User, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.d.Users {
		if u.SubToken == token {
			cp := *u
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// AddUser appends a user and persists.
func (s *Store) AddUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.d.Users {
		if existing.Name == u.Name {
			return fmt.Errorf("a user named %q already exists", u.Name)
		}
	}
	cp := *u
	s.d.Users = append(s.d.Users, &cp)
	return s.save()
}

// UpdateUser replaces a user by ID and persists.
func (s *Store) UpdateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.d.Users {
		if existing.ID == u.ID {
			cp := *u
			s.d.Users[i] = &cp
			return s.save()
		}
	}
	return ErrNotFound
}

// DeleteUser removes a user by ID and persists.
func (s *Store) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.d.Users {
		if existing.ID == id {
			s.d.Users = append(s.d.Users[:i], s.d.Users[i+1:]...)
			return s.save()
		}
	}
	return ErrNotFound
}

// Revision returns a cheap fingerprint of the current state. The VPS agent
// uses it to decide whether a reload is actually needed.
func (s *Store) Revision() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, err := json.Marshal(s.d)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", fnv64(raw))
}

// fnv64 is a small inline FNV-1a so we avoid pulling in hash/fnv for one call.
func fnv64(b []byte) uint64 {
	const (
		offset = 1469598103934665603
		prime  = 1099511628211
	)
	h := uint64(offset)
	for _, c := range b {
		h ^= uint64(c)
		h *= prime
	}
	return h
}
