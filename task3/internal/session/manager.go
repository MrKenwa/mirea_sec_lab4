// Package session управляет сессиями и одноразовыми токенами без зависимости от HTTP.
package session

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"
)

const TTL = 15 * time.Minute
const TokenTTL = 5 * time.Minute
const maxSessions = 1024

type Snapshot struct {
	ID       string
	Username string
	Token    string
}

type record struct {
	Snapshot
	Expires      time.Time
	TokenExpires time.Time
}

type Manager struct {
	mu       sync.Mutex
	sessions map[string]*record
	now      func() time.Time
}

func NewManager(now func() time.Time) *Manager {
	return &Manager{sessions: make(map[string]*record), now: now}
}

func randomToken() string {
	value := make([]byte, 32)
	_, _ = rand.Read(value)

	return hex.EncodeToString(value)
}

func (m *Manager) prune() {
	now := m.now()

	for id, current := range m.sessions {
		if !now.Before(current.Expires) {
			delete(m.sessions, id)
		}
	}
}

func (m *Manager) issueToken(current *record) {
	current.Token = randomToken()
	current.TokenExpires = m.now().Add(TokenTTL)
}

func (m *Manager) create(username string) *record {
	if len(m.sessions) >= maxSessions {
		var oldest string
		var expires time.Time

		for id, current := range m.sessions {
			if oldest == "" || current.Expires.Before(expires) {
				oldest, expires = id, current.Expires
			}
		}

		delete(m.sessions, oldest)
	}

	current := &record{
		Snapshot: Snapshot{ID: randomToken(), Username: username},
		Expires:  m.now().Add(TTL),
	}

	m.issueToken(current)
	m.sessions[current.ID] = current

	return current
}

func (m *Manager) Form(id string) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.prune()
	current := m.sessions[id]

	if current == nil {
		current = m.create("")
	} else {
		m.issueToken(current)
	}

	return current.Snapshot
}

func (m *Manager) consume(id, token string) bool {
	current := m.sessions[id]

	if current == nil || current.Token == "" || !m.now().Before(current.TokenExpires) ||
		subtle.ConstantTimeCompare([]byte(current.Token), []byte(token)) != 1 {
		return false
	}

	current.Token = ""
	current.TokenExpires = time.Time{}

	return true
}

func (m *Manager) Consume(id, token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.prune()

	return m.consume(id, token)
}

func (m *Manager) Rotate(id, username string) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.prune()
	delete(m.sessions, id)

	return m.create(username).Snapshot
}

func (m *Manager) Protected(id string) (Snapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.prune()
	current := m.sessions[id]

	if current == nil || current.Username == "" {
		return Snapshot{}, false
	}

	m.issueToken(current)

	return current.Snapshot, true
}

func (m *Manager) Logout(id, token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.prune()

	if !m.consume(id, token) {
		return false
	}

	delete(m.sessions, id)

	return true
}
