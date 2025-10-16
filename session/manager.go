package session

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"grafana-proxy/internal"
	log "github.com/sirupsen/logrus"
)

// Manager handles Grafana session management with thread-safe caching
type Manager struct {
	mu       sync.RWMutex
	session  string
	baseURL  string
	username string
	password string
}

// NewManager creates a new session manager
func NewManager(baseURL, username, password string) *Manager {
	return &Manager{
		baseURL:  baseURL,
		username: username,
		password: password,
	}
}

// GetSession returns the cached session, or empty string if not available
func (m *Manager) GetSession() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.session
}

// ClearSession invalidates the cached session
func (m *Manager) ClearSession() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = ""
}

// Login authenticates with Grafana and caches the session cookie.
// It uses a lock to prevent concurrent login attempts.
// If another goroutine has already logged in while waiting for the lock,
// it will use that session instead of logging in again.
func (m *Manager) Login(res http.ResponseWriter, r *http.Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if another request already logged in while we were waiting for the lock
	if m.session != "" {
		r.Header.Add("Cookie", m.session)
		return nil
	}

	// Clear session before attempting login
	m.session = ""

	// Prepare login request
	loginBody, _ := json.Marshal(map[string]string{
		"user":     m.username,
		"password": m.password,
	})
	body := strings.NewReader(string(loginBody))

	// Send login request
	resp, err := http.DefaultClient.Post(m.baseURL+"/login", "application/json", body)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"user": m.username,
		}).Error("Login failed")
		return err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		loginRes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(loginRes))
	}

	// Extract and cache session cookie
	internal.RemoveGrafanaSession(&r.Header)
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(c, internal.GrafanaSession) {
			// Modify cookie for third-party context (iframe embedding)
			modifiedCookie := internal.ModifyCookieForThirdParty(c)
			r.Header.Add("Cookie", c)
			res.Header().Add("Set-Cookie", modifiedCookie)
			m.session = c
			return nil
		}
	}

	return errors.New("not found grafana session after login")
}

// AddSessionToRequest adds the cached Grafana session to the request if available.
// If no session is cached, it triggers a login attempt.
func (m *Manager) AddSessionToRequest(res http.ResponseWriter, r *http.Request) {
	// Check if request already has a grafana session
	cookie := r.Header.Values("Cookie")
	for _, h := range cookie {
		if strings.Contains(h, internal.GrafanaSession) {
			return
		}
	}

	// Try to use cached session
	session := m.GetSession()
	if session != "" {
		r.Header.Add("Cookie", session)
	} else {
		// No cached session, attempt login
		err := m.Login(res, r)
		if err != nil {
			log.WithError(err).Error("Login failed")
		}
	}
}

// IsLoginRedirect checks if the response indicates authentication failure or redirect to login
func IsLoginRedirect(response *http.Response) bool {
	if response.StatusCode == 401 {
		return true
	}
	if response.StatusCode == 302 {
		location, _ := response.Location()
		if strings.Contains(location.String(), "login") {
			return true
		}
	}
	return false
}
