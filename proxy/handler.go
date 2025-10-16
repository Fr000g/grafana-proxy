package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"grafana-proxy/config"
	"grafana-proxy/internal"
	"grafana-proxy/session"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// Handler manages the reverse proxy and authentication flow
type Handler struct {
	config         *config.Config
	sessionManager *session.Manager
	proxy          *httputil.ReverseProxy
	target         *url.URL
}

// NewHandler creates a new proxy handler with session management
func NewHandler(cfg *config.Config, target *url.URL) *Handler {
	h := &Handler{
		config:         cfg,
		sessionManager: session.NewManager(cfg.BaseURL, cfg.User, cfg.Pass),
		target:         target,
	}

	// Setup reverse proxy
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.RequestURI = ""
		req.Header.Set("Origin", cfg.BaseURL)
	}

	h.proxy = &httputil.ReverseProxy{
		Director:       director,
		ModifyResponse: h.modifyResponse,
		ErrorHandler:   h.errorHandler,
	}

	return h
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(res http.ResponseWriter, r *http.Request) {
	// Add request ID to context
	requestID := uuid.New().String()
	ctx := context.WithValue(r.Context(), internal.RequestIDKey{}, requestID)
	r = r.WithContext(ctx)

	// Setup request logging
	requestLog := log.WithFields(log.Fields{
		"http_user_agent": r.Header.Get("User-Agent"),
		"host":            r.Host,
		"remote_addr":     r.Header.Get("X-Forwarded-For"),
		"request":         r.URL.Path,
		"request_full":    r.URL.String(),
		"request_method":  r.Method,
		"request_id":      internal.GetRequestID(ctx),
		"referer":         r.Referer(),
	})

	// Extract and validate token
	suppliedToken := h.extractToken(r)
	tokenAuthorized := suppliedToken != "" && suppliedToken == h.config.Token

	// Store token authorization status in context
	ctx = context.WithValue(r.Context(), internal.TokenAuthKey{}, tokenAuthorized)
	r = r.WithContext(ctx)

	// Handle logout requests
	isLogout := strings.HasPrefix(r.URL.Path, "/logout")
	if isLogout {
		h.sessionManager.ClearSession()
		internal.ResetProxyAuthCookie(res)
		internal.RemoveGrafanaSession(&r.Header)
		// Mark in context so ModifyResponse doesn't re-login
		r = r.WithContext(context.WithValue(r.Context(), internal.LogoutKey{}, true))
	}

	// Reject invalid tokens early
	if suppliedToken != "" && !tokenAuthorized {
		requestLog.Errorf("Token authorized error, token=%s, cfgToken=%s", suppliedToken, h.config.Token)
		http.Error(res, "Token authorized error", http.StatusForbidden)
		return
	}

	// For authorized requests, set persistent auth cookie and ensure grafana session
	if tokenAuthorized {
		if r.URL.Query().Get("token") != "" {
			internal.SetProxyAuthCookie(res, r.URL.Query().Get("token"))
		}
		h.sessionManager.AddSessionToRequest(res, r)
	} else {
		requestLog.Debug("No valid token supplied, proxying without auto-login")
	}

	// Buffer request body for potential retry (e.g., after re-login)
	if r.Body != nil && r.Body != http.NoBody {
		// Only buffer once; skip if already buffered
		if _, ok := r.Context().Value(internal.BodyKey{}).([]byte); !ok {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			r = r.WithContext(context.WithValue(r.Context(), internal.BodyKey{}, bodyBytes))
		}
	}

	h.proxy.ServeHTTP(res, r)
}

// modifyResponse handles the response from Grafana
func (h *Handler) modifyResponse(resp *http.Response) error {
	// Always allow credentials for browser requests
	resp.Header.Add("Access-Control-Allow-Credentials", "true")

	// Only handle authentication redirects when request was token authorized
	tokenAuthorized, _ := resp.Request.Context().Value(internal.TokenAuthKey{}).(bool)
	isLogout, _ := resp.Request.Context().Value(internal.LogoutKey{}).(bool)
	if !tokenAuthorized {
		return nil
	}

	if session.IsLoginRedirect(resp) {
		// Invalidate cached session on any login redirect
		h.sessionManager.ClearSession()

		// Don't auto re-login on explicit logout
		if isLogout {
			return nil
		}

		// Don't retry if we already retried
		if resp.Request.Context().Value(internal.RetryKey{}) != nil {
			log.Warn("Login retry failed, forwarding original response.")
			return nil
		}

		// Return custom error to trigger ErrorHandler for retry
		return errors.New("grafana-login-required")
	}

	return nil
}

// errorHandler handles errors from the reverse proxy
func (h *Handler) errorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	requestLog := log.WithFields(log.Fields{
		"request_id": internal.GetRequestID(req.Context()),
	})

	if err.Error() == "grafana-login-required" {
		requestLog.Info("Session expired or invalid, attempting to log in again.")

		if loginErr := h.sessionManager.Login(rw, req); loginErr != nil {
			requestLog.WithError(loginErr).Error("Failed to re-login to Grafana")
			http.Error(rw, "Failed to re-login to Grafana", http.StatusInternalServerError)
			return
		}

		requestLog.Info("Re-issuing original request with new session.")
		// If we buffered the request body, restore it for retry
		if bodyBytes, ok := req.Context().Value(internal.BodyKey{}).([]byte); ok {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		// Add marker to context to prevent infinite retry loop
		ctx := context.WithValue(req.Context(), internal.RetryKey{}, struct{}{})
		h.proxy.ServeHTTP(rw, req.WithContext(ctx))
		return
	}

	// Don't log context canceled errors
	if errors.Is(err, context.Canceled) {
		return
	}

	log.WithError(err).Error("Proxy error")
	rw.WriteHeader(http.StatusBadGateway)
}

// extractToken extracts the authentication token from various sources
func (h *Handler) extractToken(r *http.Request) string {
	// Try cookie first
	if authCookie, err := r.Cookie("grafana-proxy-auth"); err == nil {
		return authCookie.Value
	}

	// Try referer query parameter
	referer, _ := url.Parse(r.Referer())
	if token := referer.Query().Get("token"); token != "" {
		return token
	}

	// Try request query parameter
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}

	return ""
}
