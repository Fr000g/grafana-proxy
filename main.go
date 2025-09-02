package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/Luzifer/rconfig"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	RequestIDKey   = "request_id"
	GrafanaSession = "grafana_session"
)

// SessionCache holds the grafana session in a concurrent-safe way
type SessionCache struct {
	sync.RWMutex
	session string
}

var (
	cfg = struct {
		User      string `flag:"user,u" default:"" env:"USER" description:"Username for Grafana login"`
		Pass      string `flag:"pass,p" default:"" env:"PASS" description:"Password for Grafana login"`
		BaseURL   string `flag:"baseurl" default:"" env:"BASEURL" description:"BaseURL (excluding last /) of Grafana"`
		Listen    string `flag:"listen" default:"127.0.0.1:8081" description:"IP/Port to listen on"`
		Token     string `flag:"token" default:"" env:"TOKEN" description:"(optional) require a ?token=xyz parameter to show the dashboard"`
		LogFormat string `flag:"log-format" default:"text" env:"LOG_FORMAT" description:"Output format for logs (text/json)"`
	}{}
	base         *url.URL
	sessionCache = &SessionCache{}
)

func init() {
	if err := rconfig.Parse(&cfg); err != nil {
		log.Fatalf("Unable to parse commandline options: %s", err)
	}

	switch cfg.LogFormat {
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	default:
		log.Fatalf("Unknown log format: %s", cfg.LogFormat)
	}

	log.SetLevel(log.InfoLevel)

	if cfg.User == "" || cfg.Pass == "" || cfg.BaseURL == "" {
		rconfig.Usage()
		os.Exit(1)
	}
	if cfg.Token == "" {
		w := md5.New()
		io.WriteString(w, cfg.Pass)
		cfg.Token = fmt.Sprintf("%x", w.Sum(nil))
	}
	log.Infof("grafana proxy config: %+v", cfg)
}

// removeGrafanaSession removes the grafana session from the current request
func removeGrafanaSession(header *http.Header) {
	cookie := header.Values("Cookie")
	header.Del("Cookie")
	for _, h := range cookie {
		if !strings.Contains(h, GrafanaSession) {
			header.Add("Cookie", h)
		}
	}
}

// addGrafanaSession ensures that the request has a valid Grafana session cookie.
// It first checks for a session in the cache. If found, it adds the session
// to the request's cookies. If not found, it triggers a new login by calling loadLogin.
func addGrafanaSession(res http.ResponseWriter, r *http.Request) {
	cookie := r.Header.Values("Cookie")
	for _, h := range cookie {
		if strings.Contains(h, GrafanaSession) {
			return
		}
	}

	sessionCache.RLock()
	session := sessionCache.session
	sessionCache.RUnlock()

	if session != "" {
		r.Header.Add("Cookie", session)
	} else {
		err := loadLogin(res, r)
		if err != nil {
			log.WithError(err).Error("Login failed")
		}
	}
}

// loadLogin handles the authentication with the Grafana server.
// It sends a login request with the configured credentials, and upon success,
// it extracts the 'grafana_session' cookie from the response.
// This session is then stored in the cache for subsequent requests.
// The function uses a lock to prevent concurrent login attempts.
func loadLogin(res http.ResponseWriter, r *http.Request) error {
	sessionCache.Lock()
	defer sessionCache.Unlock()

	// After acquiring the lock, check if another request has already logged in.
	if sessionCache.session != "" {
		r.Header.Add("Cookie", sessionCache.session)
		return nil
	}

	sessionCache.session = ""
	loginBody, _ := json.Marshal(map[string]string{
		"user":     cfg.User,
		"password": cfg.Pass,
	})
	body := strings.NewReader(string(loginBody))
	resp, err := http.DefaultClient.Post(cfg.BaseURL+"/login", "application/json", body)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"user": cfg.User,
		}).Error("Login failed")
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		loginRes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(loginRes))
	}
	removeGrafanaSession(&r.Header)
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(c, GrafanaSession) {
			r.Header.Add("Cookie", c)
			res.Header().Add("Set-Cookie", c)
			sessionCache.session = c
			return nil
		}
	}
	return errors.New("not found grafana session after login")
}

// redirectLogin checks if the request response is authentication failed or redirected to the login page
func redirectLogin(response *http.Response) bool {
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

// newProxy creates the main http.Handler for the proxy.
// It sets up an httputil.ReverseProxy and uses its ModifyResponse and
// ErrorHandler hooks to implement a session-retry mechanism.
//
// The logic is as follows:
//  1. An incoming request is authenticated and the cached Grafana session is attached.
//  2. The request is proxied to Grafana.
//  3. If Grafana's response indicates an expired session (e.g., 401 or redirect),
//     ModifyResponse returns a special error.
//  4. ErrorHandler catches this error, triggers a re-login via loadLogin, and
//     retries the request once with the new session.
//
// This approach avoids response buffering (i.e. httptest.ResponseRecorder),
// ensuring that features like WebSockets that require connection hijacking work correctly.
func newProxy(target *url.URL) http.Handler {
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.RequestURI = ""
		req.Header.Set("Origin", cfg.BaseURL)
	}

	// We need to declare the proxy beforehand so we can use it in the error handler.
	proxy := &httputil.ReverseProxy{
		Director: director,
	}

	type retryKeyType struct{}
	var retryKey retryKeyType

	modifyResponse := func(resp *http.Response) error {
		if redirectLogin(resp) {
			// If we have already retried, don't do it again.
			if resp.Request.Context().Value(retryKey) != nil {
				log.Warn("Login retry failed, forwarding original response.")
				return nil
			}
			// Return a custom error to trigger the ErrorHandler for a retry.
			return errors.New("grafana-login-required")
		}
		resp.Header.Add("Access-Control-Allow-Credentials", "true")
		return nil
	}

	errorHandler := func(rw http.ResponseWriter, req *http.Request, err error) {
		requestLog := log.WithFields(log.Fields{
			"request_id": requestIDFromContext(req.Context()),
		})

		if err.Error() == "grafana-login-required" {
			requestLog.Info("Session expired or invalid, attempting to log in again.")

			if loginErr := loadLogin(rw, req); loginErr != nil {
				requestLog.WithError(loginErr).Error("Failed to re-login to Grafana")
				http.Error(rw, "Failed to re-login to Grafana", http.StatusInternalServerError)
				return
			}

			requestLog.Info("Re-issuing original request with new session.")
			// Add a marker to the context to prevent infinite retry loops.
			ctx := context.WithValue(req.Context(), retryKey, struct{}{})
			proxy.ServeHTTP(rw, req.WithContext(ctx))
			return
		}

		log.WithError(err).Error("Proxy error")
		rw.WriteHeader(http.StatusBadGateway)
	}

	proxy.ModifyResponse = modifyResponse
	proxy.ErrorHandler = errorHandler

	return http.HandlerFunc(func(res http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
		r = r.WithContext(ctx)

		requestLog := log.WithFields(log.Fields{
			"http_user_agent": r.Header.Get("User-Agent"),
			"host":            r.Host,
			"remote_addr":     r.Header.Get("X-Forwarded-For"),
			"request":         r.URL.Path,
			"request_full":    r.URL.String(),
			"request_method":  r.Method,
			"request_id":      requestIDFromContext(ctx),
			"referer":         r.Referer(),
		})

		referer, _ := url.Parse(r.Referer())
		suppliedToken := ""
		if authCookie, err := r.Cookie("grafana-proxy-auth"); err == nil {
			suppliedToken = authCookie.Value
		}
		if suppliedToken == "" && referer.Query().Get("token") != "" {
			suppliedToken = referer.Query().Get("token")
		}
		if token := r.URL.Query().Get("token"); token != "" {
			suppliedToken = token
		}

		if suppliedToken == "" {
			requestLog.Debug("No token supplied, proxying without login")
			proxy.ServeHTTP(res, r)
			return
		}

		if suppliedToken != cfg.Token {
			requestLog.Errorf("Token authorized error, token=%s, cfgToken=%s", suppliedToken, cfg.Token)
			http.Error(res, "Token authorized error", http.StatusForbidden)
			return
		}

		if r.URL.Query().Get("token") != "" {
			http.SetCookie(res, &http.Cookie{
				Name:     "grafana-proxy-auth",
				Value:    r.URL.Query().Get("token"),
				MaxAge:   31536000, // 1 Year
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
			})
		}

		addGrafanaSession(res, r)

		proxy.ServeHTTP(res, r)
	})
}

func requestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}

func main() {
	var err error
	base, err = url.Parse(cfg.BaseURL)
	if err != nil {
		log.WithError(err).WithField("base_url", base).Fatalf("BaseURL is not parsable")
	}

	proxyHandler := newProxy(base)
	log.Infof("Starting Grafana proxy on %s", cfg.Listen)
	log.Fatal(http.ListenAndServe(cfg.Listen, proxyHandler))
}
