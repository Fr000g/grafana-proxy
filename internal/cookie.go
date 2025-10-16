package internal

import (
	"net/http"
	"strings"
)

// RemoveGrafanaSession removes the grafana session cookie from the request header
func RemoveGrafanaSession(header *http.Header) {
	cookie := header.Values("Cookie")
	header.Del("Cookie")
	for _, h := range cookie {
		if !strings.Contains(h, GrafanaSession) {
			header.Add("Cookie", h)
		}
	}
}

// ModifyCookieForThirdParty modifies Set-Cookie header to support third-party contexts (iframe embedding)
// Adds SameSite=None and Secure attributes
func ModifyCookieForThirdParty(cookieHeader string) string {
	// Remove existing SameSite attribute if present
	parts := strings.Split(cookieHeader, ";")
	var filtered []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		// Skip existing SameSite attributes
		if !strings.HasPrefix(strings.ToLower(trimmed), "samesite=") {
			filtered = append(filtered, part)
		}
	}

	// Ensure Secure attribute is present
	hasSecure := false
	for _, part := range filtered {
		if strings.ToLower(strings.TrimSpace(part)) == "secure" {
			hasSecure = true
			break
		}
	}

	// Reassemble cookie with necessary attributes
	result := strings.Join(filtered, ";")
	if !hasSecure {
		result += "; Secure"
	}
	result += "; SameSite=None"

	return result
}

// ResetProxyAuthCookie clears the grafana-proxy-auth cookie on the client
func ResetProxyAuthCookie(res http.ResponseWriter) {
	http.SetCookie(res, &http.Cookie{
		Name:     "grafana-proxy-auth",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	})
}

// SetProxyAuthCookie sets a persistent authentication cookie
func SetProxyAuthCookie(res http.ResponseWriter, token string) {
	http.SetCookie(res, &http.Cookie{
		Name:     "grafana-proxy-auth",
		Value:    token,
		MaxAge:   31536000, // 1 Year
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	})
}
