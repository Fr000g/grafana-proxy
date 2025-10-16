package internal

import "context"

// Context keys for request-scoped data
type (
	RequestIDKey     struct{}
	RetryKey         struct{}
	TokenAuthKey     struct{}
	LogoutKey        struct{}
	BodyKey          struct{}
)

const (
	// GrafanaSession is the name of the Grafana session cookie
	GrafanaSession = "grafana_session"
)

// GetRequestID extracts the request ID from context
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey{}).(string); ok {
		return id
	}
	return ""
}
