package main

import (
	"net/http"
	"net/url"

	"grafana-proxy/config"
	"grafana-proxy/proxy"
	log "github.com/sirupsen/logrus"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %s", err)
	}

	// Parse base URL
	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		log.WithError(err).WithField("base_url", cfg.BaseURL).Fatalf("BaseURL is not parsable")
	}

	// Create proxy handler
	proxyHandler := proxy.NewHandler(cfg, baseURL)

	// Start server
	log.Infof("Starting Grafana proxy on %s", cfg.Listen)
	log.Fatal(http.ListenAndServe(cfg.Listen, proxyHandler))
}
