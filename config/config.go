package config

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"

	"github.com/Luzifer/rconfig"
	log "github.com/sirupsen/logrus"
)

// Config holds all application configuration
type Config struct {
	User      string `flag:"user,u" default:"" env:"USER" description:"Username for Grafana login"`
	Pass      string `flag:"pass,p" default:"" env:"PASS" description:"Password for Grafana login"`
	BaseURL   string `flag:"baseurl" default:"" env:"BASEURL" description:"BaseURL (excluding last /) of Grafana"`
	Listen    string `flag:"listen" default:"127.0.0.1:8081" description:"IP/Port to listen on"`
	Token     string `flag:"token" default:"" env:"TOKEN" description:"(optional) require a ?token=xyz parameter to show the dashboard"`
	LogFormat string `flag:"log-format" default:"text" env:"LOG_FORMAT" description:"Output format for logs (text/json)"`
}

// Load parses configuration from command-line flags and environment variables
func Load() (*Config, error) {
	cfg := &Config{}
	if err := rconfig.Parse(cfg); err != nil {
		return nil, fmt.Errorf("unable to parse commandline options: %w", err)
	}

	// Configure logging
	switch cfg.LogFormat {
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	default:
		return nil, fmt.Errorf("unknown log format: %s", cfg.LogFormat)
	}
	log.SetLevel(log.InfoLevel)

	// Validate required fields
	if cfg.User == "" || cfg.Pass == "" || cfg.BaseURL == "" {
		rconfig.Usage()
		os.Exit(1)
	}

	// Generate default token if not provided
	if cfg.Token == "" {
		w := md5.New()
		io.WriteString(w, cfg.Pass)
		cfg.Token = fmt.Sprintf("%x", w.Sum(nil))
	}

	log.Infof("grafana proxy config: %+v", cfg)
	return cfg, nil
}
