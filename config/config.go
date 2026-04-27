package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	APIKey string `json:"api_key"`
	APIURL string `json:"api_url"`
}

func DefaultConfig() *Config {
	return &Config{
		APIURL: "https://app.alertkick.com",
	}
}

func Load(configFile string) (*Config, error) {
	cfg := DefaultConfig()

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err == nil {
			if err := json.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	if v := os.Getenv("ALERTKICK_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("ALERTKICK_API_URL"); v != "" {
		cfg.APIURL = v
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("ALERTKICK_API_KEY is required (set env var or use -config file)")
	}

	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")

	return cfg, nil
}
