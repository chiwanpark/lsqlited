package server

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level server configuration, usually loaded from a YAML
// file. Example:
//
//	listen:
//	  host: 127.0.0.1
//	  port: 7890
//	databases:
//	  app:
//	    path: /var/lib/lsqlited/app.sqlite3
//	  metrics:
//	    path: /var/lib/lsqlited/metrics.sqlite3
//	    read_only: true
type Config struct {
	Listen    ListenConfig              `yaml:"listen"`
	Databases map[string]DatabaseConfig `yaml:"databases"`
}

// ListenConfig configures the TCP listener.
type ListenConfig struct {
	// Host is the address to bind to. An empty host binds to all interfaces.
	Host string `yaml:"host"`
	// Port is the TCP port to listen on.
	Port int `yaml:"port"`
}

// DatabaseConfig configures a single served SQLite database.
type DatabaseConfig struct {
	// Path is the filesystem path of the SQLite database file.
	Path string `yaml:"path"`
	// ReadOnly opens the database in read-only mode when true.
	ReadOnly bool `yaml:"read_only"`
	// BusyTimeoutMS sets the SQLite busy timeout in milliseconds.
	// Defaults to 5000 when zero.
	BusyTimeoutMS int `yaml:"busy_timeout_ms"`
}

// LoadConfig reads and validates a YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("server: read config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("server: parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("server: invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

// Validate checks the configuration for obvious mistakes.
func (c *Config) Validate() error {
	if c.Listen.Port < 1 || c.Listen.Port > 65535 {
		return fmt.Errorf("listen.port must be between 1 and 65535, got %d", c.Listen.Port)
	}
	if len(c.Databases) == 0 {
		return fmt.Errorf("at least one database must be configured")
	}
	for name, db := range c.Databases {
		if name == "" {
			return fmt.Errorf("database name must not be empty")
		}
		if db.Path == "" {
			return fmt.Errorf("databases.%s.path must not be empty", name)
		}
		if db.BusyTimeoutMS < 0 {
			return fmt.Errorf("databases.%s.busy_timeout_ms must not be negative", name)
		}
	}
	return nil
}
