package server

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level server configuration, usually loaded from a YAML
// file. See config.example.yaml for the full set of keys.
type Config struct {
	Listen ListenConfig `yaml:"listen"`
	// Limits bound the work a single statement may do.
	Limits `yaml:",inline"`
	// MaxConnections bounds the SQLite connections one database may have open
	// at a time, which is how many statements it can run in parallel. Zero
	// leaves it unbounded.
	MaxConnections int `yaml:"max_connections"`
	// Params are SQLite DSN query parameters appended to the "file:" URI of
	// every database, e.g. mode=ro. See the go-sqlite3 documentation for the
	// supported set.
	Params Params `yaml:"params"`
	// Extensions are loadable SQLite extensions registered on every
	// connection to every database.
	Extensions Extensions `yaml:"extensions"`
	// TLS configures transport security. Omitted, the protocol travels in
	// cleartext.
	TLS  TLSConfig  `yaml:"tls"`
	Auth AuthConfig `yaml:"auth"`
	// Databases maps the logical name a client connects to onto the path of
	// the SQLite file serving it. Every database is opened the same way, from
	// the settings above.
	Databases map[string]string `yaml:"databases"`
}

// ListenConfig configures the TCP listener. An empty host binds to all
// interfaces.
type ListenConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
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
	if err := c.Params.validate(); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	if err := c.Limits.validate(); err != nil {
		return err
	}
	if c.MaxConnections < 0 {
		return fmt.Errorf("max_connections must not be negative, got %d", c.MaxConnections)
	}
	if err := c.Extensions.validate(); err != nil {
		return fmt.Errorf("extensions%w", err)
	}
	if err := c.TLS.validate(); err != nil {
		return err
	}
	if len(c.Databases) == 0 {
		return fmt.Errorf("at least one database must be configured")
	}
	for name, path := range c.Databases {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("database name must not be empty")
		}
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("databases.%s must name a path", name)
		}
	}
	// Validated last so that grants are checked against known-good databases.
	return c.Auth.validate(c.Databases)
}
