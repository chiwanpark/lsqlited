package server

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level server configuration, usually loaded from a YAML
// file. Example:
//
//	listen:
//	  host: 127.0.0.1
//	  port: 7890
//	params: _journal_mode=WAL
//	databases:
//	  app:
//	    path: /var/lib/lsqlited/app.sqlite3
//	  archive:
//	    path: /var/lib/lsqlited/archive.sqlite3
//	    params: mode=ro&immutable=true
type Config struct {
	Listen ListenConfig `yaml:"listen"`
	// Params are SQLite DSN query parameters applied to every database.
	// Per-database params take precedence over them.
	Params    Params                    `yaml:"params"`
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
	// Params are extra SQLite DSN query parameters appended to the
	// "file:" URI used to open the database, e.g. mode=ro or
	// immutable=true. They override the server-wide Config.Params. See the
	// go-sqlite3 documentation for the full list of supported parameters.
	Params Params `yaml:"params"`
}

// Params holds extra SQLite DSN query parameters. In YAML it may be written
// either as a mapping or as a URL-style query string:
//
//	params:
//	  mode: ro
//	  immutable: true
//
//	params: mode=ro&immutable=true
type Params map[string]string

// UnmarshalYAML accepts either a mapping or a query string.
func (p *Params) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var raw string
		if err := node.Decode(&raw); err != nil {
			return err
		}
		parsed, err := ParseParams(raw)
		if err != nil {
			return err
		}
		*p = parsed
		return nil
	case yaml.MappingNode:
		m := make(map[string]string)
		if err := node.Decode(&m); err != nil {
			return err
		}
		*p = Params(m)
		return nil
	default:
		return fmt.Errorf("params must be a mapping or a query string")
	}
}

// ParseParams parses a URL-style query string such as
// "mode=ro&immutable=true" into Params.
func ParseParams(raw string) (Params, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "?")
	if raw == "" {
		return nil, nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid params %q: %w", raw, err)
	}
	params := make(Params, len(values))
	for key, vals := range values {
		if len(vals) > 1 {
			return nil, fmt.Errorf("invalid params %q: key %q is repeated", raw, key)
		}
		params[key] = vals[0]
	}
	return params, nil
}

// keys returns the parameter names in sorted order.
func (p Params) keys() []string {
	keys := make([]string, 0, len(p))
	for key := range p {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// merge returns a new Params holding the entries of p with those of override
// applied on top.
func (p Params) merge(override Params) Params {
	if len(p) == 0 && len(override) == 0 {
		return nil
	}
	merged := make(Params, len(p)+len(override))
	for key, val := range p {
		merged[key] = val
	}
	for key, val := range override {
		merged[key] = val
	}
	return merged
}

// validate rejects empty parameter names.
func (p Params) validate() error {
	for _, key := range p.keys() {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("parameter name must not be empty")
		}
	}
	return nil
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
		if err := db.Params.validate(); err != nil {
			return fmt.Errorf("databases.%s.params: %w", name, err)
		}
	}
	return nil
}
