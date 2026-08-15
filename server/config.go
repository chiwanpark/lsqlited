package server

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chiwanpark/lsqlited/internal/auth"
)

// Config is the top-level server configuration, usually loaded from a YAML
// file. Example:
//
//	listen:
//	  host: 127.0.0.1
//	  port: 7890
//	params: _journal_mode=WAL
//	auth:
//	  users:
//	    alice:
//	      verifier: "SCRAM-SHA-256$4096:..."
//	      databases: [app]
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
	Params Params `yaml:"params"`
	// Auth configures client authentication. When no users are listed the
	// server accepts every connection without authenticating it.
	Auth      AuthConfig                `yaml:"auth"`
	Databases map[string]DatabaseConfig `yaml:"databases"`
}

// AuthConfig configures challenge-response authentication.
type AuthConfig struct {
	// Iterations is the PBKDF2 iteration count used when deriving a
	// verifier from a plaintext password, and the one advertised for
	// unknown users. Zero selects auth.DefaultIterations. Raising it makes
	// offline guessing more expensive but slows down every new client
	// connection, since clients derive the salted password on connect.
	Iterations int `yaml:"iterations"`
	// Users maps account names to their credentials.
	Users map[string]UserConfig `yaml:"users"`
}

// UserConfig holds the credentials of a single account and the databases it
// may access. Exactly one of Verifier and Password must be set.
type UserConfig struct {
	// Verifier is a precomputed credential in the form
	// "SCRAM-SHA-256$<iterations>:<salt>$<storedKey>:<serverKey>", as
	// produced by "lsqlited -hash-password". This is the recommended form:
	// the configuration file never contains the password itself.
	Verifier string `yaml:"verifier"`
	// Password is a plaintext password, converted to a verifier when the
	// configuration is loaded. Convenient, but it leaves the password
	// readable in the configuration file.
	Password string `yaml:"password"`
	// Databases lists the logical database names the account may use. Every
	// name must match an entry under Config.Databases.
	//
	// Omitting the key grants access to every configured database. An
	// explicit empty list (databases: []) grants access to none, which
	// suspends the account without deleting its credentials.
	Databases []string `yaml:"databases"`
}

// Account is the runtime form of a UserConfig: a credential together with
// the set of databases it may reach.
type Account struct {
	// Verifier holds the material used to check the client proof.
	Verifier *auth.Verifier
	// databases is the set of database names the account may access, or nil
	// when it may access all of them.
	databases map[string]struct{}
}

// CanAccess reports whether the account may use the named database.
func (a *Account) CanAccess(database string) bool {
	if a.databases == nil {
		return true
	}
	_, ok := a.databases[database]
	return ok
}

// account derives the runtime account for the user.
func (u UserConfig) account(iterations int) (*Account, error) {
	verifier, err := u.verifier(iterations)
	if err != nil {
		return nil, err
	}
	return &Account{Verifier: verifier, databases: u.databaseSet()}, nil
}

// databaseSet returns the granted database names, or nil for unrestricted
// access. Note that an omitted list decodes to a nil slice while an explicit
// empty list does not, which is what distinguishes "all" from "none".
func (u UserConfig) databaseSet() map[string]struct{} {
	if u.Databases == nil {
		return nil
	}
	set := make(map[string]struct{}, len(u.Databases))
	for _, name := range u.Databases {
		set[name] = struct{}{}
	}
	return set
}

// validate checks the credential without running the key derivation.
func (u UserConfig) validate() error {
	switch {
	case u.Verifier != "" && u.Password != "":
		return fmt.Errorf("set either verifier or password, not both")
	case u.Verifier != "":
		_, err := auth.ParseVerifier(u.Verifier)
		return err
	case u.Password != "":
		return nil
	default:
		return fmt.Errorf("either verifier or password must be set")
	}
}

// verifier derives the runtime credential for the account.
func (u UserConfig) verifier(iterations int) (*auth.Verifier, error) {
	if err := u.validate(); err != nil {
		return nil, err
	}
	if u.Verifier != "" {
		return auth.ParseVerifier(u.Verifier)
	}
	return auth.NewVerifier(u.Password, iterations)
}

// Accounts derives the runtime account of every configured user. It returns
// nil when authentication is disabled.
func (a AuthConfig) Accounts() (map[string]*Account, error) {
	if len(a.Users) == 0 {
		return nil, nil
	}
	accounts := make(map[string]*Account, len(a.Users))
	for name, user := range a.Users {
		account, err := user.account(a.iterations())
		if err != nil {
			return nil, fmt.Errorf("auth.users.%s: %w", name, err)
		}
		accounts[name] = account
	}
	return accounts, nil
}

// iterations returns the configured PBKDF2 iteration count, or the default.
func (a AuthConfig) iterations() int {
	if a.Iterations <= 0 {
		return auth.DefaultIterations
	}
	return a.Iterations
}

// validate checks the authentication section. Grants are cross-checked
// against databases so that a typo in a database name is caught at load
// time rather than surfacing as a denied query later.
func (a AuthConfig) validate(databases map[string]DatabaseConfig) error {
	if a.Iterations != 0 && (a.Iterations < auth.MinIterations || a.Iterations > auth.MaxIterations) {
		return fmt.Errorf("auth.iterations must be between %d and %d, got %d",
			auth.MinIterations, auth.MaxIterations, a.Iterations)
	}
	for _, name := range sortedKeys(a.Users) {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("auth.users: user name must not be empty")
		}
		user := a.Users[name]
		if err := user.validate(); err != nil {
			return fmt.Errorf("auth.users.%s: %w", name, err)
		}
		seen := make(map[string]struct{}, len(user.Databases))
		for _, database := range user.Databases {
			if _, ok := databases[database]; !ok {
				return fmt.Errorf("auth.users.%s.databases: unknown database %q", name, database)
			}
			if _, dup := seen[database]; dup {
				return fmt.Errorf("auth.users.%s.databases: database %q is listed twice", name, database)
			}
			seen[database] = struct{}{}
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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
	// Validated last so that grants are checked against known-good databases.
	if err := c.Auth.validate(c.Databases); err != nil {
		return err
	}
	return nil
}
