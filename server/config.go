package server

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/chiwanpark/lsqlited/internal/auth"
	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// DefaultMaxResponseBytes bounds an encoded response body when the
// configuration is silent. It matches the frame limit of the wire protocol,
// which no response can exceed anyway.
const DefaultMaxResponseBytes = protocol.MaxMessageSize

// Config is the top-level server configuration, usually loaded from a YAML
// file. Example:
//
//	listen:
//	  host: 127.0.0.1
//	  port: 7890
//	params: _journal_mode=WAL
//	query_timeout: 60
//	max_rows: 5000
//	extensions: [/usr/lib/sqlite3/vector0.so]
//	tls:
//	  cert: /etc/lsqlited/server.crt
//	  key: /etc/lsqlited/server.key
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
//	    max_rows: 1000
type Config struct {
	Listen ListenConfig `yaml:"listen"`
	// Limits bound the work a single statement may do. They apply to every
	// database, unless the database sets its own.
	Limits `yaml:",inline"`
	// MaxConnections bounds the SQLite connections one database may have
	// open at a time, which is how many statements it can run in parallel.
	// Zero (the default) leaves it unbounded. A database may set its own.
	MaxConnections int `yaml:"max_connections"`
	// Params are SQLite DSN query parameters applied to every database.
	// Per-database params take precedence over them.
	Params Params `yaml:"params"`
	// Extensions are loadable SQLite extensions registered on every
	// connection to every database. Per-database extensions are loaded
	// after them.
	Extensions Extensions `yaml:"extensions"`
	// TLS configures transport security. When it is omitted the wire
	// protocol travels in cleartext.
	TLS TLSConfig `yaml:"tls"`
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

// Limits bound the work a single statement may do. They are the daemon's own
// safety net: a client may ask for a tighter bound, but never for a looser
// one. Every field may be set at the top level of the configuration and
// under databases.<name>.
type Limits struct {
	// QueryTimeout is the upper bound on how long a single statement may
	// run, in seconds. Zero (the default) leaves statements unbounded.
	QueryTimeout int64 `yaml:"query_timeout"`
	// TransactionTimeout is how long a transaction may sit without a
	// request, in seconds, before the daemon rolls it back and drops the
	// session. A transaction holds SQLite's write lock from the moment it
	// begins, so a client that walks away from one keeps every other writer
	// waiting. Zero (the default) waits forever.
	TransactionTimeout int64 `yaml:"transaction_timeout"`
	// MaxRows is the upper bound on the number of rows one query result may
	// carry. Zero (the default) leaves results unbounded.
	MaxRows int64 `yaml:"max_rows"`
	// MaxResponseBytes is the upper bound on an encoded response body. Zero
	// selects DefaultMaxResponseBytes; the value can be lowered but not
	// raised beyond the frame limit of the protocol.
	MaxResponseBytes int64 `yaml:"max_response_bytes"`
}

// statementLimits are the bounds that apply to one statement, once the
// configuration and the client's request have been reconciled. The timeout
// is a duration here because a client may ask for finer granularity than the
// whole seconds the configuration is written in.
type statementLimits struct {
	timeout            time.Duration
	transactionTimeout time.Duration
	maxRows            int64
	maxResponseBytes   int64
}

// resolve combines the server-wide limits in l with those of a database,
// which win where they are set, and applies the default response size.
func (l Limits) resolve(db Limits) statementLimits {
	resolved := statementLimits{
		timeout: time.Duration(minNonZero(l.QueryTimeout, db.QueryTimeout)) * time.Second,
		transactionTimeout: time.Duration(minNonZero(
			l.TransactionTimeout, db.TransactionTimeout)) * time.Second,
		maxRows:          minNonZero(l.MaxRows, db.MaxRows),
		maxResponseBytes: db.MaxResponseBytes,
	}
	if resolved.maxResponseBytes == 0 {
		resolved.maxResponseBytes = l.MaxResponseBytes
	}
	if resolved.maxResponseBytes <= 0 || resolved.maxResponseBytes > DefaultMaxResponseBytes {
		resolved.maxResponseBytes = DefaultMaxResponseBytes
	}
	return resolved
}

// validate rejects negative bounds and response sizes the protocol could not
// carry, so that a configuration mistake is caught at load time.
func (l Limits) validate() error {
	if l.QueryTimeout < 0 {
		return fmt.Errorf("query_timeout must not be negative, got %d", l.QueryTimeout)
	}
	if l.TransactionTimeout < 0 {
		return fmt.Errorf("transaction_timeout must not be negative, got %d", l.TransactionTimeout)
	}
	if l.MaxRows < 0 {
		return fmt.Errorf("max_rows must not be negative, got %d", l.MaxRows)
	}
	if l.MaxResponseBytes < 0 {
		return fmt.Errorf("max_response_bytes must not be negative, got %d", l.MaxResponseBytes)
	}
	if l.MaxResponseBytes > DefaultMaxResponseBytes {
		return fmt.Errorf("max_response_bytes must not exceed %d, got %d",
			int64(DefaultMaxResponseBytes), l.MaxResponseBytes)
	}
	return nil
}

// minNonZero returns the smaller of two bounds, reading zero as "no bound".
func minNonZero[T int64 | time.Duration](a, b T) T {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case b < a:
		return b
	default:
		return a
	}
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
	// Limits bound the work a single statement on this database may do,
	// overriding the server-wide values.
	Limits `yaml:",inline"`
	// MaxConnections bounds the SQLite connections this database may have
	// open at a time, overriding the server-wide value. Zero takes the
	// server's, and zero there leaves it unbounded.
	MaxConnections int `yaml:"max_connections"`
	// Params are extra SQLite DSN query parameters appended to the
	// "file:" URI used to open the database, e.g. mode=ro or
	// immutable=true. They override the server-wide Config.Params. See the
	// go-sqlite3 documentation for the full list of supported parameters.
	Params Params `yaml:"params"`
	// Extensions are loadable SQLite extensions registered on every
	// connection to this database, in addition to the server-wide
	// Config.Extensions.
	Extensions Extensions `yaml:"extensions"`
}

// Extension identifies an external SQLite extension to load into every
// connection of a database. In YAML it may be written either as a plain
// path or as a mapping naming the entry point:
//
//	extensions:
//	  - /usr/lib/sqlite3/vector0.so
//	  - path: /usr/lib/sqlite3/misc.so
//	    entrypoint: sqlite3_misc_init
type Extension struct {
	// Path is the filesystem path of the shared library to load. The
	// platform's dynamic loader resolves it, so a bare file name is looked
	// up along the usual search path.
	Path string `yaml:"path"`
	// Entrypoint is the initialization symbol to call. When empty, SQLite
	// picks the default one: sqlite3_extension_init, falling back to a
	// name derived from the file name.
	Entrypoint string `yaml:"entrypoint"`
}

// String renders the extension the way it is written in the configuration.
func (e Extension) String() string {
	if e.Entrypoint == "" {
		return e.Path
	}
	return e.Path + ":" + e.Entrypoint
}

// UnmarshalYAML accepts either a path or a mapping.
func (e *Extension) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var path string
		if err := node.Decode(&path); err != nil {
			return err
		}
		*e = Extension{Path: path}
		return nil
	case yaml.MappingNode:
		// Node.Decode does not inherit the decoder's KnownFields setting,
		// so unknown keys are rejected by hand to keep typos loud.
		if err := knownFields(node, "path", "entrypoint"); err != nil {
			return err
		}
		// The local type drops the UnmarshalYAML method, avoiding recursion.
		type plain Extension
		var ext plain
		if err := node.Decode(&ext); err != nil {
			return err
		}
		*e = Extension(ext)
		return nil
	default:
		return fmt.Errorf("extension must be a path or a mapping")
	}
}

// knownFields rejects mapping keys outside the allowed set.
func knownFields(node *yaml.Node, allowed ...string) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("field %s not found in type server.Extension", key)
		}
	}
	return nil
}

// Extensions is an ordered list of SQLite extensions. They are loaded in the
// order they are listed, except that entries without an explicit entry point
// are loaded first.
type Extensions []Extension

// merge returns the extensions of e followed by those of override, dropping
// entries that are already present. It lets a database repeat a server-wide
// extension without loading it twice.
func (e Extensions) merge(override Extensions) Extensions {
	if len(e) == 0 && len(override) == 0 {
		return nil
	}
	merged := make(Extensions, 0, len(e)+len(override))
	seen := make(map[Extension]struct{}, len(e)+len(override))
	add := func(exts Extensions) {
		for _, ext := range exts {
			if _, dup := seen[ext]; dup {
				continue
			}
			seen[ext] = struct{}{}
			merged = append(merged, ext)
		}
	}
	add(e)
	add(override)
	return merged
}

// defaultEntrypoints returns the paths of the extensions that do not name an
// entry point, letting SQLite work it out on its own.
func (e Extensions) defaultEntrypoints() []string {
	var paths []string
	for _, ext := range e {
		if ext.Entrypoint == "" {
			paths = append(paths, ext.Path)
		}
	}
	return paths
}

// strings renders the extensions for logs and error messages.
func (e Extensions) strings() []string {
	if len(e) == 0 {
		return nil
	}
	out := make([]string, 0, len(e))
	for _, ext := range e {
		out = append(out, ext.String())
	}
	return out
}

// validate rejects empty paths and exact duplicates.
func (e Extensions) validate() error {
	seen := make(map[Extension]struct{}, len(e))
	for i, ext := range e {
		if strings.TrimSpace(ext.Path) == "" {
			return fmt.Errorf("[%d]: path must not be empty", i)
		}
		if ext.Entrypoint != strings.TrimSpace(ext.Entrypoint) {
			return fmt.Errorf("[%d]: entrypoint %q must not have surrounding whitespace", i, ext.Entrypoint)
		}
		if _, dup := seen[ext]; dup {
			return fmt.Errorf("[%d]: extension %s is listed twice", i, ext)
		}
		seen[ext] = struct{}{}
	}
	return nil
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

// databaseConfig returns the configuration of a database with the
// server-wide defaults filled in, so that whatever opens it reads one
// complete set of values rather than consulting two.
func (c *Config) databaseConfig(name string) (DatabaseConfig, bool) {
	cfg, ok := c.Databases[name]
	if !ok {
		return DatabaseConfig{}, false
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = c.MaxConnections
	}
	return cfg, true
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
		if err := db.Extensions.validate(); err != nil {
			return fmt.Errorf("databases.%s.extensions%w", name, err)
		}
		if err := db.Limits.validate(); err != nil {
			return fmt.Errorf("databases.%s.%w", name, err)
		}
		if db.MaxConnections < 0 {
			return fmt.Errorf("databases.%s.max_connections must not be negative, got %d",
				name, db.MaxConnections)
		}
	}
	// Validated last so that grants are checked against known-good databases.
	if err := c.Auth.validate(c.Databases); err != nil {
		return err
	}
	return nil
}
