package lsqlited

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultDialTimeout = 10 * time.Second

type dsnConfig struct {
	addr        string
	database    string
	dialTimeout time.Duration
	username    string
	password    string
	// queryTimeout bounds a statement on the server when the caller's context
	// carries no deadline of its own. Zero asks for no limit.
	queryTimeout time.Duration
	// maxRows caps the rows a query may return. Zero asks for no limit.
	maxRows int64
	// tls is nil when the connection is plaintext.
	tls *tls.Config
}

func parseDSN(dsn string) (*dsnConfig, error) {
	cfg, err := parseDSNParts(dsn)
	if err != nil {
		return nil, fmt.Errorf("lsqlited: invalid DSN %q: %w", dsn, err)
	}
	return cfg, nil
}

func parseDSNParts(dsn string) (*dsnConfig, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	if u.Scheme != DriverName {
		return nil, fmt.Errorf("scheme must be %q", DriverName)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	port := u.Port()
	if port == "" {
		port = DefaultPort
	}
	database := strings.Trim(u.Path, "/")
	if database == "" {
		return nil, fmt.Errorf("missing database name")
	}
	cfg := &dsnConfig{addr: net.JoinHostPort(host, port), database: database}
	if u.User != nil {
		cfg.username = u.User.Username()
		if cfg.username == "" {
			return nil, fmt.Errorf("missing user name")
		}
		password, ok := u.User.Password()
		if !ok {
			return nil, fmt.Errorf("missing password")
		}
		cfg.password = password
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("bad query string: %w", err)
	}
	if err := checkDSNParams(q); err != nil {
		return nil, err
	}
	if cfg.dialTimeout, err = durationParam(q, "dial_timeout", defaultDialTimeout); err != nil {
		return nil, err
	}
	if cfg.queryTimeout, err = durationParam(q, "query_timeout", 0); err != nil {
		return nil, err
	}
	if cfg.maxRows, err = int64Param(q, "max_rows"); err != nil {
		return nil, err
	}
	ssl, err := parseSSLOptions(q)
	if err != nil {
		return nil, err
	}
	// Certificates are read now rather than per connection, so a typo in a
	// path is reported by sql.Open instead of by the first query.
	if cfg.tls, err = ssl.tlsConfig(host); err != nil {
		return nil, err
	}
	return cfg, nil
}

// knownDSNParams is the set of recognized query parameters. Unknown ones are
// rejected rather than ignored: silently dropping a misspelled ssl_mode would
// hand the caller a cleartext connection it believed was encrypted.
var knownDSNParams = map[string]bool{
	"dial_timeout":    true,
	"query_timeout":   true,
	"max_rows":        true,
	"ssl_mode":        true,
	"ssl_ca":          true,
	"ssl_cert":        true,
	"ssl_key":         true,
	"ssl_server_name": true,
}

func checkDSNParams(q url.Values) error {
	unknown := make([]string, 0, len(q))
	for key := range q {
		if !knownDSNParams[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("unknown parameter(s) %s", strings.Join(unknown, ", "))
}

// durationParam reads a non-negative duration, falling back to def when the
// parameter is absent.
func durationParam(q url.Values, key string, def time.Duration) (time.Duration, error) {
	v := q.Get(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("bad %s: %w", key, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s must not be negative", key)
	}
	return d, nil
}

// int64Param reads a non-negative integer, defaulting to zero.
func int64Param(q url.Values, key string) (int64, error) {
	v := q.Get(key)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad %s: %w", key, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s must not be negative", key)
	}
	return n, nil
}
