// Package lsqlited provides a database/sql driver for the lsqlited daemon, a lightweight TCP server for SQLite
// databases. Import it for its side effects and open a DSN of the form
//
//	lsqlited://[user:password@]host:port/database[?param=value&...]
//
// where database is the logical name configured on the server.
package lsqlited

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"sync"
	"time"
)

// DriverName is the name the driver registers under with database/sql.
const DriverName = "lsqlited"

// DefaultPort is the port used when the DSN omits one.
const DefaultPort = "7890"

func init() {
	sql.Register(DriverName, &Driver{})
}

// Driver implements driver.Driver and driver.DriverContext.
type Driver struct{}

var (
	_ driver.Driver        = (*Driver)(nil)
	_ driver.DriverContext = (*Driver)(nil)
)

// Open opens a new connection using the given DSN.
func (d *Driver) Open(dsn string) (driver.Conn, error) {
	c, err := d.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return c.Connect(context.Background())
}

// OpenConnector parses the DSN and returns a connector.
func (d *Driver) OpenConnector(dsn string) (driver.Connector, error) {
	cfg, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	return &connector{driver: d, cfg: cfg}, nil
}

type connector struct {
	driver *Driver
	cfg    *dsnConfig

	// mu guards the memoized salted password. Deriving it costs a PBKDF2 run, so connections that see the same salt and
	// iteration count reuse it.
	mu         sync.Mutex
	salt       []byte
	iterations int
	salted     []byte
}

var _ driver.Connector = (*connector)(nil)

func (c *connector) Driver() driver.Driver { return c.driver }

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	d := net.Dialer{Timeout: c.cfg.dialTimeout}
	nc, err := d.DialContext(ctx, "tcp", c.cfg.addr)
	if err != nil {
		return nil, fmt.Errorf("lsqlited: dial %s: %w", c.cfg.addr, err)
	}
	if nc, err = c.tlsHandshake(ctx, nc); err != nil {
		return nil, err
	}
	cn := &conn{
		nc:           nc,
		database:     c.cfg.database,
		queryTimeout: c.cfg.queryTimeout,
		maxRows:      c.cfg.maxRows,
	}
	if c.cfg.username != "" {
		if err := c.authenticate(ctx, cn); err != nil {
			_ = cn.Close()
			return nil, err
		}
	}
	return cn, nil
}

// tlsHandshake upgrades a freshly dialed connection to TLS, and is a no-op when ssl_mode is disable. dial_timeout
// bounds the handshake too, since a peer that stalls halfway through it is as unreachable as one that never accepts the
// connection.
func (c *connector) tlsHandshake(ctx context.Context, nc net.Conn) (net.Conn, error) {
	if c.cfg.tls == nil {
		return nc, nil
	}
	if c.cfg.dialTimeout > 0 {
		if err := nc.SetDeadline(time.Now().Add(c.cfg.dialTimeout)); err != nil {
			_ = nc.Close()
			return nil, fmt.Errorf("lsqlited: %w", err)
		}
	}
	tc := tls.Client(nc, c.cfg.tls)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("lsqlited: tls handshake with %s: %w", c.cfg.addr, err)
	}
	if err := tc.SetDeadline(time.Time{}); err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("lsqlited: %w", err)
	}
	return tc, nil
}
