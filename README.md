# lsqlited

`lsqlited` is a lightweight and simple daemon that serves SQLite databases over TCP. It ships with two components:

1. **Server** (`cmd/lsqlited`) — a daemon configured by a YAML file that listens on a TCP port and executes queries against configured SQLite database files.
2. **Driver** (`github.com/chiwanpark/lsqlited`) — a pure-Go `database/sql` driver that talks to the server, so clients use the standard Go database API.

## Requirements

- Go 1.24 or newer (tested against Go 1.24, 1.25, and 1.26)
- A C compiler with `CGO_ENABLED=1` to build the server, since it links the SQLite3 C library

## Installation

```sh
CGO_ENABLED=1 go install github.com/chiwanpark/lsqlited/cmd/lsqlited@latest
```

## Running the Server

Create a configuration file (see [`config.example.yaml`](config.example.yaml)):

```yaml
listen:
  host: 127.0.0.1   # empty host binds to all interfaces
  port: 7890

params: _journal_mode=WAL # SQLite open parameters for every database

databases:
  app:
    path: /var/lib/lsqlited/app.sqlite3
  metrics:
    path: /var/lib/lsqlited/metrics.sqlite3
    params: _busy_timeout=10000 # busy timeout in ms (default: 5000)
  archive:
    path: /var/lib/lsqlited/archive.sqlite3
    params: mode=ro&immutable=true # read-only, never written to
  cached:
    path: /var/lib/lsqlited/cached.sqlite3
    params:                # the mapping form works too
      cache: shared
      _synchronous: NORMAL
```

Then start the daemon:

```sh
lsqlited -config /etc/lsqlited/config.yaml
```

Each entry under `databases` maps a logical database name to a SQLite file. Database files are opened lazily on first use and shared across client connections. The daemon shuts down gracefully on `SIGINT`/`SIGTERM`.

### Open Parameters

SQLite open parameters can be set server-wide with the top-level `params` key and per database with `databases.<name>.params`. Both accept either a query string or a mapping:

```yaml
params: _journal_mode=WAL&_foreign_keys=true

# equivalent
params:
  _journal_mode: WAL
  _foreign_keys: true
```

Parameters are appended to the `file:` URI handed to SQLite, so anything the [go-sqlite3 driver](https://pkg.go.dev/github.com/mattn/go-sqlite3#hdr-Connection_String) understands works — `mode`, `immutable`, `cache`, `vfs`, `_journal_mode`, `_foreign_keys`, `_txlock`, and so on.

### Authentication

By default the daemon accepts every connection. Adding an `auth.users` section turns on authentication for all clients:

```yaml
auth:
  iterations: 4096   # PBKDF2 cost, optional (default 4096)
  users:
    alice:
      verifier: "SCRAM-SHA-256$4096:4X/1Oev...==$hUeU8ys...=:aX9c/LV...="
    bob:
      password: hunter2
```

Each account is configured with exactly one of:

- `verifier` — a precomputed credential, so the password never appears in the configuration file. **Recommended.** Generate one with `-hash-password`:

  ```sh
  printf '%s' 'hunter2' | lsqlited -hash-password
  SCRAM-SHA-256$4096:4X/1Oev...==$hUeU8ys...=:aX9c/LV...=
  ```

- `password` — a plaintext password, converted to a verifier when the configuration is loaded. Convenient, but readable by anyone who can read the file.

Clients then supply credentials in the DSN:

```go
db, err := sql.Open("lsqlited", "lsqlited://alice:s3cret@127.0.0.1:7890/app")
```

Unauthenticated requests to a server with configured users are refused with `authentication required`, and a bad user name or password is refused with a deliberately vague `authentication failed`.

Flags:

| Flag | Default | Description |
| --- | --- | --- |
| `-config` | `lsqlited.yaml` | Path to the YAML configuration file |
| `-log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `-hash-password` | `false` | Read a password from stdin, print an `auth.users` verifier, and exit |
| `-iterations` | `4096` | PBKDF2 iteration count used by `-hash-password` |

## Using the Driver

```go
package main

import (
	"database/sql"
	"fmt"

	_ "github.com/chiwanpark/lsqlited"
)

func main() {
	db, err := sql.Open("lsqlited", "lsqlited://127.0.0.1:7890/app")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)"); err != nil {
		panic(err)
	}
	if _, err := db.Exec("INSERT OR REPLACE INTO kv VALUES (?, ?)", "greeting", "hello"); err != nil {
		panic(err)
	}

	var v string
	if err := db.QueryRow("SELECT v FROM kv WHERE k = ?", "greeting").Scan(&v); err != nil {
		panic(err)
	}
	fmt.Println(v)
}
```

The DSN has the form:

```
lsqlited://[user:password@]host:port/database[?dial_timeout=10s]
```

- `database` is the logical name configured on the server.
- `port` defaults to `7890` when omitted.
- `dial_timeout` sets the TCP connect timeout (default `10s`).
- `user:password` are required when the server has authentication enabled; percent-encode any reserved characters. Supplying one without the other is an error.

Transactions (`db.Begin` / `db.BeginTx`), prepared statements, and context cancellation are supported. Query parameters are positional (`?`); named parameters are not supported.

## Wire Protocol

The protocol is intentionally simple: each message is a 4-byte big-endian length header followed by a JSON body (at most 64 MiB). The client sends a request and receives exactly one response.

Request:

```json
{"type": "query", "database": "app", "query": "SELECT v FROM kv WHERE k = ?",
 "args": [{"t": "text", "v": "greeting"}]}
```

Response:

```json
{"columns": ["v"], "rows": [[{"t": "text", "v": "hello"}]]}
```

Request types are `ping`, `query`, `exec`, `begin`, `commit`, `rollback`, `auth_init`, and `auth`. Values are tagged (`null`, `int`, `float`, `bool`, `text`, `blob`, `time`) and transported as strings to preserve full `int64` precision; blobs are base64-encoded and times use RFC 3339.

Each TCP connection is a session on the server. `begin` pins a dedicated SQLite transaction to the session until `commit` or `rollback`; a dropped connection rolls back any open transaction automatically.

When the server has authentication enabled, a session must complete the `auth_init`/`auth` exchange before any other request type is accepted:

```json
{"type": "auth_init", "user": "alice", "nonce": "<base64 client nonce>"}
{"auth": {"salt": "<base64>", "iterations": 4096, "nonce": "<base64 server nonce>"}}

{"type": "auth", "proof": "<base64 client proof>"}
{"signature": "<base64 server signature>"}
```

## Limitations

- Query results are fully buffered in memory before being sent, so very large result sets are subject to the 64 MiB message limit.
- Authentication protects the credentials, but the connection itself is not encrypted: queries and results travel in cleartext. Run it on a trusted network or behind a tunnel.
- Authorization is all-or-nothing: any authenticated user may access every configured database.
- Named query parameters and custom transaction isolation levels are not supported.

## Development

```sh
go test ./...        # unit and end-to-end tests
go test -race ./...
```

CI runs the full suite against every supported Go version on each push to `main`. To reproduce a specific version locally without installing it system-wide:

```sh
GOTOOLCHAIN=go1.24.0 go test ./...
```

## License

[MIT](LICENSE)
