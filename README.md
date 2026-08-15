# lsqlited

`lsqlited` is a lightweight and simple daemon that serves SQLite databases over TCP. It ships with two components:

1. **Server** (`cmd/lsqlited`) — a daemon configured by a YAML file that listens on a TCP port and executes queries against configured SQLite database files.
2. **Driver** (`github.com/chiwanpark/lsqlited`) — a pure-Go `database/sql` driver that talks to the server, so clients use the standard Go database API.

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

databases:
  app:
    path: /var/lib/lsqlited/app.sqlite3
  metrics:
    path: /var/lib/lsqlited/metrics.sqlite3
    read_only: true        # reject writes for this database
    busy_timeout_ms: 10000 # SQLite busy timeout (default: 5000)
```

Then start the daemon:

```sh
lsqlited -config /etc/lsqlited/config.yaml
```

Each entry under `databases` maps a logical database name to a SQLite file. Database files are opened lazily on first use and shared across client connections. The daemon shuts down gracefully on `SIGINT`/`SIGTERM`.

Flags:

| Flag | Default | Description |
| --- | --- | --- |
| `-config` | `lsqlited.yaml` | Path to the YAML configuration file |
| `-log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

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
lsqlited://host:port/database[?dial_timeout=10s]
```

- `database` is the logical name configured on the server.
- `port` defaults to `7890` when omitted.
- `dial_timeout` sets the TCP connect timeout (default `10s`).

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

Request types are `ping`, `query`, `exec`, `begin`, `commit`, and `rollback`. Values are tagged (`null`, `int`, `float`, `bool`, `text`, `blob`, `time`) and transported as strings to preserve full `int64` precision; blobs are base64-encoded and times use RFC 3339.

Each TCP connection is a session on the server. `begin` pins a dedicated SQLite transaction to the session until `commit` or `rollback`; a dropped connection rolls back any open transaction automatically.

## Limitations

- Query results are fully buffered in memory before being sent, so very large result sets are subject to the 64 MiB message limit.
- No authentication or encryption — run it on a trusted network or behind a tunnel.
- Named query parameters and custom transaction isolation levels are not supported.

## Development

```sh
go test ./...        # unit and end-to-end tests
go test -race ./...
```

## License

[MIT](LICENSE)
