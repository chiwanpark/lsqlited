# lsqlited

`lsqlited` is a lightweight and simple daemon that serves SQLite databases over TCP. It ships with two components:

1. **Server** (`cmd/lsqlited`) — a daemon configured by a YAML file that listens on a TCP port and executes queries against configured SQLite database files.
2. **Driver** (`github.com/chiwanpark/lsqlited`) — a pure-Go `database/sql` driver that talks to the server, so clients use the standard Go database API.

## Requirements

- Go 1.24 or newer (tested against Go 1.24, 1.25, and 1.26)
- A C compiler with `CGO_ENABLED=1` to build the server, since it links the SQLite3 C library

## Installation

The daemon links the SQLite C library, so it needs CGO:

```sh
CGO_ENABLED=1 go install github.com/chiwanpark/lsqlited/cmd/lsqlited@latest
```

Or run the published image:

```sh
docker run --rm -v /etc/lsqlited:/etc/lsqlited ghcr.io/chiwanpark/lsqlited:1.2634.2 -config /etc/lsqlited/lsqlited.yaml
```

The driver is a separate concern: it speaks TCP and never opens a database file, so it is pure Go and builds with
`CGO_ENABLED=0`.

```sh
go get github.com/chiwanpark/lsqlited@latest
```

## Running the Server

Create a configuration file (see [`config.example.yaml`](config.example.yaml)):

```yaml
listen:
  host: 127.0.0.1   # empty host binds to all interfaces
  port: 7890

params: _journal_mode=WAL # SQLite open parameters for every database

query_timeout: 60         # interrupt any statement running longer, in seconds
max_rows: 5000            # refuse a result larger than this

extensions:               # loadable extensions for every database
- /usr/lib/sqlite3/vector0.so

databases:
  app: /var/lib/lsqlited/app.sqlite3
  metrics: /var/lib/lsqlited/metrics.sqlite3
  archive: /var/lib/lsqlited/archive.sqlite3
```

Then start the daemon:

```sh
lsqlited -config /etc/lsqlited/config.yaml
```

Each entry under `databases` maps a logical database name to a SQLite file. Every database is opened the same way, from the settings above — there are no per-database overrides. Files are opened lazily on first use and shared across client connections. The daemon shuts down gracefully on `SIGINT`/`SIGTERM`.

### Open Parameters

SQLite open parameters are set with the top-level `params` key, which accepts either a query string or a mapping:

```yaml
params: _journal_mode=WAL&_foreign_keys=true

# equivalent
params:
  _journal_mode: WAL
  _foreign_keys: true
```

Parameters are appended to the `file:` URI handed to SQLite, so anything the [go-sqlite3 driver](https://pkg.go.dev/github.com/mattn/go-sqlite3#hdr-Connection_String) understands works — `mode`, `immutable`, `cache`, `vfs`, `_journal_mode`, `_foreign_keys`, `_txlock`, and so on. They apply to every database, so `mode=ro` serves the whole daemon read-only; to serve one file read-only and another writable, run a second daemon.

### Limits

A daemon shared by several clients needs a way to stop one statement from taking the whole process with it. Three keys bound what a single statement may do, for every database it serves:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `query_timeout` | integer (seconds) | unset (unlimited) | Upper bound on how long a statement may run |
| `transaction_timeout` | integer (seconds) | unset (unlimited) | How long a transaction may sit idle before it is rolled back |
| `max_rows` | integer | unset (unlimited) | Upper bound on the rows in one result |

A result too large to fit in one protocol frame (64 MiB) is refused with `ErrResponseTooLarge`, whatever these say.

```yaml
query_timeout: 60       # seconds
max_rows: 5000
```

A client may ask for a tighter bound than these, with the `query_timeout` and `max_rows` DSN parameters or a context deadline, but never for a looser one.

```go
switch {
case errors.Is(err, lsqlited.ErrTimeout):
	// the statement was interrupted
case errors.Is(err, lsqlited.ErrTooManyRows), errors.Is(err, lsqlited.ErrResponseTooLarge):
	// the result was too big to return
}
```

### Connections

Statements on one database run in parallel, each on its own SQLite connection: readers never block one another, and only writers take turns. `max_connections` bounds that pool:

```yaml
max_connections: 16       # per database, for every database
```

Omitted, the pool is unbounded. Either way the daemon keeps as many connections warm as the bound allows — a core's worth when there is none — because opening one reopens the file, reparses the schema and reloads every extension.

A statement waiting for a free connection waits under its `query_timeout`, and an open transaction holds a connection until it commits or rolls back.

### Transactions and Concurrent Writes

SQLite allows any number of readers but only one writer at a time, and the daemon runs a transaction on one connection from beginning to end. Which lock a transaction takes, and when, is decided when it begins:

```go
tx, err := db.Begin()                                          // write: takes the lock now
tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})     // read: runs alongside readers
```

A read-only transaction issues `BEGIN` and runs deferred, alongside every other reader; the daemon sets `query_only` on its connection, so a write inside one is refused rather than quietly promoting it to a writer.

Outside a transaction each statement is its own, and SQLite applies it atomically; concurrent writers queue on the write lock for up to `_busy_timeout` (5s by default). When that runs out, the error carries the code `busy` and the driver matches `lsqlited.ErrBusy` — nothing is wrong with the statement, and repeating it is the remedy:

```go
if errors.Is(err, lsqlited.ErrBusy) {
	// another connection held the lock; try again
}
```

### Extensions

External SQLite extensions are listed with the top-level `extensions` key. The daemon loads them into every connection it opens to every database, so the functions, collations, and virtual tables they provide are available to all clients:

```yaml
extensions:
- /usr/lib/sqlite3/vector0.so           # entry point left to SQLite
- path: /usr/lib/sqlite3/misc.so        # explicit initialization symbol
  entrypoint: sqlite3_misc_init
```

An entry is either the path of a shared library or a mapping with `path` and an optional `entrypoint`. Without `entrypoint`, SQLite picks the initialization symbol itself: `sqlite3_extension_init`, falling back to a name derived from the file name (`spellfix.so` → `sqlite3_spellfix_init`). Paths are resolved by the platform's dynamic loader, so a bare file name is looked up along the usual search path.

Entries without an `entrypoint` are loaded before those with one. A library that cannot be loaded fails the database at open time, and the error names it.

Extensions are not part of the wire protocol: clients cannot ask for one, and `load_extension()` remains unavailable in queries. They run in the daemon's process with its privileges, so load only libraries you trust.

### TLS

Without a `tls` section the daemon serves plaintext TCP and everything — queries, results, and the databases they contain — is readable by anyone on the path. Point it at a certificate and key to encrypt the transport:

```yaml
tls:
  cert: /etc/lsqlited/server.crt   # PEM certificate, intermediates appended
  key: /etc/lsqlited/server.key    # PEM private key
  client_ca: /etc/lsqlited/ca.crt  # optional: require client certificates
  min_version: "1.2"               # optional: "1.2" (default) or "1.3"
```

Clients then ask for TLS in the DSN:

```go
db, err := sql.Open("lsqlited", "lsqlited://alice:s3cret@db.example.com:7890/app?ssl_ca=/etc/ssl/ca.crt")
```

A certificate for testing can be generated with `openssl`:

```sh
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout server.key -out server.crt \
  -subj '/CN=db.example.com' -addext 'subjectAltName=DNS:db.example.com'
```

### Authentication

By default the daemon accepts every connection. Adding an `auth.users` section turns on authentication for all clients:

```yaml
auth:
  users:
    alice:
      verifier: "SCRAM-SHA-256$4096:4X/1Oev...==$hUeU8ys...=:aX9c/LV...="
      databases: [app, metrics]
    bob:
      verifier: "SCRAM-SHA-256$4096:1fDfTNq...==$gELeGJ1...=:9fli77X...="
      databases: [archive]
    admin:
      verifier: "SCRAM-SHA-256$4096:zWGk/XH...==$9/iVbds...=:q8XsJEH...="
      # no `databases` key: every database
```

An account is configured with a `verifier` and nothing else, so the password never appears in the configuration file. Generate one with `-hash-password`:

```sh
printf '%s' 'hunter2' | lsqlited -hash-password
SCRAM-SHA-256$4096:4X/1Oev...==$hUeU8ys...=:aX9c/LV...=
```

The PBKDF2 cost is chosen there, with `-iterations`, and the verifier carries it — there is nothing to keep in sync in the configuration file. Clients run the derivation once per connection, so a large count makes connecting measurably slower.

Clients then supply credentials in the DSN:

```go
db, err := sql.Open("lsqlited", "lsqlited://alice:s3cret@127.0.0.1:7890/app")
```

Unauthenticated requests to a server with configured users are refused with `authentication required`, and a bad user name or password is refused with a deliberately vague `authentication failed`. An unknown user still gets a challenge, fabricated to look like a real one, so the handshake cannot be used to tell which accounts exist.

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
lsqlited://[user:password@]host:port/database[?param=value&...]
```

- `database` is the logical name configured on the server.
- `port` defaults to `7890` when omitted.
- `user:password` are required when the server has authentication enabled; percent-encode any reserved characters. Supplying one without the other is an error.

| Parameter | Default | Description |
| --- | --- | --- |
| `dial_timeout` | `10s` | TCP connect and TLS handshake timeout |
| `query_timeout` | none | Server-side time limit for a statement, as a duration (`30s`) |
| `max_rows` | `0` | Largest result the server may return, `0` for no limit |
| `ssl_mode` | `disable` | `disable`, `require`, `verify-ca`, or `verify-full` |
| `ssl_ca` | system pool | PEM bundle of CAs trusted to sign the server certificate |
| `ssl_cert` | | Client certificate presented for mutual TLS |
| `ssl_key` | | Private key matching `ssl_cert` |
| `ssl_server_name` | the host dialed | Name to verify and send as SNI |

The SSL modes follow the familiar libpq semantics:

| Mode | Encrypted | Chain checked | Host name checked |
| --- | --- | --- | --- |
| `disable` | no | no | no |
| `require` | yes | no | no |
| `verify-ca` | yes | yes | no |
| `verify-full` | yes | yes | yes |

Transactions (`db.Begin` / `db.BeginTx`, including `sql.TxOptions{ReadOnly: true}`), prepared statements, and context cancellation are supported. Query parameters are positional (`?`); named parameters are not supported. `Rows.ColumnTypes` reports the declared SQLite type of each column — `INTEGER`, `TEXT`, and so on, empty for an expression, a literal or an aggregate — including for a result with no rows.

`query_timeout` bounds a statement whose context carries no deadline of its own. When it does carry one, the remaining time is sent instead, so an ordinary `context.WithTimeout` bounds the work inside the daemon as well:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
rows, err := db.QueryContext(ctx, "SELECT ...") // the daemon gets the 5s too
```

### Errors

A request the server rejects comes back as a `*ServerError`, which carries the server's message unchanged — usually SQLite's own wording, which is what an application shows to whoever wrote the statement:

```go
var serverErr *lsqlited.ServerError
if errors.As(err, &serverErr) {
	fmt.Println(serverErr.Message) // "no such column: foo"
	fmt.Println(serverErr.Code)    // "", "timeout", "too_many_rows", "response_too_large", "busy"
}
```

The classified ones also match a sentinel under `errors.Is`: `ErrTimeout`, `ErrTooManyRows`, `ErrResponseTooLarge`, and `ErrBusy`. Everything else — dialing, I/O, protocol failures — surfaces as the underlying error.

## Wire Protocol

The protocol is intentionally simple: each message is a 4-byte big-endian length header followed by a JSON body (at most 64 MiB). The client sends a request and receives exactly one response.

There is no in-band upgrade to TLS: a listener either speaks TLS or it does not, and the framing below is what flows inside the TLS session. A plaintext client therefore cannot be tricked into downgrading, and it also means the server and its clients must agree on TLS out of band.

Request:

```json
{"type": "query", "database": "app", "query": "SELECT v FROM kv WHERE k = ?",
 "args": [{"t": "text", "v": "greeting"}], "timeout_ms": 5000, "max_rows": 5000}
```

Response:

```json
{"columns": ["v"], "column_types": ["TEXT"], "rows": [[{"t": "text", "v": "hello"}]]}
```

`timeout_ms` and `max_rows` are the limits the client asks for; the server enforces the tighter of those and its own. Both are optional, and a request that omits them is bounded by the server's configuration alone. `column_types` is parallel to `columns` and holds each column's declared type, empty where there is none.

A failed request answers with `error`, and with `code` when the reason is one the client can act on:

```json
{"error": "result exceeds the row limit of 5000", "code": "too_many_rows"}
```

The codes are `timeout`, `too_many_rows`, `response_too_large`, and `busy`; `error` carries the underlying message with no prefix. A request that is canceled because the client hung up gets no answer at all, there being nobody left to answer.

Request types are `ping`, `query`, `exec`, `begin`, `commit`, `rollback`, `auth_init`, and `auth`. Values are tagged (`null`, `int`, `float`, `bool`, `text`, `blob`, `time`) and transported as strings to preserve full `int64` precision; blobs are base64-encoded and times use RFC 3339.

Each TCP connection is a session on the server. `begin` pins a SQLite connection to the session until `commit` or `rollback`, and `"read_only": true` asks for a deferred, read-only transaction instead of one that takes the write lock; a dropped connection rolls back any open transaction automatically.

When the server has authentication enabled, a session must complete the `auth_init`/`auth` exchange before any other request type is accepted:

```json
{"type": "auth_init", "user": "alice", "nonce": "<base64 client nonce>"}
{"auth": {"salt": "<base64>", "iterations": 4096, "nonce": "<base64 server nonce>"}}

{"type": "auth", "proof": "<base64 client proof>"}
{"signature": "<base64 server signature>"}
```

## Limitations

- Query results are fully buffered in memory before being sent, so a result larger than the 64 MiB message limit is refused rather than streamed. Use `max_rows`, or paginate, to stay under it.
- Limits bound one statement at a time; how many run at once is bounded only by `max_connections`.
- Access control is per database, not per table or per statement: an account that may reach a database may read and write all of it.
- Every database a daemon serves is opened the same way, with the same parameters, limits, pool size and extensions. Serving one database differently means running a second daemon.
- Extensions are loaded from the configuration file only, and a change to the list takes effect when the daemon restarts.
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
