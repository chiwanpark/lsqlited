// Command lsqlited is a lightweight daemon that serves SQLite databases over TCP.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/chiwanpark/lsqlited/internal/auth"
	"github.com/chiwanpark/lsqlited/internal/version"
	"github.com/chiwanpark/lsqlited/server"
)

// limitValue renders a configured bound for the startup log, naming the unset case rather than printing a bare zero.
func limitValue(value string, unset bool) string {
	if unset {
		return "unlimited"
	}
	return value
}

func main() {
	configPath := flag.String("config", "lsqlited.yaml", "path to the YAML configuration file")
	initdbDir := flag.String("initdb", "", "directory of SQL scripts applied to the databases this start creates")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	hashPassword := flag.Bool("hash-password", false, "read a password from stdin, print an auth.users verifier, and exit")
	iterations := flag.Int("iterations", auth.DefaultIterations, "PBKDF2 iteration count used by -hash-password")
	showVersion := flag.Bool("version", false, "print the server version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	if *hashPassword {
		if err := printVerifier(os.Stdin, os.Stdout, *iterations); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level %q\n", *logLevel)
		os.Exit(2)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Installed before the databases are seeded so that a long initialization can still be interrupted.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg, server.WithLogger(logger))
	if *initdbDir != "" {
		if err := srv.InitDatabases(ctx, *initdbDir); err != nil {
			logger.Error("failed to initialize databases", "error", err)
			os.Exit(1)
		}
	}
	if err := srv.Start(); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}
	logger.Info("lsqlited started",
		"addr", srv.Addr(),
		"databases", len(cfg.Databases),
		"tls", srv.TLSEnabled(),
		"auth", len(cfg.Auth.Users) > 0,
		"query_timeout", limitValue(strconv.FormatInt(cfg.QueryTimeout, 10)+"s", cfg.QueryTimeout == 0),
		"max_rows", limitValue(strconv.FormatInt(cfg.MaxRows, 10), cfg.MaxRows == 0))
	if !srv.TLSEnabled() {
		logger.Warn("TLS is disabled, queries and results travel in cleartext")
	}

	<-ctx.Done()

	logger.Info("shutting down")
	if err := srv.Close(); err != nil {
		logger.Error("shutdown failed", "error", err)
		os.Exit(1)
	}
}

// printVerifier reads a password from in and writes its verifier to out, so that the configuration file never has to
// hold the password itself.
func printVerifier(in io.Reader, out io.Writer, iterations int) error {
	raw, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	password := strings.TrimRight(string(raw), "\r\n")
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	if iterations != 0 && (iterations < auth.MinIterations || iterations > auth.MaxIterations) {
		return fmt.Errorf("iterations must be between %d and %d", auth.MinIterations, auth.MaxIterations)
	}
	verifier, err := auth.NewVerifier(password, iterations)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, verifier)
	return err
}
