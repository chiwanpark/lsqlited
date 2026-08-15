// Command lsqlited is a lightweight daemon that serves SQLite databases
// over TCP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/chiwanpark/lsqlited/server"
)

func main() {
	configPath := flag.String("config", "lsqlited.yaml", "path to the YAML configuration file")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	flag.Parse()

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

	srv := server.New(cfg, server.WithLogger(logger))
	if err := srv.Start(); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}
	logger.Info("lsqlited started", "addr", srv.Addr(), "databases", len(cfg.Databases))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("shutting down")
	if err := srv.Close(); err != nil {
		logger.Error("shutdown failed", "error", err)
		os.Exit(1)
	}
}
