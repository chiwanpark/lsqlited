package server

import (
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Extensions of the files InitDatabases applies. A dump is often kept compressed, so gzip is unpacked on the way in
// rather than requiring the operator to unpack it first.
const (
	scriptExt = ".sql"
	gzipExt   = ".sql.gz"
)

// InitDatabases applies the SQL scripts under dir to the databases this start creates, which is how a container image
// seeds an empty volume. The layout mirrors the convention of the other database images:
//
//	dir/001-common.sql      applied to every configured database
//	dir/app/001-schema.sql  applied to the database named "app"
//
// Files are applied in name order, those in dir before those in the subdirectory, on one connection so that a script
// leaves its PRAGMAs and temporary tables to the next. A database whose file already exists is left alone, so the
// scripts run exactly once: when the file is made. A missing dir, or one holding nothing that applies, is a no-op.
//
// Anything else in dir is ignored with a warning, since an init directory is usually a mounted volume and may hold
// entries the daemon has no business reading. A script that fails takes the start with it, and the database it was
// half-way through is removed so that the next start begins again from an empty file.
//
// It must be called before Start, while nothing is being served.
func (s *Server) InitDatabases(ctx context.Context, dir string) error {
	s.mu.Lock()
	running := s.ln != nil || s.closed
	s.mu.Unlock()
	if running {
		return errors.New("server: InitDatabases must be called before Start")
	}

	common, targeted, err := s.collectScripts(dir)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(s.cfg.Databases)) {
		scripts := make([]string, 0, len(common)+len(targeted[name]))
		scripts = append(scripts, common...)
		scripts = append(scripts, targeted[name]...)
		if len(scripts) == 0 {
			continue
		}
		path := s.cfg.Databases[name]
		fresh, err := isFresh(path)
		if err != nil {
			return fmt.Errorf("server: initialize database %q: %w", name, err)
		}
		if !fresh {
			s.logger.Debug("skipping initialization of an existing database", "database", name, "path", path)
			continue
		}
		if err := s.initDatabase(ctx, name, path, scripts); err != nil {
			return err
		}
	}
	return nil
}

// collectScripts reads the init directory, returning the scripts that apply to every database and, by database name,
// those that apply to one alone.
func (s *Server) collectScripts(dir string) (common []string, targeted map[string][]string, err error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		// Nothing is mounted, which is the ordinary case rather than a mistake.
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("server: read init directory: %w", err)
	}
	targeted = make(map[string][]string)
	// ReadDir sorts its entries by name, which is the order the scripts are applied in.
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		switch {
		case entry.IsDir():
			if _, ok := s.cfg.Databases[entry.Name()]; !ok {
				s.logger.Warn("ignoring an init directory that names no configured database", "path", path)
				continue
			}
			scripts, err := s.readScriptDir(path)
			if err != nil {
				return nil, nil, err
			}
			targeted[entry.Name()] = scripts
		case isScript(entry.Name()):
			common = append(common, path)
		default:
			s.logger.Warn("ignoring an init file that is not a script", "path", path)
		}
	}
	return common, targeted, nil
}

// readScriptDir returns the scripts of a per-database subdirectory.
func (s *Server) readScriptDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("server: read init directory: %w", err)
	}
	var scripts []string
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() || !isScript(entry.Name()) {
			// Only one level is meaningful: a subdirectory here would name a database inside a database.
			s.logger.Warn("ignoring an init file that is not a script", "path", path)
			continue
		}
		scripts = append(scripts, path)
	}
	return scripts, nil
}

// initDatabase creates a database and applies its scripts. The handle is opened the way the daemon opens every
// database, so the configured params and extensions are in force while the scripts run.
func (s *Server) initDatabase(ctx context.Context, name, path string, scripts []string) error {
	s.logger.Info("initializing database", "database", name, "path", path, "scripts", len(scripts))
	db, err := openSQLite(path, s.cfg)
	if err != nil {
		return fmt.Errorf("server: initialize database %q: %w", name, err)
	}
	err = applyScripts(ctx, db, scripts, s.logger.With("database", name))
	// The handle is dropped either way: the daemon reopens the database on first use, and a failed initialization has to
	// let go of the file before it can be removed.
	if closeErr := db.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		s.discard(path)
		return fmt.Errorf("server: initialize database %q: %w", name, err)
	}
	return nil
}

// applyScripts runs the scripts in order on a single connection.
func applyScripts(ctx context.Context, db *sql.DB, scripts []string, logger *slog.Logger) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	for _, path := range scripts {
		statements, err := readScript(path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(statements) == "" {
			continue
		}
		// A dump brings its own BEGIN and COMMIT, so the script is not wrapped in a transaction of the daemon's making.
		if _, err := conn.ExecContext(ctx, statements); err != nil {
			return fmt.Errorf("run %s: %w", path, err)
		}
		logger.Debug("applied an init script", "script", path)
	}
	return nil
}

// readScript reads a script, unpacking it when it is gzipped.
func readScript(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var r io.Reader = f
	if strings.HasSuffix(path, gzipExt) {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(data), nil
}

// discard removes a database whose initialization failed, along with the journal files beside it. What is deleted was
// created by this run, or was the empty file a volume mount left behind; keeping it would mean the next start finds a
// database that exists, skips the scripts, and serves half a schema.
func (s *Server) discard(path string) {
	for _, p := range []string{path, path + "-journal", path + "-wal", path + "-shm"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.logger.Warn("could not remove a half-initialized database, delete it before starting again",
				"path", p, "error", err)
		}
	}
}

// isFresh reports whether path is a database this start creates: either missing, or the empty file a volume mount
// leaves in place of one.
func isFresh(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if info.IsDir() {
		return false, fmt.Errorf("%s is a directory", path)
	}
	return info.Size() == 0, nil
}

// isScript reports whether name is a file InitDatabases applies.
func isScript(name string) bool {
	if strings.HasPrefix(name, ".") {
		// Editor swap files and the like, which a mounted directory tends to collect.
		return false
	}
	return strings.HasSuffix(name, scriptExt) || strings.HasSuffix(name, gzipExt)
}
