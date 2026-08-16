package server

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Params holds extra SQLite DSN query parameters. In YAML it is written either
// as a mapping or as a URL-style query string:
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

// ParseParams parses a query string such as "mode=ro&immutable=true".
func ParseParams(raw string) (Params, error) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "?")
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

// validate rejects empty parameter names.
func (p Params) validate() error {
	for key := range p {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("parameter name must not be empty")
		}
	}
	return nil
}

// Extension identifies an external SQLite extension to load into every
// connection of a database. In YAML it is written either as a plain path or as
// a mapping naming the entry point:
//
//	extensions:
//	- /usr/lib/sqlite3/vector0.so
//	- path: /usr/lib/sqlite3/misc.so
//	  entrypoint: sqlite3_misc_init
type Extension struct {
	// Path is the shared library to load, resolved by the platform's dynamic
	// loader, so a bare file name is looked up along the usual search path.
	Path string `yaml:"path"`
	// Entrypoint is the initialization symbol to call. When empty, SQLite
	// picks sqlite3_extension_init, falling back to a name derived from the
	// file name.
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
		// Node.Decode does not inherit the decoder's KnownFields setting, so
		// unknown keys are rejected by hand to keep typos loud.
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

// Extensions is an ordered list of SQLite extensions.
type Extensions []Extension

// defaultEntrypoints returns the paths of the extensions that name no entry
// point, letting SQLite work it out on its own.
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
