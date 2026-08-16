package server

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chiwanpark/lsqlited/internal/auth"
)

// AuthConfig configures challenge-response authentication.
type AuthConfig struct {
	// Users maps account names to their credentials.
	Users map[string]UserConfig `yaml:"users"`
}

// UserConfig holds the credential of a single account and the databases it
// may access.
type UserConfig struct {
	// Verifier is the credential produced by "lsqlited -hash-password", which
	// also decides the PBKDF2 cost.
	Verifier string `yaml:"verifier"`
	// Databases lists the database names the account may use; every name must
	// match an entry under Config.Databases.
	Databases []string `yaml:"databases"`
}

// Account is the runtime form of a UserConfig.
type Account struct {
	Verifier *auth.Verifier
	// databases is the set of names the account may access, or nil when it
	// may access all of them.
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

// Accounts derives the runtime account of every configured user, returning nil
// when authentication is disabled.
func (a AuthConfig) Accounts() (map[string]*Account, error) {
	if len(a.Users) == 0 {
		return nil, nil
	}
	accounts := make(map[string]*Account, len(a.Users))
	for name, user := range a.Users {
		account, err := user.account()
		if err != nil {
			return nil, fmt.Errorf("auth.users.%s: %w", name, err)
		}
		accounts[name] = account
	}
	return accounts, nil
}

// decoyIterations is the PBKDF2 count advertised to unknown users. Taking the
// one most accounts use keeps a fabricated challenge indistinguishable from a
// real one, without a configuration key that could be set to something no
// account actually uses. Ties go to the smaller count.
func decoyIterations(accounts map[string]*Account) int {
	counts := make(map[int]int, len(accounts))
	for _, account := range accounts {
		counts[account.Verifier.Iterations]++
	}
	best, seen := auth.DefaultIterations, 0
	for iterations, n := range counts {
		if n > seen || (n == seen && iterations < best) {
			best, seen = iterations, n
		}
	}
	return best
}

// validate checks the authentication section. Grants are cross-checked against
// databases so that a typo in a database name is caught at load time rather
// than surfacing as a denied query later.
func (a AuthConfig) validate(databases map[string]string) error {
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

// account derives the runtime account for the user.
func (u UserConfig) account() (*Account, error) {
	verifier, err := auth.ParseVerifier(u.Verifier)
	if err != nil {
		return nil, err
	}
	return &Account{Verifier: verifier, databases: u.databaseSet()}, nil
}

// databaseSet returns the granted names, or nil for unrestricted access. An
// omitted list decodes to a nil slice while an explicit empty list does not,
// which is what distinguishes "all" from "none".
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

// validate checks the credential.
func (u UserConfig) validate() error {
	if u.Verifier == "" {
		return fmt.Errorf("verifier must be set, generate one with -hash-password")
	}
	_, err := auth.ParseVerifier(u.Verifier)
	return err
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
