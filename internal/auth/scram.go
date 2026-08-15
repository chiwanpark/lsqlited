// Package auth implements the challenge-response authentication used by
// lsqlited. The scheme follows SCRAM-SHA-256 (RFC 5802) closely enough to
// inherit its security properties, while using the lsqlited JSON framing
// instead of the SASL text encoding.
//
// The password never travels over the wire. Instead:
//
//	saltedPassword = PBKDF2-SHA256(password, salt, iterations)
//	clientKey      = HMAC-SHA256(saltedPassword, "Client Key")
//	storedKey      = SHA256(clientKey)
//	serverKey      = HMAC-SHA256(saltedPassword, "Server Key")
//
// The server persists only salt, iterations, storedKey and serverKey (a
// Verifier). The client proves knowledge of the password by sending
//
//	clientProof = clientKey XOR HMAC-SHA256(storedKey, authMessage)
//
// from which the server recovers clientKey and checks SHA256(clientKey)
// against storedKey. Because the server stores storedKey rather than
// clientKey, a leaked configuration file does not by itself allow an
// attacker to authenticate.
//
// The server answers with HMAC-SHA256(serverKey, authMessage), which lets
// the client authenticate the server in turn. Both directions are bound to
// fresh random nonces, so recorded handshakes cannot be replayed.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Mechanism is the name of the authentication mechanism, used as the prefix
// of the textual verifier encoding.
const Mechanism = "SCRAM-SHA-256"

const (
	// DefaultIterations is the PBKDF2 iteration count used when deriving a
	// verifier from a plaintext password. It matches the PostgreSQL default:
	// clients run the derivation once per new connection, so a much larger
	// count would make connection setup noticeably slower.
	DefaultIterations = 4096
	// MinIterations is the smallest iteration count accepted by both peers.
	MinIterations = 1000
	// MaxIterations bounds the work a malicious server can force a client to
	// perform during the handshake.
	MaxIterations = 1 << 20

	// SaltLen is the length in bytes of a generated salt.
	SaltLen = 16
	// MinSaltLen is the smallest salt accepted in an encoded verifier. It is
	// the floor recommended by RFC 8018, and also what crypto/pbkdf2 demands
	// under GODEBUG=fips140=only.
	MinSaltLen = 16
	// NonceLen is the length in bytes of a generated nonce.
	NonceLen = 24
	// MinNonceLen is the smallest nonce accepted from the peer.
	MinNonceLen = 16

	keyLen = sha256.Size
)

var (
	clientKeyLabel = []byte("Client Key")
	serverKeyLabel = []byte("Server Key")
)

// Verifier holds everything the server needs to check a client proof. It
// is password-equivalent only in the sense that it allows offline guessing;
// it cannot be replayed as a credential.
type Verifier struct {
	Iterations int
	Salt       []byte
	StoredKey  []byte
	ServerKey  []byte
}

// NewVerifier derives a verifier for password using a freshly generated
// random salt. A non-positive iterations value selects DefaultIterations.
func NewVerifier(password string, iterations int) (*Verifier, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("auth: generate salt: %w", err)
	}
	return DeriveVerifier(password, salt, iterations)
}

// DeriveVerifier derives a verifier for password with an explicit salt. A
// non-positive iterations value selects DefaultIterations.
func DeriveVerifier(password string, salt []byte, iterations int) (*Verifier, error) {
	if iterations <= 0 {
		iterations = DefaultIterations
	}
	salted, err := SaltPassword(password, salt, iterations)
	if err != nil {
		return nil, err
	}
	clientKey := hmacSum(salted, clientKeyLabel)
	storedKey := sha256.Sum256(clientKey)
	return &Verifier{
		Iterations: iterations,
		Salt:       salt,
		StoredKey:  storedKey[:],
		ServerKey:  hmacSum(salted, serverKeyLabel),
	}, nil
}

// Verify reports whether proof is a valid client proof for authMessage.
func (v *Verifier) Verify(authMessage string, proof []byte) bool {
	if len(proof) != keyLen || len(v.StoredKey) != keyLen {
		return false
	}
	signature := hmacSum(v.StoredKey, []byte(authMessage))
	clientKey := make([]byte, keyLen)
	for i := range clientKey {
		clientKey[i] = proof[i] ^ signature[i]
	}
	storedKey := sha256.Sum256(clientKey)
	return subtle.ConstantTimeCompare(storedKey[:], v.StoredKey) == 1
}

// ServerSignature returns the proof of possession the server sends back so
// that the client can authenticate the server.
func (v *Verifier) ServerSignature(authMessage string) []byte {
	return hmacSum(v.ServerKey, []byte(authMessage))
}

// String encodes the verifier in the PostgreSQL SCRAM verifier format:
//
//	SCRAM-SHA-256$<iterations>:<salt>$<storedKey>:<serverKey>
//
// where salt and keys are base64 (standard encoding).
func (v *Verifier) String() string {
	return fmt.Sprintf("%s$%d:%s$%s:%s",
		Mechanism,
		v.Iterations,
		base64.StdEncoding.EncodeToString(v.Salt),
		base64.StdEncoding.EncodeToString(v.StoredKey),
		base64.StdEncoding.EncodeToString(v.ServerKey),
	)
}

// IsVerifier reports whether s looks like an encoded verifier rather than a
// plaintext password.
func IsVerifier(s string) bool {
	return strings.HasPrefix(s, Mechanism+"$")
}

// ParseVerifier decodes the textual form produced by Verifier.String.
func ParseVerifier(s string) (*Verifier, error) {
	rest, ok := strings.CutPrefix(s, Mechanism+"$")
	if !ok {
		return nil, fmt.Errorf("auth: verifier must start with %q", Mechanism+"$")
	}
	head, tail, ok := strings.Cut(rest, "$")
	if !ok {
		return nil, fmt.Errorf("auth: malformed verifier: missing %q separator", "$")
	}
	iterStr, saltStr, ok := strings.Cut(head, ":")
	if !ok {
		return nil, fmt.Errorf("auth: malformed verifier: missing iteration count")
	}
	iterations, err := strconv.Atoi(iterStr)
	if err != nil {
		return nil, fmt.Errorf("auth: malformed verifier: bad iteration count %q", iterStr)
	}
	if iterations < MinIterations || iterations > MaxIterations {
		return nil, fmt.Errorf("auth: verifier iteration count %d out of range [%d, %d]",
			iterations, MinIterations, MaxIterations)
	}
	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, fmt.Errorf("auth: malformed verifier: bad salt: %w", err)
	}
	if len(salt) < MinSaltLen {
		return nil, fmt.Errorf("auth: malformed verifier: salt must be at least %d bytes, got %d",
			MinSaltLen, len(salt))
	}
	storedStr, serverStr, ok := strings.Cut(tail, ":")
	if !ok {
		return nil, fmt.Errorf("auth: malformed verifier: missing server key")
	}
	storedKey, err := base64.StdEncoding.DecodeString(storedStr)
	if err != nil {
		return nil, fmt.Errorf("auth: malformed verifier: bad stored key: %w", err)
	}
	serverKey, err := base64.StdEncoding.DecodeString(serverStr)
	if err != nil {
		return nil, fmt.Errorf("auth: malformed verifier: bad server key: %w", err)
	}
	if len(storedKey) != keyLen || len(serverKey) != keyLen {
		return nil, fmt.Errorf("auth: malformed verifier: keys must be %d bytes", keyLen)
	}
	return &Verifier{
		Iterations: iterations,
		Salt:       salt,
		StoredKey:  storedKey,
		ServerKey:  serverKey,
	}, nil
}

// DecoyVerifier deterministically fabricates a verifier for an unknown user
// so that the server's challenge looks identical whether or not the account
// exists. Proofs checked against it never succeed, and repeated probes for
// the same name always observe the same salt.
func DecoyVerifier(secret []byte, user string, iterations int) *Verifier {
	if iterations < MinIterations {
		iterations = DefaultIterations
	}
	salt := hmacSum(secret, []byte("decoy salt:"+user))
	return &Verifier{
		Iterations: iterations,
		Salt:       salt[:SaltLen],
		StoredKey:  hmacSum(secret, []byte("decoy stored:"+user)),
		ServerKey:  hmacSum(secret, []byte("decoy server:"+user)),
	}
}

// SaltPassword derives the salted password shared by both peers. It fails
// only on out-of-range parameters, which both peers reject before getting
// this far, or when running under GODEBUG=fips140=only with a verifier whose
// salt is too short.
func SaltPassword(password string, salt []byte, iterations int) ([]byte, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("auth: derive salted password: %w", err)
	}
	return salted, nil
}

// ClientProof computes the proof the client sends to the server.
func ClientProof(saltedPassword []byte, authMessage string) []byte {
	clientKey := hmacSum(saltedPassword, clientKeyLabel)
	storedKey := sha256.Sum256(clientKey)
	signature := hmacSum(storedKey[:], []byte(authMessage))
	proof := make([]byte, keyLen)
	for i := range proof {
		proof[i] = clientKey[i] ^ signature[i]
	}
	return proof
}

// ServerSignature computes the signature the client expects back from the
// server, from the client's own salted password.
func ServerSignature(saltedPassword []byte, authMessage string) []byte {
	return hmacSum(hmacSum(saltedPassword, serverKeyLabel), []byte(authMessage))
}

// AuthMessage builds the string both peers sign. Every parameter that
// influences the handshake is covered, so a man in the middle cannot swap
// the salt or downgrade the iteration count without the proof failing. The
// user name is base64-encoded to keep the separators unambiguous.
func AuthMessage(user string, clientNonce, serverNonce, salt []byte, iterations int) string {
	enc := base64.StdEncoding
	var b strings.Builder
	b.WriteString("lsqlited-auth-v1,u=")
	b.WriteString(enc.EncodeToString([]byte(user)))
	b.WriteString(",c=")
	b.WriteString(enc.EncodeToString(clientNonce))
	b.WriteString(",s=")
	b.WriteString(enc.EncodeToString(serverNonce))
	b.WriteString(",salt=")
	b.WriteString(enc.EncodeToString(salt))
	b.WriteString(",i=")
	b.WriteString(strconv.Itoa(iterations))
	return b.String()
}

// Nonce returns NonceLen cryptographically random bytes.
func Nonce() ([]byte, error) {
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("auth: generate nonce: %w", err)
	}
	return nonce, nil
}

// Secret returns a random per-process secret used to derive decoy verifiers.
func Secret() ([]byte, error) {
	secret := make([]byte, keyLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("auth: generate secret: %w", err)
	}
	return secret, nil
}

func hmacSum(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
