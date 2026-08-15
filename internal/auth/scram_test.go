package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestSaltPasswordVector pins the key derivation to the published
// PBKDF2-HMAC-SHA256 test vector. crypto/pbkdf2 has its own test suite, so
// this exists to catch a miswired call: the wrong hash, or arguments in the
// wrong order.
func TestSaltPasswordVector(t *testing.T) {
	cases := []struct {
		password   string
		salt       string
		iterations int
		want       string
	}{
		{"password", "salt", 1,
			"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 2,
			"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{"password", "salt", 4096,
			"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}
	for _, tc := range cases {
		got, err := SaltPassword(tc.password, []byte(tc.salt), tc.iterations)
		if err != nil {
			t.Fatalf("SaltPassword: %v", err)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("SaltPassword(%q, %q, %d) = %s, want %s",
				tc.password, tc.salt, tc.iterations, hex.EncodeToString(got), tc.want)
		}
	}
}

// TestSaltLengthMeetsFIPSFloor pins the invariant that keeps SaltPassword
// from failing in practice: every salt we generate or accept is at least the
// 128 bits crypto/pbkdf2 requires under GODEBUG=fips140=only.
func TestSaltLengthMeetsFIPSFloor(t *testing.T) {
	const fipsFloor = 128 / 8
	if MinSaltLen < fipsFloor {
		t.Errorf("MinSaltLen = %d, want at least %d", MinSaltLen, fipsFloor)
	}
	if SaltLen < MinSaltLen {
		t.Errorf("SaltLen = %d, want at least MinSaltLen (%d)", SaltLen, MinSaltLen)
	}
	v, err := NewVerifier("s3cret", MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if len(v.Salt) < MinSaltLen {
		t.Errorf("generated salt is %d bytes, want at least %d", len(v.Salt), MinSaltLen)
	}
}

// TestDeriveVerifierRFC7677 checks the key schedule against the
// SCRAM-SHA-256 test vector from RFC 7677 section 3.
func TestDeriveVerifierRFC7677(t *testing.T) {
	salt, err := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	v, err := DeriveVerifier("pencil", salt, 4096)
	if err != nil {
		t.Fatalf("DeriveVerifier: %v", err)
	}

	const wantStored = "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY="
	const wantServer = "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
	if got := base64.StdEncoding.EncodeToString(v.StoredKey); got != wantStored {
		t.Errorf("StoredKey = %s, want %s", got, wantStored)
	}
	if got := base64.StdEncoding.EncodeToString(v.ServerKey); got != wantServer {
		t.Errorf("ServerKey = %s, want %s", got, wantServer)
	}
}

// handshake runs a full exchange and reports whether the client proof was
// accepted and whether the server signature matched.
func handshake(t *testing.T, v *Verifier, user, password string) (accepted, serverOK bool) {
	t.Helper()
	clientNonce, err := Nonce()
	if err != nil {
		t.Fatalf("client nonce: %v", err)
	}
	serverNonce, err := Nonce()
	if err != nil {
		t.Fatalf("server nonce: %v", err)
	}
	msg := AuthMessage(user, clientNonce, serverNonce, v.Salt, v.Iterations)
	salted, err := SaltPassword(password, v.Salt, v.Iterations)
	if err != nil {
		t.Fatalf("salt password: %v", err)
	}

	accepted = v.Verify(msg, ClientProof(salted, msg))
	serverOK = bytes.Equal(v.ServerSignature(msg), ServerSignature(salted, msg))
	return accepted, serverOK
}

func TestHandshakeSucceedsWithCorrectPassword(t *testing.T) {
	v, err := NewVerifier("s3cret", MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	accepted, serverOK := handshake(t, v, "alice", "s3cret")
	if !accepted {
		t.Error("client proof was rejected")
	}
	if !serverOK {
		t.Error("server signature did not match")
	}
}

func TestHandshakeFailsWithWrongPassword(t *testing.T) {
	v, err := NewVerifier("s3cret", MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if accepted, _ := handshake(t, v, "alice", "wrong"); accepted {
		t.Error("client proof was accepted for the wrong password")
	}
}

// TestProofIsBoundToNonces documents the replay protection: a proof
// captured from one handshake is worthless in another.
func TestProofIsBoundToNonces(t *testing.T) {
	v, err := NewVerifier("s3cret", MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	salted, err := SaltPassword("s3cret", v.Salt, v.Iterations)
	if err != nil {
		t.Fatalf("salt password: %v", err)
	}

	clientNonce, _ := Nonce()
	firstServerNonce, _ := Nonce()
	secondServerNonce, _ := Nonce()

	captured := ClientProof(salted, AuthMessage("alice", clientNonce, firstServerNonce, v.Salt, v.Iterations))
	replayed := AuthMessage("alice", clientNonce, secondServerNonce, v.Salt, v.Iterations)
	if v.Verify(replayed, captured) {
		t.Error("a proof from an earlier handshake was replayed successfully")
	}
}

// TestAuthMessageCoversChallengeParameters ensures a man in the middle
// cannot alter the advertised salt or iteration count unnoticed.
func TestAuthMessageCoversChallengeParameters(t *testing.T) {
	clientNonce, _ := Nonce()
	serverNonce, _ := Nonce()
	salt := []byte("0123456789abcdef")
	base := AuthMessage("alice", clientNonce, serverNonce, salt, 4096)

	variants := map[string]string{
		"user":       AuthMessage("bob", clientNonce, serverNonce, salt, 4096),
		"salt":       AuthMessage("alice", clientNonce, serverNonce, []byte("fedcba9876543210"), 4096),
		"iterations": AuthMessage("alice", clientNonce, serverNonce, salt, 1000),
		"nonce":      AuthMessage("alice", clientNonce, clientNonce, salt, 4096),
	}
	for name, variant := range variants {
		if variant == base {
			t.Errorf("auth message does not cover %s", name)
		}
	}
}

// TestAuthMessageResistsSeparatorInjection ensures a crafted user name
// cannot forge the remainder of the message.
func TestAuthMessageResistsSeparatorInjection(t *testing.T) {
	nonce := bytes.Repeat([]byte{1}, NonceLen)
	salt := []byte("0123456789abcdef")
	honest := AuthMessage("alice", nonce, nonce, salt, 4096)
	crafted := AuthMessage("alice,c=AQEB,s=AQEB", nonce, nonce, salt, 4096)
	if honest == crafted {
		t.Error("user name is not unambiguously encoded")
	}
}

func TestVerifierRoundTrip(t *testing.T) {
	original, err := NewVerifier("s3cret", MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	encoded := original.String()
	if !IsVerifier(encoded) {
		t.Errorf("IsVerifier(%q) = false", encoded)
	}
	if strings.Contains(encoded, "s3cret") {
		t.Error("encoded verifier leaks the password")
	}

	parsed, err := ParseVerifier(encoded)
	if err != nil {
		t.Fatalf("parse verifier: %v", err)
	}
	if parsed.Iterations != original.Iterations ||
		!bytes.Equal(parsed.Salt, original.Salt) ||
		!bytes.Equal(parsed.StoredKey, original.StoredKey) ||
		!bytes.Equal(parsed.ServerKey, original.ServerKey) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", parsed, original)
	}
}

func TestParseVerifierRejectsMalformedInput(t *testing.T) {
	valid, err := NewVerifier("s3cret", MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(valid.StoredKey)
	salt := base64.StdEncoding.EncodeToString(valid.Salt)
	cases := map[string]string{
		"empty":              "",
		"plaintext":          "s3cret",
		"wrong mechanism":    "SCRAM-SHA-1$4096:" + salt + "$" + key + ":" + key,
		"missing keys":       "SCRAM-SHA-256$4096:" + salt,
		"missing server key": "SCRAM-SHA-256$4096:" + salt + "$" + key,
		"bad iterations":     "SCRAM-SHA-256$many:" + salt + "$" + key + ":" + key,
		"low iterations":     "SCRAM-SHA-256$1:" + salt + "$" + key + ":" + key,
		"huge iterations":    "SCRAM-SHA-256$999999999:" + salt + "$" + key + ":" + key,
		"empty salt":         "SCRAM-SHA-256$4096:$" + key + ":" + key,
		"short salt":         "SCRAM-SHA-256$4096:c2FsdA==$" + key + ":" + key,
		"bad salt":           "SCRAM-SHA-256$4096:not!base64$" + key + ":" + key,
		"short key":          "SCRAM-SHA-256$4096:" + salt + "$c2hvcnQ=:" + key,
	}
	for name, encoded := range cases {
		if _, err := ParseVerifier(encoded); err == nil {
			t.Errorf("%s: ParseVerifier(%q) succeeded, want error", name, encoded)
		}
	}
}

// TestDecoyVerifier checks that challenges for unknown users are stable and
// never accept a proof.
func TestDecoyVerifier(t *testing.T) {
	secret, err := Secret()
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	first := DecoyVerifier(secret, "ghost", DefaultIterations)
	second := DecoyVerifier(secret, "ghost", DefaultIterations)
	if !bytes.Equal(first.Salt, second.Salt) {
		t.Error("decoy salt is not stable across challenges")
	}
	if len(first.Salt) != SaltLen {
		t.Errorf("decoy salt length = %d, want %d", len(first.Salt), SaltLen)
	}
	if other := DecoyVerifier(secret, "phantom", DefaultIterations); bytes.Equal(first.Salt, other.Salt) {
		t.Error("decoy salt is shared between different users")
	}
	if accepted, _ := handshake(t, first, "ghost", "anything"); accepted {
		t.Error("decoy verifier accepted a proof")
	}
}

func TestVerifyRejectsMalformedProof(t *testing.T) {
	v, err := NewVerifier("s3cret", MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	msg := AuthMessage("alice", make([]byte, NonceLen), make([]byte, NonceLen), v.Salt, v.Iterations)
	for _, proof := range [][]byte{nil, {}, make([]byte, 16), make([]byte, 64)} {
		if v.Verify(msg, proof) {
			t.Errorf("Verify accepted a %d-byte proof", len(proof))
		}
	}
}
