package lsqlited

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/chiwanpark/lsqlited/internal/auth"
	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// authenticate runs the challenge-response handshake. The password is used only to derive a proof bound to both peers'
// nonces, so an observer learns nothing reusable, and the server's reply is checked in turn so that a rogue server
// cannot impersonate the real one.
func (c *connector) authenticate(ctx context.Context, cn *conn) error {
	clientNonce, err := auth.Nonce()
	if err != nil {
		return fmt.Errorf("lsqlited: %w", err)
	}
	resp, err := cn.roundTrip(ctx, &protocol.Request{
		Type:  protocol.TypeAuthInit,
		User:  c.cfg.username,
		Nonce: base64.StdEncoding.EncodeToString(clientNonce),
	})
	if err != nil {
		return err
	}
	if resp.Auth == nil {
		return errors.New("lsqlited: server did not send an authentication challenge")
	}
	salt, err := base64.StdEncoding.DecodeString(resp.Auth.Salt)
	if err != nil || len(salt) == 0 {
		return errors.New("lsqlited: invalid authentication challenge: bad salt")
	}
	serverNonce, err := base64.StdEncoding.DecodeString(resp.Auth.Nonce)
	if err != nil || len(serverNonce) < auth.MinNonceLen {
		return errors.New("lsqlited: invalid authentication challenge: bad nonce")
	}
	iterations := resp.Auth.Iterations
	if iterations < auth.MinIterations || iterations > auth.MaxIterations {
		return fmt.Errorf("lsqlited: invalid authentication challenge: iteration count %d out of range [%d, %d]",
			iterations, auth.MinIterations, auth.MaxIterations)
	}

	salted, err := c.saltedPassword(salt, iterations)
	if err != nil {
		return err
	}
	message := auth.AuthMessage(c.cfg.username, clientNonce, serverNonce, salt, iterations)
	final, err := cn.roundTrip(ctx, &protocol.Request{
		Type:  protocol.TypeAuth,
		Proof: base64.StdEncoding.EncodeToString(auth.ClientProof(salted, message)),
	})
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(final.Signature)
	if err != nil || !hmac.Equal(signature, auth.ServerSignature(salted, message)) {
		return errors.New("lsqlited: server signature mismatch, refusing to trust the server")
	}
	return nil
}

// saltedPassword derives (and memoizes) PBKDF2(password, salt, iterations).
func (c *connector) saltedPassword(salt []byte, iterations int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.salted != nil && c.iterations == iterations && bytes.Equal(c.salt, salt) {
		return c.salted, nil
	}
	salted, err := auth.SaltPassword(c.cfg.password, salt, iterations)
	if err != nil {
		return nil, fmt.Errorf("lsqlited: %w", err)
	}
	c.salt, c.iterations, c.salted = salt, iterations, salted
	return salted, nil
}
