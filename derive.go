// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/eszio/age-plugin-sshagent/internal/bech32"
)

const (
	pluginName = "sshagent"

	// payloadVersion is the first byte of the identity payload. Bump it for
	// any change to the payload layout or the derivation scheme.
	payloadVersion = 0x01

	saltSize        = 16
	fingerprintSize = sha256.Size

	challengeContext = "age-plugin-sshagent/v1/derive"
	hkdfContext      = "age-plugin-sshagent/v1/x25519"
)

// identityData is the public payload encoded in an AGE-PLUGIN-SSHAGENT-1...
// string. It contains no secret material: only a reference to which agent key
// to use (a SHA-256 fingerprint) and a per-identity random salt. The actual
// decryption key is re-derived on demand from the agent's signature.
type identityData struct {
	fingerprint [fingerprintSize]byte // SHA-256 of the ssh public key wire format
	salt        [saltSize]byte
}

func newIdentityData(key ssh.PublicKey) (*identityData, error) {
	d := &identityData{fingerprint: sha256.Sum256(key.Marshal())}
	if _, err := rand.Read(d.salt[:]); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *identityData) encode() []byte {
	out := make([]byte, 0, 1+fingerprintSize+saltSize)
	out = append(out, payloadVersion)
	out = append(out, d.fingerprint[:]...)
	out = append(out, d.salt[:]...)
	return out
}

func parseIdentityData(data []byte) (*identityData, error) {
	if len(data) != 1+fingerprintSize+saltSize {
		return nil, fmt.Errorf("malformed identity payload: unexpected length %d", len(data))
	}
	if data[0] != payloadVersion {
		return nil, fmt.Errorf("unsupported identity version %d (this binary supports version %d)", data[0], payloadVersion)
	}
	d := &identityData{}
	copy(d.fingerprint[:], data[1:1+fingerprintSize])
	copy(d.salt[:], data[1+fingerprintSize:])
	return d, nil
}

// challenge is the message the agent signs. It is domain-separated by a fixed
// context string and bound to the identity's salt, so the signature (and the
// key derived from it) can't be obtained by tricking the user into signing
// something else, and two identities over the same ssh key are independent.
func (d *identityData) challenge() []byte {
	c := make([]byte, 0, len(challengeContext)+1+saltSize)
	c = append(c, challengeContext...)
	c = append(c, 0x00)
	c = append(c, d.salt[:]...)
	return c
}

// deriveX25519 asks the agent to sign the identity's challenge with the
// referenced key and derives an X25519 age identity from the signature.
// The ssh private key never leaves the agent. The derivation is repeatable
// because Ed25519 signatures are deterministic (RFC 8032); only ssh-ed25519
// keys are accepted for that reason (sk-* keys mix in a counter, RSA agents
// may use randomized PSS padding).
func deriveX25519(ag agent.Agent, key ssh.PublicKey, d *identityData) (*age.X25519Identity, error) {
	if key.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("unsupported ssh key type %q: only ssh-ed25519 keys produce deterministic signatures", key.Type())
	}
	challenge := d.challenge()
	sig, err := ag.Sign(key, challenge)
	if err != nil {
		return nil, fmt.Errorf("ssh agent refused to sign: %v", err)
	}
	// A misbehaving agent would silently derive a different identity and the
	// file would just fail to decrypt; fail loudly here instead.
	if err := key.Verify(challenge, sig); err != nil {
		return nil, fmt.Errorf("ssh agent returned an invalid signature: %v", err)
	}
	info := hkdfContext + "\x00" + string(d.fingerprint[:])
	secret, err := hkdf.Key(sha256.New, sig.Blob, d.salt[:], info, 32)
	if err != nil {
		return nil, err
	}
	s, err := bech32.Encode("AGE-SECRET-KEY-", secret)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.ToUpper(s))
}

// findAgentKey locates the ssh key referenced by the identity payload among
// the keys currently loaded in the agent.
func findAgentKey(ag agent.Agent, d *identityData) (ssh.PublicKey, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("cannot list ssh agent keys: %v", err)
	}
	for _, k := range keys {
		if sha256.Sum256(k.Marshal()) == d.fingerprint {
			return k, nil
		}
	}
	return nil, fmt.Errorf("ssh key %s is not loaded in the agent: add it with ssh-add and retry",
		rawFingerprint(d.fingerprint))
}

func rawFingerprint(fp [fingerprintSize]byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(fp[:])
}

// deriveFromPayload is the full decrypt-side path: parse the payload, find the
// key in the agent, and derive the X25519 identity.
func deriveFromPayload(data []byte) (*age.X25519Identity, error) {
	d, err := parseIdentityData(data)
	if err != nil {
		return nil, err
	}
	ag, err := connectAgent()
	if err != nil {
		return nil, err
	}
	key, err := findAgentKey(ag, d)
	if err != nil {
		return nil, err
	}
	return deriveX25519(ag, key, d)
}
