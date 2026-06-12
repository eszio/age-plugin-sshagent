// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func newTestAgent(t *testing.T, comment string) (agent.Agent, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: comment}); err != nil {
		t.Fatal(err)
	}
	keys, err := kr.List()
	if err != nil {
		t.Fatal(err)
	}
	return kr, keys[0]
}

func TestDeriveDeterministic(t *testing.T) {
	kr, key := newTestAgent(t, "a@b")
	d, err := newIdentityData(key)
	if err != nil {
		t.Fatal(err)
	}
	id1, err := deriveX25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := deriveX25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	if id1.String() != id2.String() {
		t.Error("derivation is not deterministic")
	}
	if id1.Recipient().String() != id2.Recipient().String() {
		t.Error("recipients differ")
	}
}

func TestSaltSeparatesIdentities(t *testing.T) {
	kr, key := newTestAgent(t, "a@b")
	d1, _ := newIdentityData(key)
	d2, _ := newIdentityData(key)
	id1, err := deriveX25519(kr, key, d1)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := deriveX25519(kr, key, d2)
	if err != nil {
		t.Fatal(err)
	}
	if id1.String() == id2.String() {
		t.Error("identities with different salts must differ")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	kr, key := newTestAgent(t, "a@b")
	d, _ := newIdentityData(key)
	id, err := deriveX25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello mnemon")
	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-derive from scratch, as a fresh process would.
	id2, err := deriveX25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(&ciphertext, id2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("got %q, want %q", got, plaintext)
	}
}

func TestPayloadRoundtrip(t *testing.T) {
	_, key := newTestAgent(t, "a@b")
	d, _ := newIdentityData(key)
	parsed, err := parseIdentityData(d.encode())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.fingerprint != d.fingerprint || parsed.salt != d.salt {
		t.Error("payload did not round-trip")
	}
}

func TestPayloadRejectsBadInput(t *testing.T) {
	if _, err := parseIdentityData([]byte{0x01, 0x02}); err == nil {
		t.Error("short payload accepted")
	}
	_, key := newTestAgent(t, "a@b")
	d, _ := newIdentityData(key)
	enc := d.encode()
	enc[0] = 0x7f
	if _, err := parseIdentityData(enc); err == nil {
		t.Error("unknown version accepted")
	}
}

func TestRejectNonEd25519(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: rsaKey, Comment: "rsa@b"}); err != nil {
		t.Fatal(err)
	}
	keys, _ := kr.List()
	d, _ := newIdentityData(keys[0])
	if _, err := deriveX25519(kr, keys[0], d); err == nil {
		t.Error("rsa key accepted for derivation")
	}
	if _, err := pickKey(kr, ""); err == nil {
		t.Error("agent with only an rsa key produced an eligible pick")
	}
}

func TestPickKeySelector(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	kr := agent.NewKeyring()
	kr.Add(agent.AddedKey{PrivateKey: priv1, Comment: "work@laptop"})
	kr.Add(agent.AddedKey{PrivateKey: priv2, Comment: "personal@laptop"})

	if _, err := pickKey(kr, ""); err == nil {
		t.Error("ambiguous pick with two eligible keys must fail")
	}
	key, err := pickKey(kr, "work")
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := kr.List()
	if string(key.Marshal()) != string(keys[0].Marshal()) {
		t.Error("selector picked the wrong key")
	}
}

// serveAgent exposes an agent on a unix socket and points SSH_AUTH_SOCK at it.
func serveAgent(t *testing.T, kr agent.Agent) string {
	t.Helper()
	// macOS caps unix socket paths at 104 bytes (sun_path); avoid t.TempDir()
	// which embeds the long test name. Use a short base dir + short filename.
	dir, err := os.MkdirTemp("", "ap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(kr, conn)
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	return sock
}

func TestDeriveFromPayloadViaSocket(t *testing.T) {
	kr, key := newTestAgent(t, "sock@test")
	serveAgent(t, kr)

	d, _ := newIdentityData(key)
	id, err := deriveFromPayload(d.encode())
	if err != nil {
		t.Fatal(err)
	}
	direct, err := deriveX25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != direct.String() {
		t.Error("socket-derived identity differs from direct derivation")
	}
}

func TestDeriveFromPayloadKeyNotLoaded(t *testing.T) {
	kr, _ := newTestAgent(t, "sock@test")
	serveAgent(t, kr)

	_, other := newTestAgent(t, "other@test")
	d, _ := newIdentityData(other)
	if _, err := deriveFromPayload(d.encode()); err == nil {
		t.Error("missing agent key must fail")
	}
}
