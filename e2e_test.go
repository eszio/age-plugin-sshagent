// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/plugin"
)

// TestAgeCLIEndToEnd drives the real age binary: encrypt with stock age to the
// derived recipient (no plugin involved), then decrypt with `age -d -i` which
// invokes this plugin over the plugin protocol against a live agent socket.
func TestAgeCLIEndToEnd(t *testing.T) {
	ageBin, err := exec.LookPath("age")
	if err != nil {
		t.Skip("age binary not in PATH")
	}

	dir := t.TempDir()
	pluginBin := filepath.Join(dir, "age-plugin-sshagent")
	build := exec.Command("go", "build", "-o", pluginBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	kr, key := newTestAgent(t, "e2e@test")
	sock := serveAgent(t, kr)

	d, _ := newIdentityData(key)
	id, err := deriveX25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	recipient := id.Recipient().String()
	identityFile := filepath.Join(dir, "identity.txt")
	contents := "# public key: " + recipient + "\n" + plugin.EncodeIdentity(pluginName, d.encode()) + "\n"
	if err := os.WriteFile(identityFile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	overrides := map[string]string{
		"PATH":          dir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"SSH_AUTH_SOCK": sock,
	}
	var env []string
	for _, e := range os.Environ() {
		key := e
		if i := strings.Index(e, "="); i >= 0 {
			key = e[:i]
		}
		if _, skip := overrides[key]; !skip {
			env = append(env, e)
		}
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	plaintext := "end to end via the age CLI"

	// Encrypt: recipient is a native age1..., no plugin needed.
	encrypted := filepath.Join(dir, "msg.age")
	enc := exec.Command(ageBin, "-e", "-r", recipient, "-o", encrypted)
	enc.Stdin = strings.NewReader(plaintext)
	enc.Env = env
	if out, err := enc.CombinedOutput(); err != nil {
		t.Fatalf("age -e: %v\n%s", err, out)
	}

	// Decrypt: age discovers age-plugin-sshagent via PATH.
	dec := exec.Command(ageBin, "-d", "-i", identityFile, encrypted)
	dec.Env = env
	var stdout, stderr bytes.Buffer
	dec.Stdout, dec.Stderr = &stdout, &stderr
	if err := dec.Run(); err != nil {
		t.Fatalf("age -d: %v\n%s", err, stderr.String())
	}
	if stdout.String() != plaintext {
		t.Errorf("got %q, want %q", stdout.String(), plaintext)
	}
}
