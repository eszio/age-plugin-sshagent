// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keySel := fs.String("k", "", "select the agent key by comment or SHA256 fingerprint (substring match)")
	out := fs.String("o", "", "write the identity to `FILE` (default stdout)")
	fs.Parse(args)

	ag, err := connectAgent()
	if err != nil {
		return fatalf("%v", err)
	}
	key, err := pickKey(ag, *keySel)
	if err != nil {
		return fatalf("%v", err)
	}

	d, err := newIdentityData(key)
	if err != nil {
		return fatalf("generating salt: %v", err)
	}

	// Derive twice and compare: catches agents that don't produce
	// deterministic signatures before the user encrypts anything to a
	// recipient they could never decrypt for again.
	id1, err := deriveX25519(ag, key, d)
	if err != nil {
		return fatalf("%v", err)
	}
	id2, err := deriveX25519(ag, key, d)
	if err != nil {
		return fatalf("%v", err)
	}
	if id1.String() != id2.String() {
		return fatalf("agent produced non-deterministic signatures for %s; this key cannot be used", ssh.FingerprintSHA256(key))
	}

	recipient := id1.Recipient().String()
	identity := plugin.EncodeIdentity(pluginName, d.encode())

	w := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fatalf("%v", err)
		}
		defer f.Close()
		w = f
	}
	fmt.Fprintf(w, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "# ssh key: %s %s\n", ssh.FingerprintSHA256(key), keyComment(ag, key))
	fmt.Fprintf(w, "# public key: %s\n", recipient)
	fmt.Fprintf(w, "%s\n", identity)
	fmt.Fprintf(os.Stderr, "Public key: %s\n", recipient)
	return 0
}

// pickKey selects an ssh-ed25519 key from the agent. With an empty selector
// the agent must hold exactly one eligible key; otherwise the selector is
// matched as a substring of the key's comment or SHA256 fingerprint.
func pickKey(ag agent.Agent, selector string) (ssh.PublicKey, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("cannot list ssh agent keys: %v", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("the ssh agent holds no keys: add one with ssh-add")
	}

	var eligible []*agent.Key
	for _, k := range keys {
		if k.Type() != ssh.KeyAlgoED25519 {
			continue
		}
		if selector != "" &&
			!strings.Contains(k.Comment, selector) &&
			!strings.Contains(ssh.FingerprintSHA256(k), selector) {
			continue
		}
		eligible = append(eligible, k)
	}

	switch len(eligible) {
	case 1:
		return eligible[0], nil
	case 0:
		if selector != "" {
			return nil, fmt.Errorf("no ssh-ed25519 agent key matches %q (run 'age-plugin-sshagent list')", selector)
		}
		return nil, fmt.Errorf("the ssh agent holds no ssh-ed25519 keys (other key types are not supported; run 'age-plugin-sshagent list')")
	default:
		var lines []string
		for _, k := range eligible {
			lines = append(lines, fmt.Sprintf("  %s %s", ssh.FingerprintSHA256(k), k.Comment))
		}
		return nil, fmt.Errorf("multiple ssh-ed25519 keys match; pick one with -k:\n%s", strings.Join(lines, "\n"))
	}
}

func keyComment(ag agent.Agent, key ssh.PublicKey) string {
	keys, err := ag.List()
	if err != nil {
		return ""
	}
	marshaled := key.Marshal()
	for _, k := range keys {
		if string(k.Marshal()) == string(marshaled) {
			return k.Comment
		}
	}
	return ""
}

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.Parse(args)

	ag, err := connectAgent()
	if err != nil {
		return fatalf("%v", err)
	}
	keys, err := ag.List()
	if err != nil {
		return fatalf("cannot list ssh agent keys: %v", err)
	}
	if len(keys) == 0 {
		fmt.Println("(the ssh agent holds no keys)")
		return 0
	}
	for _, k := range keys {
		eligible := "not eligible (only ssh-ed25519 is supported)"
		if k.Type() == ssh.KeyAlgoED25519 {
			eligible = "eligible"
		}
		fmt.Printf("%s %s %s [%s]\n", k.Type(), ssh.FingerprintSHA256(k), k.Comment, eligible)
	}
	return 0
}

// cmdRecipient re-derives and prints the recipient(s) for identities read
// from a file or stdin. Useful to recover a lost public key, since the
// identity itself stores no key material.
func cmdRecipient(args []string) int {
	fs := flag.NewFlagSet("recipient", flag.ExitOnError)
	in := fs.String("i", "", "read identities from `FILE` (default stdin)")
	fs.Parse(args)

	r := io.Reader(os.Stdin)
	if *in != "" {
		f, err := os.Open(*in)
		if err != nil {
			return fatalf("%v", err)
		}
		defer f.Close()
		r = f
	}

	found := false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, data, err := plugin.ParseIdentity(line)
		if err != nil || name != pluginName {
			continue
		}
		id, err := deriveFromPayload(data)
		if err != nil {
			return fatalf("%v", err)
		}
		fmt.Println(id.Recipient().String())
		found = true
	}
	if err := scanner.Err(); err != nil {
		return fatalf("%v", err)
	}
	if !found {
		return fatalf("no AGE-PLUGIN-SSHAGENT-1 identity found in input")
	}
	return 0
}

func fatalf(format string, v ...any) int {
	fmt.Fprintf(os.Stderr, "age-plugin-sshagent: "+format+"\n", v...)
	return 1
}
