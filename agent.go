// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

// connectAgent connects to the ssh agent at SSH_AUTH_SOCK. Managing the agent
// lifecycle (starting it, loading keys) is deliberately the user's job, the
// same contract as ssh itself.
func connectAgent() (agent.ExtendedAgent, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("SSH_AUTH_SOCK is not set: start your ssh-agent and load your key")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to ssh agent at %s: %v", sock, err)
	}
	return agent.NewClient(conn), nil
}
