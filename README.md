# age-plugin-sshagent

[![CI](https://github.com/eszio/age-plugin-sshagent/actions/workflows/ci.yml/badge.svg)](https://github.com/eszio/age-plugin-sshagent/actions/workflows/ci.yml)

An [age](https://age-encryption.org) plugin that derives X25519 identities from deterministic ssh-agent signatures. Decryption keys are re-derived on demand by asking the agent to sign a fixed challenge — the ssh private key never leaves the agent and no new secret is stored on disk.

Two design properties make this practical:

1. **Recipients are native `age1...` X25519 recipients.** People encrypting to you use stock `age` with no plugin. Only you, the identity owner, need this binary — and only at decrypt time.

2. **The identity string (`AGE-PLUGIN-SSHAGENT-1...`) contains no secret material.** It encodes only the SHA-256 fingerprint of your ssh key and a random 16-byte salt. It is safe to commit to a repository, store in a dotfiles archive, or keep anywhere.

## How it works

```
agent_sign(challenge = "age-plugin-sshagent/v1/derive" || 0x00 || salt)
    → HKDF-SHA256(ikm=signature, salt=salt,
                  info="age-plugin-sshagent/v1/x25519" || 0x00 || fingerprint)
    → X25519 identity
```

The derivation is repeatable because Ed25519 signatures are deterministic (RFC 8032). Only `ssh-ed25519` keys are accepted for this reason — `sk-*` (FIDO) signatures include a counter and RSA agents may use randomized PSS padding, both of which break determinism and are therefore rejected.

The signature is verified against the public key before use. During `keygen`, the derivation runs twice and the results are compared, catching non-deterministic agents before anything is encrypted to the resulting recipient.

## Install

```
go install github.com/eszio/age-plugin-sshagent@latest
```

The binary must be on your `PATH` so that `age` can discover it as a plugin. Requires age v1.1.0 or later to decrypt.

## Usage

### Generate an identity

```
age-plugin-sshagent keygen [-k SELECTOR] [-o identity.txt]
```

With a single `ssh-ed25519` key loaded in the agent, no selector is needed. `-k` matches a substring of the key comment or its `SHA256:...` fingerprint. The identity is written to stdout, or to FILE with mode 0600 when -o is given (refusing to overwrite an existing file); the public key is also printed to stderr.

Example output:

```
# created: 2026-06-12T10:00:00Z
# ssh key: SHA256:abcdef... my-key
# public key: age1examplerecipient...
AGE-PLUGIN-SSHAGENT-1...
Public key: age1examplerecipient...        # printed to stderr
```

### Encrypt (stock age, no plugin required)

```
age -e -r age1examplerecipient... file > file.age
```

### Decrypt

```
age -d -i identity.txt file.age
```

`age` discovers the plugin automatically from `PATH` and calls it to re-derive the decryption key.

### Re-derive a lost public key

```
age-plugin-sshagent recipient -i identity.txt
```

Useful when the `# public key:` comment line is gone. Requires the agent with the key loaded.

### List agent keys

```
age-plugin-sshagent list
```

Shows all keys currently in the agent and whether each is eligible.

## Security model

### Which key types are supported and why

Only `ssh-ed25519`. Ed25519 is deterministic by construction (RFC 8032): the same key and message always produce the same signature. `sk-*` (FIDO/hardware token) keys include a hardware counter in the signature, and RSA agents may use randomized PSS padding — both produce non-deterministic signatures that would yield a different decryption key on each invocation. These key types are detected and rejected explicitly.

### Agent access equals decryption access

Anyone who can talk to your ssh-agent can request the same signature and re-derive your decryption key. This includes:

- **Processes running as your user** on the local machine.
- **Remote hosts when SSH agent forwarding is enabled** — forwarding exposes the signing capability to the remote host.

This exposure is broader than the risk in ordinary ssh authentication, where an attacker must be online at the exact moment of authentication. Here, one successful signature request yields the long-term decryption key permanently. **Do not enable ssh agent forwarding to untrusted hosts if you use this plugin.**

### Honest framing

This scheme derives key material from a signature operation ("stunt cryptography"). The age author explicitly declined ssh-agent support upstream ([FiloSottile/age#7](https://github.com/FiloSottile/age/issues/7)) because the agent protocol can only sign — it cannot perform X25519 ECDH or RSA-OAEP decryption, which are the operations age is built on. This plugin exists for users who understand and accept that tradeoff in exchange for keeping zero secrets on disk. Prior art with the same approach: [sagecipher](https://github.com/p-sherratt/sagecipher), [hiera-eyaml-sshagent](https://github.com/asottile/hiera-eyaml-sshagent).

### Key rotation

A new ssh key produces different identities. After rotating your ssh key, re-encrypt any files encrypted to the old recipient — old identities cannot be recovered without the old key in the agent.

### Agent lifecycle

The agent must be running and have the key loaded (`SSH_AUTH_SOCK` must point to it). Managing the agent — starting it, adding keys via `ssh-add`, unlocking passphrase-protected keys — is the user's responsibility, the same contract as ssh itself.

## FAQ

**Why not just keep an unencrypted age identity file?**

Threat models differ. An unencrypted identity file is readable by anything that can read the disk: backup systems, cloud sync, other users, anyone with physical access to a snapshot. This plugin keeps no secret at rest — the decryption capability lives only in the agent's memory. It is especially useful when disk contents are backed up or synced to locations outside your direct control.

**Why ed25519 only?**

Determinism. See [Which key types are supported](#which-key-types-are-supported-and-why) above.

**Can I use this with a passphrase-protected ssh key?**

Yes — that is one of the main use cases. Load the key once via `ssh-add` (or your OS keychain) and the agent holds the decrypted key in memory. The plugin requests a signature from the agent; it never sees or handles your passphrase.

## License

BSD-3-Clause, the same license as age. See [LICENSE](LICENSE).

The `internal/bech32` package is vendored from [filippo.io/age](https://github.com/FiloSottile/age) and is MIT-licensed; its original license header is preserved in the source file.
