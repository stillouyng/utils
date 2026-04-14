# Roadmap

> Back to [README](README.md)

## Planned features

- [x] **Copy the config**: Copy SSH connection info for a profile to clipboard. Example: `twc copy <name>`. Notifies if the profile uses a key (identity file); otherwise prompts for the master key and copies the connection string with the decrypted password.
- [x] **Store and copy the sudo password**: Store an encrypted sudo password per profile (same AES-256-GCM + Argon2 as SSH password, same master key). Only operation is copying it to clipboard. Example: `twc copy-sp <name>`.
- [ ] **Profile sharing**: Add `--share` flag to `twc copy <name> --share` and `--from-clip` flag to `twc add --from-clip` to make profiles portable between twc installations. For password profiles the encrypted password travels inside the blob. For key-based profiles the private key file bytes are embedded in the blob (encrypted with AES-256-GCM), and `--from-clip` writes the key to `~/.ssh/twc_<name>` on the recipient's machine — no out-of-band file transfer needed.
- [ ] **Profile sharing — TTL**: Extend `--share` with an optional `--ttl <value>` flag, e.g. `twc copy <name> --share --ttl 30M`. Supported units: `s` (seconds), `M` (minutes), `H` (hours), `d` (days), `m` (months), `y` (years) — note `M` vs `m` to avoid ambiguity; calendar units use fixed multipliers (`1m = 30d`, `1y = 365d`). The expiry timestamp is embedded in the plaintext before encryption, so AES-256-GCM authentication makes it tamper-proof — no one can extend the TTL without the master key. `twc add --from-clip` checks `now > expires_at` and rejects expired blobs before touching any credentials.
- [ ] **Config file permissions**: After writing `config.json`, restrict its permissions to owner-only (`0600` on Unix). The encrypted blobs are safe, but a world-readable config exposes the profile list, usernames, and hosts to any local user.

## Known bugs

- [x] **Config names|Command names Uniqueness**: `twc rename` and `twc add` allow setting a profile name to a reserved CLI subcommand (e.g. `add`, `list`, `remove`, `rename`, `show`, `edit`, `copy`), which makes the profile unreachable via `twc <name>`
- [ ] **Deduplicate master key prompt**: When `twc add` or `twc edit` is called with both `--password` and `--sudo-password`, the master key is prompted twice — once per secret — so the user could accidentally encrypt them under different keys. Prompt once and reuse the same master key for both secrets in the same invocation.
