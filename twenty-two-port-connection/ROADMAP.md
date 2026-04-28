# Roadmap

> Back to [README](README.md)

## Upcoming

- [ ] **Config file permissions**: After writing `config.json`, restrict its permissions to owner-only (`0600` on Unix). The encrypted blobs are safe, but a world-readable config exposes the profile list, usernames, and hosts to any local user.
- [ ] **sshpass cmdline hardening**: `twc <name>` currently spawns `sshpass -p <cleartext>`, which exposes the password in the process cmdline (`/proc/<pid>/cmdline`) to other local processes for the duration of the SSH session. Fix: write the password to a pipe and pass the read-end file descriptor via `sshpass -d <fd>` — the password never appears in the cmdline.
- [ ] **Zeroize in-memory secrets**: Decrypted passwords and keys are held as plain `String`/`Vec<u8>` on the heap; Rust does not zero memory on drop. A process memory dump could expose them. Fix: wrap sensitive decrypted values in `zeroize::Zeroizing<T>` so they are scrubbed from memory as soon as they go out of scope. (The X25519 identity private key is already protected — `x25519-dalek` uses `zeroize` internally.)
- [ ] **SCP** - handle scp w/out inputting the password: `twc scp <name>`.
## Known bugs

- [ ] **Deduplicate master key prompt**: When `twc add` or `twc edit` is called with both `--password` and `--sudo-password`, the master key is prompted twice — once per secret — so the user could accidentally encrypt them under different keys. Prompt once and reuse the same master key for both secrets in the same invocation.
- [ ] **`twc share-key` pubkey showing logic**: The key should be also copied into the clipboard as a default behavior.
## Future (post-v1.0.0)

- [ ] **`twc-handler` — server-side TTL and revocation**: A companion daemon (PAM module or `AuthorizedKeysCommand` hook) running on the target SSH server. Instead of sharing raw credentials, `twc copy --share` would issue a time-limited twc token; the server-side handler validates the token against a revocation list before allowing the connection. This shifts TTL enforcement from the client (advisory) to the server (hard), making expiry cryptographically unavoidable even if the recipient holds the decrypted credential. Requires a daemon installed on every target server — a fundamentally different deployment model from the current zero-server-dependency design.

## Released

<details>
<summary><b>TTL bug fixes</b> — sharing hardening</summary>

- **`--share` wrong flag name**: help examples and runtime error now both correctly reference `--for-key` instead of `--for`.
- **`--share --ttl` plaintext-leaks**: `twc copy` and `twc copy-sp` now block credential extraction from any shared profile.
- **`--share --ttl` profiles not marked in storage**: `SSHConfig` now carries `shared` and `expires_at`; `twc list` shows `[shared]` / `[shared · expired]` badges, `twc show` prints the expiry countdown, SSH is blocked post-expiry, and editing is blocked entirely.
- **`--share --ttl` backward compatibility**: TTL blobs now use the `TWC3:` prefix so old clients (which only accept `TWC2:`) fail with a hard error instead of silently importing and ignoring `expires_at`. See [VULNERABILITIES.md](VULNERABILITIES.md) for the remaining cooperative-trust limitation.

</details>

<details>
<summary><b>Profile sharing - TTL</b></summary>

Extend `--share` with an optional `--ttl <value>` flag, e.g. `twc copy <name> --share --for <pubkey> --ttl 30M`. Supported units: `s` (seconds), `M` (minutes), `H` (hours), `d` (days), `m` (months), `y` (years) — note `M` vs `m` to avoid ambiguity; calendar units use fixed multipliers (`1m = 30d`, `1y = 365d`). The expiry timestamp is embedded in the `ShareBlob` plaintext before ECIES encryption, so AES-256-GCM authentication makes it tamper-proof — no one can extend the TTL without the recipient's private key. `twc add --from-clip` checks `now > expires_at` and rejects expired blobs before touching any credentials.

</details>

<details>
<summary><b>Profile sharing</b> — <code>twc copy &lt;name&gt; --share --for &lt;pubkey&gt;</code> / <code>twc add --from-clip</code> / <code>twc share-key</code></summary>

`twc copy <name> --share --for <pubkey>` encrypts a portable profile blob for a specific recipient using ECIES (ephemeral X25519 + HKDF-SHA256 + AES-256-GCM). Secrets travel as plaintext *inside* the encrypted envelope — the sender decrypts them locally before building the blob, so the sender's master key never leaves their machine. `twc add --from-clip` decrypts with the recipient's identity key and re-encrypts all secrets under the recipient's own master key. For key-based profiles the private key bytes are embedded in the blob and written to `~/.ssh/twc_<name>` on import. The recipient's X25519 keypair is auto-generated on first `twc share-key` call and stored encrypted (Argon2 + AES-256-GCM) under their master key — same root of trust as everything else.

</details>

<details>
<summary><b>Store and copy the sudo password</b> — <code>twc copy-sp &lt;name&gt;</code></summary>

Store an encrypted sudo password per profile (same AES-256-GCM + Argon2 as SSH password, same master key). Only operation is copying it to clipboard. Example: `twc copy-sp <name>`.

</details>

<details>
<summary><b>Copy the config</b> — <code>twc copy &lt;name&gt;</code></summary>

Copy SSH connection info for a profile to clipboard. Notifies if the profile uses a key (identity file); otherwise prompts for the master key and copies the connection string with the decrypted password.

</details>

<details>
<summary><b>Config names | Command names uniqueness</b> (bug fix)</summary>

`twc rename` and `twc add` previously allowed setting a profile name to a reserved CLI subcommand (e.g. `add`, `list`, `remove`, `rename`, `show`, `edit`, `copy`), which made the profile unreachable via `twc <name>`.

</details>
