# twc — twc

> **Language:** **English** | [Русский](../ru/README.md)

A tiny SSH connection manager. Store your SSH profiles and connect with a single command.

## Features

- Connect to saved SSH profiles instantly
- Encrypted password storage (AES-256-GCM + Argon2)
- Key-based and passwordless auth support
- Linux and macOS: full support including password-based auth
- Windows: key-based and passwordless auth only (`sshpass` is not available on Windows)

## Roadmap & known bugs

See [ROADMAP.md](ROADMAP.md) for planned features and known issues.

Also, make sure you checked [VULNERABILITIES.md](VULNERABILITIES.md) for known security limitations.

## Installation

### macOS (Apple Silicon)

```bash
curl -L https://github.com/stillouyng/twc/releases/latest/download/twc-macos-aarch64 -o twc
chmod +x twc
sudo mv twc /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/twc  # bypass Gatekeeper
```

### macOS (Intel)

```bash
curl -L https://github.com/stillouyng/twc/releases/latest/download/twc-macos-x86_64 -o twc
chmod +x twc
sudo mv twc /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/twc
```

### Linux

```bash
curl -L https://github.com/stillouyng/twc/releases/latest/download/twc-linux-x86_64 -o twc
chmod +x twc
sudo mv twc /usr/local/bin/
```

### Windows

Download `twc-windows-x86_64.exe` from the [latest release](https://github.com/stillouyng/twc/releases/latest), rename it to `twc.exe` and place it somewhere in your PATH.

> **Note:** `sshpass` is not available on Windows, so password-based profiles (`--password`) are not supported. Use key-based (`--key`) or passwordless auth instead.

## Dependencies

| Dependency | Required for | Install |
|---|---|---|
| `sshpass` | Password-based auth (`twc <name>` with `--password` profiles) | `sudo apt install sshpass` / `brew install sshpass` |
| `ssh` | Everything | Pre-installed on Linux and macOS; on Windows use OpenSSH from Settings |

`sshpass` is **not needed** if you only use key-based or passwordless profiles.

## Usage

```bash
# Add a profile (passwordless / key-based)
twc add <name> <user> <host>
twc add <name> <user> <host> --port 2222
twc add <name> <user> <host> --key ~/.ssh/id_ed25519

# Add a profile with an encrypted SSH password
twc add <name> <user> <host> --password
# → prompts for SSH password, then master key (used to encrypt it)

# Connect
twc <name>

# List all profiles
twc list

# Remove a profile
twc remove <name>
```

## Password encryption

Passwords are never stored in plaintext. They are encrypted with AES-256-GCM using a key derived from your master key via Argon2. The master key is never stored anywhere — you are prompted for it on every connection.

## Using password-protected SSH keys

Add your key to the SSH agent once and `twc` will pick it up automatically:

```bash
ssh-add ~/.ssh/id_ed25519
twc add prod user host --key ~/.ssh/id_ed25519
twc prod  # no passphrase prompt
```

On macOS the agent persists across reboots via Keychain. On Linux you'll need to re-run `ssh-add` after each restart.

## Building from source

```bash
git clone https://github.com/stillouyng/twc
cd twc
cargo build --release
```