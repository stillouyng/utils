# twc — twenty-two-port-connection

A tiny SSH connection manager. Store your SSH profiles and connect with a single command.

## Features

- Connect to saved SSH profiles instantly
- Encrypted password storage (AES-256-GCM + Argon2)
- Key-based and passwordless auth support
- Cross-platform: Windows, Linux, macOS

## Installation

### macOS (Apple Silicon)

```bash
curl -L https://github.com/stillouyng/twenty-two-port-connection/releases/latest/download/twc-macos-aarch64 -o twc
chmod +x twc
sudo mv twc /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/twc  # bypass Gatekeeper
```

### macOS (Intel)

```bash
curl -L https://github.com/YOUR_USER/twenty-two-port-connection/releases/latest/download/twc-macos-x86_64 -o twc
chmod +x twc
sudo mv twc /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/twc
```

### Linux

```bash
curl -L https://github.com/YOUR_USER/twenty-two-port-connection/releases/latest/download/twc-linux-x86_64 -o twc
chmod +x twc
sudo mv twc /usr/local/bin/
```

### Windows

Download `twc-windows-x86_64.exe` from the [latest release](https://github.com/YOUR_USER/twenty-two-port-connection/releases/latest), rename it to `twc.exe` and place it somewhere in your PATH.

## Usage

```bash
# Add a profile (passwordless / key-based)
twc add_config <name> <user> <host>
twc add_config <name> <user> <host> --port 2222
twc add_config <name> <user> <host> --key ~/.ssh/id_ed25519

# Add a profile with an encrypted SSH password
twc add_config <name> <user> <host> --password
# → prompts for SSH password, then master key (used to encrypt it)

# Connect
twc <name>

# List all profiles
twc all_configs

# Remove a profile
twc remove_config <name>
```

## Password encryption

Passwords are never stored in plaintext. They are encrypted with AES-256-GCM using a key derived from your master key via Argon2. The master key is never stored anywhere — you are prompted for it on every connection.

## Using password-protected SSH keys

Add your key to the SSH agent once and `twc` will pick it up automatically:

```bash
ssh-add ~/.ssh/id_ed25519
twc add_config prod user host --key ~/.ssh/id_ed25519
twc prod  # no passphrase prompt
```

On macOS the agent persists across reboots via Keychain. On Linux you'll need to re-run `ssh-add` after each restart.

## Building from source

```bash
git clone https://github.com/YOUR_USER/twenty-two-port-connection
cd twenty-two-port-connection
cargo build --release
```
