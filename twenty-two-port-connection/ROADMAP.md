# Roadmap

> Back to [README](README.md)

## Planned features

- Copy the SSH connection string for a profile to clipboard for easy sharing. Example: `twc copy <name>`. Warns if profile uses a key or password (neither is included in the copied string).
- Store an encrypted sudo password per profile (same AES-256-GCM + Argon2 as SSH password, same master key). Only operation is copying it to clipboard. Example: `twc copy-sp <name>`.

## Known bugs

- `twc rename` allows renaming a profile to a reserved CLI subcommand name (e.g. `add`, `list`, `remove`, `rename`, `show`, `edit`), which makes the profile unreachable via `twc <name>`
