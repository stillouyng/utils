# Roadmap

> Back to [README](README.md)

## Planned features

- [x] **Copy the config**: Copy SSH connection info for a profile to clipboard. Example: `twc copy <name>`. Notifies if the profile uses a key (identity file); otherwise prompts for the master key and copies the connection string with the decrypted password.
- [x] **Store and copy the sudo password**: Store an encrypted sudo password per profile (same AES-256-GCM + Argon2 as SSH password, same master key). Only operation is copying it to clipboard. Example: `twc copy-sp <name>`.
- [ ] **Profile sharing**: Add `--share` flag to the copy command (`twc copy <name> --share`) and `--from-clip` flag to the add command (`twc add --from-clip`) to make profiles portable between twc installations.

## Known bugs

- `twc rename` and `twc add` allow setting a profile name to a reserved CLI subcommand (e.g. `add`, `list`, `remove`, `rename`, `show`, `edit`, `copy`), which makes the profile unreachable via `twc <name>`
