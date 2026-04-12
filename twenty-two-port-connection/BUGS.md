# Known Bugs

> Back to [README](README.md)

- `twc rename` allows renaming a profile to a reserved CLI subcommand name (e.g. `add`, `list`, `remove`, `rename`, `show`, `edit`), which makes the profile unreachable via `twc <name>`
