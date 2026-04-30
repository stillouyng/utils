# Security Limitations

> **Language:** **English** | [Русский](../ru/VULNERABILITIES.md)

> Back to [README](README.md)

This document describes known security limitations of twc that cannot be fully resolved within the current local-only, zero-server architecture. These are disclosed transparently so users can make informed trust decisions.

---

## TTL is cooperative, not cryptographic

**Affects:** `twc copy --share --ttl`

The recipient of a shared blob holds the ECIES private key needed to decrypt it. Because decryption is entirely local, a determined recipient can always read the blob contents — including `expires_at` — regardless of what the application layer enforces. Concretely:

- They can use a modified twc binary that ignores `expires_at`.
- They can download an old twc binary from before TTL support existed.
- They can decode and inspect the blob manually using standard crypto libraries.

**What twc does mitigate:**

| Mitigation | What it stops |
|---|---|
| TTL blobs use `TWC3:` prefix | Old clients fail hard instead of silently bypassing TTL |
| `twc copy` / `twc copy-sp` blocked on shared profiles | Credential extraction via twc commands after import |
| SSH blocked for expired shared profiles | Convenient access after expiry for cooperative recipients |
| `expires_at` is AES-256-GCM authenticated | Nobody can extend the TTL without the recipient's private key |

**What it does not mitigate:**

A recipient who deliberately wants to bypass the TTL can do so. TTL in twc is an **access-window agreement between cooperative parties**, not a hard cryptographic guarantee.

**Full fix:** Server-side enforcement via a `twc-handler` daemon on the target SSH server (see [ROADMAP.md — Future](ROADMAP.md)). The server would validate a time-limited token before allowing the connection, making expiry enforceable even against a recipient who has decrypted the blob.
