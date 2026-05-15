# KeePassXC Browser API - Claude Code Instructions

## Project Overview

Python library implementing the KeePassXC browser extension protocol (NaCl-encrypted JSON over a Unix socket). Used by `keepassxc-cli` and `keepassxc-ssh-agent`.

## Architecture

- **`client.py`** — `BrowserClient`: handles connection, key exchange, association, and all API actions
- **`config.py`** — `BrowserConfig`: persistent config (keypair + associations) at `~/.keepassxc/browser-api.json`
- **`models.py`** — `Entry`, `Group` dataclasses for API responses
- **`exceptions.py`** — Custom exceptions hierarchy (`KeePassXCError` base); all public methods raise on failure — they never return `False` or `None`

### Exception Hierarchy

All methods raise on failure. Exception types:

| Exception | Raised when |
|---|---|
| `ConnectionError` | Cannot connect to the KeePassXC socket (not running / path not found) |
| `DatabaseLockedError` | Database unlock timeout exceeded (polling `get-databasehash` timed out) |
| `ProtocolError` | KeePassXC returned an error response in the JSON reply |
| `KeePassXCError` | Base class — catch this to handle all library errors |

`ProtocolError.error_code: int | None` carries the KeePassXC error enum value. Notable codes:
- `6` `ACTION_CANCELLED_OR_DENIED` — user denied the access prompt
- `15` `NO_LOGINS_FOUND` — caught internally by `get_logins()`; returns `[]` instead of raising
- `19` `ACCESS_TO_ALL_ENTRIES_DENIED` — "Allow access to all entries" dialog denied

All three exception classes are exported from the top-level package:
```python
from keepassxc_browser_api.exceptions import ConnectionError, DatabaseLockedError, ProtocolError
# or
from keepassxc_browser_api import ConnectionError, DatabaseLockedError, ProtocolError
```

### KeePassXC Browser Protocol Details

See **[PROTOCOL.md](PROTOCOL.md)** for the full protocol reference (wire format, encryption, all actions, error codes, source file links).

Quick summary:
- Socket: `$TMPDIR/org.keepassxc.KeePassXC.BrowserServer` (macOS), `$XDG_RUNTIME_DIR/.../org.keepassxc.KeePassXC.BrowserServer` (Linux)
- Every JSON message MUST include a `clientID` field; this library uses `"keepassxc-browser-api"`
- Key exchange via `change-public-keys` (unencrypted), all subsequent messages use NaCl `crypto_box`
- `get-databasehash` with `triggerUnlock=true` is NON-BLOCKING — returns immediately, must poll for unlock
- `test-associate` only works when DB is unlocked
- Relevant KeePassXC source: [`src/browser/BrowserAction.cpp`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp)

### Available API Actions

| Action | Method |
|---|---|
| `change-public-keys` | `change_public_keys()` |
| `associate` | `associate()` |
| `test-associate` | `test_associate(assoc)` |
| `get-databasehash` | `trigger_unlock()` / `ensure_unlocked()` |
| `get-logins` | `get_logins(url)` |
| `set-login` | `set_login(url, user, pw)` |
| `get-database-entries` | `get_database_entries()` |
| `get-database-groups` | `get_database_groups()` |
| `create-new-group` | `create_group(name)` |
| `get-totp` | `get_totp(uuid)` |
| `delete-entry` | `delete_entry(uuid)` |
| `lock-database` | `lock_database()` |
| `generate-password` | `generate_password()` |

## Commands

```shell
# Install
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=keepassxc_browser_api --cov-report=term-missing

# Lint
ruff check --ignore=E501 --exclude=__init__.py ./keepassxc_browser_api
```

## Conventions

- Python >= 3.10, no async (threading-based for simplicity)
- `from __future__ import annotations` in all source files
- PyNaCl for NaCl crypto (not raw libsodium)
- Config files use 0600 permissions (owner-only)
- Tests use `short_tmp` fixture for Unix socket paths (macOS `tmp_path` is too long for AF_UNIX)
- Shared config at `~/.keepassxc/browser-api.json` — consumed by both `keepassxc-cli` and `keepassxc-ssh-agent`

## CI

- `lint_and_test.yml` — Unit tests + ruff lint across Python 3.10–3.14
- `pypi.yml` — Build & publish on release, then dispatch to homebrew-tap to update the formula
- `auto-release.yml` — Auto-create patch release on dependabot merge
- `auto-merge-dependabot.yml` — Auto-merge dependabot PRs
