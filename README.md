# KeePassXC Browser API

Python library for communicating with [KeePassXC](https://keepassxc.org/) via the browser extension protocol (NaCl-encrypted JSON over a Unix socket).

## Features

- NaCl-encrypted communication with KeePassXC
- One-time association flow (user approves in KeePassXC window)
- Biometric unlock (TouchID / system unlock) via `triggerUnlock`
- Full browser API support: read entries, write entries, manage groups, TOTP, password generation, lock database
- Cross-platform: macOS and Linux
- Shared config (`~/.keepassxc/browser-api.json`) — associate once, use with all tools

## Installation

```shell
pip install keepassxc-browser-api
```

## Quick start

```python
from keepassxc_browser_api import BrowserClient, BrowserConfig

config = BrowserConfig.load()
client = BrowserClient(config)

# First time: associate with KeePassXC (requires user approval)
if not config.associations:
    client.setup()
    config.save()

# API methods auto-connect, auto-unlock (triggers TouchID/biometrics if locked),
# and verify the association before every call
entries = client.get_logins("https://example.com")
for e in entries:
    print(e.name, e.login)

# Clean up when done
client.disconnect()
```

Or use the context manager for automatic cleanup:

```python
with BrowserClient(config) as client:
    entries = client.get_logins("https://example.com")
    totp = client.get_totp(entries[0].uuid)
```

## API

### `BrowserClient`

| Method | Description |
|---|---|
| `setup()` | First-time association (user approves in KeePassXC) |
| `ensure_unlocked()` | Connect and unlock (triggers TouchID if locked) |
| `get_logins(url, ...)` | Find entries matching a URL |
| `set_login(url, username, password, ...)` | Create or update an entry |
| `get_database_entries()` | Return all entries |
| `get_database_groups()` | Return all groups (tree) |
| `create_group(name, parent_uuid)` | Create a new group |
| `get_totp(uuid)` | Get TOTP code for an entry |
| `delete_entry(uuid)` | Delete an entry |
| `lock_database()` | Lock the database |
| `generate_password()` | Generate a password (uses KeePassXC settings) |
| `request_autotype(search)` | Trigger KeePassXC global auto-type |

> **Note**: `passkeys-get` and `passkeys-register` are not implemented. They require complex WebAuthn/CBOR data structures and are only available in KeePassXC builds compiled with `WITH_XC_BROWSER_PASSKEYS`.

### `BrowserConfig`

Configuration stored at `~/.keepassxc/browser-api.json` (mode 0600).

```python
config = BrowserConfig.load()        # Load from default path
config = BrowserConfig.load(path)    # Load from custom path
config.save()                        # Save to default path
config.save(path)                    # Save to custom path
```

## Protocol documentation

For a detailed description of the KeePassXC browser extension protocol (wire format, encryption, all actions, error codes), see **[PROTOCOL.md](PROTOCOL.md)**.

## Development

```shell
# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=keepassxc_browser_api

# Lint
ruff check --ignore=E501 --exclude=__init__.py ./keepassxc_browser_api
```
