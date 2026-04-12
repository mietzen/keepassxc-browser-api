# KeePassXC Browser Extension Protocol

This document describes the JSON-over-Unix-socket protocol used by the KeePassXC browser extension. The canonical KeePassXC implementation lives at [keepassxreboot/keepassxc](https://github.com/keepassxreboot/keepassxc). The most relevant source files are:

| File | Purpose |
|---|---|
| [`src/browser/BrowserAction.cpp`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp) | Per-action request handling, `triggerUnlock` logic, auth checks |
| [`src/browser/BrowserAction.h`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.h) | Action constants, `MaxUrlLength = 256` |
| [`src/browser/BrowserService.cpp`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserService.cpp) | `clientID` routing, socket message dispatch |
| [`src/browser/BrowserHost.cpp`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserHost.cpp) | Unix socket server, raw JSON read/write |
| [`src/browser/BrowserMessageBuilder.cpp`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserMessageBuilder.cpp) | NaCl encrypt/decrypt, nonce increment, error replies |
| [`src/browser/BrowserMessageBuilder.h`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserMessageBuilder.h) | Error code enum (values 1–33) |
| [`src/browser/BrowserShared.h`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserShared.h) | `NATIVEMSG_MAX_LENGTH = 1048576`, socket path helpers |
| [`src/browser/BrowserSettings.h`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserSettings.h) | `allowGetDatabaseEntriesRequest()` permission check |

---

## Transport

**Socket**: A Unix domain socket (type `SOCK_STREAM`) whose path varies by platform:

| Platform | Path |
|---|---|
| macOS | `$TMPDIR/org.keepassxc.KeePassXC.BrowserServer` |
| Linux (Flatpak) | `$XDG_RUNTIME_DIR/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer` |
| Linux (native) | `$XDG_RUNTIME_DIR/org.keepassxc.KeePassXC.BrowserServer` |

**Framing**: Messages are raw UTF-8 JSON with **no length prefix**. KeePassXC reads all available bytes with `socket->readAll()` and writes compact JSON back in a single `socket->write()` call. The max message size is **1 MB** (`NATIVEMSG_MAX_LENGTH = 1024 * 1024`).

> Source: [`BrowserHost.cpp#L77-L85`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserHost.cpp#L77)

---

## Client Identity (`clientID`)

Every message **must** include a top-level `"clientID"` string field.

```json
{ "action": "...", "clientID": "my-app-name", ... }
```

- If `clientID` is absent or empty, KeePassXC **silently drops** the message — no response is sent.
- KeePassXC maintains a separate `BrowserAction` state object per `clientID`. This means keypair negotiation and associations are scoped to a `clientID`. The same value must be used throughout a session.

> Source: [`BrowserService.cpp#L1774-L1784`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserService.cpp#L1774)

---

## Encryption

All actions except `change-public-keys` and `generate-password` use **NaCl `crypto_box_easy`** (Curve25519 + XSalsa20 + Poly1305).

**Key exchange summary**:
1. Client generates an ephemeral Curve25519 keypair (`client_pk`, `client_sk`).
2. Client sends `change-public-keys` (unencrypted) with `client_pk` and a random nonce.
3. KeePassXC responds with its own `server_pk` and echoes the nonce.
4. From this point on, both sides derive a shared box using `crypto_box_easy(client_sk, server_pk)`.

**Nonce management**:
- The client picks a random 24-byte nonce for each request.
- KeePassXC increments the nonce by 1 (`sodium_increment`, little-endian) before using it to encrypt the response.
- The client must decrypt using the incremented nonce (i.e. `nonce + 1`).

```
request nonce:   N
response nonce:  N + 1  (little-endian unsigned increment, all bytes)
```

> Source: [`BrowserMessageBuilder.cpp#L198-L260`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserMessageBuilder.cpp#L198) · [`BrowserMessageBuilder.cpp#L303`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserMessageBuilder.cpp#L303)

**Outer message** (always plaintext JSON):
```json
{
  "action":       "<action-name>",
  "message":      "<base64-encrypted-inner>",
  "nonce":        "<base64-24-byte-nonce>",
  "clientID":     "<string>",
  "triggerUnlock": "true"   // optional — see below
}
```

**Inner message** (decrypted payload):
```json
{
  "action":  "<action-name>",
  "version": "2.x.y",
  "success": "true",
  "nonce":   "<base64-incremented-nonce>",
  ...action-specific fields...
}
```

All binary data (public keys, nonces, ciphertext) is **standard Base64-encoded**.

---

## `triggerUnlock`

The outer (unencrypted) message may include `"triggerUnlock": "true"`. When present, KeePassXC will call `openDatabase(triggerUnlock=true)`, which shows the Quick Unlock / TouchID / biometrics dialog to the user.

- This call is **non-blocking** — KeePassXC returns `ERROR_KEEPASS_DATABASE_NOT_OPENED` immediately if the DB is still locked.
- Callers must poll by retrying the request until either the DB unlocks or a timeout is reached.

All actions except `change-public-keys` and `request-autotype` require the database to be open. If it is not, KeePassXC returns `ERROR_KEEPASS_DATABASE_NOT_OPENED` (code 1).

> Source: [`BrowserAction.cpp#L55-L72`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L55)

---

## Error Replies

On error, KeePassXC returns an **unencrypted** JSON object:
```json
{
  "action":    "<action-name>",
  "errorCode": "8",
  "error":     "KeePassXC association failed, try again"
}
```

All error codes are defined in [`BrowserMessageBuilder.h`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserMessageBuilder.h#L33):

| Code | Constant | Message |
|---|---|---|
| 1 | `ERROR_KEEPASS_DATABASE_NOT_OPENED` | Database not opened |
| 2 | `ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED` | Database hash not available |
| 3 | `ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED` | Client public key not received |
| 4 | `ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE` | Cannot decrypt message |
| 5 | `ERROR_KEEPASS_TIMEOUT_OR_NOT_CONNECTED` | Timeout or not connected |
| 6 | `ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED` | Action cancelled or denied |
| 7 | `ERROR_KEEPASS_CANNOT_ENCRYPT_MESSAGE` | Message encryption failed |
| 8 | `ERROR_KEEPASS_ASSOCIATION_FAILED` | KeePassXC association failed, try again |
| 9 | `ERROR_KEEPASS_KEY_CHANGE_FAILED` | Key change failed |
| 10 | `ERROR_KEEPASS_ENCRYPTION_KEY_UNRECOGNIZED` | Encryption key is not recognized |
| 11 | `ERROR_KEEPASS_NO_SAVED_DATABASES_FOUND` | No saved databases found |
| 12 | `ERROR_KEEPASS_INCORRECT_ACTION` | Incorrect action |
| 13 | `ERROR_KEEPASS_EMPTY_MESSAGE_RECEIVED` | Empty message received |
| 14 | `ERROR_KEEPASS_NO_URL_PROVIDED` | No URL provided |
| 15 | `ERROR_KEEPASS_NO_LOGINS_FOUND` | No logins found |
| 16 | `ERROR_KEEPASS_NO_GROUPS_FOUND` | No groups found |
| 17 | `ERROR_KEEPASS_CANNOT_CREATE_NEW_GROUP` | Cannot create new group |
| 18 | `ERROR_KEEPASS_NO_VALID_UUID_PROVIDED` | No valid UUID provided |
| 19 | `ERROR_KEEPASS_ACCESS_TO_ALL_ENTRIES_DENIED` | Access to all entries denied (see `get-database-entries`) |
| 20–33 | `ERROR_PASSKEYS_*` | Passkeys-specific errors (see header) |

---

## Broadcast Messages

KeePassXC sends **unsolicited broadcast messages** to all connected clients when the database state changes. These are **unencrypted**, contain no `clientID`, and arrive outside the normal request/response cycle:

| Action | Trigger |
|---|---|
| `database-locked` | Database was locked (by user, timeout, or a client's `lock-database` request) |
| `database-unlocked` | Database was unlocked |

```json
{ "action": "database-locked" }
```

> Source: [`BrowserService.cpp#L1727`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserService.cpp#L1727)

**Important**: For `lock-database` specifically, KeePassXC may send the `database-locked` broadcast **before** the encrypted `lock-database` response in the same socket write. Client implementations must handle potentially concatenated JSON objects in a single `recv()` buffer. Use `JSONDecoder.raw_decode()` (Python) or equivalent to parse only the first object.

---

## `m_associated` Flag and Session State

KeePassXC maintains a per-`clientID` `m_associated` boolean that is **reset to `false` on every `change-public-keys`** call. All authenticated actions (`get-logins`, `set-login`, `lock-database`, etc.) check this flag and return `ERROR_KEEPASS_ASSOCIATION_FAILED` (code 8) if it is not set.

**Consequence**: After every key exchange, clients **must** call `test-associate` before making any other authenticated request. Failure to do so returns error 8 silently.

**Recursion hazard**: `test-associate` must NOT be sent through the normal encrypted pipeline if that pipeline itself calls `test-associate` to verify the session — this creates infinite recursion. Implementations must use a lower-level send path (connect + key exchange only, no association check) when sending `test-associate` internally.

> Source: [`BrowserAction.cpp#L134`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L134) (reset on key exchange), [`BrowserAction.cpp#L219`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L219) (set on test-associate success)

---

### `change-public-keys`

Initiates the encrypted session. **Unencrypted** — no `message` wrapper.

> Source: [`BrowserAction.cpp#L125`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L125)

**Request** (outer, plaintext):
```json
{
  "action":    "change-public-keys",
  "publicKey": "<base64 client public key>",
  "nonce":     "<base64 24-byte random nonce>",
  "clientID":  "my-app"
}
```

**Response** (outer, plaintext):
```json
{
  "action":    "change-public-keys",
  "publicKey": "<base64 server public key>",
  "nonce":     "<base64 echoed nonce>",
  "success":   "true"
}
```

On failure (e.g. key already set and unrecognized): `errorCode: 9` or `10`.

---

### `associate`

Creates a permanent named association between this client and the database. KeePassXC shows a dialog asking the user to confirm and name the association. Requires DB to be open.

> Source: [`BrowserAction.cpp#L171`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L171)

**Inner request**:
```json
{
  "action": "associate",
  "key":    "<base64 client public key>",
  "idKey":  "<base64 separate identity public key>"
}
```

**Inner response**:
```json
{
  "action": "associate",
  "id":     "My App Name",
  "hash":   "<database hash hex string>"
}
```

The `id` string is the name the user gave the association. The `idKey` is a separate public key used only for association verification (not for message encryption). Store `id`, `idKey`, and the client keypair in persistent config.

On cancellation: `errorCode: 6`. On failure: `errorCode: 8`.

---

### `test-associate`

Verifies that a stored association is still valid for the currently open database. Returns an error if the DB is locked.

> Source: [`BrowserAction.cpp#L201`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L201)

**Inner request**:
```json
{
  "action": "test-associate",
  "id":     "My App Name",
  "key":    "<base64 idKey>"
}
```

**Inner response**:
```json
{
  "action": "test-associate",
  "id":     "My App Name",
  "hash":   "<database hash>"
}
```

On failure (DB locked, association not recognized): `errorCode: 8`.

---

### `get-databasehash`

Returns the hash of the currently open database. Used to verify the correct DB is open and as the key for storing per-DB associations. Can be combined with `triggerUnlock` to trigger the unlock dialog.

> Source: [`BrowserAction.cpp#L151`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L151)

**Inner request**:
```json
{ "action": "get-databasehash" }
```

**Inner response**:
```json
{
  "action": "get-databasehash",
  "hash":   "<hex string>"
}
```

On locked DB (without `triggerUnlock`): `errorCode: 1`.

---

### `get-logins`

Returns entries whose URL field matches the provided URL. KeePassXC applies its own URL-matching logic. Requires association.

> Source: [`BrowserAction.cpp#L225`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L225)

**Inner request**:
```json
{
  "action":    "get-logins",
  "url":       "https://example.com",
  "submitUrl": "https://example.com/login",
  "httpAuth":  "true",
  "keys": [
    { "id": "My App Name", "key": "<base64 idKey>" }
  ]
}
```

- `submitUrl`: Optional. Used for more precise form-action matching.
- `httpAuth`: Optional. Set `"true"` to search HTTP Basic Auth entries.
- `keys`: List of `{ id, key }` for all known associations (one per open database). KeePassXC matches on the `id`/`key` pair to verify authorization.
- `url` max length: **256 characters** (`BrowserAction::MaxUrlLength`).

**Inner response**:
```json
{
  "action":  "get-logins",
  "entries": [
    {
      "uuid":         "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name":         "Example",
      "login":        "user@example.com",
      "password":     "hunter2",
      "totp":         "",
      "group":        "Root/Work",
      "groupUuid":    "yyyyyyyy-...",
      "stringFields": [
        { "KPH: Notes": "some note" }
      ]
    }
  ]
}
```

On no matches: `errorCode: 15`. On no association: `errorCode: 8`.

---

### `set-login`

Creates a new entry or updates an existing one. Requires association. If `uuid` is provided, updates that entry; otherwise creates a new one.

> Source: [`BrowserAction.cpp#L294`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L294)

**Inner request**:
```json
{
  "action":    "set-login",
  "url":       "https://example.com",
  "submitUrl": "https://example.com/login",
  "id":        "My App Name",
  "login":     "user@example.com",
  "password":  "hunter2",
  "group":     "",
  "groupUuid": "",
  "uuid":      "",
  "keys": [
    { "id": "My App Name", "key": "<base64 idKey>" }
  ]
}
```

- `uuid`: If non-empty, updates the entry with that UUID. If empty, creates a new entry.
- `groupUuid`: Optional target group for new entries.

**Inner response**:
```json
{
  "action": "set-login",
  "count":  null,
  "entries": null,
  "error":  "success",
  "hash":   "<database hash>"
}
```

On invalid UUID: `errorCode: 18`. On cancellation: `errorCode: 6`.

---

### `get-database-entries`

Returns **all** entries in the database. Requires association and a specific user permission (Settings → Browser Integration → "Allow access to all entries").

> Source: [`BrowserAction.cpp#L392`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L392)
> Note: This action has no constant defined — it is matched as a raw string `"get-database-entries"` in the dispatch chain.

**Inner request**:
```json
{
  "action": "get-database-entries",
  "keys":   [ { "id": "My App Name", "key": "<base64 idKey>" } ]
}
```

**Inner response**:
```json
{
  "action":  "get-database-entries",
  "entries": [ { ...same shape as get-logins entry... } ]
}
```

On permission denied: `errorCode: 19`. On no entries: `errorCode: 16`.

---

### `get-database-groups`

Returns the full group tree of the database. Requires association.

> Source: [`BrowserAction.cpp#L367`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L367)

**Inner request**:
```json
{
  "action": "get-database-groups",
  "keys":   [ { "id": "My App Name", "key": "<base64 idKey>" } ]
}
```

**Inner response** (note the double-nesting):
```json
{
  "action": "get-database-groups",
  "groups": {
    "groups": [
      {
        "uuid":     "xxxxxxxx-...",
        "name":     "Root",
        "children": [
          { "uuid": "...", "name": "Email", "children": [] }
        ]
      }
    ]
  }
}
```

On no groups: `errorCode: 16`.

---

### `create-new-group`

Creates a new group. Requires association.

> Source: [`BrowserAction.cpp#L422`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L422)

**Inner request**:
```json
{
  "action":          "create-new-group",
  "groupName":       "New Group",
  "parentGroupUuid": "<uuid of parent group or empty for root>"
}
```

**Inner response**:
```json
{
  "action":    "create-new-group",
  "name":      "New Group",
  "uuid":      "<new group uuid>"
}
```

---

### `get-totp`

Returns the current TOTP code for an entry. Requires association.

> Source: [`BrowserAction.cpp#L448`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L448)

**Inner request**:
```json
{
  "action": "get-totp",
  "uuid":   "<entry uuid>"
}
```

**Inner response**:
```json
{
  "action": "get-totp",
  "totp":   "123456"
}
```

---

### `delete-entry`

Permanently deletes an entry by UUID. Requires association.

> Source: [`BrowserAction.cpp#L473`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L473)

**Inner request**:
```json
{
  "action": "delete-entry",
  "uuid":   "<entry uuid>"
}
```

**Inner response**:
```json
{
  "action": "delete-entry"
}
```

On invalid UUID: `errorCode: 18`.

---

### `lock-database`

Locks the currently open database. Requires association.

> Source: [`BrowserAction.cpp#L347`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L347)

**Inner request**:
```json
{
  "action": "lock-database"
}
```

**Response quirk**: KeePassXC calls `browserService()->lockDatabase()` before sending the response. This emits `databaseLocked` synchronously, which triggers a `database-locked` broadcast to all clients on the same socket **before** the encrypted `lock-database` response is written. In practice, a single `recv()` may contain `{"action":"database-locked"}{"action":"lock-database","nonce":"...","message":"..."}` concatenated.

Client implementations should parse only the first JSON object. Checking for the absence of `errorCode` (rather than attempting to decrypt a payload) is sufficient to confirm success.

---


### `generate-password`

Asks KeePassXC to generate a password using its configured generator. **This action is sent unencrypted** (no `message` wrapper), similar to `change-public-keys`. The response is partially encrypted.

> Source: [`BrowserAction.cpp#L265`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L265)

**Request** (outer, plaintext):
```json
{
  "action":   "generate-password",
  "nonce":    "<base64 random nonce>",
  "clientID": "my-app"
}
```

**Response** (outer, with encrypted `message`):
```json
{
  "action":  "generate-password",
  "nonce":   "<base64 incremented nonce>",
  "message": "<base64 encrypted inner>"
}
```

**Inner response** (decrypted):
```json
{
  "action":  "generate-password",
  "entries": [ { "login": "", "password": "Xk9#mQ2..." } ]
}
```

KeePassXC applies its own configured password profile; any parameters sent by the client are currently ignored.

---

### `request-autotype`

Triggers KeePassXC's global auto-type for the currently focused window. KeePassXC will show a picker if multiple entries match, or type immediately if only one matches. **Does not require association** (no `m_associated` check).

The `search` string is limited to **256 characters** (`BrowserAction::MaxUrlLength`).

> Source: [`BrowserAction.cpp#L500`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L500)

**Inner request**:
```json
{
  "action": "request-autotype",
  "search": "github.com"
}
```

**Inner response** (empty success):
```json
{
  "action": "request-autotype"
}
```

---

## Not Implemented: `passkeys-get` and `passkeys-register`

These two actions implement WebAuthn Passkeys authentication and registration. They require:

- KeePassXC compiled with `WITH_XC_BROWSER_PASSKEYS` (feature flag)
- Complex WebAuthn/CBOR `publicKey` credential request/creation option objects
- `origin` URL validation

They are **not implemented** in this library because the data structures are complex and use cases are browser-specific. If you need Passkeys support, refer to:

- [`BrowserAction.cpp#L523`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L523) — `passkeys-get`
- [`BrowserAction.cpp#L556`](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserAction.cpp#L556) — `passkeys-register`

---

## Typical Session Flow

```
Client                              KeePassXC
  |                                     |
  |-- change-public-keys (plaintext) -->|  (exchange Curve25519 keys)
  |<-- change-public-keys (plaintext) --|  (m_associated reset to false)
  |                                     |
  |-- test-associate ------------------>|  (must come before any auth request)
  |<-- ERROR: database not opened ------|  (DB locked → trigger unlock)
  |                                     |
  |-- get-databasehash (triggerUnlock) ->|  (show TouchID/biometrics dialog)
  |<-- ERROR: database not opened ------|  (non-blocking; poll until unlocked)
  |    ... retry after short delay ...  |
  |-- get-databasehash ----------------->|
  |<-- get-databasehash (hash: "abc") --|
  |                                     |
  |-- test-associate ------------------>|  (retry now that DB is open)
  |<-- test-associate (id: "My App") ---|  (m_associated set to true)
  |                                     |
  |-- get-logins (url: "...") -------->|  (fetch credentials)
  |<-- get-logins (entries: [...]) -----|
```

If no association exists, call `associate` after the key exchange step (and after unlocking). The user must approve the association in KeePassXC and provide a name for it.

**Key rules**:
1. `test-associate` must be called after every `change-public-keys` — KeePassXC resets `m_associated` on each key exchange.
2. `test-associate` itself only requires connection + key exchange (not a prior association). Do not route it through session management that itself calls `test-associate`.
3. If `test-associate` returns error 1 (DB not opened), trigger unlock and retry.

