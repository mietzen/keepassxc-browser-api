"""KeePassXC browser extension protocol client.

Implements the NaCl-encrypted protocol used by the KeePassXC browser extension
to communicate with the KeePassXC application.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import socket
import tempfile
import time

import nacl.exceptions
import nacl.public
import nacl.utils

from .config import Association, BrowserConfig
from .exceptions import AssociationError, NotAssociatedError, ProtocolError
from .models import Entry, Group

logger = logging.getLogger(__name__)

CLIENT_ID = "keepassxc-browser-api"


def _get_keepassxc_socket_path() -> str:
    """Get the KeePassXC browser extension socket path (platform-aware)."""
    # Linux: XDG_RUNTIME_DIR based path used by Flatpak / native installs
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    if xdg_runtime:
        flatpak_path = os.path.join(
            xdg_runtime, "app", "org.keepassxc.KeePassXC",
            "org.keepassxc.KeePassXC.BrowserServer",
        )
        if os.path.exists(flatpak_path):
            return flatpak_path
        native_path = os.path.join(xdg_runtime, "org.keepassxc.KeePassXC.BrowserServer")
        if os.path.exists(native_path):
            return native_path
    # macOS / fallback
    return os.path.join(tempfile.gettempdir(), "org.keepassxc.KeePassXC.BrowserServer")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data)


def _increment_nonce(nonce: bytes) -> bytes:
    """Increment a nonce by 1 (little-endian), matching sodium_increment().

    Processes all bytes regardless of carry to avoid timing side-channels.
    """
    n = bytearray(nonce)
    carry = 1
    for i in range(len(n)):
        val = n[i] + carry
        n[i] = val & 0xFF
        carry = val >> 8
    return bytes(n)


class BrowserClient:
    """Client for the KeePassXC browser extension protocol.

    Typical usage::

        config = BrowserConfig.load()
        client = BrowserClient(config)

        # First-time setup (requires user approval in KeePassXC)
        client.setup()
        config.save()

        # Ensure DB is unlocked (triggers TouchID/biometrics if locked)
        client.ensure_unlocked()

        # Use the API (auto-connects if needed)
        entries = client.get_logins("https://example.com")

        # Or use as a context manager
        with BrowserClient(config) as client:
            entries = client.get_logins("https://example.com")
    """

    def __init__(self, config: BrowserConfig):
        self.config = config
        self._socket: socket.socket | None = None
        self._server_public_key: nacl.public.PublicKey | None = None

        if config.client_public_key and config.client_secret_key:
            sk_bytes = _b64decode(config.client_secret_key)
            self._secret_key = nacl.public.PrivateKey(sk_bytes)
            self._public_key = self._secret_key.public_key
        else:
            self._secret_key = nacl.public.PrivateKey.generate()
            self._public_key = self._secret_key.public_key
            config.client_public_key = _b64encode(bytes(self._public_key))
            config.client_secret_key = _b64encode(bytes(self._secret_key))

    def __enter__(self) -> BrowserClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Connect to KeePassXC browser extension socket.

        Returns True on success, False if KeePassXC is not running.
        """
        path = _get_keepassxc_socket_path()
        try:
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.settimeout(5.0)
            self._socket.connect(path)
            logger.debug("Connected to KeePassXC at %s", path)
            return True
        except OSError as e:
            logger.error("Cannot connect to KeePassXC browser socket at %s: %s", path, e)
            self._socket = None
            return False

    def disconnect(self) -> None:
        """Close the connection and clear session state."""
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
            self._server_public_key = None

    def _ensure_session(self) -> bool:
        """Ensure there is an active connection with completed key exchange.

        Automatically connects and exchanges public keys if needed.
        Returns True if the session is ready, False on failure.
        """
        if self._socket and self._server_public_key:
            return True
        if not self._socket:
            if not self.connect():
                return False
        if not self._server_public_key:
            if not self.change_public_keys():
                return False
        return True

    # ------------------------------------------------------------------
    # Low-level messaging
    # ------------------------------------------------------------------

    def _send_json(self, msg: dict) -> dict | None:
        """Send a JSON message and read the JSON response."""
        if not self._socket:
            return None

        msg["clientID"] = CLIENT_ID

        data = json.dumps(msg).encode("utf-8")
        try:
            self._socket.sendall(data)
        except OSError as e:
            logger.error("Failed to send message: %s", e)
            return None

        try:
            self._socket.settimeout(self.config.unlock_timeout)
            response_data = self._socket.recv(1024 * 1024)
            if not response_data:
                return None
            return json.loads(response_data)
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Failed to read response: %s", e)
            return None

    def _encrypt(self, message: dict, nonce: bytes) -> str:
        """Encrypt a JSON message using NaCl crypto_box."""
        if not self._server_public_key:
            raise ProtocolError("No server public key (call change_public_keys first)")

        box = nacl.public.Box(self._secret_key, self._server_public_key)
        plaintext = json.dumps(message).encode("utf-8")
        encrypted = box.encrypt(plaintext, nonce)
        return _b64encode(encrypted.ciphertext)

    def _decrypt(self, encrypted_b64: str, nonce: bytes) -> dict | None:
        """Decrypt a NaCl-encrypted response."""
        if not self._server_public_key:
            return None

        box = nacl.public.Box(self._secret_key, self._server_public_key)
        try:
            ciphertext = _b64decode(encrypted_b64)
            plaintext = box.decrypt(ciphertext, nonce)
            return json.loads(plaintext)
        except (nacl.exceptions.CryptoError, json.JSONDecodeError, ValueError) as e:
            logger.error("Failed to decrypt message: %s", e)
            return None

    def _send_encrypted(self, action: str, inner: dict, *, timeout: float | None = None) -> dict | None:
        """Send an encrypted action message and return the decrypted response.

        Automatically connects and performs key exchange if needed.
        Returns the decrypted inner dict, or None on failure.
        """
        if not self._ensure_session():
            return None
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        encrypted = self._encrypt(inner, nonce)
        msg = {
            "action": action,
            "message": encrypted,
            "nonce": _b64encode(nonce),
        }

        if timeout is not None and self._socket:
            old_timeout = self._socket.gettimeout()
            self._socket.settimeout(timeout)

        response = self._send_json(msg)

        if timeout is not None and self._socket:
            self._socket.settimeout(old_timeout)

        if not response:
            return None
        if "errorCode" in response:
            logger.debug("Error response for %s: %s (code %s)", action, response.get("error"), response.get("errorCode"))
            return None

        resp_nonce_b64 = response.get("nonce", "")
        resp_message = response.get("message", "")
        if not resp_nonce_b64 or not resp_message:
            logger.error("Missing nonce or message in response for %s", action)
            return None

        resp_nonce = _b64decode(resp_nonce_b64)
        return self._decrypt(resp_message, resp_nonce)

    # ------------------------------------------------------------------
    # Protocol: key exchange & association
    # ------------------------------------------------------------------

    def change_public_keys(self) -> bool:
        """Perform NaCl key exchange with KeePassXC."""
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        msg = {
            "action": "change-public-keys",
            "publicKey": _b64encode(bytes(self._public_key)),
            "nonce": _b64encode(nonce),
        }

        response = self._send_json(msg)
        if not response:
            logger.error("No response to change-public-keys")
            return False

        if "errorCode" in response:
            logger.error("Key exchange failed: %s", response.get("error"))
            return False

        server_pk_b64 = response.get("publicKey")
        if not server_pk_b64:
            logger.error("No server public key in response")
            return False

        self._server_public_key = nacl.public.PublicKey(_b64decode(server_pk_b64))
        logger.debug("Key exchange successful")
        return True

    def associate(self) -> Association | None:
        """Associate with KeePassXC (one-time, requires user approval in KeePassXC).

        Returns the Association on success, or None on failure.
        """
        id_key = nacl.public.PrivateKey.generate()
        id_public_key = id_key.public_key

        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        inner = {
            "action": "associate",
            "key": _b64encode(bytes(self._public_key)),
            "idKey": _b64encode(bytes(id_public_key)),
        }
        encrypted = self._encrypt(inner, nonce)
        msg = {
            "action": "associate",
            "message": encrypted,
            "nonce": _b64encode(nonce),
        }

        old_timeout = self._socket.gettimeout() if self._socket else 30
        if self._socket:
            self._socket.settimeout(120)

        response = self._send_json(msg)

        if self._socket:
            self._socket.settimeout(old_timeout)

        if not response or "errorCode" in response:
            err = response.get("error") if response else "no response"
            raise AssociationError(f"Association failed: {err}")

        resp_nonce = _b64decode(response.get("nonce", ""))
        resp_message = response.get("message", "")
        if not resp_message:
            raise AssociationError("No encrypted message in associate response")

        decrypted = self._decrypt(resp_message, resp_nonce)
        if not decrypted:
            raise AssociationError("Failed to decrypt associate response")

        assoc_id = decrypted.get("id")
        db_hash = decrypted.get("hash")
        if not assoc_id:
            raise AssociationError("No association ID in response")

        association = Association(
            id=assoc_id,
            id_key=_b64encode(bytes(id_public_key)),
            key=_b64encode(bytes(id_key)),
        )

        if db_hash:
            self.config.associations[db_hash] = association

        logger.info("Associated with KeePassXC (id=%s)", assoc_id)
        return association

    def test_associate(self, association: Association) -> bool:
        """Test if an existing association is still valid."""
        inner = {
            "action": "test-associate",
            "id": association.id,
            "key": association.id_key,
        }
        result = self._send_encrypted("test-associate", inner)
        return result is not None

    def _get_connection_keys(self) -> list[dict]:
        """Build the keys array from stored associations for authenticated requests."""
        return [
            {"id": assoc.id, "key": assoc.id_key}
            for assoc in self.config.associations.values()
        ]

    # ------------------------------------------------------------------
    # Protocol: database hash / unlock
    # ------------------------------------------------------------------

    def _send_get_databasehash(self, trigger_unlock: bool = False) -> dict | None:
        """Send a get-databasehash request. Returns raw response dict."""
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        inner = {"action": "get-databasehash"}
        encrypted = self._encrypt(inner, nonce)
        msg = {
            "action": "get-databasehash",
            "message": encrypted,
            "nonce": _b64encode(nonce),
        }
        if trigger_unlock:
            msg["triggerUnlock"] = "true"
        return self._send_json(msg)

    def trigger_unlock(self) -> bool:
        """Trigger KeePassXC database unlock (biometrics/TouchID).

        Sends get-databasehash with triggerUnlock=true (non-blocking), then
        polls until the DB is unlocked or the timeout expires.

        Returns True if the database is now unlocked.
        """
        logger.debug("Sending get-databasehash with triggerUnlock=true")
        response = self._send_get_databasehash(trigger_unlock=True)

        if not response:
            logger.error("No response to unlock trigger")
            return False

        if "errorCode" not in response:
            logger.info("Database was already unlocked")
            return True

        error_code = response.get("errorCode")
        if error_code != "1":
            logger.error("Unlock failed: %s (code %s)", response.get("error"), error_code)
            return False

        logger.info("Unlock dialog triggered, waiting for user to authenticate...")
        deadline = time.monotonic() + self.config.unlock_timeout
        poll_interval = 1.0

        while time.monotonic() < deadline:
            time.sleep(poll_interval)

            self.disconnect()
            if not self.connect():
                continue
            if not self.change_public_keys():
                continue

            response = self._send_get_databasehash(trigger_unlock=False)
            if not response:
                continue

            if "errorCode" not in response:
                logger.info("Database unlocked successfully")
                return True

            logger.debug("Still locked, polling...")

        logger.warning("Timeout waiting for database unlock")
        return False

    def ensure_unlocked(self) -> bool:
        """Connect and ensure the database is unlocked.

        Handles the full flow: connect → key exchange → trigger unlock.
        Returns True if the database is now unlocked.

        Raises NotAssociatedError if no associations are configured.
        """
        if not self.config.associations:
            raise NotAssociatedError("No associations configured. Run setup() first.")

        if not self.connect():
            return False

        try:
            if not self.change_public_keys():
                return False
            return self.trigger_unlock()
        finally:
            self.disconnect()

    def setup(self) -> bool:
        """Perform initial setup: connect, key exchange, and associate.

        The user must approve the association in the KeePassXC window.
        Returns True on success.

        Raises AssociationError if the user denies or an error occurs.
        """
        if not self.connect():
            return False

        try:
            if not self.change_public_keys():
                return False

            print("Requesting association with KeePassXC...")
            print("Please approve the association in the KeePassXC window.")

            association = self.associate()
            if not association:
                return False

            print(f"Association successful! ID: {association.id}")
            return True
        finally:
            self.disconnect()

    # ------------------------------------------------------------------
    # API: read operations
    # ------------------------------------------------------------------

    def get_logins(
        self,
        url: str,
        submit_url: str = "",
        http_auth: bool = False,
    ) -> list[Entry]:
        """Return entries matching the given URL.

        KeePassXC matches entries whose URL field matches ``url``.

        Args:
            url: The site URL to look up (e.g. "https://example.com").
            submit_url: Optional form submission URL for more precise matching.
            http_auth: Set True to search HTTP Basic Auth entries.

        Returns:
            List of matching entries.
        """
        inner: dict = {
            "action": "get-logins",
            "url": url,
            "keys": self._get_connection_keys(),
        }
        if submit_url:
            inner["submitUrl"] = submit_url
        if http_auth:
            inner["httpAuth"] = "true"

        decrypted = self._send_encrypted("get-logins", inner)
        if not decrypted:
            return []

        return [Entry.from_dict(e) for e in decrypted.get("entries", [])]

    def get_database_entries(self) -> list[Entry]:
        """Return all entries in the database.

        Returns:
            List of all entries.
        """
        inner = {
            "action": "get-database-entries",
            "keys": self._get_connection_keys(),
        }
        decrypted = self._send_encrypted("get-database-entries", inner)
        if not decrypted:
            return []

        return [Entry.from_dict(e) for e in decrypted.get("entries", [])]

    def get_database_groups(self) -> list[Group]:
        """Return all groups in the database as a tree.

        Returns:
            List of root groups; each group has a ``children`` attribute.
        """
        inner = {"action": "get-database-groups"}
        decrypted = self._send_encrypted("get-database-groups", inner)
        if not decrypted:
            return []

        groups_data = decrypted.get("groups", {})
        # KeePassXC returns {"groups": {"groups": [...]}}
        if isinstance(groups_data, dict):
            groups_data = groups_data.get("groups", [])

        return [Group.from_dict(g) for g in groups_data]

    def get_totp(self, uuid: str) -> str | None:
        """Return the current TOTP code for an entry.

        Args:
            uuid: The entry UUID.

        Returns:
            TOTP code string, or None if the entry has no TOTP configured.
        """
        inner = {
            "action": "get-totp",
            "uuid": uuid,
        }
        decrypted = self._send_encrypted("get-totp", inner)
        if not decrypted:
            return None
        return decrypted.get("totp") or None

    # ------------------------------------------------------------------
    # API: write operations
    # ------------------------------------------------------------------

    def set_login(
        self,
        url: str,
        username: str,
        password: str,
        *,
        title: str = "",
        submit_url: str = "",
        uuid: str = "",
        group: str = "",
        group_uuid: str = "",
        download_favicon: bool = False,
    ) -> bool:
        """Create or update a login entry.

        Pass ``uuid`` to update an existing entry; omit to create a new one.

        Args:
            url: The URL to associate with this entry.
            username: The username/login field.
            password: The password field.
            title: Optional entry title (defaults to the URL hostname in KeePassXC).
            submit_url: Optional form submit URL.
            uuid: Existing entry UUID for updates.
            group: Target group name for new entries.
            group_uuid: Target group UUID for new entries.
            download_favicon: Ask KeePassXC to download the site's favicon.

        Returns:
            True on success.
        """
        inner: dict = {
            "action": "set-login",
            "url": url,
            "login": username,
            "password": password,
            "keys": self._get_connection_keys(),
        }
        if title:
            inner["id"] = title
        if submit_url:
            inner["submitUrl"] = submit_url
        if uuid:
            inner["uuid"] = uuid
        if group:
            inner["group"] = group
        if group_uuid:
            inner["groupUuid"] = group_uuid
        if download_favicon:
            inner["downloadFavicon"] = "true"

        decrypted = self._send_encrypted("set-login", inner)
        return decrypted is not None

    def create_group(self, name: str, parent_group_uuid: str = "") -> Group | None:
        """Create a new group in the database.

        Args:
            name: Group name.
            parent_group_uuid: UUID of the parent group. If empty, creates at root.

        Returns:
            The newly created Group, or None on failure.
        """
        inner: dict = {
            "action": "create-new-group",
            "groupName": name,
        }
        if parent_group_uuid:
            inner["groupUuid"] = parent_group_uuid

        decrypted = self._send_encrypted("create-new-group", inner)
        if not decrypted:
            return None

        return Group(
            uuid=decrypted.get("uuid", ""),
            name=decrypted.get("name", name),
        )

    def delete_entry(self, uuid: str) -> bool:
        """Delete an entry by UUID.

        Args:
            uuid: The entry UUID to delete.

        Returns:
            True on success.
        """
        inner = {
            "action": "delete-entry",
            "uuid": uuid,
        }
        decrypted = self._send_encrypted("delete-entry", inner)
        return decrypted is not None

    def lock_database(self) -> bool:
        """Lock the KeePassXC database.

        Returns:
            True if the lock command was accepted.
        """
        inner = {"action": "lock-database"}
        decrypted = self._send_encrypted("lock-database", inner)
        return decrypted is not None

    def request_autotype(self, search: str = "") -> bool:
        """Trigger KeePassXC's global auto-type for the active window.

        KeePassXC will show an entry picker if multiple matches are found,
        or auto-fill immediately when there is exactly one match.

        Does not require an existing association.

        Args:
            search: Optional search string (e.g. domain) to pre-filter entries.
                    KeePassXC ignores strings longer than 256 characters.

        Returns:
            True if KeePassXC accepted the request.
        """
        inner: dict = {"action": "request-autotype"}
        if search:
            inner["search"] = search
        decrypted = self._send_encrypted("request-autotype", inner)
        return decrypted is not None

    def generate_password(self) -> str | None:
        """Ask KeePassXC to generate a password.

        KeePassXC uses its own configured generator settings; there are no
        client-side parameters — the password profile is configured in the
        KeePassXC application settings.

        Note: Unlike other actions, the request is sent unencrypted but the
        response is encrypted using the session keys.

        Returns:
            Generated password string, or None on failure.
        """
        if not self._ensure_session():
            return None
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        msg = {
            "action": "generate-password",
            "nonce": _b64encode(nonce),
        }
        response = self._send_json(msg)
        if not response or "errorCode" in response:
            return None

        resp_nonce_b64 = response.get("nonce", "")
        resp_message = response.get("message", "")
        if not resp_message or not resp_nonce_b64:
            return None

        resp_nonce = _b64decode(resp_nonce_b64)
        decrypted = self._decrypt(resp_message, resp_nonce)
        if not decrypted:
            return None

        entries = decrypted.get("entries", [])
        if entries and isinstance(entries, list):
            return entries[0].get("password") or None
        return decrypted.get("password") or None
