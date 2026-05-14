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
        self._associated: bool = False

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
            self._associated = False

    def _ensure_session(self) -> bool:
        """Ensure there is an active connection with a verified association.

        Automatically connects, exchanges public keys, triggers biometric unlock
        if the database is locked, and verifies the association.
        Returns True if the session is ready, False on failure.
        """
        if self._socket and self._server_public_key and self._associated:
            return True
        if not self._socket:
            if not self.connect():
                return False
        if not self._server_public_key:
            if not self.change_public_keys():
                return False
        if not self._associated:
            if not self._run_test_associate(warn_on_failure=False):
                # DB may be locked — trigger biometric unlock and retry
                logger.info("Association failed; triggering database unlock...")
                if not self.trigger_unlock():
                    return False
                # trigger_unlock reconnects and re-exchanges keys internally
                if not self._run_test_associate():
                    return False
        return True

    def _ensure_keys(self) -> bool:
        """Ensure connection and key exchange only (no association check).

        Used internally by _test_associate_raw to avoid infinite recursion:
        test_associate must not call _ensure_session which calls _run_test_associate
        which calls test_associate again.
        """
        if not self._socket:
            if not self.connect():
                return False
        if not self._server_public_key:
            if not self.change_public_keys():
                return False
        return True

    def _run_test_associate(self, *, warn_on_failure: bool = True) -> bool:
        """Run test-associate for all stored associations.

        KeePassXC resets its internal m_associated flag on every key exchange.
        This must be called after change_public_keys() before any authenticated
        request (get-logins, set-login, lock-database, etc.).
        Returns True if at least one association is still valid.
        """
        if not self.config.associations:
            logger.warning("No associations stored — run setup() first")
            return False
        for association in self.config.associations.values():
            if self._test_associate_raw(association):
                self._associated = True
                return True
        if warn_on_failure:
            logger.warning("All stored associations are invalid — re-run setup()")
        return False

    # ------------------------------------------------------------------
    # Low-level messaging
    # ------------------------------------------------------------------

    def _send_json(self, msg: dict) -> dict | None:
        """Send a JSON message and read the JSON response.

        KeePassXC may send additional broadcast messages (e.g. ``database-locked``)
        immediately after the real response, concatenated in the same recv buffer.
        We parse only the first complete JSON object and discard the rest.
        """
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
            # Use JSONDecoder to parse only the first object; ignore any
            # trailing data (e.g. an unsolicited database-locked broadcast).
            obj, _ = json.JSONDecoder().raw_decode(response_data.decode("utf-8"))
            return obj
        except (OSError, json.JSONDecodeError, ValueError) as e:
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
            logger.warning("Error response for %s: %s (code %s)", action, response.get("error"), response.get("errorCode"))
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
        """Perform NaCl key exchange with KeePassXC.

        KeePassXC resets its m_associated flag on every key exchange, so
        test-associate must be called again afterwards.
        """
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
        self._associated = False  # KeePassXC resets m_associated on key exchange
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

    def _test_associate_raw(self, association: Association) -> bool:
        """Send test-associate using only connection + key exchange (no association check).

        This is the internal version used by _run_test_associate to avoid infinite
        recursion: calling test_associate → _send_encrypted → _ensure_session →
        _run_test_associate → test_associate.
        """
        if not self._ensure_keys():
            return False
        inner = {
            "action": "test-associate",
            "id": association.id,
            "key": association.id_key,
        }
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        encrypted = self._encrypt(inner, nonce)
        msg = {
            "action": "test-associate",
            "message": encrypted,
            "nonce": _b64encode(nonce),
        }
        response = self._send_json(msg)
        if not response or "errorCode" in response:
            return False
        resp_nonce_b64 = response.get("nonce", "")
        resp_message = response.get("message", "")
        if not resp_nonce_b64 or not resp_message:
            return False
        return self._decrypt(resp_message, _b64decode(resp_nonce_b64)) is not None

    def test_associate(self, association: Association) -> bool:
        """Test if an existing association is still valid."""
        return self._test_associate_raw(association)

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
        submit_url: str = "",
        uuid: str = "",
        group: str = "",
        group_uuid: str = "",
        download_favicon: bool = False,
    ) -> bool:
        """Create or update a login entry.

        Pass ``uuid`` to update an existing entry; omit to create a new one.

        The entry title is always derived from the URL hostname by KeePassXC;
        it cannot be set via the protocol.

        Args:
            url: The URL to associate with this entry.
            username: The username/login field.
            password: The password field.
            submit_url: Optional form submit URL.
            uuid: Existing entry UUID for updates.
            group: Target group name for new entries.
            group_uuid: Target group UUID for new entries. KeePassXC only
                performs the UUID lookup when ``group`` is also non-empty;
                if only ``group_uuid`` is supplied this method sets both
                fields automatically.
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
        if submit_url:
            inner["submitUrl"] = submit_url
        if uuid:
            inner["uuid"] = uuid
        if group_uuid and not group:
            # KeePassXC only enters UUID-based group lookup when "group" is
            # non-empty (BrowserService::addEntry). Supply group_uuid as the
            # trigger value so the UUID lookup is actually performed.
            inner["group"] = group_uuid
            inner["groupUuid"] = group_uuid
        else:
            if group:
                inner["group"] = group
            if group_uuid:
                inner["groupUuid"] = group_uuid
        if download_favicon:
            inner["downloadFavicon"] = "true"

        decrypted = self._send_encrypted("set-login", inner)
        return decrypted is not None

    def create_group(self, name: str) -> Group | None:
        """Create a new group in the database.

        KeePassXC creates groups by path: use ``/`` to create nested groups,
        e.g. ``"Work/Projects"`` creates *Projects* inside *Work*.
        If all path segments already exist, KeePassXC returns the existing
        leaf group without creating duplicates.

        Args:
            name: Group name or ``/``-separated path (e.g. ``"Parent/Child``).

        Returns:
            The newly created (or already-existing) Group, or None on failure.
        """
        inner: dict = {
            "action": "create-new-group",
            "groupName": name,
        }

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

        KeePassXC sends a bare response (no encrypted message) for this action,
        followed by an unsolicited database-locked broadcast. We check for the
        absence of an error code rather than trying to decrypt a payload.

        Returns:
            True if the lock command was accepted.
        """
        if not self._ensure_session():
            return False
        inner = {"action": "lock-database"}
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        encrypted = self._encrypt(inner, nonce)
        msg = {
            "action": "lock-database",
            "message": encrypted,
            "nonce": _b64encode(nonce),
        }
        response = self._send_json(msg)
        return response is not None and "errorCode" not in response


