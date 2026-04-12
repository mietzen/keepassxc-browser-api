"""Tests for the KeePassXC browser protocol client."""

from __future__ import annotations

import base64
import json
import socket
import threading

import nacl.public
import nacl.utils
import pytest

from keepassxc_browser_api.client import (
    BrowserClient,
    _b64decode,
    _b64encode,
    _increment_nonce,
    CLIENT_ID,
)
from keepassxc_browser_api.config import Association, BrowserConfig
from keepassxc_browser_api.exceptions import AssociationError, NotAssociatedError
from keepassxc_browser_api.models import Entry, Group


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_b64_roundtrip(self):
        data = b"\x00\x01\x02\xff"
        assert _b64decode(_b64encode(data)) == data

    def test_b64encode_ascii(self):
        result = _b64encode(b"hello")
        assert isinstance(result, str)
        assert result == base64.b64encode(b"hello").decode("ascii")

    def test_increment_nonce_simple(self):
        nonce = b"\x00" * 24
        result = _increment_nonce(nonce)
        assert result[0] == 1
        assert result[1:] == b"\x00" * 23

    def test_increment_nonce_carry(self):
        nonce = b"\xff" + b"\x00" * 23
        result = _increment_nonce(nonce)
        assert result[0] == 0
        assert result[1] == 1
        assert result[2:] == b"\x00" * 22

    def test_increment_nonce_all_ff(self):
        nonce = b"\xff" * 24
        result = _increment_nonce(nonce)
        assert result == b"\x00" * 24


# ---------------------------------------------------------------------------
# BrowserClient initialisation
# ---------------------------------------------------------------------------


class TestBrowserClientInit:
    def test_generates_keypair(self):
        config = BrowserConfig()
        client = BrowserClient(config)
        assert config.client_public_key != ""
        assert config.client_secret_key != ""

    def test_loads_existing_keypair(self):
        sk = nacl.public.PrivateKey.generate()
        pk = sk.public_key
        config = BrowserConfig(
            client_public_key=_b64encode(bytes(pk)),
            client_secret_key=_b64encode(bytes(sk)),
        )
        client = BrowserClient(config)
        assert bytes(client._public_key) == bytes(pk)

    def test_keypair_consistency(self):
        config = BrowserConfig()
        BrowserClient(config)
        pk1 = config.client_public_key
        sk1 = config.client_secret_key

        BrowserClient(config)
        assert config.client_public_key == pk1
        assert config.client_secret_key == sk1


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


class TestBrowserClientConnect:
    def test_connect_nonexistent_socket(self):
        config = BrowserConfig()
        client = BrowserClient(config)
        import keepassxc_browser_api.client as bc
        original = bc._get_keepassxc_socket_path
        bc._get_keepassxc_socket_path = lambda: "/tmp/nonexistent-keepassxc-test.sock"
        try:
            assert client.connect() is False
        finally:
            bc._get_keepassxc_socket_path = original

    def test_disconnect_when_not_connected(self):
        config = BrowserConfig()
        client = BrowserClient(config)
        client.disconnect()  # Should not raise

    def test_ensure_unlocked_no_associations(self):
        config = BrowserConfig()
        client = BrowserClient(config)
        with pytest.raises(NotAssociatedError):
            client.ensure_unlocked()


# ---------------------------------------------------------------------------
# Mock KeePassXC server helpers
# ---------------------------------------------------------------------------


class MockKeePassXC:
    """Minimal mock of KeePassXC's browser extension socket server."""

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self._server_key = nacl.public.PrivateKey.generate()
        self._client_public_key: nacl.public.PublicKey | None = None
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.received_messages: list[dict] = []
        self._response_queue: list[dict] = []

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.socket_path)
        self._sock.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def queue_response(self, response: dict) -> None:
        self._response_queue.append(response)

    def _serve(self) -> None:
        try:
            conn, _ = self._sock.accept()
            with conn:
                data = conn.recv(65536)
                msg = json.loads(data)
                self.received_messages.append(msg)

                if self._response_queue:
                    resp = self._response_queue.pop(0)
                else:
                    resp = self._build_change_public_keys_response(msg)
                conn.sendall(json.dumps(resp).encode())
        except Exception:
            pass

    def _build_change_public_keys_response(self, msg: dict) -> dict:
        self._client_public_key = nacl.public.PublicKey(_b64decode(msg["publicKey"]))
        return {
            "action": "change-public-keys",
            "publicKey": _b64encode(bytes(self._server_key.public_key)),
            "nonce": msg["nonce"],
            "success": "true",
        }

    def encrypt_response(self, client_public_key_b64: str, inner: dict, nonce_b64: str) -> tuple[str, str]:
        """Encrypt an inner dict for sending back to the client."""
        client_pk = nacl.public.PublicKey(_b64decode(client_public_key_b64))
        box = nacl.public.Box(self._server_key, client_pk)
        nonce = _b64decode(nonce_b64)
        incremented_nonce = _increment_nonce(nonce)
        plaintext = json.dumps(inner).encode("utf-8")
        encrypted = box.encrypt(plaintext, incremented_nonce)
        return _b64encode(encrypted.ciphertext), _b64encode(incremented_nonce)


# ---------------------------------------------------------------------------
# Change public keys
# ---------------------------------------------------------------------------


class TestChangePublicKeys:
    def test_change_public_keys_success(self, short_tmp):
        sock_path = f"{short_tmp}/kp.sock"
        config = BrowserConfig()
        client = BrowserClient(config)

        server = MockKeePassXC(sock_path)
        server.start()

        import keepassxc_browser_api.client as bc
        original = bc._get_keepassxc_socket_path
        bc._get_keepassxc_socket_path = lambda: sock_path
        try:
            assert client.connect() is True
            assert client.change_public_keys() is True
            assert client._server_public_key is not None
        finally:
            bc._get_keepassxc_socket_path = original
            client.disconnect()
            server.stop()

    def test_change_public_keys_error_response(self, short_tmp):
        sock_path = f"{short_tmp}/kp.sock"
        config = BrowserConfig()
        client = BrowserClient(config)

        server = MockKeePassXC(sock_path)
        server.queue_response({"errorCode": "7", "error": "some error"})
        server.start()

        import keepassxc_browser_api.client as bc
        original = bc._get_keepassxc_socket_path
        bc._get_keepassxc_socket_path = lambda: sock_path
        try:
            assert client.connect() is True
            assert client.change_public_keys() is False
        finally:
            bc._get_keepassxc_socket_path = original
            client.disconnect()
            server.stop()



# ---------------------------------------------------------------------------
# request_autotype tests
# ---------------------------------------------------------------------------


class TestRequestAutotype:
    def test_request_autotype_calls_send_encrypted(self):
        from unittest.mock import MagicMock, patch

        config = BrowserConfig()
        client = BrowserClient(config)

        with patch.object(client, "_send_encrypted", return_value={"action": "request-autotype"}) as mock_send:
            result = client.request_autotype()
            assert result is True
            mock_send.assert_called_once_with("request-autotype", {"action": "request-autotype"})

    def test_request_autotype_with_search(self):
        from unittest.mock import patch

        config = BrowserConfig()
        client = BrowserClient(config)

        with patch.object(client, "_send_encrypted", return_value={"action": "request-autotype"}) as mock_send:
            result = client.request_autotype(search="github.com")
            assert result is True
            _, call_inner = mock_send.call_args[0]
            assert call_inner["search"] == "github.com"

    def test_request_autotype_returns_false_on_failure(self):
        from unittest.mock import patch

        config = BrowserConfig()
        client = BrowserClient(config)

        with patch.object(client, "_send_encrypted", return_value=None):
            result = client.request_autotype()
            assert result is False


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestEntryModel:
    def test_from_dict_basic(self):
        d = {
            "uuid": "abc123",
            "name": "Example",
            "login": "user@example.com",
            "password": "s3cr3t",
        }
        entry = Entry.from_dict(d)
        assert entry.uuid == "abc123"
        assert entry.name == "Example"
        assert entry.login == "user@example.com"
        assert entry.password == "s3cr3t"
        assert entry.totp == ""

    def test_from_dict_with_totp(self):
        d = {
            "uuid": "xyz",
            "name": "TOTP Entry",
            "login": "user",
            "password": "pass",
            "totp": "123456",
        }
        entry = Entry.from_dict(d)
        assert entry.totp == "123456"

    def test_roundtrip(self):
        original = Entry(uuid="u1", name="Test", login="user", password="pw", group="Root")
        restored = Entry.from_dict(original.to_dict())
        assert restored.uuid == original.uuid
        assert restored.name == original.name


class TestGroupModel:
    def test_from_dict_basic(self):
        d = {"uuid": "g1", "name": "Root", "children": []}
        group = Group.from_dict(d)
        assert group.uuid == "g1"
        assert group.name == "Root"
        assert group.children == []

    def test_from_dict_nested(self):
        d = {
            "uuid": "g1",
            "name": "Root",
            "children": [
                {"uuid": "g2", "name": "Work", "children": []},
                {"uuid": "g3", "name": "Personal", "children": [
                    {"uuid": "g4", "name": "Finance", "children": []},
                ]},
            ],
        }
        group = Group.from_dict(d)
        assert len(group.children) == 2
        assert group.children[1].children[0].name == "Finance"

    def test_flat_list(self):
        d = {
            "uuid": "g1",
            "name": "Root",
            "children": [
                {"uuid": "g2", "name": "Work", "children": []},
            ],
        }
        group = Group.from_dict(d)
        flat = group.flat_list()
        assert len(flat) == 2
        names = {g.name for g in flat}
        assert names == {"Root", "Work"}


# ---------------------------------------------------------------------------
# Context manager & _ensure_session
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_context_manager_disconnects(self):
        config = BrowserConfig()
        client = BrowserClient(config)
        mock_sock = type("MockSock", (), {"close": lambda self: None, "gettimeout": lambda self: None})()
        client._socket = mock_sock
        client._server_public_key = "fake"
        client._associated = True
        with client:
            assert client._socket is not None
        assert client._socket is None
        assert client._server_public_key is None
        assert client._associated is False

    def test_ensure_session_already_connected(self):
        config = BrowserConfig()
        client = BrowserClient(config)
        mock_sock = type("MockSock", (), {"close": lambda self: None})()
        client._socket = mock_sock
        client._server_public_key = "fake"
        client._associated = True
        assert client._ensure_session() is True

    def test_ensure_session_no_socket(self):
        config = BrowserConfig()
        client = BrowserClient(config)
        # connect will fail (no real socket)
        import keepassxc_browser_api.client as bc
        original = bc._get_keepassxc_socket_path
        bc._get_keepassxc_socket_path = lambda: "/tmp/nonexistent-keepassxc-test.sock"
        try:
            assert client._ensure_session() is False
        finally:
            bc._get_keepassxc_socket_path = original
