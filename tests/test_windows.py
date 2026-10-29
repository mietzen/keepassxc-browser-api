"""Native messaging framing and Windows transport regression tests."""

import io
import queue
import struct
from unittest.mock import MagicMock

import pytest

from keepassxc_browser_api import windows
from keepassxc_browser_api.client import BrowserClient
from keepassxc_browser_api.config import BrowserConfig


@pytest.fixture
def proxy(monkeypatch):
    process = MagicMock()
    process.stdin = io.BytesIO()
    process.stdout = io.BytesIO(struct.pack("<I", 2) + b"{}")
    process.poll.return_value = 0
    monkeypatch.setattr(windows, "_proxy_path", lambda: "keepassxc-proxy.exe")
    monkeypatch.setattr(windows.subprocess, "CREATE_NO_WINDOW", 0, raising=False)
    monkeypatch.setattr(windows.subprocess, "Popen", lambda *args, **kwargs: process)
    return process


def test_windows_connection_avoids_unix_socket(monkeypatch, proxy):
    import keepassxc_browser_api.client as module

    monkeypatch.setattr(module.sys, "platform", "win32")
    client = BrowserClient(BrowserConfig())
    try:
        client.connect()
        assert isinstance(client._socket, windows.NativeMessagingSocket)
    finally:
        client.disconnect()
    assert not client._socket


def test_native_messaging_framing(proxy):
    transport = windows.NativeMessagingSocket()
    try:
        request = b'{"action":"test"}'
        transport.sendall(request)
        assert proxy.stdin.getvalue() == struct.pack("<I", len(request)) + request
        assert transport.recv(1024) == b"{}"
    finally:
        transport.close()
    assert not transport._reader.is_alive()


def test_partial_reads_and_writes(proxy):
    class PartialReader(io.BytesIO):
        def read(self, size):
            return super().read(min(size, 1))

    class PartialWriter(io.BytesIO):
        def write(self, data):
            return super().write(data[:1])

    proxy.stdout = PartialReader(struct.pack("<I", 2) + b"{}")
    proxy.stdin = PartialWriter()
    transport = windows.NativeMessagingSocket()
    try:
        transport.sendall(b"{}")
        assert proxy.stdin.getvalue() == struct.pack("<I", 2) + b"{}"
        assert transport.recv(1024) == b"{}"
    finally:
        transport.close()


@pytest.mark.parametrize("size", [0, windows.MAX_MESSAGE_SIZE + 1])
def test_rejects_invalid_response_size(proxy, size):
    proxy.stdout = io.BytesIO(struct.pack("<I", size))
    transport = windows.NativeMessagingSocket()
    try:
        with pytest.raises(OSError, match="response size"):
            transport.recv(1024)
    finally:
        transport.close()


def test_truncated_response_is_not_returned(proxy):
    proxy.stdout = io.BytesIO(struct.pack("<I", 10) + b"{}")
    transport = windows.NativeMessagingSocket()
    try:
        with pytest.raises(OSError, match="disconnected"):
            transport.recv(1024)
    finally:
        transport.close()


def test_receive_timeout():
    transport = windows.NativeMessagingSocket.__new__(windows.NativeMessagingSocket)
    transport._responses = queue.Queue()
    transport._closed = False
    transport.settimeout(0.01)
    assert transport.gettimeout() == 0.01
    with pytest.raises(TimeoutError):
        transport.recv(1024)


def test_close_reaps_proxy(proxy):
    proxy.poll.return_value = None
    transport = windows.NativeMessagingSocket()
    transport.close()
    transport.close()
    proxy.terminate.assert_called_once()
    proxy.wait.assert_called_once_with(timeout=2)
    assert proxy.stdin.closed
    assert proxy.stdout.closed


def test_close_kills_unresponsive_proxy(proxy):
    proxy.poll.return_value = None
    proxy.wait.side_effect = [windows.subprocess.TimeoutExpired("proxy", 2), None]
    transport = windows.NativeMessagingSocket()
    transport.close()
    proxy.kill.assert_called_once()


def test_use_after_close(proxy):
    transport = windows.NativeMessagingSocket()
    transport.close()
    with pytest.raises(OSError, match="closed"):
        transport.sendall(b"{}")
    with pytest.raises(OSError, match="closed"):
        transport.recv(1024)


def test_missing_proxy_is_connection_error(monkeypatch):
    import keepassxc_browser_api.client as module
    from keepassxc_browser_api.exceptions import ConnectionError

    monkeypatch.setattr(module.sys, "platform", "win32")

    def missing():
        raise OSError("Cannot find keepassxc-proxy.exe")

    monkeypatch.setattr(windows, "_proxy_path", missing)
    with pytest.raises(ConnectionError, match="Cannot find"):
        BrowserClient(BrowserConfig()).connect()
