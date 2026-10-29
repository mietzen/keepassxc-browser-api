"""Socket-compatible transport through KeePassXC's native messaging proxy."""

from __future__ import annotations

import json
import csv
import os
from pathlib import Path
import queue
import struct
import subprocess
import threading


MAX_MESSAGE_SIZE = 1024 * 1024


def protect_config_file(path: Path) -> None:
    """Restrict a newly created configuration file to the current Windows SID."""
    system32 = Path(os.environ["SystemRoot"]) / "System32"
    identity = subprocess.check_output(
        [str(system32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    sid = next(csv.reader(identity.splitlines()))[1]
    if not sid.startswith("S-1-"):
        raise OSError("Cannot determine current Windows account SID")
    subprocess.run(
        [
            str(system32 / "icacls.exe"),
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:F",
            "/q",
        ],
        check=True,
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def _proxy_path() -> str:
    import winreg

    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for browser in (r"Google\Chrome", "Mozilla"):
            key = rf"SOFTWARE\{browser}\NativeMessagingHosts\org.keepassxc.keepassxc_browser"
            try:
                with winreg.OpenKey(hive, key) as registration:
                    manifest = winreg.QueryValue(registration, None)
                path = Path(
                    json.loads(Path(manifest).read_text(encoding="utf-8"))["path"]
                )
                if (
                    path.is_absolute()
                    and path.is_file()
                    and path.name.lower() == "keepassxc-proxy.exe"
                ):
                    return str(path)
            except (OSError, ValueError, KeyError, TypeError):
                continue
    for variable in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        directory = os.environ.get(variable)
        if directory:
            path = Path(directory) / "KeePassXC" / "keepassxc-proxy.exe"
            if path.is_file():
                return str(path)
    raise OSError(
        "Cannot find keepassxc-proxy.exe; install KeePassXC with Browser Integration enabled"
    )


class NativeMessagingSocket:
    """Translate raw JSON to the proxy's length-prefixed stdin/stdout protocol.

    A reader thread permits socket-style response timeouts without blocking the
    caller indefinitely. Closing the transport also reaps the proxy process.
    """

    def __init__(self) -> None:
        self._timeout: float | None = 5.0
        self._responses: queue.Queue[bytes | OSError] = queue.Queue()
        self._closed = False
        self._process = subprocess.Popen(
            [_proxy_path()],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self._reader = threading.Thread(target=self._read_messages, daemon=True)
        self._reader.start()

    def _read_exactly(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = self._process.stdout.read(size - len(data))
            if not chunk:
                raise OSError("KeePassXC native messaging proxy disconnected")
            data.extend(chunk)
        return bytes(data)

    def _read_messages(self) -> None:
        try:
            while not self._closed:
                size = struct.unpack("<I", self._read_exactly(4))[0]
                if not 0 < size <= MAX_MESSAGE_SIZE:
                    raise OSError("Invalid native messaging response size")
                self._responses.put(self._read_exactly(size))
        except (OSError, ValueError) as error:
            self._responses.put(OSError(str(error)))

    def sendall(self, data: bytes) -> None:
        if self._closed:
            raise OSError("Native messaging transport is closed")
        if not 0 < len(data) <= MAX_MESSAGE_SIZE:
            raise OSError("Invalid native messaging request size")
        frame = memoryview(struct.pack("<I", len(data)) + data)
        while frame:
            written = self._process.stdin.write(frame)
            if not written:
                raise OSError("KeePassXC native messaging proxy disconnected")
            frame = frame[written:]
        self._process.stdin.flush()

    def recv(self, size: int) -> bytes:
        if self._closed:
            raise OSError("Native messaging transport is closed")
        try:
            response = self._responses.get(timeout=self._timeout)
        except queue.Empty:
            raise TimeoutError("Timed out waiting for KeePassXC") from None
        if isinstance(response, OSError):
            raise response
        if len(response) > size:
            raise OSError("Native messaging response exceeds receive buffer")
        return response

    def settimeout(self, timeout: float | None) -> None:
        self._timeout = timeout

    def gettimeout(self) -> float | None:
        return self._timeout

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
        self._reader.join(timeout=2)
        self._process.stdin.close()
        self._process.stdout.close()
