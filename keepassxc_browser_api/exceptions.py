"""Custom exceptions for the KeePassXC browser API library."""

from __future__ import annotations


class KeePassXCError(Exception):
    """Base exception for all KeePassXC browser API errors."""


class ConnectionError(KeePassXCError):
    """Could not connect to KeePassXC."""


class AssociationError(KeePassXCError):
    """Association with KeePassXC failed or was denied."""


class NotAssociatedError(KeePassXCError):
    """No valid association exists. Run setup() first."""


class DatabaseLockedError(KeePassXCError):
    """The KeePassXC database is locked and could not be unlocked."""


class ProtocolError(KeePassXCError):
    """Unexpected response from KeePassXC (encryption, JSON, protocol errors)."""

    def __init__(self, message: str = "", *, error_code: int | None = None):
        super().__init__(message)
        self.error_code = error_code
