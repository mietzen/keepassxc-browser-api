"""KeePassXC Browser API library.

A Python library for communicating with KeePassXC via the browser extension
protocol (NaCl-encrypted JSON over a Unix socket).
"""

from __future__ import annotations

from .client import BrowserClient
from .config import Association, BrowserConfig
from .exceptions import AssociationError, KeePassXCError, NotAssociatedError
from .models import Entry, Group

__all__ = [
    "BrowserClient",
    "BrowserConfig",
    "Association",
    "Entry",
    "Group",
    "KeePassXCError",
    "AssociationError",
    "NotAssociatedError",
]
