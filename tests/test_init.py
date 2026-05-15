"""Tests for the __init__ public API surface."""

from __future__ import annotations

import keepassxc_browser_api


class TestPublicAPI:
    def test_exports(self):
        assert hasattr(keepassxc_browser_api, "BrowserClient")
        assert hasattr(keepassxc_browser_api, "BrowserConfig")
        assert hasattr(keepassxc_browser_api, "Association")
        assert hasattr(keepassxc_browser_api, "Entry")
        assert hasattr(keepassxc_browser_api, "Group")
        assert hasattr(keepassxc_browser_api, "KeePassXCError")
        assert hasattr(keepassxc_browser_api, "AssociationError")
        assert hasattr(keepassxc_browser_api, "ConnectionError")
        assert hasattr(keepassxc_browser_api, "DatabaseLockedError")
        assert hasattr(keepassxc_browser_api, "NotAssociatedError")
        assert hasattr(keepassxc_browser_api, "ProtocolError")
