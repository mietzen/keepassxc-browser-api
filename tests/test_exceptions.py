"""Tests for custom exceptions."""

from __future__ import annotations

from keepassxc_browser_api.exceptions import (
    AssociationError,
    DatabaseLockedError,
    KeePassXCError,
    NotAssociatedError,
    ProtocolError,
)


class TestExceptions:
    def test_hierarchy(self):
        for exc_cls in (AssociationError, DatabaseLockedError, NotAssociatedError, ProtocolError):
            assert issubclass(exc_cls, KeePassXCError)

    def test_raise_and_catch_base(self):
        with pytest.raises(KeePassXCError):
            raise AssociationError("test")

    def test_message(self):
        err = NotAssociatedError("Run setup() first.")
        assert "setup()" in str(err)


import pytest
