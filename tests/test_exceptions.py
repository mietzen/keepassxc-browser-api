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

    def test_protocol_error_default_error_code(self):
        err = ProtocolError("bad response")
        assert err.error_code is None

    def test_protocol_error_with_error_code(self):
        err = ProtocolError("access denied", error_code=6)
        assert err.error_code == 6
        assert "access denied" in str(err)

    def test_protocol_error_inherits_from_keepassxc_error(self):
        err = ProtocolError("test", error_code=15)
        assert isinstance(err, KeePassXCError)


import pytest
