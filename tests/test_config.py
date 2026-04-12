"""Tests for BrowserConfig persistence."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from keepassxc_browser_api.config import Association, BrowserConfig, DEFAULT_UNLOCK_TIMEOUT


class TestAssociation:
    def test_roundtrip(self):
        a = Association(id="test-id", id_key="pubkey_b64", key="seckey_b64")
        restored = Association.from_dict(a.to_dict())
        assert restored.id == a.id
        assert restored.id_key == a.id_key
        assert restored.key == a.key


class TestBrowserConfig:
    def test_defaults(self):
        config = BrowserConfig()
        assert config.unlock_timeout == DEFAULT_UNLOCK_TIMEOUT
        assert config.client_public_key == ""
        assert config.client_secret_key == ""
        assert config.associations == {}

    def test_roundtrip(self):
        config = BrowserConfig(
            unlock_timeout=60,
            client_public_key="pub",
            client_secret_key="sec",
            associations={"hash1": Association(id="assoc1", id_key="ik1", key="k1")},
        )
        restored = BrowserConfig.from_dict(config.to_dict())
        assert restored.unlock_timeout == 60
        assert restored.client_public_key == "pub"
        assert restored.client_secret_key == "sec"
        assert "hash1" in restored.associations
        assert restored.associations["hash1"].id == "assoc1"

    def test_save_and_load(self, tmp_path):
        config_path = tmp_path / "browser-api.json"
        config = BrowserConfig(
            client_public_key="mypubkey",
            client_secret_key="myseckey",
            associations={"h1": Association(id="a1", id_key="ik1", key="k1")},
        )
        config.save(config_path)

        assert config_path.exists()
        mode = config_path.stat().st_mode
        assert not (mode & 0o077), "Config file should be owner-only (0600)"

        loaded = BrowserConfig.load(config_path)
        assert loaded.client_public_key == "mypubkey"
        assert "h1" in loaded.associations

    def test_load_nonexistent_returns_default(self, tmp_path):
        config = BrowserConfig.load(tmp_path / "nonexistent.json")
        assert config.client_public_key == ""

    def test_load_warns_on_insecure_permissions(self, tmp_path, caplog):
        config_path = tmp_path / "browser-api.json"
        config = BrowserConfig(client_public_key="pk", client_secret_key="sk")
        config.save(config_path)
        # Make it world-readable
        config_path.chmod(0o644)

        import logging
        with caplog.at_level(logging.WARNING, logger="keepassxc_browser_api.config"):
            BrowserConfig.load(config_path)

        assert any("insecure permissions" in r.message for r in caplog.records)

    def test_save_creates_parent_dir(self, tmp_path):
        config_path = tmp_path / "subdir" / "browser-api.json"
        config = BrowserConfig()
        config.save(config_path)
        assert config_path.exists()
