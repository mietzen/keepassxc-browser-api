"""Persistent configuration for the KeePassXC browser API library."""

from __future__ import annotations

import json
import logging
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_CONFIG_DIR = Path.home() / ".keepassxc"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "browser-api.json"

DEFAULT_UNLOCK_TIMEOUT = 30

logger = logging.getLogger(__name__)


@dataclass
class Association:
    """Stored association with a KeePassXC database."""

    id: str
    id_key: str  # base64-encoded identity public key
    key: str     # base64-encoded identity secret key

    def to_dict(self) -> dict:
        return {"id": self.id, "id_key": self.id_key, "key": self.key}

    @classmethod
    def from_dict(cls, d: dict) -> Association:
        return cls(id=d["id"], id_key=d["id_key"], key=d["key"])


@dataclass
class BrowserConfig:
    """Configuration for the KeePassXC browser API connection.

    Shared between keepassxc-cli and keepassxc-ssh-agent so that a single
    association covers both tools.
    """

    unlock_timeout: int = DEFAULT_UNLOCK_TIMEOUT
    # NaCl keypair for browser protocol communication (base64-encoded)
    client_public_key: str = ""
    client_secret_key: str = ""
    # Per-database associations (keyed by database hash)
    associations: dict[str, Association] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "unlock_timeout": self.unlock_timeout,
            "client_public_key": self.client_public_key,
            "client_secret_key": self.client_secret_key,
            "associations": {k: v.to_dict() for k, v in self.associations.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> BrowserConfig:
        associations = {}
        for k, v in d.get("associations", {}).items():
            associations[k] = Association.from_dict(v)
        return cls(
            unlock_timeout=d.get("unlock_timeout", DEFAULT_UNLOCK_TIMEOUT),
            client_public_key=d.get("client_public_key", ""),
            client_secret_key=d.get("client_secret_key", ""),
            associations=associations,
        )

    def save(self, path: Path | None = None) -> None:
        path = path or DEFAULT_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(path.parent), stat.S_IRWXU)
        # Write to a temp file with 0600 permissions, then atomically rename
        # to avoid a race window where secrets are world-readable.
        tmp_path = path.with_suffix(".tmp")
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.to_dict(), f, indent=2)
        except BaseException:
            os.unlink(tmp_path)
            raise
        os.replace(tmp_path, path)

    @classmethod
    def load(cls, path: Path | None = None) -> BrowserConfig:
        path = path or DEFAULT_CONFIG_PATH
        if not path.exists():
            return cls()
        mode = path.stat().st_mode
        if mode & 0o077:
            logger.warning(
                "Config file %s has insecure permissions %o; expected 0600. "
                "Fix with: chmod 600 %s",
                path, mode & 0o777, path,
            )
        with open(path) as f:
            return cls.from_dict(json.load(f))
