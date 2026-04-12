"""Data models for KeePassXC browser API responses."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Entry:
    """A KeePassXC database entry."""

    uuid: str
    name: str
    login: str
    password: str
    totp: str = ""
    group: str = ""
    group_uuid: str = ""
    # Additional string fields (e.g. Notes, custom fields)
    string_fields: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> Entry:
        return cls(
            uuid=d.get("uuid", ""),
            name=d.get("name", ""),
            login=d.get("login", ""),
            password=d.get("password", ""),
            totp=d.get("totp", ""),
            group=d.get("group", ""),
            group_uuid=d.get("groupUuid", ""),
            string_fields=d.get("stringFields", []),
        )

    def to_dict(self) -> dict:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "login": self.login,
            "password": self.password,
            "totp": self.totp,
            "group": self.group,
            "groupUuid": self.group_uuid,
            "stringFields": self.string_fields,
        }


@dataclass
class Group:
    """A KeePassXC database group."""

    uuid: str
    name: str
    children: list[Group] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> Group:
        children = [Group.from_dict(c) for c in d.get("children", [])]
        return cls(
            uuid=d.get("uuid", ""),
            name=d.get("name", ""),
            children=children,
        )

    def to_dict(self) -> dict:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "children": [c.to_dict() for c in self.children],
        }

    def flat_list(self) -> list[Group]:
        """Return a flat list of this group and all descendants."""
        result = [self]
        for child in self.children:
            result.extend(child.flat_list())
        return result
