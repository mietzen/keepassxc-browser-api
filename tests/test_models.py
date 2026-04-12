"""Tests for data models."""

from __future__ import annotations

from keepassxc_browser_api.models import Entry, Group


class TestEntry:
    def test_string_fields(self):
        d = {
            "uuid": "u1",
            "name": "Test",
            "login": "user",
            "password": "pass",
            "stringFields": [{"Notes": "some note"}],
        }
        entry = Entry.from_dict(d)
        assert entry.string_fields == [{"Notes": "some note"}]

    def test_group_info(self):
        d = {
            "uuid": "u1",
            "name": "Test",
            "login": "user",
            "password": "pass",
            "group": "Work",
            "groupUuid": "g1",
        }
        entry = Entry.from_dict(d)
        assert entry.group == "Work"
        assert entry.group_uuid == "g1"


class TestGroup:
    def test_flat_list_deep(self):
        root = Group(
            uuid="g1",
            name="Root",
            children=[
                Group(
                    uuid="g2",
                    name="Level1",
                    children=[
                        Group(uuid="g3", name="Level2"),
                    ],
                )
            ],
        )
        flat = root.flat_list()
        assert len(flat) == 3
        assert flat[0].name == "Root"
        assert flat[-1].name == "Level2"
