"""Unit tests for config.json schema validation."""

import json
from pathlib import Path

import pytest

import droidnet.config as cfg
from droidnet.config import _validate_config


# ── _validate_config (pure, no I/O) ─────────────────────────────────

def test_validate_fills_defaults_when_keys_missing():
    out = _validate_config({})
    assert out == {"excluded_ips": [], "trusted_ips": [], "db_retention_days": 90}


def test_validate_accepts_well_formed():
    raw = {
        "excluded_ips":      ["192.168.1.100"],
        "trusted_ips":       ["192.168.1.1", "192.168.1.50"],
        "db_retention_days": 30,
    }
    assert _validate_config(raw) == raw


def test_validate_drops_non_string_list_entries():
    raw = {"excluded_ips": ["1.1.1.1", 42, None, "2.2.2.2"]}
    out = _validate_config(raw)
    assert out["excluded_ips"] == ["1.1.1.1", "2.2.2.2"]


def test_validate_replaces_wrong_type_with_default():
    raw = {"excluded_ips": "not-a-list", "db_retention_days": "ninety"}
    out = _validate_config(raw)
    assert out["excluded_ips"] == []
    assert out["db_retention_days"] == 90


def test_validate_rejects_bool_for_int_field():
    # bool is a subclass of int in Python — easy footgun, must be rejected.
    raw = {"db_retention_days": True}
    out = _validate_config(raw)
    assert out["db_retention_days"] == 90


def test_validate_rejects_non_dict_top_level():
    out = _validate_config(["not", "a", "dict"])  # type: ignore[arg-type]
    assert out == {"excluded_ips": [], "trusted_ips": [], "db_retention_days": 90}


def test_validate_ignores_unknown_keys():
    raw = {"trusted_ips": ["1.1.1.1"], "rogue_key": "x"}
    out = _validate_config(raw)
    assert "rogue_key" not in out
    assert out["trusted_ips"] == ["1.1.1.1"]


# ── load_user_config (file-backed) ──────────────────────────────────

def test_load_returns_defaults_when_file_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cfg, "CONFIG_FILE", tmp_path / "absent.json")
    out = cfg.load_user_config()
    assert out == {"excluded_ips": [], "trusted_ips": [], "db_retention_days": 90}


def test_load_validates_real_file(tmp_path: Path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "excluded_ips": ["1.1.1.1", 42],
        "db_retention_days": "bad",
    }))
    monkeypatch.setattr(cfg, "CONFIG_FILE", p)
    out = cfg.load_user_config()
    assert out["excluded_ips"] == ["1.1.1.1"]
    assert out["db_retention_days"] == 90


def test_load_returns_defaults_on_corrupt_json(tmp_path: Path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text("{ this is not json")
    monkeypatch.setattr(cfg, "CONFIG_FILE", p)
    out = cfg.load_user_config()
    assert out["excluded_ips"] == []
