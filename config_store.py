"""Load/save layer buat semua file config (settings, whitelist, protect list).

Semua file YAML di-manage lewat UI, modul ini yang baca/tulis ke disk.
Rule di-CRUD by index (list-based) — simpel & cukup buat pemakaian lokal.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime
from typing import Any

import yaml

BASE_DIR = os.getenv("CONFIG_DIR", os.path.dirname(os.path.abspath(__file__)))

SETTINGS_PATH = os.path.join(BASE_DIR, "settings.yaml")
WHITELIST_PATH = os.path.join(BASE_DIR, "whitelist.yaml")
PROTECT_PATH = os.path.join(BASE_DIR, "protect_list.yaml")
AUDIT_PATH = os.path.join(BASE_DIR, "audit.jsonl")
_CONFIG_LOCK = threading.RLock()


class RuleConflictError(Exception):
    """Rule berubah sejak form edit dibuka."""


# Pilihan shift buat dropdown UI.
# CATATAN: cuma shift 1 yang CONFIRMED dari reverse-engineering (PROJECT_SPEC §3.2).
# Shift 2 & 3 ADALAH ASUMSI pola 8-jam standar SOC — value string-nya HARUS
# diverifikasi persis lewat DevTools upstream sebelum dipakai produksi, karena backend
# nyocokin string mentah. Kalau salah, fetch bakal balik kosong tanpa error.
SHIFT_OPTIONS = [
    "1 (00:00 - 08:00)",
    "2 (08:00 - 16:00)",
    "3 (16:00 - 00:00)",
]


def current_shift(now: datetime | None = None) -> str:
    """Shift aktif dari jam sistem lokal (blok 8 jam, mulai 00:00)."""
    return SHIFT_OPTIONS[(now or datetime.now()).hour // 8]

DEFAULT_SETTINGS: dict[str, Any] = {
    "poll_interval_seconds": 300,
    "protect_high_severity": True,
    "page_size": 100,
    # Maks alarm yang di-close dalam SATU sapu (lintas semua grup reason).
    # 0 = tanpa batas (close semua yang match). Beda dari batch_size yang cuma
    # ngatur jumlah ID per HTTP request.
    "max_close_per_cycle": 100,
    "action_delay_min_seconds": 3,
    "action_delay_max_seconds": 7,
    "dry_run": True,
    "enable_suppress_fallback": False,
}

# Rentang fetch tetap: hari ini (last_days=1) + shift aktif dari jam sistem.
FETCH_LAST_DAYS = "1"

# Panjang minimum substring alarm_name_contains di whitelist. Substring
# pendek (mis. "error") bisa nyapu hampir semua alarm.
# ponytail: guard panjang doang; kalau masih kebobolan, tambah preview match.
MIN_CONTAINS_LEN = 6

# Field matching yang valid per tipe rule (dipakai buat validasi input UI).
WHITELIST_FIELDS = [
    "alarm_name_equals",
    "alarm_name_contains",
    "alarm_type_equals",
    "agent_name_equals",
    "client_equals",
]
PROTECT_FIELDS = [
    "severity_equals",
    "alarm_name_equals",
    "alarm_name_contains",
]
WHITELIST_DISPOSITIONS = ("False Positive", "Exclusion")


def _read_yaml(path: str) -> Any:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _write_yaml(path: str, data: Any) -> None:
    """Tulis atomik: tulis ke temp file lalu replace, biar file config nggak
    korup kalau proses mati di tengah tulis."""
    dir_name = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


# ---------- Settings ----------

def load_settings() -> dict[str, Any]:
    with _CONFIG_LOCK:
        data = _read_yaml(SETTINGS_PATH) or {}
        merged = dict(DEFAULT_SETTINGS)
        if isinstance(data, dict):
            merged.update({k: data[k] for k in data if k in DEFAULT_SETTINGS})
        return merged


def save_settings(settings: dict[str, Any]) -> None:
    with _CONFIG_LOCK:
        current = load_settings()
        current.update({k: settings[k] for k in settings if k in DEFAULT_SETTINGS})
        _write_yaml(SETTINGS_PATH, current)


def append_audit(records: list[dict[str, Any]]) -> None:
    """Append record ke audit log mutation (JSON Lines, append-only)."""
    if not records:
        return
    lines = "".join(
        json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in records
    )
    with _CONFIG_LOCK, open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(lines)


# ---------- Rules (whitelist & protect) ----------

def _clean_rule(rule: dict[str, Any], allowed_fields: list[str]) -> dict[str, Any]:
    """Ambil hanya field valid + reason, buang value kosong. Reason wajib ada."""
    cleaned: dict[str, Any] = {}
    for field in allowed_fields:
        val = rule.get(field)
        if val is not None and str(val).strip() != "":
            cleaned[field] = str(val).strip()
    if not cleaned:
        raise ValueError("Rule harus punya minimal satu field matching yang keisi.")
    reason = str(rule.get("reason", "")).strip()
    if not reason:
        raise ValueError("Rule wajib punya 'reason'.")
    cleaned["reason"] = reason
    return cleaned


def clean_whitelist_rule(rule: dict[str, Any]) -> dict[str, Any]:
    cleaned = _clean_rule(rule, WHITELIST_FIELDS)
    contains = cleaned.get("alarm_name_contains", "")
    if contains and len(contains) < MIN_CONTAINS_LEN:
        raise ValueError(
            f"alarm_name_contains minimal {MIN_CONTAINS_LEN} karakter (terlalu luas)."
        )
    disposition = str(rule.get("disposition", "False Positive")).strip()
    if disposition not in WHITELIST_DISPOSITIONS:
        raise ValueError("Disposition whitelist tidak valid.")
    cleaned["disposition"] = disposition
    return cleaned


def whitelist_rule_version(rule: dict[str, Any]) -> str:
    canonical = json.dumps(rule, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_whitelist() -> list[dict[str, Any]]:
    data = _read_yaml(WHITELIST_PATH) or {}
    rules = data.get("whitelist") if isinstance(data, dict) else None
    return rules if isinstance(rules, list) else []


def save_whitelist(rules: list[dict[str, Any]]) -> None:
    with _CONFIG_LOCK:
        _write_yaml(WHITELIST_PATH, {"whitelist": rules})


def load_protect() -> list[dict[str, Any]]:
    data = _read_yaml(PROTECT_PATH) or {}
    rules = data.get("protect") if isinstance(data, dict) else None
    return rules if isinstance(rules, list) else []


def save_protect(rules: list[dict[str, Any]]) -> None:
    with _CONFIG_LOCK:
        _write_yaml(PROTECT_PATH, {"protect": rules})


def add_whitelist_rule(rule: dict[str, Any]) -> None:
    with _CONFIG_LOCK:
        rules = load_whitelist()
        rules.append(clean_whitelist_rule(rule))
        save_whitelist(rules)


def update_whitelist_rule(
    index: int, rule: dict[str, Any], *, expected_version: str
) -> None:
    with _CONFIG_LOCK:
        rules = load_whitelist()
        if not 0 <= index < len(rules):
            raise IndexError("Index rule whitelist di luar jangkauan.")
        if not expected_version or whitelist_rule_version(rules[index]) != expected_version:
            raise RuleConflictError("Rule berubah. Refresh halaman sebelum edit ulang.")
        rules[index] = clean_whitelist_rule(rule)
        save_whitelist(rules)


def delete_whitelist_rule(index: int) -> None:
    with _CONFIG_LOCK:
        rules = load_whitelist()
        if not 0 <= index < len(rules):
            raise IndexError("Index rule whitelist di luar jangkauan.")
        rules.pop(index)
        save_whitelist(rules)


def add_protect_rule(rule: dict[str, Any]) -> None:
    with _CONFIG_LOCK:
        rules = load_protect()
        rules.append(_clean_rule(rule, PROTECT_FIELDS))
        save_protect(rules)


def update_protect_rule(index: int, rule: dict[str, Any]) -> None:
    with _CONFIG_LOCK:
        rules = load_protect()
        if not 0 <= index < len(rules):
            raise IndexError("Index rule protect di luar jangkauan.")
        rules[index] = _clean_rule(rule, PROTECT_FIELDS)
        save_protect(rules)


def delete_protect_rule(index: int) -> None:
    with _CONFIG_LOCK:
        rules = load_protect()
        if not 0 <= index < len(rules):
            raise IndexError("Index rule protect di luar jangkauan.")
        rules.pop(index)
        save_protect(rules)
