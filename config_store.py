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
from datetime import datetime, timedelta, timezone
from datetime import time as dtime
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


# Shift SOC: (jam mulai, string shift_time upstream). String label HARUS persis
# sama dengan value tombol shift di upstream (backend nyocokin string mentah) —
# kalau salah, fetch balik kosong tanpa error. upstream masih pakai jam lama
# (00-08, 08-16, 16-00); L1 pindah jadwal baru tapi tombol upstream belum berubah,
# jadi jam pemicu ikut batas upstream biar string & shift aktif selalu cocok.
SHIFTS = (
    (0, "1 (00:00 - 08:00)"),
    (8, "2 (08:00 - 16:00)"),
    (16, "3 (16:00 - 00:00)"),
)
SHIFT_OPTIONS = [label for _, label in SHIFTS]

# Selama 1 jam pertama shift baru, shift sebelumnya ikut disapu (sisa alarm
# yang belum ke-close pas pergantian shift).
SHIFT_GRACE = timedelta(hours=1)

# Shift boundaries and date filter on the upstream server run on UTC+5 (verified 2026-11-06:
# created_at is UTC and shift 2 = 01:00-08:59 UTC), not the PC clock (UTC+7).
UPSTREAM_TZ = timezone(timedelta(hours=5))


def _upstream_now() -> datetime:
    return datetime.now(UPSTREAM_TZ).replace(tzinfo=None)


def _shift_start(t: datetime) -> tuple[datetime, str]:
    """(waktu mulai, label) shift yang lagi jalan di waktu t."""
    candidates = [
        (datetime.combine(t.date() - timedelta(days=d), dtime(hour)), label)
        for d in (0, 1)
        for hour, label in SHIFTS
    ]
    return max(c for c in candidates if c[0] <= t)


def current_shift(now: datetime | None = None) -> str:
    """Label shift aktif dari jam upstream (UTC+5)."""
    return _shift_start(now or _upstream_now())[1]


def shift_windows(now: datetime | None = None) -> list[tuple[str, str, str]]:
    """Window fetch [(shift_time, date_from, date_to)], urut lama -> baru.
    Range tanggal = tanggal mulai shift s/d tanggal selesai (shift 22-06
    nyebrang tengah malam). Shift sebelumnya ikut kalau masih dalam grace."""
    now = now or _upstream_now()
    start, label = _shift_start(now)
    windows = [(label, start.date().isoformat(), now.date().isoformat())]
    if now - start < SHIFT_GRACE:
        prev_start, prev_label = _shift_start(start - timedelta(seconds=1))
        windows.insert(
            0, (prev_label, prev_start.date().isoformat(), start.date().isoformat())
        )
    return windows

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


def audit_verified_count() -> int:
    """Jumlah alarm unik yang take+verdict-nya verified (sumber: audit.jsonl).
    Baris rusak di-skip. ponytail: scan full file tiap call — oke sampai
    ratusan ribu baris; kalau lambat, simpan counter terpisah."""
    ids: set[str] = set()
    try:
        with open(AUDIT_PATH, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("verified") is True:
                    ids.add(str(rec.get("alarm_id")))
    except FileNotFoundError:
        return 0
    return len(ids)


# ---------- Rules (whitelist & protect) ----------

def _clean_rule(rule: dict[str, Any], allowed_fields: list[str]) -> dict[str, Any]:
    """Ambil hanya field valid + reason, buang value kosong. Reason wajib ada."""
    cleaned: dict[str, Any] = {}
    for field in allowed_fields:
        val = rule.get(field)
        if val is not None and str(val).strip() != "":
            cleaned[field] = str(val).strip()
    if not cleaned:
        raise ValueError("Rule needs at least one filled matching field.")
    reason = str(rule.get("reason", "")).strip()
    if not reason:
        raise ValueError("Rule requires a 'reason'.")
    cleaned["reason"] = reason
    return cleaned


def clean_whitelist_rule(rule: dict[str, Any]) -> dict[str, Any]:
    cleaned = _clean_rule(rule, WHITELIST_FIELDS)
    disposition = str(rule.get("disposition", "False Positive")).strip()
    if disposition not in WHITELIST_DISPOSITIONS:
        raise ValueError("Invalid whitelist disposition.")
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
            raise IndexError("Whitelist rule index out of range.")
        if not expected_version or whitelist_rule_version(rules[index]) != expected_version:
            raise RuleConflictError("Rule changed. Refresh the page before editing again.")
        rules[index] = clean_whitelist_rule(rule)
        save_whitelist(rules)


def delete_whitelist_rule(index: int) -> None:
    with _CONFIG_LOCK:
        rules = load_whitelist()
        if not 0 <= index < len(rules):
            raise IndexError("Whitelist rule index out of range.")
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
            raise IndexError("Protect rule index out of range.")
        rules[index] = _clean_rule(rule, PROTECT_FIELDS)
        save_protect(rules)


def delete_protect_rule(index: int) -> None:
    with _CONFIG_LOCK:
        rules = load_protect()
        if not 0 <= index < len(rules):
            raise IndexError("Protect rule index out of range.")
        rules.pop(index)
        save_protect(rules)
