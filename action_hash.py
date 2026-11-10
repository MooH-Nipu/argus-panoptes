"""Ambil Next-Action hash langsung dari platform, biar nggak perlu update manual.

Platform Next.js naruh `createServerReference("<hash>", ..., "<namaAction>")` di
chunk JS. Chunk itu berubah tiap redeploy, jadi nama action-nya yang stabil —
kita cari nama, ambil hash-nya.

Dipakai bot: `refresh(cookie, log=...)` sekali saat start, dan lagi tiap kali
server balas 400 `Invalid Server Action request.` (hash basi). Nama file
argus_core.py nggak ditulis ulang; konstanta module-nya yang di-patch runtime.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

import httpx

import argus_core as core

# nama action di platform -> konstanta di argus_core
FETCH_ACTION = "fetchAlarms"
TAKE_ACTION = "takeAlarm"
CLOSE_ACTION = "setStatusAndMessageNew"

_REF_RE = re.compile(r'createServerReference\)?\(\s*"([0-9a-f]{40,64})"\s*,[^"]*?"(\w+)"\)')
_SCRIPT_RE = re.compile(r'static/chunks/[A-Za-z0-9_\-./]+?\.js')


def _chunk_urls(html: str, seen: set[str]) -> list[str]:
    return [f"/_next/{p}" for p in set(_SCRIPT_RE.findall(html)) - seen]


def _crawl(
    client: httpx.Client,
    origin: str,
    cookie: str,
    page_path: str,
    follow: bool = True,
    max_requests: int = 120,
) -> dict[str, str]:
    """Turun dari satu halaman ke chunk-chunk JS-nya (ikut lazy import sampai habis)."""
    headers = {"Cookie": cookie, "User-Agent": core.BROWSER_UA}
    resp = client.get(origin + page_path, headers=headers, follow_redirects=True)
    if resp.status_code != 200:
        return {}

    seen: set[str] = set()
    queue = _chunk_urls(resp.text, seen)
    found: dict[str, str] = {}
    requests_made = 0

    while queue and requests_made < max_requests:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        requests_made += 1
        chunk = client.get(origin + path, headers=headers)
        if chunk.status_code != 200:
            continue
        text = chunk.text
        found.update({name: h for h, name in _REF_RE.findall(text)})
        if follow:
            queue.extend(_chunk_urls(text, seen))
    return found


def discover(
    base_url: str,
    cookie: str,
    group_id: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
) -> dict[str, str]:
    """Balikin {namaAction: hash}. `group_id` diperlukan buat take/close —
    action itu cuma ada di halaman detail /x-alarm/<group_id>."""
    origin = core._origin(base_url)
    names: dict[str, str] = {}
    with core._new_client() as client:
        names.update(_crawl(client, origin, cookie, core.ALARM_PATH))
        if group_id:
            names.update(_crawl(client, origin, cookie, f"{core.ALARM_PATH}/{group_id}"))
    if log:
        log(f"Hash discovery: {len(names)} action found "
            f"(fetch={FETCH_ACTION in names}, "
            f"take={TAKE_ACTION in names}, close={CLOSE_ACTION in names}).")
    return names


def apply(names: dict[str, str], log: Optional[Callable[[str], None]] = None) -> list[str]:
    """Tulis hash yang ketemu ke konstanta argus_core. Balikin nama yang berubah."""
    changed: list[str] = []
    if (h := names.get(FETCH_ACTION)) and h != core.ACTION_FETCH:
        core.ACTION_FETCH = h
        changed.append(FETCH_ACTION)
    if (h := names.get(CLOSE_ACTION)) and h != core.ACTION_CLOSE:
        core.ACTION_CLOSE = h
        changed.append(CLOSE_ACTION)
    if (h := names.get(TAKE_ACTION)) and core.ACTION_TAKE != [h]:
        core.ACTION_TAKE = [h]
        changed.append(TAKE_ACTION)
    if log:
        log("Hash updated: " + (", ".join(changed) if changed else "none (still current)."))
    return changed


def refresh(
    base_url: str,
    cookie: str,
    group_id: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
) -> list[str]:
    """Discover + apply. Nggak pernah raise: gagal ambil hash = pakai yang lama."""
    try:
        return apply(discover(base_url, cookie, group_id=group_id, log=log), log=log)
    except (httpx.HTTPError, core.ArgusError) as exc:
        if log:
            log(f"Hash discovery failed, keeping current hashes: {exc}")
        return []
