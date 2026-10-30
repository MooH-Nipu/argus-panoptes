"""Engine Argus Panoptes.

Isi:
  - login()                : NextAuth credentials flow (PROJECT_SPEC §3.4)
  - fetch_all_open_alarms(): loop page ambil alarm status="Undefined" (§3.2)
  - close_alarms()         : submit FP/Exclusion per alarm (§3.3, §4.4)
  - verify_disposition()   : re-fetch tab tujuan, cek ID beneran pindah (§4.4)
  - evaluate_alarm()       : matching prioritas protect-sev -> protect -> whitelist (§4.3)

Semua request server action pakai HTTP client biasa (httpx) — nggak perlu
browser automation karena upstream credentials-based tanpa OTP/SSO (§3.4).
"""

from __future__ import annotations

import importlib.util
import json
import secrets
import time
from contextlib import nullcontext
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx

# --- Next-Action hash (dari reverse-engineering, PROJECT_SPEC §3.2/§3.3) ---
# CATATAN: hash ini BISA BERUBAH kalau upstream di-redeploy. Kalau bot gagal terus
# (bukan sesekali), kemungkinan besar hash-nya berubah -> re-capture via DevTools.
ACTION_FETCH = "bee83c17d35226c023bbd6e224127ffb35c2a0ce"
ACTION_CLOSE = "c5c23f25ee9d43b0c9dbcbad2972fdccc7ff6a28"

# --- Alur TAKE alarm (2 langkah: TAKE dulu, baru set FP) ---
# Confirmed dari capture DevTools + docx "alur close alarm": alarm HARUS di-take
# (di-claim) dulu sebelum bisa di-set False Positive. Set FP tanpa take -> server
# balik 200 tapi alarm nggak pindah (silent fail).
# Pas klik "Take Alarm" di UI ada 4 request POST /x-alarm. Kita replikasi 3 yang
# payload-nya cuma ID (mutation/claim); #4 (payload berisi {size,page,client})
# di-SKIP karena itu cuma fetch daftar "similar alerts" buat display (ada pagination).
# Payload masing-masing: ["<id>"] buat 2 pertama, ["<id>", ""] buat ketiga.
ACTION_TAKE = [
    "3ebcfca0facaca8d3d0356d1158ab7011ad5b05b",  # payload ["id"]
    "3a4e0f37dc4683a3aab86fc3aa8cd13f0cbac521",  # payload ["id"]
    "78b466fbcc6b7b8cf1b9315f3daab22e06d47bb9",  # payload ["id", ""]
]

# Reason max 250 char (dari modal "Reason for Escalation (Optional) — Max 250 characters").
REASON_MAX_LEN = 250

# Path halaman list alarm di upstream. Server action Next.js di-POST ke path
# halaman tempat action dipanggil (BUKAN root "/"). Confirmed dari deployment:
# Request URL = {origin}/x-alarm. Kalau upstream pindah path, ganti di sini.
ALARM_PATH = "/x-alarm"

# Status tab di upstream (§3.2).
STATUS_UNDEFINED = "Undefined"
STATUS_FALSE_POSITIVE = "False Positive"
STATUS_EXCLUSION = "Exclusion"
DISPOSITIONS = {STATUS_FALSE_POSITIVE, STATUS_EXCLUSION}

# Kategori arg1 buat alur suppress/whitelist (§3.3, capture DevTools). Alarm
# grup (punya "Similar Alerts") silent-fail di jalur FP 3-argumen biasa; harus
# lewat format 4-argumen dengan kategori "Whitelist" + config toggle per-alarm.
WHITELIST_CATEGORY = "Whitelist"

# track_by toggle di modal Suppress (gambar b). Default dua-duanya OFF
# (isSelected=false) — persis "biarin default" yang di-capture.
SUPPRESS_TRACK_BY = ("src_ip", "dest_ip")

# Severity yang dianggap "tinggi" buat toggle protect-severity (§4.2).
HIGH_SEVERITIES = {"high", "critical"}

DEFAULT_TIMEOUT = 30.0
MAX_RETRIES = 3
RETRY_BACKOFF = 2.0  # detik, dikali attempt


def _h2_available() -> bool:
    """HTTP/2 (paket `h2`) terpasang? Browser selalu pakai h2 di HTTPS —
    jalur login nyoba ikut biar transport-nya sama."""
    return importlib.util.find_spec("h2") is not None


def _new_client(http2: bool = False) -> httpx.Client:
    """Build client for private-IP upstream servers with self-signed TLS."""
    if http2 and _h2_available():
        return httpx.Client(
            follow_redirects=False,
            timeout=DEFAULT_TIMEOUT,
            verify=False,  # Internal self-signed upstream; private-IP HTTPS enforced.  # nosec B501
            http2=True,
        )
    return httpx.Client(
        follow_redirects=False,
        timeout=DEFAULT_TIMEOUT,
        verify=False,  # Internal self-signed upstream; private-IP HTTPS enforced.  # nosec B501
    )


class ArgusError(Exception):
    """Error umum saat komunikasi dengan upstream."""


class LoginError(ArgusError):
    """Login gagal (kredensial salah / flow berubah)."""


class ArgusAuthError(ArgusError):
    """Sesi upstream tidak valid; retry tidak akan memperbaikinya."""


class ArgusParseError(ArgusError):
    """Response bukan format RSC yang diharapkan (baris '1:' nggak ketemu).
    Ini error PERMANEN — retry nggak akan nolong. Terjadi mis. pas alarm udah
    ke-take orang lain lalu di-take ulang: server balik response non-RSC.
    Dibedain dari ArgusError transient (5xx/network) biar retry loop langsung
    nyerah, nggak buang ~13 detik/alarm."""


# ---------- RSC response parser (§3.1) ----------

def parse_rsc_response(raw_text: str) -> Any:
    """Server action upstream balikin format RSC streaming (multi-baris `N:{...}`).
    Data utama selalu di baris yang diawali `1:`."""
    for line in raw_text.splitlines():
        if line.startswith("1:"):
            return json.loads(line[2:])
    raise ArgusParseError("Baris data '1:' nggak ketemu di response RSC.")


# ---------- Origin & Header builder ----------

def _origin(base_url: str) -> str:
    """Ambil scheme+host doang (buang path/query). Bikin login & server action
    tahan kalau user terlanjur nempelin path (misal /x-alarm) di Base URL."""
    p = urlparse(base_url.strip())
    if p.scheme and p.netloc:
        return f"{p.scheme}://{p.netloc}"
    # Fallback kalau user cuma isi host tanpa scheme.
    return base_url.rstrip("/")


def _action_headers(base_url: str, cookie: str, action: str, referer_path: str) -> dict[str, str]:
    origin = _origin(base_url)
    return {
        "Content-Type": "text/plain;charset=UTF-8",
        "Next-Action": action,
        "Origin": origin,
        "Referer": origin + "/" + referer_path.lstrip("/"),
        "Cookie": cookie,
    }


def _call_server_action(
    client: httpx.Client,
    base_url: str,
    cookie: str,
    action: str,
    payload: Any,
    referer_path: str,
    retry_transient: bool = True,
) -> Any:
    """POST server action + retry buat error transient (5xx / network).
    Balikin hasil sudah di-parse dari RSC.

    POST ke {origin}{referer_path} (path halaman list alarm), BUKAN root "/".
    POST ke root kena 308 redirect di deployment asli."""
    url = _origin(base_url) + "/" + referer_path.lstrip("/")
    headers = _action_headers(base_url, cookie, action, referer_path)
    body = json.dumps(payload)

    attempts = MAX_RETRIES if retry_transient else 1
    last_exc: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            resp = client.post(url, headers=headers, content=body, timeout=DEFAULT_TIMEOUT)
            if resp.status_code >= 500:
                raise ArgusError(f"Server error {resp.status_code} dari upstream.")
            if resp.status_code == 403:
                raise ArgusAuthError(
                    "403 Forbidden — sesi kemungkinan expired atau Next-Action hash berubah."
                )
            resp.raise_for_status()
            return parse_rsc_response(resp.text)
        except (ArgusParseError, ArgusAuthError):
            raise
        except (httpx.TransportError, ArgusError) as exc:
            last_exc = exc
            if attempt < attempts:
                time.sleep(RETRY_BACKOFF * attempt)
            else:
                raise
    raise ArgusError(f"Gagal setelah {attempts} percobaan: {last_exc}")


# ---------- Login (§3.4) ----------

# Jalur login minik browser sepersis mungkin — sejak update Sep-2026
# endpoint auth upstream nge-reset request non-browser (nginx balas 502) walau
# kredensialnya benar. Ditiru: urutan navigasi, header, dan transport (h2).
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

# Client hints ala Chrome (persis dari capture browser 2026-09-25).
_CHROME_HINTS = {
    "Sec-Ch-Ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}


def _login_headers(base_url: str, *, nav: bool = False) -> dict[str, str]:
    """Header ala Chrome. `nav=True` untuk request navigasi halaman (buka
    URL langsung), default untuk fetch API dari aplikasinya."""
    origin = _origin(base_url)
    common = {
        "User-Agent": BROWSER_UA,
        "Accept-Language": "en-US,en;q=0.9",
        **_CHROME_HINTS,
    }
    if nav:
        return {
            **common,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Upgrade-Insecure-Requests": "1",
        }
    return {
        **common,
        "Accept": "*/*",
        "Referer": f"{origin}/auth/login",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Priority": "u=1, i",
    }


def login(base_url: str, username: str, password: str) -> str:
    """NextAuth credentials login. Balikin string cookie sesi buat dipakai
    di semua request server action selanjutnya.

    Nggak butuh Playwright — pure HTTP karena nggak ada OTP/SSO (§3.4)."""
    base = _origin(base_url)
    with _new_client(http2=True) as client:
        # Step 0: tiruin navigasi browser: halaman login → signin → providers.
        # Ini yang bikin cookie __Secure-next-auth.callback-url kese-set di
        # jar — browser selalu bawa cookie itu ke POST credentials, request
        # langsung-API nggak. Best-effort; gate sebenarnya di step csrf+POST.
        try:
            client.get(f"{base}/auth/login", headers=_login_headers(base, nav=True))
            client.get(
                f"{base}/api/auth/signin",
                params={"callbackUrl": f"{base}/auth/login"},
                headers=_login_headers(base),
            )
            client.get(
                f"{base}/api/auth/providers",
                headers={**_login_headers(base), "Content-Type": "application/json"},
            )
        except httpx.HTTPError:
            pass

        # Step 1: ambil CSRF token.
        csrf_resp = client.get(
            f"{base}/api/auth/csrf",
            headers={**_login_headers(base), "Content-Type": "application/json"},
        )
        csrf_resp.raise_for_status()
        try:
            csrf_token = csrf_resp.json()["csrfToken"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise LoginError(f"Gagal ambil csrfToken: {exc}")

        # Cookie dari step csrf (kadang ada csrf cookie yang perlu ikut dikirim).
        pre_cookies = client.cookies

        # Step 2: POST kredensial.
        # PENTING: login_method harus persis "Basic" (B kapital). Capture browser
        # pasca-update upstream (2026-09-25) nunjukin server strict soal nilai ini —
        # lowercase "basic" dibales 401 CredentialsSignin walau kredensial bener.
        form = {
            "username": username,
            "password": password,
            "login_method": "Basic",
            "client": "",
            "otp_code": "0",
            "redirect": "false",
            "csrfToken": csrf_token,
            "callbackUrl": f"{base}/auth/login",
            "json": "true",
        }
        login_resp = client.post(
            f"{base}/api/auth/callback/credentials",
            data=form,
            cookies=pre_cookies,
            headers={**_login_headers(base), "Origin": base},
        )
        if login_resp.status_code >= 400:
            # Sertakan body respons biar error di UI langsung nunjukin alasan
            # asli dari upstream (mis. error=CredentialsSignin&code=...) — bukan
            # cuma "401 Unauthorized" yang bikin nebak-nebak.
            body = " ".join((login_resp.text or "").split())[:300]
            raise LoginError(
                f"upstream menolak login (HTTP {login_resp.status_code}). "
                f"Respons: {body or '<kosong>'}"
            )

        # Step 3: ekstrak session token dari cookie jar.
        session_cookie = _extract_session_cookie(client.cookies)
        if not session_cookie:
            raise LoginError(
                "Login gagal — session token nggak ketemu. "
                "Cek username/password, atau flow login upstream mungkin berubah."
            )
        return session_cookie


def _extract_session_cookie(jar: httpx.Cookies) -> str:
    """Rakit string Cookie dari cookie jar. Prioritas next-auth session token,
    tapi ikutkan cookie lain yang relevan juga biar aman."""
    wanted_prefixes = ("next-auth.session-token", "__Secure-next-auth.session-token")
    parts: list[str] = []
    has_session = False
    for name, value in jar.items():
        if name.startswith(wanted_prefixes):
            has_session = True
        parts.append(f"{name}={value}")
    if not has_session:
        return ""
    return "; ".join(parts)


# ---------- Fetch alarms (§3.2) ----------

def _build_fetch_payload(
    page: int,
    page_size: int,
    shift_time: str,
    status: str,
    date_from: str = "",
    date_to: str = "",
    last_days: str = "1",
) -> list:
    """Payload fetch alarm. date range vs last_days MUTUALLY EXCLUSIVE (§3.2,
    confirmed dari payload upstream): kalau date_from & date_to keisi (format
    YYYY-MM-DD), keduanya dikirim dan last_days dikosongin. Kalau nggak, pakai
    last_days. Shift_time selalu dikirim (AND sama range/last_days)."""
    df = (date_from or "").strip()
    dt = (date_to or "").strip()
    use_range = bool(df and dt)
    return [{
        "size": str(page_size),
        "page": str(page),
        "date_to": dt if use_range else "",
        "date_from": df if use_range else "",
        "client": "",
        "last_days": "" if use_range else (last_days or "1"),
        "search": "",
        "filter": {"filters": [{"field": "", "value": "", "operator": ""}]},
        "severity": "",
        "shift_time": shift_time,
        "status": status,
    }]


def fetch_alarms_page(
    client: httpx.Client,
    base_url: str,
    cookie: str,
    page: int,
    page_size: int,
    shift_time: str,
    status: str = STATUS_UNDEFINED,
    date_from: str = "",
    date_to: str = "",
    last_days: str = "1",
) -> dict[str, Any]:
    payload = _build_fetch_payload(
        page, page_size, shift_time, status, date_from, date_to, last_days
    )
    result = _call_server_action(
        client, base_url, cookie, ACTION_FETCH, payload, referer_path=ALARM_PATH,
    )
    if not isinstance(result, dict):
        raise ArgusError(
            f"Response fetch nggak sesuai format. Dapet tipe {type(result).__name__}, "
            "harusnya dict. Format response upstream kemungkinan berubah."
        )
    return result


def fetch_all_open_alarms(
    base_url: str,
    cookie: str,
    shift_time: str,
    page_size: int = 100,
    status: str = STATUS_UNDEFINED,
    log: Optional[Callable[[str], None]] = None,
    date_from: str = "",
    date_to: str = "",
    last_days: str = "1",
    client: Optional[httpx.Client] = None,
) -> list[dict[str, Any]]:
    """Loop semua page buat status tertentu (default Undefined)."""
    alarms: list[dict[str, Any]] = []
    scope = nullcontext(client) if client else _new_client()
    with scope as http:
        first = fetch_alarms_page(
            http, base_url, cookie, 1, page_size, shift_time, status,
            date_from, date_to, last_days,
        )
        alarms.extend(first.get("data", []) or [])
        total_pages = int(first.get("totalPages", 1) or 1)
        if log:
            log(f"Fetch '{status}': {first.get('totalItems', '?')} item, {total_pages} page.")
        for page in range(2, total_pages + 1):
            data = fetch_alarms_page(
                http, base_url, cookie, page, page_size, shift_time, status,
                date_from, date_to, last_days,
            )
            alarms.extend(data.get("data", []) or [])
            if log:
                log(f"  page {page}/{total_pages} ok ({len(alarms)} terkumpul).")
    return alarms


# ---------- Matching logic (§4.3) ----------

def _norm(s: Any) -> str:
    """Normalisasi buat matching. Selain lower+trim, samain varian dash
    (en-dash/em-dash/minus -> hyphen biasa) + collapse whitespace jadi 1 spasi.
    Ini nutup bug exact-match gagal gara-gara beda karakter tak-kasat-mata:
    judul upstream sering pakai en-dash '–' (U+2013) sementara rule diketik hyphen
    '-' (U+002D) — mata sama, `==` beda."""
    text = str(s or "")
    for dash in ("–", "—", "−"):  # en-dash, em-dash, minus sign
        text = text.replace(dash, "-")
    text = " ".join(text.split())  # collapse whitespace (termasuk NBSP via split)
    return text.strip().lower()


def _match_rule(alarm: dict[str, Any], rule: dict[str, Any]) -> bool:
    """True kalau alarm cocok SEMUA field matching yang keisi di rule (AND)."""
    name = _norm(alarm.get("alarm_name"))
    atype = _norm(alarm.get("alarm_type"))
    agent = _norm(alarm.get("agent_name"))
    client = _norm(alarm.get("client"))
    sev = _norm(alarm.get("severity"))

    checks = {
        "alarm_name_equals": lambda v: name == _norm(v),
        "alarm_name_contains": lambda v: _norm(v) in name,
        "alarm_type_equals": lambda v: atype == _norm(v),
        "agent_name_equals": lambda v: agent == _norm(v),
        "client_equals": lambda v: client == _norm(v),
        "severity_equals": lambda v: sev == _norm(v),
    }
    matched_any = False
    for field, check in checks.items():
        if field in rule and str(rule[field]).strip() != "":
            if not check(rule[field]):
                return False
            matched_any = True
    return matched_any


def evaluate_alarm(
    alarm: dict[str, Any],
    whitelist: list[dict[str, Any]],
    protect: list[dict[str, Any]],
    protect_high_severity: bool,
) -> tuple[str, str]:
    """Tentukan aksi buat 1 alarm sesuai urutan prioritas §4.3.

    Balikin (action, reason):
      - ("skip",  reason)  -> jangan disentuh
      - ("close", reason)  -> tandai buat di-close sebagai FP
      - ("leave", "")      -> biarkan di Undefined (nggak match apa-apa)
    """
    # 1. Toggle protect severity tinggi.
    if protect_high_severity and _norm(alarm.get("severity")) in HIGH_SEVERITIES:
        return ("skip", f"Protect: severity '{alarm.get('severity')}' (toggle high-severity ON)")

    # 2. Protect list.
    for rule in protect:
        if _match_rule(alarm, rule):
            return ("skip", f"Protect: {rule.get('reason', 'match protect_list')}")

    # 3. Whitelist.
    for rule in whitelist:
        if _match_rule(alarm, rule):
            action = "exclude" if rule.get("disposition") == STATUS_EXCLUSION else "close"
            return (action, rule.get("reason", "Known false positive"))

    # 4. Nggak match apa-apa.
    return ("leave", "")


# ---------- Close alarms (§3.3, §4.4) ----------

def _take_alarm(
    client: httpx.Client,
    base_url: str,
    cookie: str,
    aid: str,
) -> None:
    """Langkah 1: TAKE (claim) alarm. Replikasi 3 request POST yang browser kirim
    pas klik "Take Alarm" (lihat komentar ACTION_TAKE). Tanpa ini, set FP gagal
    diam-diam. Payload: 2 pertama ["id"], ketiga ["id", ""]."""
    for i, action in enumerate(ACTION_TAKE):
        payload = [aid, ""] if i == 2 else [aid]
        _call_server_action(
            client, base_url, cookie, action, payload, referer_path=ALARM_PATH,
            retry_transient=False,
        )


def _wait_random_delay(
    action_delay: tuple[int, int],
    wait: Optional[Callable[[float], bool]],
    log: Optional[Callable[[str], None]],
    label: str,
) -> bool:
    low, high = action_delay
    if not 0 <= low <= high:
        raise ValueError("Range jeda aksi tidak valid.")
    seconds = low + secrets.randbelow(high - low + 1)
    if seconds == 0:
        return False
    if log:
        log(f"  Jeda random {seconds}s {label}.")
    if wait:
        return bool(wait(seconds))
    time.sleep(seconds)
    return False


def close_alarms(
    base_url: str,
    cookie: str,
    ids: list[str],
    reason: str,
    log: Optional[Callable[[str], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    skip_take_ids: Optional[set[str]] = None,
    confirm_owner: Optional[Callable[[str], bool]] = None,
    disposition: str = STATUS_FALSE_POSITIVE,
    wait: Optional[Callable[[float], bool]] = None,
    action_delay: tuple[int, int] = (0, 0),
    delay_before_first: bool = False,
) -> set[str]:
    """Mutasi alarm PER-ALARM: TAKE dulu, lalu set disposition (§3.3).
    Alur ini confirmed dari capture DevTools: mutation tanpa take = silent fail.

    Batch multi-ID di-DROP karena take kelihatannya per-alarm. Reason dipotong 250
    char (batas modal upstream). Balikin jumlah alarm yang berhasil dikirim (bukan
    verified — verifikasi terpisah). Alarm yang error di-skip, sisanya lanjut.

    should_stop: callback dicek di awal tiap iterasi — kalau True, berhenti di
    tengah loop (biar tombol Stop responsif, nggak nunggu ratusan alarm kelar).

    skip_take_ids: ID yang udah ke-take akun sendiri (field `email` == user login).
    Buat ID ini, langkah take di-SKIP (take ulang alarm yang udah ke-take = server
    balik response non-RSC = gagal). Langsung set disposition aja."""
    if not ids:
        return set()
    if confirm_owner is None:
        raise ValueError("confirm_owner wajib untuk mutation.")
    if disposition not in DISPOSITIONS:
        raise ValueError(f"Disposition tidak valid: {disposition}")
    reason = (reason or "")[:REASON_MAX_LEN]
    if skip_take_ids is None:
        skip_take_ids = set()
    submitted: set[str] = set()
    with _new_client() as client:
        for index, aid in enumerate(ids):
            if (index or delay_before_first) and _wait_random_delay(
                action_delay, wait, log, "sebelum alarm berikutnya"
            ):
                break
            if should_stop and should_stop():
                if log:
                    log(f"  Stop — close dihentikan ({len(submitted)}/{len(ids)} terkirim).")
                break
            try:
                # Langkah 1: take/claim — SKIP kalau udah ke-take sendiri.
                if aid in skip_take_ids:
                    if log:
                        log(f"  [{aid}] udah ke-take sendiri, skip take.")
                else:
                    _take_alarm(client, base_url, cookie, aid)
                    skip_take_ids.add(aid)
                    if _wait_random_delay(
                        action_delay, wait, log, f"setelah take [{aid}] sebelum verdict"
                    ):
                        break
                    if should_stop and should_stop():
                        break
                if not confirm_owner(aid):
                    if log:
                        log(f"  GAGAL [{aid}]: ownership sebelum mutation tidak terkonfirmasi.")
                    continue
                if should_stop and should_stop():
                    break
                # Langkah 2: set disposition (format 3-argumen, §3.3).
                payload = [[aid], disposition, reason]
                _call_server_action(
                    client, base_url, cookie, ACTION_CLOSE, payload,
                    referer_path=ALARM_PATH, retry_transient=False,
                )
                submitted.add(aid)
                if log:
                    log(f"  take+{disposition} [{aid}] ok ({len(submitted)}/{len(ids)}).")
            except ArgusError as exc:
                if log:
                    log(f"  GAGAL [{aid}]: {exc}")
    return submitted


# ---------- Suppress (alarm grup / similar-alerts, §3.3) ----------

def _build_suppress_config(ids: list[str]) -> list[dict[str, Any]]:
    """Bangun arg3 (array config toggle) buat submit suppress. Urutan CONFIRMED
    dari capture DevTools multi-ID: semua src_ip dulu (satu per ID), baru semua
    dest_ip. group_id tiap object = ID alarm-nya sendiri, toggle default OFF."""
    config: list[dict[str, Any]] = []
    for track_by in SUPPRESS_TRACK_BY:
        for aid in ids:
            config.append({
                "isSelected": False,
                "group_id": aid,
                "type": "suppress",
                "track_by": track_by,
                "count": "",
                "seconds": "",
                "is_subnet": False,
            })
    return config


def suppress_alarms(
    base_url: str,
    cookie: str,
    ids: list[str],
    reason: str,
    log: Optional[Callable[[str], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    skip_take_ids: Optional[set[str]] = None,
    confirm_owner: Optional[Callable[[str], bool]] = None,
    wait: Optional[Callable[[float], bool]] = None,
    action_delay: tuple[int, int] = (0, 0),
    delay_before_first: bool = False,
) -> set[str]:
    """Close alarm lewat jalur SUPPRESS (format 4-argumen). Dipakai buat alarm
    yang silent-fail di jalur FP 3-argumen biasa — yaitu alarm grup / punya
    "Similar Alerts" (§3.3).

    Beda dari close_alarms cuma di payload submit:
      - close_alarms : [[id], "False Positive", reason]          (3 arg)
      - suppress     : [[id], "Whitelist", reason, [configs]]    (4 arg)
    Hash & take sama persis (ACTION_CLOSE + ACTION_TAKE), jadi nggak ada
    Next-Action baru.

    Di-close PER-ALARM (bukan atomic per-grup): keterkaitan grup nggak keliatan
    di hasil fetch (group_id beda-beda per alarm), jadi bot nggak bisa
    ngelompokin di depan. Tiap alarm di-suppress sendiri — arg0 1 ID, arg3 2
    config (src_ip + dest_ip). Balikin jumlah yang berhasil dikirim."""
    if not ids:
        return set()
    if confirm_owner is None:
        raise ValueError("confirm_owner wajib untuk mutation.")
    reason = (reason or "")[:REASON_MAX_LEN]
    submitted: set[str] = set()
    with _new_client() as client:
        for index, aid in enumerate(ids):
            if (index or delay_before_first) and _wait_random_delay(
                action_delay, wait, log, "sebelum alarm berikutnya"
            ):
                break
            if should_stop and should_stop():
                if log:
                    log(f"  Stop — suppress dihentikan ({len(submitted)}/{len(ids)} terkirim).")
                break
            try:
                # Take dulu (sama kayak jalur FP — tanpa ini set status silent-fail).
                # Skip take kalau alarm udah ke-take akun sendiri (server nolak
                # take ulang -> parse error). Langsung submit suppress aja.
                if not (skip_take_ids and aid in skip_take_ids):
                    _take_alarm(client, base_url, cookie, aid)
                    if skip_take_ids is not None:
                        skip_take_ids.add(aid)
                    if _wait_random_delay(
                        action_delay, wait, log, f"setelah take [{aid}] sebelum verdict"
                    ):
                        break
                    if should_stop and should_stop():
                        break
                if not confirm_owner(aid):
                    if log:
                        log(f"  GAGAL suppress [{aid}]: ownership sebelum mutation tidak terkonfirmasi.")
                    continue
                if should_stop and should_stop():
                    break
                payload = [
                    [aid],
                    WHITELIST_CATEGORY,
                    reason,
                    _build_suppress_config([aid]),
                ]
                _call_server_action(
                    client, base_url, cookie, ACTION_CLOSE, payload,
                    referer_path=ALARM_PATH, retry_transient=False,
                )
                submitted.add(aid)
                if log:
                    log(f"  suppress [{aid}] ok ({len(submitted)}/{len(ids)}).")
            except ArgusError as exc:
                if log:
                    log(f"  GAGAL suppress [{aid}]: {exc}")
    return submitted


# ---------- Verify (§4.4) ----------

def verify_disposition(
    base_url: str,
    cookie: str,
    ids: list[str],
    shift_time: str,
    page_size: int = 100,
    log: Optional[Callable[[str], None]] = None,
    date_from: str = "",
    date_to: str = "",
    last_days: str = "1",
    disposition: str = STATUS_FALSE_POSITIVE,
) -> tuple[set[str], set[str]]:
    """Re-fetch tab disposition, cek ID mana yang beneran pindah."""
    if not ids:
        return (set(), set())
    if disposition not in DISPOSITIONS:
        raise ValueError(f"Disposition tidak valid: {disposition}")
    moved_alarms = fetch_all_open_alarms(
        base_url, cookie, shift_time, page_size=page_size,
        status=disposition, log=None,
        date_from=date_from, date_to=date_to, last_days=last_days,
    )
    moved_ids = {str(a.get("_id")) for a in moved_alarms}
    want = {str(i) for i in ids}
    verified = want & moved_ids
    missing = want - moved_ids
    if log and missing:
        log(f"  WARNING: {len(missing)} ID nggak keliatan di tab {disposition}: {sorted(missing)}")
    return (verified, missing)


def verify_false_positive(*args, **kwargs) -> tuple[set[str], set[str]]:
    return verify_disposition(*args, **kwargs, disposition=STATUS_FALSE_POSITIVE)
