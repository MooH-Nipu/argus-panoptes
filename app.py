"""Flask control panel Argus Panoptes.

Model pemakaian (PROJECT_SPEC §5): lokal per-PC, on-demand. Analyst buka
http://localhost:5000 -> login (username+password akun upstream) -> pilih shift
& interval -> Start -> bot jalan di background thread, sapu tiap interval,
live log muncul di dashboard -> Stop kapan aja.

Whitelist & protect list di-CRUD lewat halaman Rules. Setting (interval,
shift, toggle protect-severity) diatur dari dashboard.

CATATAN KEAMANAN: app ini didesain buat localhost. Password upstream cuma
dipegang di memory selama bot jalan (buat login sekali di awal), nggak
disimpan ke disk. Jangan expose ke network tanpa HTTPS + auth tambahan.
"""

from __future__ import annotations

import ipaddress
import secrets
import threading
import time
from collections import deque
from datetime import datetime
from functools import wraps
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import config_store as cfg
import argus_core as core

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # sesi Flask lokal, regenerate tiap start
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    MAX_CONTENT_LENGTH=16 * 1024,
)

MAX_LOG_LINES = 500
MIN_POLL_INTERVAL = 30
MAX_POLL_INTERVAL = 86_400
MAX_CLOSE_LIMIT = 500
MAX_ACTION_DELAY = 300
SESSION_IDLE_TTL = 8 * 60 * 60
LOGIN_WINDOW = 60
LOGIN_LIMIT = 5


class BotState:
    """State satu bot per sesi analyst. Thread + log buffer + kontrol stop."""

    def __init__(self) -> None:
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.logs: deque[str] = deque(maxlen=MAX_LOG_LINES)
        self.running = False
        self.base_url = ""
        self.username = ""
        self.upstream_cookie = ""
        self.last_activity = time.time()
        self.last_cycle: str = ""
        # Epoch (detik) kapan siklus berikutnya mulai. 0 = lagi nggak cooldown
        # (bot lagi kerja / belum jalan). Dipakai UI buat hitung mundur.
        self.next_cycle_at: float = 0.0
        self.stats = {"closed": 0, "skipped": 0, "left": 0, "cycles": 0}

    def log(self, msg: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            self.logs.append(f"[{stamp}] {msg}")

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            # Sisa detik cooldown sampai siklus berikutnya (0 kalau lagi kerja
            # atau nggak jalan). Server yang ngitung biar nggak beda jam browser.
            cooldown = max(0, int(self.next_cycle_at - time.time())) if self.next_cycle_at else 0
            return {
                "running": self.running,
                "logs": list(self.logs),
                "stats": dict(self.stats),
                "last_cycle": self.last_cycle,
                "username": self.username,
                "base_url": self.base_url,
                "cooldown": cooldown,
            }


# Bot per session id. Lokal jadi praktis 1 user, tapi tetap keyed by session.
RUNNING_BOTS: dict[str, BotState] = {}
_BOTS_LOCK = threading.Lock()
_LOGIN_ATTEMPTS: dict[tuple[str, str], deque[float]] = {}
_LOGIN_LOCK = threading.Lock()


def _get_sid() -> str:
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)
    return session["sid"]


def _get_bot(create: bool = False) -> Optional[BotState]:
    sid = _get_sid()
    with _BOTS_LOCK:
        bot = RUNNING_BOTS.get(sid)
        if bot and not bot.running and time.time() - bot.last_activity > SESSION_IDLE_TTL:
            bot.upstream_cookie = ""
            RUNNING_BOTS.pop(sid, None)
            bot = None
        if bot is None and create:
            bot = BotState()
            RUNNING_BOTS[sid] = bot
        if bot:
            bot.last_activity = time.time()
        return bot


def _login_allowed(username: str) -> bool:
    key = (request.remote_addr or "unknown", username.casefold())
    now = time.time()
    with _LOGIN_LOCK:
        attempts = _LOGIN_ATTEMPTS.setdefault(key, deque())
        while attempts and now - attempts[0] >= LOGIN_WINDOW:
            attempts.popleft()
        if len(attempts) >= LOGIN_LIMIT:
            return False
        attempts.append(now)
        return True


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


PRIVATE_UPSTREAM_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def _is_private_upstream_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return any(address in network for network in PRIVATE_UPSTREAM_NETWORKS)


def validate_base_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Base URL must be HTTPS with a valid host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Base URL must not contain credentials, query, or fragment.")
    if parsed.path not in ("", "/"):
        raise ValueError("Base URL must not contain a path.")
    try:
        port = 443 if parsed.port is None else parsed.port
    except ValueError as exc:
        raise ValueError("Invalid Base URL port.") from exc
    if port < 1:
        raise ValueError("Invalid Base URL port.")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("upstream Base URL must be a private IP literal, not a hostname.") from exc
    if not _is_private_upstream_address(str(address)):
        raise ValueError("upstream Base URL must point to a safe private network.")
    display_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"https://{display_host}" + (f":{port}" if port != 443 else "")


def validate_start_settings(form: Any, defaults: dict[str, Any]) -> dict[str, Any]:
    interval = _to_int(form.get("poll_interval_seconds"), -1)
    if not MIN_POLL_INTERVAL <= interval <= MAX_POLL_INTERVAL:
        raise ValueError(f"Interval must be {MIN_POLL_INTERVAL}-{MAX_POLL_INTERVAL} seconds.")
    max_close = _to_int(form.get("max_close_per_cycle"), -1)
    if not 1 <= max_close <= MAX_CLOSE_LIMIT:
        raise ValueError(f"Max close must be 1-{MAX_CLOSE_LIMIT}.")
    delay_min = _to_int(
        form.get("action_delay_min_seconds"), defaults["action_delay_min_seconds"]
    )
    delay_max = _to_int(
        form.get("action_delay_max_seconds"), defaults["action_delay_max_seconds"]
    )
    if not 0 <= delay_min <= delay_max <= MAX_ACTION_DELAY:
        raise ValueError(f"Action delay must be 0-{MAX_ACTION_DELAY} seconds with min <= max.")
    return {
        **defaults,
        "poll_interval_seconds": interval,
        "max_close_per_cycle": max_close,
        "action_delay_min_seconds": delay_min,
        "action_delay_max_seconds": delay_max,
        "protect_high_severity": form.get("protect_high_severity") == "on",
        "dry_run": form.get("live_mode") != "on",
        "enable_suppress_fallback": form.get("enable_suppress_fallback") == "on",
    }


app.jinja_env.globals.update(
    csrf_token=_csrf_token,
    whitelist_rule_version=cfg.whitelist_rule_version,
)


@app.before_request
def verify_csrf():
    if request.method != "POST":
        return None
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(supplied, expected):
        return jsonify({"ok": False, "error": "Invalid CSRF token. Refresh the page."}), 403
    return None


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


# ---------- Auth level-aplikasi ----------
# Browser hanya menyimpan sid acak. Cookie upstream tinggal di BotState server-side.

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        bot = _get_bot()
        if not bot or not bot.upstream_cookie:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Kalau udah login, langsung ke dashboard.
        bot = _get_bot()
        if bot and bot.upstream_cookie:
            return redirect(url_for("index"))
        return render_template("login.html")

    base_url = (request.form.get("base_url") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not base_url or not username or not password:
        return render_template("login.html", error="Base URL, username, and password are required.")
    if not _login_allowed(username):
        return render_template("login.html", error="Too many login attempts. Try again in a minute."), 429

    try:
        base_url = validate_base_url(base_url)
        cookie = core.login(base_url, username, password)
    except (ValueError, core.LoginError, core.ArgusError, httpx.HTTPError) as exc:
        return render_template(
            "login.html", error=f"Login failed: {exc}", base_url=base_url,
            username=username,
        )

    bot = _get_bot(create=True)
    if bot is None:
        raise RuntimeError("Failed to create local session state.")
    bot.upstream_cookie = cookie
    bot.base_url = base_url.rstrip("/")
    bot.username = username
    session["base_url"] = base_url
    session["username"] = username
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    # Stop bot dulu kalau lagi jalan (cookie-nya bakal ilang).
    bot = _get_bot()
    if bot and bot.running:
        bot.stop_event.set()
    if bot:
        if bot.thread and bot.thread.is_alive():
            bot.thread.join(timeout=2)
        bot.upstream_cookie = ""
        with _BOTS_LOCK:
            RUNNING_BOTS.pop(_get_sid(), None)
    session.clear()
    return redirect(url_for("login"))


# ---------- Bot loop ----------

def _bot_loop(bot: BotState, cookie: str, settings: dict[str, Any]) -> None:
    """Loop utama: sapu tiap interval sampai stop_event di-set (§8).
    Window shift dihitung dari jam sistem tiap awal siklus (cfg.shift_windows)."""
    page_size = int(settings["page_size"])

    interval = int(settings["poll_interval_seconds"])
    protect_high = bool(settings["protect_high_severity"])
    max_close = int(settings["max_close_per_cycle"])
    action_delay = (
        int(settings["action_delay_min_seconds"]),
        int(settings["action_delay_max_seconds"]),
    )

    limit_txt = "unlimited" if max_close <= 0 else f"max {max_close}/sweep"
    bot.log(f"Bot started. Auto shift (system clock, 1h grace), interval={interval}s, "
            f"protect_high_severity={'ON' if protect_high else 'OFF'}, "
            f"close {limit_txt}, random action delay={action_delay[0]}-{action_delay[1]}s.")

    try:
        while not bot.stop_event.is_set():
            cycle_start = time.time()
            # Budget max_close dibagi antar window (shift lama + baru) biar
            # cap per sapu nggak dobel pas grace period.
            budget = max_close
            for shift, date_from, date_to in cfg.shift_windows():
                if budget <= 0 or bot.stop_event.is_set():
                    break
                bot.log(f"Cycle start. Shift {shift}, dates {date_from} to {date_to}.")
                budget -= _run_one_cycle(
                    bot, cookie, shift, page_size, protect_high, budget,
                    date_from=date_from, date_to=date_to, last_days="",
                    dry_run=bool(settings.get("dry_run", True)),
                    enable_suppress_fallback=bool(
                        settings.get("enable_suppress_fallback", False)),
                    action_delay=action_delay,
                )

            with bot.lock:
                bot.stats["cycles"] += 1
                bot.last_cycle = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Sleep interval, tapi cek stop tiap detik biar responsif.
            elapsed = time.time() - cycle_start
            remaining = max(0, interval - int(elapsed))
            if remaining:
                bot.log(f"Cycle done. Next cycle in {remaining}s.")
                with bot.lock:
                    bot.next_cycle_at = time.time() + remaining
            bot.stop_event.wait(remaining)
            with bot.lock:
                bot.next_cycle_at = 0.0
    except core.ArgusAuthError as exc:
        bot.log(f"AUTH ERROR: {exc} Please log in again.")
    except core.ArgusError as exc:
        bot.log(f"Cycle ERROR: {exc}")
    except Exception as exc:  # noqa: BLE001 - worker must fail closed and reset state
        bot.log(f"Unexpected ERROR: {exc}")
    finally:
        bot.log("Bot stopped.")
        with bot.lock:
            bot.running = False
            bot.next_cycle_at = 0.0


def _run_one_cycle(
    bot: BotState,
    cookie: str,
    shift: str,
    page_size: int,
    protect_high: bool,
    max_close: int,
    date_from: str = "",
    date_to: str = "",
    last_days: str = "1",
    dry_run: bool = True,
    enable_suppress_fallback: bool = False,
    action_delay: tuple[int, int] = (0, 0),
) -> int:
    """Satu siklus sapu: fetch -> evaluate -> group -> close -> verify (§4.4).
    Balikin jumlah kandidat yang dipakai dari budget max_close.

    max_close: batas maks alarm yang di-close per sapu (<=0 = tanpa batas).
    Yang kelebihan ditunda ke sapu berikutnya.
    date_from/date_to (YYYY-MM-DD) vs last_days mutually exclusive — fetch &
    verify pakai range yang SAMA biar verify nggak false-negative."""
    whitelist = cfg.load_whitelist()
    protect = cfg.load_protect()

    alarms = core.fetch_all_open_alarms(
        bot.base_url, cookie, shift, page_size=page_size,
        status=core.STATUS_UNDEFINED, log=bot.log,
        date_from=date_from, date_to=date_to, last_days=last_days,
    )
    if not alarms:
        bot.log("No Undefined alarms in this shift. (If upstream's Undefined tab is not "
                "empty, the shift string in config_store.SHIFTS probably doesn't match.)")
        return 0

    # Kelompokkan alarm yang ditandai close by reason (§4.4).
    # Field `email` di alarm = email peng-take (kosong kalau belum di-take).
    # Bandingin sama username login (yang juga email) buat tau "ke-take sendiri".
    my_email = core._norm(bot.username)
    to_close: dict[tuple[str, str], list[str]] = {}
    skip_take_ids: set[str] = set()
    names: dict[str, str] = {}
    n_skip = 0
    n_leave = 0
    n_other = 0
    for alarm in alarms:
        action, reason = core.evaluate_alarm(alarm, whitelist, protect, protect_high)
        aid = str(alarm.get("_id"))
        name = alarm.get("alarm_name", "?")
        if action in {"close", "exclude"}:
            disposition = (
                core.STATUS_EXCLUSION if action == "exclude" else core.STATUS_FALSE_POSITIVE
            )
            taker_email = core._norm(alarm.get("email"))
            # Di-take analyst lain -> JANGAN sentuh (bisa nabrak investigasi orang).
            if taker_email and taker_email != my_email:
                n_other += 1
                bot.log(f"LEAVE [{aid}] {name} — taken by another analyst ({alarm.get('email')})")
                continue
            # Di-take sendiri -> tandai skip-take (take ulang = gagal non-RSC).
            if taker_email and taker_email == my_email:
                skip_take_ids.add(aid)
            to_close.setdefault((disposition, reason), []).append(aid)
            names[aid] = str(name)
        elif action == "skip":
            n_skip += 1
            bot.log(f"SKIP [{aid}] {name} — {reason}")
        else:
            n_leave += 1

    total_close = sum(len(v) for v in to_close.values())

    # Batas maks close per sapu (<=0 = tanpa batas). Ambil per grup reason
    # sesuai urutan alarm datang; sisanya ditunda ke sapu berikutnya.
    deferred = 0
    if max_close and max_close > 0 and total_close > max_close:
        trimmed: dict[tuple[str, str], list[str]] = {}
        budget = max_close
        for key, ids in to_close.items():
            if budget <= 0:
                break
            take = ids[:budget]
            trimmed[key] = take
            budget -= len(take)
        deferred = total_close - max_close
        to_close = trimmed
        total_close = max_close

    bot.log(f"Evaluation: {total_close} to mutate, {n_skip} skipped, "
            f"{n_leave} left for manual review"
            + (f", {n_other} taken by other analysts" if n_other else "")
            + (f" ({len(skip_take_ids)} already taken by you, skipping take)" if skip_take_ids else "")
            + (f", {deferred} deferred (limit {max_close}/sweep)." if deferred else "."))

    with bot.lock:
        bot.stats["skipped"] += n_skip
        bot.stats["left"] += n_leave

    if dry_run:
        for (disposition, reason), ids in to_close.items():
            bot.log(
                f'DRY RUN — {len(ids)} {disposition} candidates, '
                f'reason: "{reason}" IDs={ids}'
            )
        return total_close

    # Close per kelompok reason, lalu verifikasi.
    should_stop = bot.stop_event.is_set

    def confirm_owner(aid: str) -> bool:
        refreshed = core.fetch_all_open_alarms(
            bot.base_url, cookie, shift, page_size=page_size,
            status=core.STATUS_UNDEFINED, log=None,
            date_from=date_from, date_to=date_to, last_days=last_days,
        )
        return any(
            str(alarm.get("_id")) == aid
            and core._norm(alarm.get("email")) == my_email
            for alarm in refreshed
        )

    for group_index, ((disposition, reason), ids) in enumerate(to_close.items()):
        # Stop dicek antar-grup — kalau user klik Stop, jangan mulai grup baru.
        if should_stop():
            bot.log("Stop — cycle halted before next group.")
            break
        bot.log(f"Setting {len(ids)} alarms to {disposition}, reason: \"{reason}\"")
        submitted = core.close_alarms(
            bot.base_url, cookie, ids, reason,
            log=bot.log, should_stop=should_stop,
            skip_take_ids=skip_take_ids, confirm_owner=confirm_owner,
            disposition=disposition,
            wait=bot.stop_event.wait, action_delay=action_delay,
            delay_before_first=group_index > 0,
        )
        # Audit di finally: mutation yang udah kekirim tetap tercatat walau
        # verify error/Stop. verified=None = belum sempat diverifikasi.
        verified: Optional[set[str]] = None
        try:
            verified, missing = core.verify_disposition(
                bot.base_url, cookie, sorted(submitted), shift, page_size=page_size,
                log=bot.log, date_from=date_from, date_to=date_to, last_days=last_days,
                disposition=disposition,
            )
            bot.log(
                f"  Verified {len(verified)}/{len(submitted)} moved to {disposition} tab."
            )
            use_suppress = (
                disposition == core.STATUS_FALSE_POSITIVE and enable_suppress_fallback
            )
            if missing and use_suppress and not should_stop():
                bot.log("  Waiting 2s, then re-verifying before suppress fallback.")
                if not bot.stop_event.wait(2):
                    verified_retry, missing = core.verify_false_positive(
                        bot.base_url, cookie, sorted(missing), shift, page_size=page_size,
                        log=bot.log, date_from=date_from, date_to=date_to,
                        last_days=last_days,
                    )
                    verified |= verified_retry
        finally:
            _audit(bot, submitted, names, disposition, reason, verified, "verdict")

        # Fallback: alarm yang silent-fail di jalur FP 3-argumen (biasanya alarm
        # grup / punya "Similar Alerts") coba lewat jalur suppress 4-argumen.
        # Keterkaitan grup nggak keliatan di fetch, jadi kita nggak deteksi di
        # depan — pakai `missing` dari verify sebagai sinyal butuh suppress.
        # Suppress fallback hanya valid untuk jalur False Positive.
        if missing and use_suppress and not should_stop():
            miss_ids = sorted(missing)
            bot.log(f"  {len(miss_ids)} alarms did not move — trying suppress path.")
            suppressed = core.suppress_alarms(
                bot.base_url, cookie, miss_ids, reason, log=bot.log,
                should_stop=should_stop,
                skip_take_ids=skip_take_ids,
                confirm_owner=confirm_owner,
                wait=bot.stop_event.wait, action_delay=action_delay,
            )
            verified2: Optional[set[str]] = None
            try:
                verified2, missing2 = core.verify_false_positive(
                    bot.base_url, cookie, miss_ids, shift, page_size=page_size, log=bot.log,
                    date_from=date_from, date_to=date_to, last_days=last_days,
                )
            finally:
                _audit(bot, suppressed, names, disposition, reason, verified2, "suppress")
            bot.log(f"  Suppress verified {len(verified2)}/{len(miss_ids)} moved to FP tab.")
            if missing2:
                bot.log(f"  WARNING: {len(missing2)} still did not move "
                        f"(both FP and suppress failed): {sorted(missing2)}")
            verified = verified | verified2

        with bot.lock:
            bot.stats["closed"] += len(verified)
    return total_close


def _audit(
    bot: BotState,
    ids: set[str],
    names: dict[str, str],
    disposition: str,
    reason: str,
    verified: Optional[set[str]],
    via: str,
) -> None:
    """Catat mutation yang terkirim ke audit.jsonl. Gagal tulis = raise
    (worker berhenti) — lebih baik stop daripada close tanpa jejak."""
    ts = datetime.now().isoformat(timespec="seconds")
    cfg.append_audit([
        {
            "ts": ts,
            "user": bot.username,
            "alarm_id": aid,
            "alarm_name": names.get(aid, ""),
            "disposition": disposition,
            "reason": reason,
            "via": via,
            "verified": None if verified is None else aid in verified,
        }
        for aid in sorted(ids)
    ])


# Milestone achievement (jumlah alarm verified). Display doang.
ACHIEVEMENTS = (
    (0, "Fresh Intern Energy",
     "Still believes every alarm is a real attack. Adorable."),
    (1_000, "Alarm Janitor",
     "A thousand alarms swept. Nobody said thanks. Nobody ever will."),
    (5_000, "Professional Noise Ignorer",
     "Can tell a real 'critical' from an agent having a bad day."),
    (10_000, "False Positive Whisperer",
     "Alarms go quiet when you walk by. They know."),
    (20_000, "SIEM Sweeper Supreme",
     "The Undefined tab is empty more often than your fridge at month's end."),
    (50_000, "Ticket Queue Exorcist",
     "You banish alarm queues like demons. Vendor rules fear you now."),
    (100_000, "Lord of the Undefined Tab",
     "A hundred thousand verdicts. You're not an analyst anymore. You're SOC lore."),
)


def achievement_progress(count: int) -> dict[str, Any]:
    reached = [a for a in ACHIEVEMENTS if count >= a[0]]
    upcoming = [a for a in ACHIEVEMENTS if count < a[0]]
    floor, title, description = reached[-1]
    nxt = upcoming[0] if upcoming else None
    pct = 100 if nxt is None else int((count - floor) * 100 / (nxt[0] - floor))
    return {
        "count": count,
        "title": title,
        "description": description,
        "unlocked": [name for need, name, _ in reached if need > 0],
        "next_title": nxt[1] if nxt else "",
        "next_at": nxt[0] if nxt else 0,
        "percent": pct,
        "ladder": [
            {"at": need, "title": name, "description": desc, "unlocked": count >= need}
            for need, name, desc in ACHIEVEMENTS
        ],
    }


# ---------- Routes: dashboard ----------

@app.route("/health")
def health():
    return jsonify({"ok": True})


@app.route("/favicon.ico")
def favicon():
    # Browser selalu minta favicon; 204 biar console nggak 404.
    return "", 204


@app.route("/")
@login_required
def index():
    bot = _get_bot()
    settings = cfg.load_settings()
    return render_template(
        "index.html",
        running=bot.running if bot else False,
        shift_windows=cfg.shift_windows(),
        settings=settings,
        username=session.get("username", ""),
        base_url=session.get("base_url", ""),
    )


@app.route("/start", methods=["POST"])
@login_required
def start():
    bot = _get_bot(create=True)
    if bot is None:
        raise RuntimeError("Failed to create local session state.")
    cookie = bot.upstream_cookie
    base_url = bot.base_url
    if not cookie or not base_url:
        return jsonify({"ok": False, "error": "Login session expired. Please log in again."}), 401

    try:
        settings = validate_start_settings(request.form, cfg.load_settings())
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    with bot.lock:
        if bot.running:
            return jsonify({"ok": False, "error": "Bot is already running."}), 400
        cfg.save_settings(settings)
        bot.stop_event.clear()
        bot.running = True
        bot.logs.clear()
        bot.stats = {"closed": 0, "skipped": 0, "left": 0, "cycles": 0}
        thread = threading.Thread(target=_bot_loop, args=(bot, cookie, settings), daemon=True)
        bot.thread = thread
    thread.start()
    return jsonify({"ok": True, "dry_run": settings["dry_run"]})


@app.route("/stop", methods=["POST"])
@login_required
def stop():
    bot = _get_bot()
    if not bot or not bot.running:
        return jsonify({"ok": False, "error": "Bot is not running."}), 400
    bot.stop_event.set()
    bot.log("Stop requested, waiting for cycle to halt...")
    return jsonify({"ok": True})


@app.route("/status")
@login_required
def status():
    bot = _get_bot()
    if not bot:
        return jsonify({"running": False, "logs": [], "stats": {}, "last_cycle": ""})
    return jsonify(bot.snapshot())


# ---------- Routes: rules CRUD ----------

@app.route("/achievements")
@login_required
def achievements():
    return jsonify(achievement_progress(cfg.audit_verified_count()))


@app.route("/rules")
@login_required
def rules():
    return render_template(
        "rules.html",
        whitelist=cfg.load_whitelist(),
        protect=cfg.load_protect(),
        whitelist_fields=cfg.WHITELIST_FIELDS,
        whitelist_dispositions=cfg.WHITELIST_DISPOSITIONS,
        protect_fields=cfg.PROTECT_FIELDS,
    )


@app.route("/rules/whitelist/add", methods=["POST"])
@login_required
def add_whitelist():
    return _handle_rule_add(
        cfg.WHITELIST_FIELDS, cfg.add_whitelist_rule, extra_fields=("disposition",)
    )


@app.route("/rules/whitelist/edit/<int:index>", methods=["POST"])
@login_required
def edit_whitelist(index: int):
    rule = {
        field: request.form.get(field, "")
        for field in [*cfg.WHITELIST_FIELDS, "disposition"]
    }
    rule["reason"] = request.form.get("reason", "")
    try:
        cfg.update_whitelist_rule(
            index,
            rule,
            expected_version=request.form.get("expected_version", ""),
        )
    except IndexError:
        return "Whitelist rule not found.", 404
    except (ValueError, cfg.RuleConflictError) as exc:
        status = 409 if isinstance(exc, cfg.RuleConflictError) else 400
        return render_template(
            "rules.html",
            whitelist=cfg.load_whitelist(),
            protect=cfg.load_protect(),
            whitelist_fields=cfg.WHITELIST_FIELDS,
            whitelist_dispositions=cfg.WHITELIST_DISPOSITIONS,
            protect_fields=cfg.PROTECT_FIELDS,
            error=str(exc),
        ), status
    return redirect(url_for("rules"))


@app.route("/rules/whitelist/delete/<int:index>", methods=["POST"])
@login_required
def delete_whitelist(index: int):
    try:
        cfg.delete_whitelist_rule(index)
    except IndexError:
        pass
    return redirect(url_for("rules"))


@app.route("/rules/protect/add", methods=["POST"])
@login_required
def add_protect():
    return _handle_rule_add(cfg.PROTECT_FIELDS, cfg.add_protect_rule)


@app.route("/rules/protect/delete/<int:index>", methods=["POST"])
@login_required
def delete_protect(index: int):
    try:
        cfg.delete_protect_rule(index)
    except IndexError:
        pass
    return redirect(url_for("rules"))


def _handle_rule_add(fields: list[str], add_fn, extra_fields: tuple[str, ...] = ()) -> Any:
    rule = {f: request.form.get(f, "") for f in [*fields, *extra_fields]}
    rule["reason"] = request.form.get("reason", "")
    try:
        add_fn(rule)
    except ValueError as exc:
        # Simpel: kembali ke halaman rules. Validasi juga ada di UI.
        return render_template(
            "rules.html",
            whitelist=cfg.load_whitelist(),
            protect=cfg.load_protect(),
            whitelist_fields=cfg.WHITELIST_FIELDS,
            whitelist_dispositions=cfg.WHITELIST_DISPOSITIONS,
            protect_fields=cfg.PROTECT_FIELDS,
            error=str(exc),
        )
    return redirect(url_for("rules"))


# ---------- Helpers ----------

def _to_int(val: Any, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


if __name__ == "__main__":
    # Localhost only (§5). Debug off biar nggak bocorin trace ke browser.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
