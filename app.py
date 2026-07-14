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

import os
import secrets
import threading
import time
from collections import deque
from datetime import datetime
from functools import wraps
from typing import Any, Optional

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

MAX_LOG_LINES = 500


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


def _get_sid() -> str:
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)
    return session["sid"]


def _get_bot(create: bool = False) -> Optional[BotState]:
    sid = _get_sid()
    with _BOTS_LOCK:
        bot = RUNNING_BOTS.get(sid)
        if bot is None and create:
            bot = BotState()
            RUNNING_BOTS[sid] = bot
        return bot


# ---------- Auth level-aplikasi ----------
# Login sekali -> cookie upstream + base_url disimpan di Flask session (server-side
# signed cookie). Password TIDAK disimpan. Semua halaman di-gate; kalau session
# kosong -> redirect ke /login. Cookie upstream bisa expired (session upstream timeout);
# kalau bot mulai kena 403, user tinggal logout+login lagi.

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("upstream_cookie"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Kalau udah login, langsung ke dashboard.
        if session.get("upstream_cookie"):
            return redirect(url_for("index"))
        return render_template("login.html")

    base_url = (request.form.get("base_url") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not base_url or not username or not password:
        return render_template("login.html", error="Base URL, username, dan password wajib diisi.")

    try:
        cookie = core.login(base_url, username, password)
    except core.LoginError as exc:
        return render_template("login.html", error=f"Login gagal: {exc}", base_url=base_url, username=username)
    except Exception as exc:
        return render_template("login.html", error=f"Login error: {exc}", base_url=base_url, username=username)

    session["upstream_cookie"] = cookie
    session["base_url"] = base_url.rstrip("/")
    session["username"] = username
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    # Stop bot dulu kalau lagi jalan (cookie-nya bakal ilang).
    bot = _get_bot()
    if bot and bot.running:
        bot.stop_event.set()
    session.pop("upstream_cookie", None)
    session.pop("base_url", None)
    session.pop("username", None)
    return redirect(url_for("login"))


# ---------- Bot loop ----------

def _bot_loop(bot: BotState, cookie: str, settings: dict[str, Any]) -> None:
    """Loop utama: sapu tiap interval sampai stop_event di-set (§8)."""
    shift = settings["shift_time"]
    page_size = int(settings["page_size"])
    batch_size = int(settings["batch_size"])
    interval = int(settings["poll_interval_seconds"])
    protect_high = bool(settings["protect_high_severity"])
    max_close = int(settings["max_close_per_cycle"])
    date_from = str(settings.get("date_from", "") or "")
    date_to = str(settings.get("date_to", "") or "")
    last_days = str(settings.get("last_days", "1") or "1")

    if date_from and date_to:
        range_txt = f"tanggal {date_from} s/d {date_to}"
    else:
        range_txt = f"{last_days} hari terakhir"
    limit_txt = "tanpa batas" if max_close <= 0 else f"maks {max_close}/sapu"
    bot.log(f"Bot start. Shift='{shift}', range={range_txt}, interval={interval}s, "
            f"protect_high_severity={'ON' if protect_high else 'OFF'}, "
            f"close {limit_txt}.")

    while not bot.stop_event.is_set():
        cycle_start = time.time()
        try:
            _run_one_cycle(bot, cookie, shift, page_size, batch_size, protect_high,
                           max_close, date_from, date_to, last_days)
        except core.ArgusError as exc:
            bot.log(f"ERROR siklus: {exc}")
        except Exception as exc:  # jangan biarkan thread mati diam-diam
            bot.log(f"ERROR tak terduga: {exc}")

        with bot.lock:
            bot.stats["cycles"] += 1
            bot.last_cycle = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Sleep interval, tapi cek stop tiap detik biar responsif.
        elapsed = time.time() - cycle_start
        remaining = max(0, interval - int(elapsed))
        if remaining:
            bot.log(f"Siklus selesai. Tunggu {remaining}s sampai siklus berikutnya.")
            with bot.lock:
                bot.next_cycle_at = time.time() + remaining
        for _ in range(remaining):
            if bot.stop_event.is_set():
                break
            time.sleep(1)
        # Mulai kerja lagi -> nggak cooldown.
        with bot.lock:
            bot.next_cycle_at = 0.0

    bot.log("Bot berhenti.")
    with bot.lock:
        bot.running = False
        bot.next_cycle_at = 0.0


def _run_one_cycle(
    bot: BotState,
    cookie: str,
    shift: str,
    page_size: int,
    batch_size: int,
    protect_high: bool,
    max_close: int,
    date_from: str = "",
    date_to: str = "",
    last_days: str = "1",
) -> None:
    """Satu siklus sapu: fetch -> evaluate -> group -> close -> verify (§4.4).

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
        bot.log("Nggak ada alarm Undefined di shift ini.")
        return

    # Kelompokkan alarm yang ditandai close by reason (§4.4).
    # Field `email` di alarm = email peng-take (kosong kalau belum di-take).
    # Bandingin sama username login (yang juga email) buat tau "ke-take sendiri".
    my_email = core._norm(bot.username)
    to_close: dict[str, list[str]] = {}
    skip_take_ids: set[str] = set()
    n_skip = 0
    n_leave = 0
    n_other = 0
    for alarm in alarms:
        action, reason = core.evaluate_alarm(alarm, whitelist, protect, protect_high)
        aid = str(alarm.get("_id"))
        name = alarm.get("alarm_name", "?")
        if action == "close":
            taker_email = core._norm(alarm.get("email"))
            # Di-take analyst lain -> JANGAN sentuh (bisa nabrak investigasi orang).
            if taker_email and taker_email != my_email:
                n_other += 1
                bot.log(f"LEAVE [{aid}] {name} — ke-take analyst lain ({alarm.get('email')})")
                continue
            # Di-take sendiri -> tandai skip-take (take ulang = gagal non-RSC).
            if taker_email and taker_email == my_email:
                skip_take_ids.add(aid)
            to_close.setdefault(reason, []).append(aid)
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
        trimmed: dict[str, list[str]] = {}
        budget = max_close
        for reason, ids in to_close.items():
            if budget <= 0:
                break
            take = ids[:budget]
            trimmed[reason] = take
            budget -= len(take)
        deferred = total_close - max_close
        to_close = trimmed
        total_close = max_close

    bot.log(f"Evaluasi: {total_close} akan di-close, {n_skip} di-skip, "
            f"{n_leave} dibiarkan (manual)"
            + (f", {n_other} ke-take analyst lain" if n_other else "")
            + (f" ({len(skip_take_ids)} di antaranya ke-take sendiri, skip take)" if skip_take_ids else "")
            + (f", {deferred} ditunda (batas {max_close}/sapu)." if deferred else "."))

    with bot.lock:
        bot.stats["skipped"] += n_skip
        bot.stats["left"] += n_leave

    # Close per kelompok reason, lalu verifikasi.
    should_stop = bot.stop_event.is_set
    for reason, ids in to_close.items():
        # Stop dicek antar-grup — kalau user klik Stop, jangan mulai grup baru.
        if should_stop():
            bot.log("Stop — siklus dihentikan sebelum grup berikutnya.")
            break
        bot.log(f"Close {len(ids)} alarm, reason: \"{reason}\"")
        sent = core.close_alarms(
            bot.base_url, cookie, ids, reason,
            batch_size=batch_size, log=bot.log, should_stop=should_stop,
            skip_take_ids=skip_take_ids,
        )
        verified, missing = core.verify_false_positive(
            bot.base_url, cookie, ids, shift, page_size=page_size, log=bot.log,
            date_from=date_from, date_to=date_to, last_days=last_days,
        )
        bot.log(f"  Verified {len(verified)}/{sent} pindah ke tab FP.")

        # Fallback: alarm yang silent-fail di jalur FP 3-argumen (biasanya alarm
        # grup / punya "Similar Alerts") coba lewat jalur suppress 4-argumen.
        # Keterkaitan grup nggak keliatan di fetch, jadi kita nggak deteksi di
        # depan — pakai `missing` dari verify sebagai sinyal butuh suppress.
        # Skip fallback kalau lagi stop (biar Stop langsung ngefek).
        if missing and not should_stop():
            miss_ids = sorted(missing)
            bot.log(f"  {len(miss_ids)} alarm nggak pindah — coba jalur suppress.")
            core.suppress_alarms(
                bot.base_url, cookie, miss_ids, reason, log=bot.log,
                should_stop=should_stop,
                skip_take_ids=skip_take_ids,
            )
            verified2, missing2 = core.verify_false_positive(
                bot.base_url, cookie, miss_ids, shift, page_size=page_size, log=bot.log,
                date_from=date_from, date_to=date_to, last_days=last_days,
            )
            bot.log(f"  Suppress verified {len(verified2)}/{len(miss_ids)} pindah ke tab FP.")
            if missing2:
                bot.log(f"  WARNING: {len(missing2)} tetap nggak pindah "
                        f"(FP & suppress dua-duanya gagal): {sorted(missing2)}")
            verified = verified | verified2

        with bot.lock:
            bot.stats["closed"] += len(verified)


# ---------- Routes: dashboard ----------

@app.route("/")
@login_required
def index():
    bot = _get_bot()
    settings = cfg.load_settings()
    return render_template(
        "index.html",
        running=bot.running if bot else False,
        shift_options=cfg.SHIFT_OPTIONS,
        settings=settings,
        username=session.get("username", ""),
        base_url=session.get("base_url", ""),
    )


@app.route("/start", methods=["POST"])
@login_required
def start():
    bot = _get_bot(create=True)
    if bot.running:
        return jsonify({"ok": False, "error": "Bot sudah jalan."}), 400

    cookie = session.get("upstream_cookie")
    base_url = session.get("base_url", "")
    if not cookie or not base_url:
        return jsonify({"ok": False, "error": "Sesi login habis. Login ulang."}), 401

    # Simpan/gabung setting dari form.
    settings = cfg.load_settings()
    form_settings = {
        "shift_time": request.form.get("shift_time") or settings["shift_time"],
        "poll_interval_seconds": _to_int(request.form.get("poll_interval_seconds"),
                                         settings["poll_interval_seconds"]),
        "max_close_per_cycle": _to_int(request.form.get("max_close_per_cycle"),
                                       settings["max_close_per_cycle"]),
        "protect_high_severity": request.form.get("protect_high_severity") == "on",
        # Date range (format YYYY-MM-DD). Kalau kosong, fallback ke last_days.
        "date_from": (request.form.get("date_from") or "").strip(),
        "date_to": (request.form.get("date_to") or "").strip(),
        "last_days": (request.form.get("last_days") or "").strip() or settings["last_days"],
    }
    settings.update(form_settings)
    cfg.save_settings(settings)

    bot.stop_event.clear()
    bot.base_url = base_url
    bot.username = session.get("username", "")
    bot.running = True
    with bot.lock:
        bot.logs.clear()
        bot.stats = {"closed": 0, "skipped": 0, "left": 0, "cycles": 0}

    thread = threading.Thread(target=_bot_loop, args=(bot, cookie, settings), daemon=True)
    bot.thread = thread
    thread.start()
    return jsonify({"ok": True})


@app.route("/stop", methods=["POST"])
def stop():
    bot = _get_bot()
    if not bot or not bot.running:
        return jsonify({"ok": False, "error": "Bot nggak lagi jalan."}), 400
    bot.stop_event.set()
    bot.log("Stop diminta, menunggu siklus berhenti...")
    return jsonify({"ok": True})


@app.route("/status")
def status():
    bot = _get_bot()
    if not bot:
        return jsonify({"running": False, "logs": [], "stats": {}, "last_cycle": ""})
    return jsonify(bot.snapshot())


# ---------- Routes: rules CRUD ----------

@app.route("/rules")
@login_required
def rules():
    return render_template(
        "rules.html",
        whitelist=cfg.load_whitelist(),
        protect=cfg.load_protect(),
        whitelist_fields=cfg.WHITELIST_FIELDS,
        protect_fields=cfg.PROTECT_FIELDS,
    )


@app.route("/rules/whitelist/add", methods=["POST"])
@login_required
def add_whitelist():
    return _handle_rule_add(cfg.WHITELIST_FIELDS, cfg.add_whitelist_rule)


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


def _handle_rule_add(fields: list[str], add_fn) -> Any:
    rule = {f: request.form.get(f, "") for f in fields}
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
