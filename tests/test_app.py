from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
import yaml

import app


class PackagedConfigTests(unittest.TestCase):
    def test_whitelist_starts_empty_for_manual_entry(self) -> None:
        path = Path(__file__).resolve().parents[1] / "whitelist.yaml"
        self.assertEqual(yaml.safe_load(path.read_text(encoding="utf-8")), {"whitelist": []})

    def test_whitelist_update_rejects_stale_index_target(self) -> None:
        original = {
            "alarm_name_equals": "Alarm A",
            "disposition": "False Positive",
            "reason": "Known benign",
        }
        moved_target = {
            "alarm_name_equals": "Alarm B",
            "disposition": "Exclusion",
            "reason": "Ticketed",
        }
        with patch.object(app.cfg, "load_whitelist", return_value=[moved_target]), patch.object(
            app.cfg, "save_whitelist"
        ) as save:
            with self.assertRaises(app.cfg.RuleConflictError):
                app.cfg.update_whitelist_rule(
                    0,
                    {**original, "reason": "Edited"},
                    expected_version=app.cfg.whitelist_rule_version(original),
                )

        save.assert_not_called()


class StartSettingsValidationTests(unittest.TestCase):
    def test_alarm_count_rule_validation(self) -> None:
        cleaned = app.cfg.clean_whitelist_rule(
            {"alarm_count_gte": "200", "reason": "high volume"}
        )
        self.assertEqual(cleaned["alarm_count_gte"], "200")

        # "007" dinormalkan biar rule version stabil
        self.assertEqual(
            app.cfg.clean_whitelist_rule(
                {"alarm_count_lte": "007", "reason": "r"}
            )["alarm_count_lte"],
            "7",
        )

        for bad in ({"alarm_count_gte": "abc"}, {"alarm_count_gte": "-5"},
                    {"alarm_count_lte": "1.5"}, {"alarm_count_gte": " "}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                app.cfg.clean_whitelist_rule({**bad, "reason": "r"})

        with self.assertRaisesRegex(ValueError, "must be <="):
            app.cfg.clean_whitelist_rule(
                {"alarm_count_gte": "500", "alarm_count_lte": "100", "reason": "r"}
            )

    def test_alarm_count_rule_roundtrips_through_yaml(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(app.cfg, "WHITELIST_PATH", os.path.join(tmp, "w.yaml")):
                app.cfg.add_whitelist_rule(
                    {"alarm_count_gte": "100", "alarm_count_lte": "500", "reason": "r"}
                )
                rules = app.cfg.load_whitelist()

        self.assertEqual(rules[0]["alarm_count_gte"], "100")
        self.assertEqual(rules[0]["alarm_count_lte"], "500")

    def test_whitelist_accepts_client_field(self) -> None:
        cleaned = app.cfg._clean_rule(
            {"alarm_name_equals": "Alarm A", "client_equals": "DP-TASPEN", "reason": "FP"},
            app.cfg.WHITELIST_FIELDS,
        )

        self.assertEqual(cleaned["client_equals"], "DP-TASPEN")

    def test_whitelist_accepts_exclusion_disposition(self) -> None:
        cleaned = app.cfg.clean_whitelist_rule({
            "alarm_name_equals": "Alarm A",
            "disposition": "Exclusion",
            "reason": "Already ticketed",
        })

        self.assertEqual(cleaned["disposition"], "Exclusion")

    def test_whitelist_defaults_to_false_positive(self) -> None:
        cleaned = app.cfg.clean_whitelist_rule({
            "alarm_name_equals": "Alarm A",
            "reason": "Known FP",
        })

        self.assertEqual(cleaned["disposition"], "False Positive")

    def test_whitelist_rejects_unknown_disposition(self) -> None:
        with self.assertRaisesRegex(ValueError, "disposition"):
            app.cfg.clean_whitelist_rule({
                "alarm_name_equals": "Alarm A",
                "disposition": "Delete",
                "reason": "Nope",
            })

    def test_rejects_unbounded_and_malformed_settings(self) -> None:
        invalid = {
            "shift_time": "garbage",
            "poll_interval_seconds": "0",
            "max_close_per_cycle": "-1",
            "date_from": "2026-02-02",
            "date_to": "",
            "last_days": "wat",
        }

        with self.assertRaisesRegex(ValueError, "Interval"):
            app.validate_start_settings(invalid, app.cfg.DEFAULT_SETTINGS)

    def test_start_settings_ignore_client_time_fields(self) -> None:
        settings = app.validate_start_settings(
            {
                "shift_time": "garbage",
                "date_from": "2020-01-01",
                "date_to": "2020-01-02",
                "last_days": "365",
                "poll_interval_seconds": "30",
                "max_close_per_cycle": "25",
            },
            app.cfg.DEFAULT_SETTINGS,
        )

        for key in ("shift_time", "date_from", "date_to", "last_days"):
            self.assertNotIn(key, settings)

    def test_current_shift_follows_upstream_wib_clock(self) -> None:
        from datetime import datetime, timedelta, timezone

        # Jam UTC yang di-fix harus dipetakan ke WIB, bukan UTC+5 (bug lama:
        # batas shift geser 2 jam). 01:00 UTC = 08:00 WIB = awal shift 2.
        utc = timezone.utc
        cases = [
            (datetime(2026, 10, 30, 17, 0, tzinfo=utc), "1 (00:00 - 08:00)"),  # 00:00 WIB
            (datetime(2026, 10, 30, 1, 0, tzinfo=utc), "2 (08:00 - 16:00)"),    # 08:00 WIB
            (datetime(2026, 10, 30, 8, 59, tzinfo=utc), "2 (08:00 - 16:00)"),   # 15:59 WIB
            (datetime(2026, 10, 30, 9, 0, tzinfo=utc), "3 (16:00 - 00:00)"),    # 16:00 WIB
            (datetime(2026, 10, 30, 16, 59, tzinfo=utc), "3 (16:00 - 00:00)"),  # 23:59 WIB
        ]
        for moment, label in cases:
            wib = (moment + timedelta(hours=7)).replace(tzinfo=None)
            with self.subTest(utc=moment.isoformat()):
                self.assertEqual(app.cfg.current_shift(wib), label)
        self.assertEqual(app.cfg.UPSTREAM_TZ.utcoffset(None), timedelta(hours=7))

    def test_shift_boundaries_at_platform_hours(self) -> None:
        from datetime import datetime

        s1, s2, s3 = app.cfg.SHIFT_OPTIONS
        cases = [(0, s1), (7, s1), (8, s2), (15, s2), (16, s3), (23, s3)]
        for hour, label in cases:
            with self.subTest(hour=hour):
                self.assertEqual(
                    app.cfg.current_shift(datetime(2026, 10, 30, hour, 59)), label
                )

    def test_shift_windows_include_previous_shift_for_one_hour(self) -> None:
        from datetime import datetime

        s1, s2, s3 = app.cfg.SHIFT_OPTIONS
        cases = [
            # 08:30 -> shift 2 + sisa shift 1 (mulai hari sama 00:00)
            (datetime(2026, 10, 30, 8, 30), [
                (s1, "2026-10-30", "2026-10-30"), (s2, "2026-10-30", "2026-10-30")]),
            # 09:00 pas -> grace habis, shift 2 doang
            (datetime(2026, 10, 30, 9, 0), [(s2, "2026-10-30", "2026-10-30")]),
            # 16:15 -> shift 3 baru + sisa shift 2
            (datetime(2026, 10, 30, 16, 15), [
                (s2, "2026-10-30", "2026-10-30"), (s3, "2026-10-30", "2026-10-30")]),
            # 00:30 -> shift 1 baru + sisa shift 3 (mulai kemarin 16:00, nyebrang midnight)
            (datetime(2026, 10, 31, 0, 30), [
                (s3, "2026-10-30", "2026-10-31"), (s1, "2026-10-31", "2026-10-31")]),
            # 15:59 -> shift 2 doang (grace shift 2 udah habis)
            (datetime(2026, 10, 30, 15, 59), [(s2, "2026-10-30", "2026-10-30")]),
        ]
        for now, expected in cases:
            with self.subTest(now=now):
                self.assertEqual(app.cfg.shift_windows(now), expected)

    def test_bot_loop_shares_close_budget_across_shift_windows(self) -> None:
        bot = app.BotState()
        calls = []

        def fake_cycle(bot_, cookie, shift, page_size, protect, budget, **kw):
            calls.append((shift, budget, kw["date_from"], kw["date_to"]))
            return 30

        windows = [("old", "2026-10-29", "2026-10-30"), ("new", "2026-10-30", "2026-10-30")]
        settings = {**app.cfg.DEFAULT_SETTINGS, "max_close_per_cycle": 40}
        with patch.object(app.cfg, "shift_windows", return_value=windows), patch.object(
            app, "_run_one_cycle", side_effect=fake_cycle
        ), patch.object(bot.stop_event, "wait", side_effect=lambda s: bot.stop_event.set()):
            app._bot_loop(bot, "cookie", settings)

        self.assertEqual(calls, [
            ("new", 40, "2026-10-30", "2026-10-30"),
            ("old", 10, "2026-10-29", "2026-10-30"),
        ])

    def test_active_shift_swept_before_grace_shift_cannot_starve_it(self) -> None:
        """Kalau sisa alarm shift lama ngabisin budget, shift aktif tetap kesapu."""
        bot = app.BotState()
        calls = []

        def fake_cycle(bot_, cookie, shift, page_size, protect, budget, **kw):
            calls.append(shift)
            return budget  # window pertama makan seluruh budget

        windows = [("old", "2026-10-29", "2026-10-30"), ("new", "2026-10-30", "2026-10-30")]
        settings = {**app.cfg.DEFAULT_SETTINGS, "max_close_per_cycle": 100}
        with patch.object(app.cfg, "shift_windows", return_value=windows), patch.object(
            app, "_run_one_cycle", side_effect=fake_cycle
        ), patch.object(bot.stop_event, "wait", side_effect=lambda s: bot.stop_event.set()):
            app._bot_loop(bot, "cookie", settings)

        self.assertEqual(calls[0], "new")

    def test_whitelist_accepts_any_contains_length(self) -> None:
        for value in ("x", "error", "Invalid URI"):
            cleaned = app.cfg.clean_whitelist_rule(
                {"alarm_name_contains": value, "reason": "x"}
            )
            self.assertEqual(cleaned["alarm_name_contains"], value)

    def test_accepts_bounded_settings_and_defaults_to_dry_run(self) -> None:
        settings = app.validate_start_settings(
            {
                "shift_time": app.cfg.SHIFT_OPTIONS[0],
                "poll_interval_seconds": "30",
                "max_close_per_cycle": "25",
                "date_from": "",
                "date_to": "",
                "last_days": "2",
                "protect_high_severity": "on",
            },
            app.cfg.DEFAULT_SETTINGS,
        )

        self.assertEqual(settings["poll_interval_seconds"], 30)
        self.assertEqual(settings["max_close_per_cycle"], 25)
        self.assertTrue(settings["protect_high_severity"])
        self.assertTrue(settings["dry_run"])

    def test_accepts_bounded_action_delay_range(self) -> None:
        settings = app.validate_start_settings(
            {
                "shift_time": app.cfg.SHIFT_OPTIONS[0],
                "poll_interval_seconds": "30",
                "max_close_per_cycle": "25",
                "date_from": "",
                "date_to": "",
                "last_days": "1",
                "action_delay_min_seconds": "3",
                "action_delay_max_seconds": "7",
            },
            app.cfg.DEFAULT_SETTINGS,
        )

        self.assertEqual(settings["action_delay_min_seconds"], 3)
        self.assertEqual(settings["action_delay_max_seconds"], 7)

    def test_rejects_reversed_action_delay_range(self) -> None:
        form = {
            "shift_time": app.cfg.SHIFT_OPTIONS[0],
            "poll_interval_seconds": "30",
            "max_close_per_cycle": "25",
            "date_from": "",
            "date_to": "",
            "last_days": "1",
            "action_delay_min_seconds": "8",
            "action_delay_max_seconds": "2",
        }

        with self.assertRaisesRegex(ValueError, "Action delay"):
            app.validate_start_settings(form, app.cfg.DEFAULT_SETTINGS)


class CycleDispositionTests(unittest.TestCase):
    def test_exclusion_uses_exclusion_verification_without_suppress(self) -> None:
        bot = app.BotState()
        bot.base_url = "https://upstream.test"
        bot.username = "analyst"
        alarm = {
            "_id": "A",
            "alarm_name": "Alarm A",
            "client": "PAC",
            "severity": "medium",
            "email": "analyst",
        }
        rule = {
            "alarm_name_equals": "Alarm A",
            "client_equals": "PAC",
            "disposition": "Exclusion",
            "reason": "Already ticketed",
        }
        with patch.object(app.cfg, "load_whitelist", return_value=[rule]), patch.object(
            app.cfg, "load_protect", return_value=[]
        ), patch.object(app.core, "fetch_all_open_alarms", return_value=[alarm]), patch.object(
            app.core, "close_alarms", return_value={"A"}
        ) as close, patch.object(
            app.core, "verify_disposition", return_value=({"A"}, set())
        ) as verify, patch.object(app.core, "suppress_alarms") as suppress:
            app._run_one_cycle(
                bot,
                "cookie",
                app.cfg.SHIFT_OPTIONS[0],
                100,
                False,
                10,
                dry_run=False,
                enable_suppress_fallback=True,
            )

        self.assertEqual(close.call_args.kwargs["disposition"], "Exclusion")
        self.assertEqual(verify.call_args.kwargs["disposition"], "Exclusion")
        suppress.assert_not_called()

    def _live_cycle(self, verify_effect):
        bot = app.BotState()
        bot.base_url = "https://upstream.test"
        bot.username = "analyst"
        alarm = {"_id": "A", "alarm_name": "Alarm A", "severity": "low", "email": "analyst"}
        rule = {"alarm_name_equals": "Alarm A", "disposition": "False Positive", "reason": "FP"}
        with patch.object(app.cfg, "load_whitelist", return_value=[rule]), patch.object(
            app.cfg, "load_protect", return_value=[]
        ), patch.object(app.core, "fetch_all_open_alarms", return_value=[alarm]), patch.object(
            app.core, "close_alarms", return_value={"A"}
        ), patch.object(
            app.core, "verify_disposition", side_effect=verify_effect
        ), patch.object(app.cfg, "append_audit") as audit:
            try:
                app._run_one_cycle(
                    bot, "cookie", app.cfg.SHIFT_OPTIONS[0], 100, False, 10, dry_run=False
                )
            except app.core.ArgusError:
                pass
        return audit

    def test_live_cycle_writes_audit_record(self) -> None:
        audit = self._live_cycle(lambda *a, **k: ({"A"}, set()))

        (records,), _ = audit.call_args
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["alarm_id"], "A")
        self.assertEqual(records[0]["alarm_name"], "Alarm A")
        self.assertEqual(records[0]["reason"], "FP")
        self.assertEqual(records[0]["via"], "verdict")
        self.assertIs(records[0]["verified"], True)

    def test_audit_survives_verify_failure(self) -> None:
        def boom(*a, **k):
            raise app.core.ArgusError("timeout")

        audit = self._live_cycle(boom)

        (records,), _ = audit.call_args
        self.assertEqual(records[0]["alarm_id"], "A")
        self.assertIsNone(records[0]["verified"])

    def test_dry_run_writes_no_audit(self) -> None:
        bot = app.BotState()
        bot.username = "analyst"
        alarm = {"_id": "A", "alarm_name": "Alarm A", "severity": "low"}
        rule = {"alarm_name_equals": "Alarm A", "reason": "FP"}
        with patch.object(app.cfg, "load_whitelist", return_value=[rule]), patch.object(
            app.cfg, "load_protect", return_value=[]
        ), patch.object(app.core, "fetch_all_open_alarms", return_value=[alarm]), patch.object(
            app.cfg, "append_audit"
        ) as audit:
            app._run_one_cycle(bot, "cookie", app.cfg.SHIFT_OPTIONS[0], 100, False, 10)

        audit.assert_not_called()


class LoginTaglineTests(unittest.TestCase):
    def test_login_title_rotates_through_taglines(self) -> None:
        client = app.app.test_client()
        seen = set()
        for _ in range(40):
            html = client.get("/login").get_data(as_text=True)
            hits = [t for t in app.LOGIN_TAGLINES if f"<h1>{t}</h1>" in html]
            self.assertEqual(len(hits), 1)
            seen.add(hits[0])
        self.assertGreater(len(seen), 1)


class AchievementTests(unittest.TestCase):
    def test_progress_milestones(self) -> None:
        cases = [
            (0, "Fresh Intern Energy", "Alarm Janitor", 0, []),
            (500, "Fresh Intern Energy", "Alarm Janitor", 50, []),
            (1_000, "Alarm Janitor", "Professional Noise Ignorer", 0, ["Alarm Janitor"]),
            (3_000, "Alarm Janitor", "Professional Noise Ignorer", 50, ["Alarm Janitor"]),
            (100_000, "Lord of the Undefined Tab", "", 100, None),
            (250_000, "Lord of the Undefined Tab", "", 100, None),
        ]
        for count, title, nxt, pct, unlocked in cases:
            with self.subTest(count=count):
                prog = app.achievement_progress(count)
                self.assertEqual(prog["title"], title)
                self.assertEqual(prog["next_title"], nxt)
                self.assertEqual(prog["percent"], pct)
                if unlocked is not None:
                    self.assertEqual(prog["unlocked"], unlocked)
        self.assertEqual(len(app.achievement_progress(100_000)["unlocked"]), 6)
        self.assertTrue(all(desc for _, _, desc in app.ACHIEVEMENTS))
        ladder = app.achievement_progress(5_000)["ladder"]
        self.assertEqual(len(ladder), len(app.ACHIEVEMENTS))
        self.assertEqual([t["unlocked"] for t in ladder], [True, True, True] + [False] * 4)
        self.assertEqual(
            app.achievement_progress(1_000)["description"], app.ACHIEVEMENTS[1][2]
        )

    def test_verified_count_dedups_and_skips_unverified(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory(dir=os.getenv("TMPDIR")) as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            with patch.object(app.cfg, "AUDIT_PATH", path), \
                    patch.object(app.cfg, "STATS_PATH", os.path.join(tmp, "stats.json")):
                self.assertEqual(app.cfg.audit_verified_count(), 0)
                app.cfg.append_audit([
                    {"alarm_id": "A", "verified": True},
                    {"alarm_id": "A", "verified": True},
                    {"alarm_id": "B", "verified": False},
                    {"alarm_id": "C", "verified": None},
                    {"alarm_id": "D", "verified": True},
                ])
                with open(path, "a", encoding="utf-8") as f:
                    f.write("not json\n")
                self.assertEqual(app.cfg.audit_verified_count(), 2)


class AuditFileTests(unittest.TestCase):
    def test_append_audit_writes_json_lines(self) -> None:
        import json
        import os
        import tempfile

        with tempfile.TemporaryDirectory(dir=os.getenv("TMPDIR")) as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            with patch.object(app.cfg, "AUDIT_PATH", path):
                app.cfg.append_audit([{"alarm_id": "A"}, {"alarm_id": "B"}])
                app.cfg.append_audit([{"alarm_id": "C"}])
                app.cfg.append_audit([])
            with open(path, encoding="utf-8") as f:
                ids = [json.loads(line)["alarm_id"] for line in f]

        self.assertEqual(ids, ["A", "B", "C"])

    def test_verified_count_survives_audit_loss(self) -> None:
        """Progress achievement nggak boleh balik 0 kalau audit.jsonl hilang."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory(dir=os.getenv("TMPDIR")) as tmp:
            with patch.object(app.cfg, "AUDIT_PATH", os.path.join(tmp, "audit.jsonl")), \
                    patch.object(app.cfg, "STATS_PATH", os.path.join(tmp, "stats.json")):
                app.cfg.append_audit([
                    {"alarm_id": "A", "verified": True},
                    {"alarm_id": "B", "verified": True},
                ])
                self.assertEqual(app.cfg.audit_verified_count(), 2)
                os.remove(os.path.join(tmp, "audit.jsonl"))
                self.assertEqual(app.cfg.audit_verified_count(), 2)
                # ponytail: setelah log hilang, ID baru nggak bisa didedupe
                # lawan yang lama — count nge-floor di high-water sampai
                # jumlah di file baru lewat angka itu.
                app.cfg.append_audit([{"alarm_id": "C", "verified": True}])
                self.assertEqual(app.cfg.audit_verified_count(), 2)


class WebSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        app.RUNNING_BOTS.clear()
        app._LOGIN_ATTEMPTS.clear()
        app.app.config.update(TESTING=True)
        self.client = app.app.test_client()

    def csrf(self) -> str:
        self.client.get("/login")
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_post_without_csrf_is_rejected(self) -> None:
        response = self.client.post("/login", data={})
        self.assertEqual(response.status_code, 403)

    def test_login_uses_dynamic_private_ip_without_origin_env(self) -> None:
        token = self.csrf()
        with patch.dict("os.environ", {}, clear=True), patch.object(
            app.core, "login", return_value="SECRET_UPSTREAM_TOKEN"
        ) as upstream_login:
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "base_url": "https://10.20.30.40:8443/",
                    "username": "analyst",
                    "password": "password",
                },
            )

        self.assertEqual(response.status_code, 302)
        upstream_login.assert_called_once_with(
            "https://10.20.30.40:8443", "analyst", "password"
        )

    def test_login_rejects_hostname_to_prevent_dns_rebinding(self) -> None:
        with self.assertRaisesRegex(ValueError, "private IP literal"):
            app.validate_base_url("https://upstream.internal")

    def test_login_rejects_public_or_local_targets(self) -> None:
        for target in (
            "https://8.8.8.8",
            "https://100.64.0.1",
            "https://127.0.0.1",
            "https://169.254.169.254",
            "https://198.18.0.1",
        ):
            with self.subTest(target=target), self.assertRaisesRegex(
                ValueError, "safe private network"
            ):
                app.validate_base_url(target)

    def test_login_accepts_private_ipv6_literal(self) -> None:
        self.assertEqual(
            app.validate_base_url("https://[fd12:3456::10]:8443"),
            "https://[fd12:3456::10]:8443",
        )

    def test_login_rejects_invalid_or_zero_port(self) -> None:
        for target in ("https://10.20.30.40:0", "https://10.20.30.40:99999"):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "port"):
                app.validate_base_url(target)

    def test_upstream_cookie_never_enters_browser_session(self) -> None:
        token = self.csrf()
        with patch.object(app.core, "login", return_value="SECRET_UPSTREAM_TOKEN"):
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "base_url": "https://10.20.30.40",
                    "username": "analyst",
                    "password": "password",
                },
            )

        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertNotIn("upstream_cookie", session)
            bot = app.RUNNING_BOTS[session["sid"]]
        self.assertEqual(bot.upstream_cookie, "SECRET_UPSTREAM_TOKEN")

    def test_upstream_network_failure_returns_login_error(self) -> None:
        token = self.csrf()
        upstream_request = httpx.Request("POST", "https://10.20.30.40/login")
        with patch.object(
            app.core, "login",
            side_effect=httpx.ConnectError("upstream unavailable", request=upstream_request),
        ):
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "base_url": "https://10.20.30.40",
                    "username": "analyst",
                    "password": "password",
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Login failed", response.data)
        self.assertNotIn(b"Traceback", response.data)

    def test_status_requires_login(self) -> None:
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 302)

    def test_status_exposes_live_shift_windows_for_ui(self) -> None:
        """/status harus bawa shift aktif biar badge UI ikut ganti tanpa refresh."""
        token = self.csrf()
        with patch.object(app.core, "login", return_value="TOKEN"), patch.object(
            app.cfg, "shift_windows",
            return_value=[("2 (08:00 - 16:00)", "2026-10-30", "2026-10-30")],
        ):
            self.client.post("/login", data={
                "csrf_token": token,
                "base_url": "https://10.20.30.40",
                "username": "analyst",
                "password": "password",
            })
            data = self.client.get("/status").json

        self.assertEqual(
            data["shift_windows"], [["2 (08:00 - 16:00)", "2026-10-30", "2026-10-30"]]
        )
        self.assertRegex(data["clock"], r"^\d{2}:\d{2}:\d{2}$")

    def test_health_is_public_and_minimal(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"ok": True})
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_login_request_body_is_bounded(self) -> None:
        token = self.csrf()
        response = self.client.post(
            "/login",
            data={"csrf_token": token, "base_url": "x" * 20_000, "username": "a", "password": "b"},
        )
        self.assertEqual(response.status_code, 413)

    def test_login_rate_limit_blocks_sixth_attempt(self) -> None:
        token = self.csrf()
        data = {
            "csrf_token": token,
            "base_url": "https://10.20.30.40",
            "username": "analyst",
            "password": "wrong",
        }
        with patch.object(app.core, "login", side_effect=app.core.LoginError("bad credentials")):
            for _ in range(5):
                self.assertEqual(self.client.post("/login", data=data).status_code, 200)
            self.assertEqual(self.client.post("/login", data=data).status_code, 429)

    def test_expired_server_session_is_removed(self) -> None:
        bot = app.BotState()
        bot.upstream_cookie = "token"
        bot.last_activity = 0
        app.RUNNING_BOTS["expired"] = bot
        with app.app.test_request_context("/status"):
            app.session["sid"] = "expired"
            with patch.object(app.time, "time", return_value=app.SESSION_IDLE_TTL + 1):
                self.assertIsNone(app._get_bot())

        self.assertNotIn("expired", app.RUNNING_BOTS)
        self.assertEqual(bot.upstream_cookie, "")

    def test_rules_ui_offers_exclusion_disposition(self) -> None:
        self.csrf()
        with self.client.session_transaction() as session:
            sid = session["sid"]
            session["username"] = "analyst"
        bot = app.BotState()
        bot.upstream_cookie = "token"
        app.RUNNING_BOTS[sid] = bot

        response = self.client.get("/rules")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="disposition"', response.data)
        self.assertIn(b'Exclusion', response.data)

    def test_whitelist_post_passes_exclusion_disposition(self) -> None:
        token = self.csrf()
        with self.client.session_transaction() as session:
            sid = session["sid"]
            session["username"] = "analyst"
        bot = app.BotState()
        bot.upstream_cookie = "token"
        app.RUNNING_BOTS[sid] = bot

        with patch.object(app.cfg, "add_whitelist_rule") as add_rule:
            response = self.client.post("/rules/whitelist/add", data={
                "csrf_token": token,
                "alarm_name_equals": "Alarm A",
                "client_equals": "PAC",
                "disposition": "Exclusion",
                "reason": "Already ticketed",
            })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(add_rule.call_args.args[0]["disposition"], "Exclusion")

    def test_rules_ui_has_prefilled_whitelist_edit_form(self) -> None:
        self.csrf()
        with self.client.session_transaction() as session:
            sid = session["sid"]
            session["username"] = "analyst"
        bot = app.BotState()
        bot.upstream_cookie = "token"
        app.RUNNING_BOTS[sid] = bot
        rule = {
            "alarm_name_equals": "Alarm A",
            "client_equals": "PAC",
            "disposition": "Exclusion",
            "reason": "Already ticketed",
        }

        with patch.object(app.cfg, "load_whitelist", return_value=[rule]):
            response = self.client.get("/rules")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'action="/rules/whitelist/edit/0"', response.data)
        self.assertIn(b'value="Alarm A"', response.data)
        self.assertIn(b'value="PAC"', response.data)
        self.assertIn(b'value="Already ticketed"', response.data)
        self.assertIn(b'<option value="Exclusion" selected>', response.data)
        self.assertIn(b'name="expected_version"', response.data)

    def test_whitelist_edit_post_updates_selected_rule(self) -> None:
        token = self.csrf()
        with self.client.session_transaction() as session:
            sid = session["sid"]
            session["username"] = "analyst"
        bot = app.BotState()
        bot.upstream_cookie = "token"
        app.RUNNING_BOTS[sid] = bot

        with patch.object(app.cfg, "update_whitelist_rule") as update_rule:
            response = self.client.post("/rules/whitelist/edit/2", data={
                "csrf_token": token,
                "alarm_name_equals": "Alarm B",
                "client_equals": "DCI",
                "disposition": "False Positive",
                "reason": "Known benign",
                "expected_version": "version-1",
            })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(update_rule.call_args.args[0], 2)
        self.assertEqual(update_rule.call_args.args[1], {
            "alarm_name_equals": "Alarm B",
            "alarm_name_contains": "",
            "alarm_type_equals": "",
            "agent_name_equals": "",
            "client_equals": "DCI",
            "alarm_count_gte": "",
            "alarm_count_lte": "",
            "disposition": "False Positive",
            "reason": "Known benign",
        })
        self.assertEqual(update_rule.call_args.kwargs["expected_version"], "version-1")

    def test_whitelist_edit_stale_version_returns_conflict(self) -> None:
        token = self.csrf()
        with self.client.session_transaction() as session:
            sid = session["sid"]
            session["username"] = "analyst"
        bot = app.BotState()
        bot.upstream_cookie = "token"
        app.RUNNING_BOTS[sid] = bot

        with patch.object(
            app.cfg,
            "update_whitelist_rule",
            side_effect=app.cfg.RuleConflictError("Rule changed. Refresh the page."),
        ):
            response = self.client.post("/rules/whitelist/edit/1", data={
                "csrf_token": token,
                "alarm_name_equals": "Alarm B",
                "disposition": "False Positive",
                "reason": "Known benign",
                "expected_version": "stale-version",
            })

        self.assertEqual(response.status_code, 409)
        self.assertIn(b"Rule changed", response.data)

    def test_whitelist_edit_invalid_index_returns_not_found(self) -> None:
        token = self.csrf()
        with self.client.session_transaction() as session:
            sid = session["sid"]
            session["username"] = "analyst"
        bot = app.BotState()
        bot.upstream_cookie = "token"
        app.RUNNING_BOTS[sid] = bot

        with patch.object(app.cfg, "update_whitelist_rule", side_effect=IndexError):
            response = self.client.post("/rules/whitelist/edit/99", data={
                "csrf_token": token,
                "alarm_name_equals": "Alarm B",
                "disposition": "False Positive",
                "reason": "Known benign",
                "expected_version": "version-1",
            })

        self.assertEqual(response.status_code, 404)

    def test_running_bot_rejects_start_without_saving_settings(self) -> None:
        token = self.csrf()
        with self.client.session_transaction() as session:
            sid = session["sid"]
            session["username"] = "analyst"
        bot = app.BotState()
        bot.upstream_cookie = "token"
        bot.base_url = "https://upstream.test"
        bot.running = True
        app.RUNNING_BOTS[sid] = bot
        data = {
            "csrf_token": token,
            "shift_time": app.cfg.SHIFT_OPTIONS[0],
            "poll_interval_seconds": "30",
            "max_close_per_cycle": "25",
            "last_days": "1",
        }
        with patch.object(app.cfg, "save_settings") as save:
            response = self.client.post("/start", data=data)

        self.assertEqual(response.status_code, 400)
        save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
