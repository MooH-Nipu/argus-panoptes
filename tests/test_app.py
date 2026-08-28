from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
import yaml

import app


class NativeEnvironmentTests(unittest.TestCase):
    def test_dotenv_does_not_override_exported_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, ".env")
            path.write_text("ARGUS_TLS_INSECURE=true\n", encoding="utf-8")
            with patch.dict(os.environ, {"ARGUS_TLS_INSECURE": "false"}, clear=True):
                app._load_env(path)

                self.assertEqual(os.environ["ARGUS_TLS_INSECURE"], "false")

    def test_native_startup_loads_dotenv_tls_setting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, ".env").write_text("ARGUS_TLS_INSECURE=true\n", encoding="utf-8")
            project = Path(__file__).resolve().parents[1]
            command = (
                "import runpy, flask; "
                "flask.Flask.run=lambda *args, **kwargs: None; "
                f"runpy.run_path({str(project / 'app.py')!r}, run_name='__main__'); "
                "import argus_core as core; "
                "client=core._new_client(); "
                "print(client._transport._pool._ssl_context.verify_mode); client.close()"
            )
            environment = {
                key: value
                for key, value in os.environ.items()
                if key not in {"ARGUS_CA_BUNDLE", "ARGUS_TLS_INSECURE"}
            }
            result = subprocess.run(
                [sys.executable, "-c", command],
                cwd=directory,
                env={**environment, "PYTHONPATH": str(project)},
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "0")


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
        with self.assertRaisesRegex(ValueError, "Disposition"):
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

        with self.assertRaisesRegex(ValueError, "Shift"):
            app.validate_start_settings(invalid, app.cfg.DEFAULT_SETTINGS)

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

        with self.assertRaisesRegex(ValueError, "Jeda aksi"):
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
        with self.assertRaisesRegex(ValueError, "IP private literal"):
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
                ValueError, "jaringan private"
            ):
                app.validate_base_url(target)

    def test_login_accepts_private_ipv6_literal(self) -> None:
        self.assertEqual(
            app.validate_base_url("https://[fd12:3456::10]:8443"),
            "https://[fd12:3456::10]:8443",
        )

    def test_login_rejects_invalid_or_zero_port(self) -> None:
        for target in ("https://10.20.30.40:0", "https://10.20.30.40:99999"):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "Port"):
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
        self.assertIn(b"Login gagal", response.data)
        self.assertNotIn(b"Traceback", response.data)

    def test_status_requires_login(self) -> None:
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 302)

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
            side_effect=app.cfg.RuleConflictError("Rule berubah. Refresh halaman."),
        ):
            response = self.client.post("/rules/whitelist/edit/1", data={
                "csrf_token": token,
                "alarm_name_equals": "Alarm B",
                "disposition": "False Positive",
                "reason": "Known benign",
                "expected_version": "stale-version",
            })

        self.assertEqual(response.status_code, 409)
        self.assertIn(b"Rule berubah", response.data)

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
