from __future__ import annotations

import unittest
from unittest.mock import patch

import app


class StartSettingsValidationTests(unittest.TestCase):
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


class WebSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        app.RUNNING_BOTS.clear()
        app.app.config.update(TESTING=True)
        self.client = app.app.test_client()

    def csrf(self) -> str:
        self.client.get("/login")
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_post_without_csrf_is_rejected(self) -> None:
        response = self.client.post("/login", data={})
        self.assertEqual(response.status_code, 403)

    def test_upstream_cookie_never_enters_browser_session(self) -> None:
        token = self.csrf()
        with patch.dict("os.environ", {"ARGUS_ALLOWED_ORIGINS": "https://upstream.test"}), patch.object(
            app.core, "login", return_value="SECRET_UPSTREAM_TOKEN"
        ):
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "base_url": "https://upstream.test",
                    "username": "analyst",
                    "password": "password",
                },
            )

        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertNotIn("upstream_cookie", session)
            bot = app.RUNNING_BOTS[session["sid"]]
        self.assertEqual(bot.upstream_cookie, "SECRET_UPSTREAM_TOKEN")

    def test_status_requires_login(self) -> None:
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 302)

    def test_health_is_public_and_minimal(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"ok": True})


if __name__ == "__main__":
    unittest.main()
