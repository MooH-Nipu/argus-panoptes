from __future__ import annotations

import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx

import argus_core as core


class Response:
    def __init__(self, status_code: int, text: str = '1:{"ok":true}') -> None:
        self.status_code = status_code
        self.text = text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad", request=None, response=None)


class Client:
    def __init__(self, responses: list[Response]) -> None:
        self.responses = responses
        self.calls = 0

    def post(self, *args, **kwargs):
        response = self.responses[self.calls]
        self.calls += 1
        return response


class TLSConfigurationTests(unittest.TestCase):
    def test_client_always_accepts_internal_self_signed_certificate(self) -> None:
        with patch.object(core.httpx, "Client") as client:
            core._new_client()

        client.assert_called_once_with(
            follow_redirects=False,
            timeout=core.DEFAULT_TIMEOUT,
            verify=False,
        )

    def test_login_client_requests_http2_when_h2_available(self) -> None:
        with patch.object(core, "_h2_available", return_value=True):
            with patch.object(core.httpx, "Client") as client:
                core._new_client(http2=True)

        client.assert_called_once_with(
            follow_redirects=False,
            timeout=core.DEFAULT_TIMEOUT,
            verify=False,
            http2=True,
        )

    def test_login_client_falls_back_to_http1_without_h2(self) -> None:
        with patch.object(core, "_h2_available", return_value=False):
            with patch.object(core.httpx, "Client") as client:
                core._new_client(http2=True)

        client.assert_called_once_with(
            follow_redirects=False,
            timeout=core.DEFAULT_TIMEOUT,
            verify=False,
        )


def _mock_login_client(handler) -> httpx.Client:
    """Client httpx asli + MockTransport — encoding form login diuji beneran."""
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )


class LoginFlowTests(unittest.TestCase):
    def test_login_mirrors_browser_navigation_and_form(self) -> None:
        order: list[str] = []
        seen_headers: dict[str, httpx.Headers] = {}
        seen_body: dict[str, str] = {}

        def capture(request: httpx.Request) -> None:
            order.append(request.url.path)
            seen_headers[request.url.path] = request.headers
            seen_body[request.url.path] = request.content.decode() if request.content else ""

        def handler(request: httpx.Request) -> httpx.Response:
            capture(request)
            path = request.url.path
            if path == "/auth/login":
                return httpx.Response(
                    200,
                    text="<html>login</html>",
                    headers={
                        "set-cookie": (
                            "__Secure-next-auth.callback-url"
                            "=https%3A%2F%2Fupstream.test%2Fauth%2Flogin; Path=/; Secure"
                        )
                    },
                )
            if path == "/api/auth/signin":
                return httpx.Response(302, headers={"location": "/auth/login"})
            if path == "/api/auth/providers":
                return httpx.Response(200, json={"credentials": {}})
            if path == "/api/auth/csrf":
                return httpx.Response(
                    200,
                    json={"csrfToken": "csrf-tok"},
                    headers={"set-cookie": "__Host-next-auth.csrf-token=csrf-tok; Path=/; Secure"},
                )
            if path == "/api/auth/callback/credentials":
                return httpx.Response(
                    200,
                    json={"url": "https://upstream.test/auth/login"},
                    headers={
                        "set-cookie": "__Secure-next-auth.session-token=session-abc; Path=/; Secure"
                    },
                )
            return httpx.Response(404)

        with patch.object(core, "_new_client", return_value=_mock_login_client(handler)):
            cookie = core.login("https://upstream.test", "user@x.id", "pw")

        # Urutan request persis alur browser: halaman login → signin →
        # providers → csrf → POST credentials.
        self.assertEqual(
            order,
            [
                "/auth/login",
                "/api/auth/signin",
                "/api/auth/providers",
                "/api/auth/csrf",
                "/api/auth/callback/credentials",
            ],
        )

        form = parse_qs(seen_body["/api/auth/callback/credentials"])
        self.assertEqual(form["login_method"], ["Basic"])
        self.assertEqual(form["callbackUrl"], ["https://upstream.test/auth/login"])
        self.assertEqual(form["csrfToken"], ["csrf-tok"])
        self.assertIn("__Secure-next-auth.session-token=session-abc", cookie)

        callback_headers = seen_headers["/api/auth/callback/credentials"]
        # Cookie callback-url yang di-set halaman login harus kebawa ke POST.
        self.assertIn("__Secure-next-auth.callback-url", callback_headers["cookie"])

        # Header ala Chrome — platform nge-reset request non-browser (502).
        for path in ("/api/auth/csrf", "/api/auth/callback/credentials"):
            self.assertTrue(seen_headers[path]["user-agent"].startswith("Mozilla/5.0"))
            self.assertEqual(seen_headers[path]["referer"], "https://upstream.test/auth/login")
            self.assertEqual(seen_headers[path]["sec-ch-ua-platform"], '"Windows"')
        self.assertEqual(callback_headers["origin"], "https://upstream.test")

    def test_login_error_includes_upstream_response_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/auth/csrf":
                return httpx.Response(200, json={"csrfToken": "csrf-tok"})
            return httpx.Response(
                401,
                text='{"url":"https://upstream.test/auth/login?error=CredentialsSignin&code=credentials"}',
            )

        with patch.object(core, "_new_client", return_value=_mock_login_client(handler)):
            with self.assertRaises(core.LoginError) as ctx:
                core.login("https://upstream.test", "user@x.id", "pw")

        message = str(ctx.exception)
        self.assertIn("401", message)
        self.assertIn("CredentialsSignin", message)

    def test_login_reports_missing_csrf_token(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        with patch.object(core, "_new_client", return_value=_mock_login_client(handler)):
            with self.assertRaises(core.LoginError) as ctx:
                core.login("https://upstream.test", "user@x.id", "pw")

        self.assertIn("csrfToken", str(ctx.exception))


class RuleMatchingTests(unittest.TestCase):
    def test_client_equals_matches_case_insensitively(self) -> None:
        alarm = {"alarm_name": "Alarm A", "client": "DP-TASPEN"}
        rule = {"alarm_name_equals": "Alarm A", "client_equals": "dp-taspen"}

        self.assertTrue(core._match_rule(alarm, rule))

    def test_client_and_alarm_name_must_both_match(self) -> None:
        alarm = {"alarm_name": "Alarm A", "client": "PAC"}
        rule = {"alarm_name_equals": "Alarm A", "client_equals": "DP-TASPEN"}

        self.assertFalse(core._match_rule(alarm, rule))

    def test_exclusion_rule_returns_exclude_action(self) -> None:
        alarm = {"alarm_name": "Alarm A", "client": "PAC", "severity": "medium"}
        whitelist = [{
            "alarm_name_equals": "Alarm A",
            "client_equals": "PAC",
            "disposition": "Exclusion",
            "reason": "Already ticketed",
        }]

        self.assertEqual(
            core.evaluate_alarm(alarm, whitelist, [], False),
            ("exclude", "Already ticketed"),
        )


class DispositionVerificationTests(unittest.TestCase):
    def test_exclusion_verification_fetches_exclusion_tab(self) -> None:
        with patch.object(
            core,
            "fetch_all_open_alarms",
            return_value=[{"_id": "A"}],
        ) as fetch:
            verified, missing = core.verify_disposition(
                "https://upstream.test",
                "cookie",
                ["A"],
                "1 (00:00 - 08:00)",
                disposition="Exclusion",
            )

        self.assertEqual(verified, {"A"})
        self.assertEqual(missing, set())
        self.assertEqual(fetch.call_args.kwargs["status"], "Exclusion")

    def test_verification_retries_when_tab_list_lags(self) -> None:
        with patch.object(
            core, "fetch_all_open_alarms", side_effect=[[], [{"_id": "A"}]]
        ) as fetch, patch.object(core.time, "sleep") as sleep:
            verified, missing = core.verify_disposition(
                "https://upstream.test", "cookie", ["A"], "1 (00:00 - 08:00)",
                disposition="Exclusion",
            )

        self.assertEqual((verified, missing), ({"A"}, set()))
        self.assertEqual(fetch.call_count, 2)
        sleep.assert_called_once_with(core.VERIFY_RETRY_DELAY)


class ServerActionRetryTests(unittest.TestCase):
    def test_auth_error_is_never_retried(self) -> None:
        client = Client([Response(403), Response(200)])

        with self.assertRaises(core.ArgusAuthError):
            core._call_server_action(client, "https://upstream.test", "c", "a", [], "/x-alarm")

        self.assertEqual(client.calls, 1)

    def test_mutation_server_error_is_never_retried(self) -> None:
        client = Client([Response(500), Response(200)])

        with self.assertRaises(core.ArgusError):
            core._call_server_action(
                client,
                "https://upstream.test",
                "c",
                "a",
                [],
                "/x-alarm",
                retry_transient=False,
            )

        self.assertEqual(client.calls, 1)


class ClaimFallbackTests(unittest.TestCase):
    def test_close_can_delay_before_first_alarm_for_cross_group_spacing(self) -> None:
        events: list[object] = []

        with patch.object(core, "_take_alarm", side_effect=lambda *args: events.append("take")), patch.object(
            core, "_call_server_action", return_value={"ok": True}
        ), patch.object(core.secrets, "randbelow", return_value=1):
            submitted = core.close_alarms(
                "https://upstream.test",
                "cookie",
                ["A"],
                "reason",
                confirm_owner=lambda aid: True,
                wait=lambda seconds: events.append(("wait", seconds)) or False,
                action_delay=(3, 7),
                delay_before_first=True,
            )

        self.assertEqual(submitted, {"A"})
        self.assertEqual(events[:2], [("wait", 4), "take"])

    def test_stop_during_take_blocks_verdict_even_with_zero_delay(self) -> None:
        stopped = False
        mutations: list[object] = []

        def take(*args):
            nonlocal stopped
            stopped = True

        with patch.object(core, "_take_alarm", side_effect=take), patch.object(
            core, "_call_server_action", side_effect=lambda *args, **kwargs: mutations.append(args[4])
        ):
            submitted = core.close_alarms(
                "https://upstream.test",
                "cookie",
                ["A"],
                "reason",
                confirm_owner=lambda aid: True,
                should_stop=lambda: stopped,
                wait=lambda seconds: stopped,
                action_delay=(0, 0),
            )

        self.assertEqual(submitted, set())
        self.assertEqual(mutations, [])

    def test_stop_during_owner_check_blocks_verdict(self) -> None:
        stopped = False
        mutations: list[object] = []

        def confirm(aid):
            nonlocal stopped
            stopped = True
            return True

        with patch.object(core, "_take_alarm"), patch.object(
            core, "_call_server_action", side_effect=lambda *args, **kwargs: mutations.append(args[4])
        ):
            submitted = core.close_alarms(
                "https://upstream.test",
                "cookie",
                ["A"],
                "reason",
                confirm_owner=confirm,
                should_stop=lambda: stopped,
                wait=lambda seconds: stopped,
                action_delay=(0, 0),
            )

        self.assertEqual(submitted, set())
        self.assertEqual(mutations, [])

    def test_close_uses_same_random_range_after_take_and_between_alarms(self) -> None:
        events: list[object] = []

        def take(client, base, cookie, aid):
            events.append(("take", aid))

        def confirm(aid):
            events.append(("confirm", aid))
            return True

        def wait(seconds):
            events.append(("wait", seconds))
            return False

        with patch.object(core, "_take_alarm", side_effect=take), patch.object(
            core, "_call_server_action", side_effect=lambda *args, **kwargs: events.append(
                ("mutate", args[4][0][0])
            )
        ), patch.object(core.secrets, "randbelow", side_effect=[1, 2, 3]):
            submitted = core.close_alarms(
                "https://upstream.test",
                "cookie",
                ["A", "B"],
                "reason",
                confirm_owner=confirm,
                wait=wait,
                action_delay=(3, 7),
            )

        self.assertEqual(submitted, {"A", "B"})
        self.assertEqual(events, [
            ("take", "A"), ("wait", 4), ("confirm", "A"), ("mutate", "A"),
            ("wait", 5),
            ("take", "B"), ("wait", 6), ("confirm", "B"), ("mutate", "B"),
        ])

    def test_exclusion_uses_captured_three_argument_payload(self) -> None:
        payloads: list[object] = []
        original_take = core._take_alarm
        original_call = core._call_server_action
        try:
            core._take_alarm = lambda *args: None
            core._call_server_action = lambda *args, **kwargs: payloads.append(args[4])
            submitted = core.close_alarms(
                "https://upstream.test",
                "c",
                ["148256423787"],
                "alarm already raised to ticket",
                disposition="Exclusion",
                confirm_owner=lambda aid: True,
            )
        finally:
            core._take_alarm = original_take
            core._call_server_action = original_call

        self.assertEqual(submitted, {"148256423787"})
        self.assertEqual(
            payloads,
            [[ ["148256423787"], "Exclusion", "alarm already raised to ticket" ]],
        )

    def test_exclusion_rechecks_ownership_for_already_taken_alarm(self) -> None:
        payloads: list[object] = []
        original_call = core._call_server_action
        try:
            core._call_server_action = lambda *args, **kwargs: payloads.append(args[4])
            submitted = core.close_alarms(
                "https://upstream.test",
                "c",
                ["A"],
                "Ticketed",
                skip_take_ids={"A"},
                disposition="Exclusion",
                confirm_owner=lambda aid: False,
            )
        finally:
            core._call_server_action = original_call

        self.assertEqual(submitted, set())
        self.assertEqual(payloads, [])

    def test_close_requires_ownership_callback(self) -> None:
        with self.assertRaisesRegex(ValueError, "confirm_owner"):
            core.close_alarms("https://upstream.test", "c", ["A"], "reason")

    def test_suppress_requires_ownership_callback(self) -> None:
        with self.assertRaisesRegex(ValueError, "confirm_owner"):
            core.suppress_alarms("https://upstream.test", "c", ["A"], "reason")

    def test_suppress_rechecks_ownership_for_already_taken_alarm(self) -> None:
        payloads: list[object] = []
        original_call = core._call_server_action
        try:
            core._call_server_action = lambda *args, **kwargs: payloads.append(args[4])
            submitted = core.suppress_alarms(
                "https://upstream.test",
                "c",
                ["A"],
                "reason",
                skip_take_ids={"A"},
                confirm_owner=lambda aid: False,
            )
        finally:
            core._call_server_action = original_call

        self.assertEqual(submitted, set())
        self.assertEqual(payloads, [])

    def test_successful_take_is_recorded_for_fallback(self) -> None:
        claimed: set[str] = set()
        original_take = core._take_alarm
        original_call = core._call_server_action
        try:
            core._take_alarm = lambda client, base, cookie, aid: claimed.add(aid)
            core._call_server_action = lambda *args, **kwargs: {"ok": True}
            submitted = core.close_alarms(
                "https://upstream.test", "c", ["A"], "reason",
                skip_take_ids=claimed, confirm_owner=lambda aid: True,
            )
        finally:
            core._take_alarm = original_take
            core._call_server_action = original_call

        self.assertEqual(submitted, {"A"})
        self.assertEqual(claimed, {"A"})

    def test_close_aborts_when_claim_owner_is_not_confirmed(self) -> None:
        calls: list[object] = []
        original_take = core._take_alarm
        original_call = core._call_server_action
        try:
            core._take_alarm = lambda *args: None
            core._call_server_action = lambda *args, **kwargs: calls.append(args[4])
            submitted = core.close_alarms(
                "https://upstream.test",
                "c",
                ["A"],
                "reason",
                confirm_owner=lambda aid: False,
            )
        finally:
            core._take_alarm = original_take
            core._call_server_action = original_call

        self.assertEqual(submitted, set())
        self.assertEqual(calls, [])

    def test_suppress_aborts_when_claim_owner_is_not_confirmed(self) -> None:
        calls: list[object] = []
        original_take = core._take_alarm
        original_call = core._call_server_action
        try:
            core._take_alarm = lambda *args: None
            core._call_server_action = lambda *args, **kwargs: calls.append(args[4])
            submitted = core.suppress_alarms(
                "https://upstream.test",
                "c",
                ["A"],
                "reason",
                confirm_owner=lambda aid: False,
            )
        finally:
            core._take_alarm = original_take
            core._call_server_action = original_call

        self.assertEqual(submitted, set())
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
