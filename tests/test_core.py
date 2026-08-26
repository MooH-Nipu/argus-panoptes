from __future__ import annotations

import unittest
from unittest.mock import patch

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
    def test_client_uses_explicit_ca_bundle(self) -> None:
        with patch.dict(
            "os.environ", {"ARGUS_CA_BUNDLE": "local-certs/upstream.pem"}, clear=True
        ), patch.object(core.httpx, "Client") as client:
            core._new_client()

        client.assert_called_once_with(
            follow_redirects=False,
            timeout=core.DEFAULT_TIMEOUT,
            verify="local-certs/upstream.pem",
        )

    def test_tls_verification_is_enabled_by_default(self) -> None:
        with patch.dict("os.environ", {}, clear=True), patch.object(
            core.httpx, "Client"
        ) as client:
            core._new_client()

        self.assertTrue(client.call_args.kwargs["verify"])

    def test_insecure_tls_requires_explicit_opt_in(self) -> None:
        with patch.dict(
            "os.environ", {"ARGUS_TLS_INSECURE": "true"}, clear=True
        ), patch.object(core.httpx, "Client") as client:
            core._new_client()

        self.assertFalse(client.call_args.kwargs["verify"])

    def test_ca_bundle_takes_precedence_over_insecure_opt_in(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "ARGUS_CA_BUNDLE": "local-certs/upstream.pem",
                "ARGUS_TLS_INSECURE": "true",
            },
            clear=True,
        ), patch.object(core.httpx, "Client") as client:
            core._new_client()

        self.assertEqual(client.call_args.kwargs["verify"], "local-certs/upstream.pem")


class RuleMatchingTests(unittest.TestCase):
    def test_client_equals_matches_case_insensitively(self) -> None:
        alarm = {"alarm_name": "Alarm A", "client": "DP-TASPEN"}
        rule = {"alarm_name_equals": "Alarm A", "client_equals": "dp-taspen"}

        self.assertTrue(core._match_rule(alarm, rule))

    def test_client_and_alarm_name_must_both_match(self) -> None:
        alarm = {"alarm_name": "Alarm A", "client": "PAC"}
        rule = {"alarm_name_equals": "Alarm A", "client_equals": "DP-TASPEN"}

        self.assertFalse(core._match_rule(alarm, rule))


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
    def test_successful_take_is_recorded_for_fallback(self) -> None:
        claimed: set[str] = set()
        original_take = core._take_alarm
        original_call = core._call_server_action
        try:
            core._take_alarm = lambda client, base, cookie, aid: claimed.add(aid)
            core._call_server_action = lambda *args, **kwargs: {"ok": True}
            submitted = core.close_alarms(
                "https://upstream.test", "c", ["A"], "reason", skip_take_ids=claimed
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
