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
