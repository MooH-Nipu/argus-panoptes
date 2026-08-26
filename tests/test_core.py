from __future__ import annotations

import unittest

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
            sent = core.close_alarms(
                "https://upstream.test", "c", ["A"], "reason", skip_take_ids=claimed
            )
        finally:
            core._take_alarm = original_take
            core._call_server_action = original_call

        self.assertEqual(sent, 1)
        self.assertEqual(claimed, {"A"})

    def test_close_aborts_when_claim_owner_is_not_confirmed(self) -> None:
        submitted: list[object] = []
        original_take = core._take_alarm
        original_call = core._call_server_action
        try:
            core._take_alarm = lambda *args: None
            core._call_server_action = lambda *args, **kwargs: submitted.append(args[4])
            sent = core.close_alarms(
                "https://upstream.test",
                "c",
                ["A"],
                "reason",
                confirm_owner=lambda aid: False,
            )
        finally:
            core._take_alarm = original_take
            core._call_server_action = original_call

        self.assertEqual(sent, 0)
        self.assertEqual(submitted, [])


if __name__ == "__main__":
    unittest.main()
