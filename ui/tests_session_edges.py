"""The chat facade under the UI, and the edges of a session.

    python3 -m unittest ui.tests_session_edges

A pause ends the chat turn but not the run. The next message resumes this server's run, and
only from the conversation that started it. It is neither an approval nor a new plan. A
message while an approval is pending has no effect. A browser page cannot post here. An
orphaned pause is named as such.
"""
from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest import mock

from booking_demo.continuation import record_launch
from . import agent_api
from .tests_ui import _handler

LAUNCH = "b" * 32


def _chat(text: str, conversation: str | None = None, headers: dict | None = None):
    extra = dict(headers or {})
    if conversation:
        extra[agent_api.CHAT_HEADER] = conversation
    h = _handler(agent_api.Handler, "/v1/chat/completions",
                 {"model": "v5-duffel", "stream": False, "messages": [{"role": "user", "content": text}]}, extra)
    h.replies = []
    h._reply = lambda model, stream, lines: h.replies.append(list(lines))
    return h


class _Base(unittest.TestCase):
    def setUp(self):
        self.demo = pathlib.Path(tempfile.mkdtemp(prefix="edges-"))
        self.run = self.demo / "20260925T140000Z-v5-custom-openai-duffel"
        self.run.mkdir()
        record_launch(self.demo, LAUNCH, self.run)
        agent_api.BINDINGS.clear()
        for p in (mock.patch.object(agent_api, "DEMO_DIR", self.demo),
                  mock.patch("booking_demo.serve.DEMO_DIR", self.demo),
                  mock.patch.object(agent_api.LAUNCHER, "launch_id", LAUNCH),
                  mock.patch.object(agent_api, "cluster_preflight", return_value=[])):
            p.start()
            self.addCleanup(p.stop)

    def busy(self, value: bool):
        p = mock.patch.object(type(agent_api.LAUNCHER), "busy", new_callable=mock.PropertyMock, return_value=value)
        p.start()
        self.addCleanup(p.stop)

    def events(self, *kinds_or_events):
        ev = [k if isinstance(k, dict) else {"kind": k} for k in kinds_or_events]
        (self.run / "events.json").write_text(json.dumps(ev))

    def pause(self):
        self.events({"kind": "start", "mode": "v5", "domain": "booking-duffel", "run_id": "demo-9"},
                    {"kind": "paused", "run_id": "demo-9", "next_step": "pay_order", "state": "WAITING_FOR_USER_CONTINUATION",
                     "message": "The order ord_1 (50.11 EUR) has been created and is ready for payment."})
        (self.run / "chat-request.json").write_text(json.dumps(
            {"kind": "chat", "chat_id": "c1", "run_id": "demo-9", "next_step": "pay_order"}))


class APauseEndsTheTurnNotTheRun(_Base):
    def test_the_stream_stops_at_the_pause(self):
        self.busy(True)
        self.pause()
        (self.run / "events.json").write_text(json.dumps(
            json.loads((self.run / "events.json").read_text()) + [{"kind": "end", "run_status": "COMPLETED"}]))
        lines = list(agent_api.follow_events(self.run, 0, timeout=5))
        self.assertIn("ready for payment", lines[-1])
        self.assertIn("not an approval", lines[-1])
        self.assertFalse(any("COMPLETED" in l for l in lines), "narration went past the pause")


class TheNextMessageResumesTheSameRun(_Base):
    def test_resume_from_the_starting_conversation_plans_nothing(self):
        self.busy(True)
        self.pause()
        agent_api.BINDINGS[self.run.name] = "conv-A"
        with mock.patch.object(agent_api.LAUNCHER, "start") as start, \
             mock.patch.object(agent_api, "follow_events", return_value=iter(["(following)"])):
            h = _chat("Mach mit der Zahlung weiter.", "conv-A")
            h.do_POST()
        start.assert_not_called()
        self.assertEqual(json.loads((self.run / "chat.json").read_text()),
                         {"chat_id": "c1", "text": "Mach mit der Zahlung weiter."})
        self.assertFalse((self.run / "approval.json").exists())

    def test_another_conversation_cannot_resume_it(self):
        self.busy(True)
        self.pause()
        agent_api.BINDINGS[self.run.name] = "conv-A"
        with mock.patch.object(agent_api.LAUNCHER, "start") as start:
            h = _chat("Continue with the payment.", "conv-B")
            h.do_POST()
        start.assert_not_called()
        self.assertIn("another conversation", h.replies[0][0])
        self.assertFalse((self.run / "chat.json").exists())

    def test_one_pause_takes_one_reply(self):
        self.busy(True)
        self.pause()
        with mock.patch.object(agent_api, "follow_events", return_value=iter([])):
            _chat("go on").do_POST()
            second = _chat("go on again")
            second.do_POST()
        self.assertIn("already answered", second.replies[0][0])
        self.assertEqual(json.loads((self.run / "chat.json").read_text())["text"], "go on")


class MessagesWhileAnApprovalIsPending(_Base):
    def test_five_times_continue_create_nothing(self):
        self.busy(True)
        self.events("start", {"kind": "decision", "tool": "pay_order", "status": "REQUIRE_APPROVAL"})
        (self.run / "approval-request.json").write_text(json.dumps({"approval_id": "x", "tool": "pay_order"}))
        before = (self.run / "approval-request.json").read_text()
        with mock.patch.object(agent_api.LAUNCHER, "start",
                               return_value=(409, {"error": "a run is still going"})) as start:
            for _ in range(5):
                h = _chat("mach weiter")
                h.do_POST()
                self.assertIn("your decision", h.replies[0][0])
        self.assertEqual(start.call_count, 5, "each attempt is refused by the busy launcher")
        self.assertFalse((self.run / "chat.json").exists())
        self.assertFalse((self.run / "approval.json").exists())
        self.assertEqual((self.run / "approval-request.json").read_text(), before, "the pending request is untouched")


class BrowsersCannotPostHere(_Base):
    def test_text_plain_and_foreign_origin_start_nothing(self):
        with mock.patch.object(agent_api.LAUNCHER, "start") as start:
            for headers in ({"Content-Type": "text/plain"}, {"Origin": "http://evil.example"},
                            {"Origin": "http://localhost:3000"}):
                h = _chat("Book a flight", headers=headers)
                h.do_POST()
                self.assertEqual(h.code, 403, headers)
        start.assert_not_called()


class AnOrphanedPauseIsNamed(_Base):
    def test_a_new_message_after_a_dead_pause_says_so_and_starts_a_new_run(self):
        self.busy(False)
        self.pause()
        with mock.patch.object(agent_api.LAUNCHER, "start", return_value=(200, {"started": True})) as start, \
             mock.patch.object(agent_api, "follow_run", return_value=iter([])):
            h = _chat("Book a flight to JFK")
            h.do_POST()
        start.assert_called_once()
        self.assertIn("PAUSED_ORPHANED", h.replies[0][0])
        self.assertFalse((self.run / "chat.json").exists(), "the orphan is not answered")


class TheApprovalPanelIsNotBoundToLatest(_Base):
    """A CLI run that moves `latest` neither hides nor captures the panel's request."""

    def test_a_request_of_a_non_latest_run_is_listed_and_answerable(self):
        from booking_demo.approval_record import approval_id
        from .approval_api import ApprovalStore
        req = {"seq": 5, "step": 3, "tool": "pay_order", "arguments": {"order_id": "ord_1"},
               "fragment_hash": "f" * 64, "policy_hash": "p" * 64}
        req["approval_id"] = approval_id("demo-9", req)
        (self.run / "approval-request.json").write_text(json.dumps(req))
        other = self.demo / "20260925T150000Z-v5-clean-scripted-duffel"
        other.mkdir()
        (self.demo / "latest.json").write_text(json.dumps({"dir": other.name}))
        store = ApprovalStore(self.demo)
        self.assertEqual([r["run"] for r in store.pending()], [self.run.name])
        self.assertEqual(store.decide(req["approval_id"], "p" * 64, True)[0], 200)
        self.assertTrue((self.run / "approval.json").exists())
        self.assertFalse((other / "approval.json").exists())


class ThePanelRefusesCrossSitePosts(_Base):
    def test_text_plain_and_foreign_origin_are_403(self):
        from .tests_ui import _post_handler
        for headers in ({"Content-Type": "text/plain"}, {"Origin": "http://localhost:3000"}):
            h = _post_handler("/api/approvals/x/approve", {"policy_hash": "p"}, headers)
            h.do_POST()
            self.assertEqual(h.code, 403, headers)
        h = _post_handler("/api/approvals/x/approve", {"policy_hash": "p"}, {"Origin": "http://localhost:8766"})
        h.do_POST()
        self.assertEqual(h.code, 404, "its own origin passes the guard and meets the normal checks")


if __name__ == "__main__":
    unittest.main()
