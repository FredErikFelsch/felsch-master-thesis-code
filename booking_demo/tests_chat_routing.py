"""The dashboard's chat routing: one input, resume instead of replan.

While this server's own run waits in WAITING_FOR_USER_CONTINUATION, a message sent to /run
resumes that run without a new plan, a new policy or an approval. A pause of a run this
server did not launch (a CLI run moved `latest`) is not answered from here. Otherwise /run
starts a new run.
"""
from __future__ import annotations

import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from . import serve
from .continuation import is_orphaned, launched_run, record_launch

LAUNCH = "a" * 32


class _Req:
    """Drive Handler.do_POST without a socket."""

    def __init__(self, path: str, body: dict, headers: dict | None = None) -> None:
        raw = json.dumps(body).encode()
        self.h = serve.Handler.__new__(serve.Handler)
        self.h.path = path
        self.h.headers = {"Content-Length": str(len(raw)), "Content-Type": "application/json", **(headers or {})}
        self.h.rfile = io.BytesIO(raw)
        self.sent: list = []
        self.h._send = lambda code, body, ctype="application/json": self.sent.append((code, json.loads(body)))

    def post(self):
        self.h.do_POST()
        return self.sent[-1]


class _Base(unittest.TestCase):
    def setUp(self):
        self.demo = pathlib.Path(tempfile.mkdtemp(prefix="chat-route-"))
        self.run = self.demo / "20260925T120000Z-v5-custom-openai-duffel"
        self.run.mkdir()
        (self.demo / "latest.json").write_text(json.dumps({"dir": self.run.name}))
        for p in (mock.patch.object(serve, "DEMO_DIR", self.demo),
                  mock.patch.object(serve.LAUNCHER, "launch_id", LAUNCH)):
            p.start()
            self.addCleanup(p.stop)
        record_launch(self.demo, LAUNCH, self.run)

    def _busy(self, value: bool):
        p = mock.patch.object(type(serve.LAUNCHER), "busy", new_callable=mock.PropertyMock, return_value=value)
        p.start()
        self.addCleanup(p.stop)

    def _waiting(self, run: pathlib.Path | None = None):
        (run or self.run).joinpath("chat-request.json").write_text(json.dumps(
            {"kind": "chat", "state": "WAITING_FOR_USER_CONTINUATION", "chat_id": "abc",
             "run_id": "demo-1", "next_step": "pay_order"}))


class TheChatRoutesToTheWaitingRun(_Base):
    """A message resumes the run this server launched, and otherwise starts a new one."""

    def test_the_launch_names_the_run_not_latest(self):
        self.assertEqual(launched_run(self.demo, LAUNCH), self.run)
        self.assertIsNone(launched_run(self.demo, "../../etc"), "a launch id is a hex token")

    def test_a_message_resumes_the_waiting_run_and_starts_nothing(self):
        self._waiting()
        self._busy(True)
        with mock.patch.object(serve.LAUNCHER, "start") as start:
            code, body = _Req("/run", {"task": "Continue with the payment."}).post()
        self.assertEqual((code, body["resumed"], body["next_step"]), (200, True, "pay_order"))
        start.assert_not_called()
        self.assertEqual(json.loads((self.run / "chat.json").read_text()),
                         {"chat_id": "abc", "text": "Continue with the payment."})
        self.assertFalse((self.run / "approval.json").exists(), "a chat message is never an approval")

    def test_a_second_reply_to_the_same_pause_is_refused(self):
        self._waiting()
        self._busy(True)
        _Req("/run", {"task": "go on"}).post()
        code, body = _Req("/chat", {"text": "go on, twice"}).post()
        self.assertEqual(code, 409)
        self.assertEqual(json.loads((self.run / "chat.json").read_text())["text"], "go on")

    def test_a_pause_of_a_run_this_server_did_not_launch_is_not_answered(self):
        other = self.demo / "20260925T130000Z-v5-clean-scripted-duffel"
        other.mkdir()
        (self.demo / "latest.json").write_text(json.dumps({"dir": other.name}))   # a CLI run moved latest
        self._waiting(other)
        self._busy(True)
        with mock.patch.object(serve.LAUNCHER, "start", return_value=(409, {"error": "a run is still going"})):
            code, _ = _Req("/run", {"task": "Continue with the payment."}).post()
        self.assertEqual(code, 409)
        self.assertFalse((other / "chat.json").exists())

    def test_without_a_waiting_run_the_message_starts_a_run(self):
        with mock.patch.object(serve.LAUNCHER, "start", return_value=(200, {"started": True})) as start:
            code, body = _Req("/run", {"task": "Book a flight"}).post()
        self.assertEqual((code, body), (200, {"started": True}))
        start.assert_called_once()

    def test_a_stale_request_of_a_dead_run_does_not_capture_the_message(self):
        self._waiting()
        self._busy(False)
        with mock.patch.object(serve.LAUNCHER, "start", return_value=(200, {"started": True})) as start:
            _Req("/run", {"task": "Book a flight"}).post()
        start.assert_called_once()
        self.assertFalse((self.run / "chat.json").exists())

    def test_chat_without_a_waiting_run_is_refused(self):
        code, _ = _Req("/chat", {"text": "go on"}).post()
        self.assertEqual(code, 409)


class TheDashboardAnswersOnlyWhatItShowed(_Base):
    """An approval answer must name the pending request the dashboard displayed."""

    def _pend(self):
        from .approval_record import approval_id
        req = {"seq": 5, "step": 3, "tool": "pay_order", "arguments": {"order_id": "ord_1"},
               "fragment_hash": "f" * 64, "policy_hash": "p" * 64}
        req["approval_id"] = approval_id("demo-1", req)
        (self.run / "approval-request.json").write_text(json.dumps(req))
        serve._APPROVALS = None
        return req

    def test_a_bare_granted_is_not_an_answer(self):
        self._pend()
        code, _ = _Req("/approve", {"granted": True}).post()
        self.assertEqual(code, 404)
        self.assertFalse((self.run / "approval.json").exists())

    def test_the_displayed_request_is_answered_exactly_once(self):
        req = self._pend()
        ok = _Req("/approve", {"approval_id": req["approval_id"], "policy_hash": "p" * 64, "granted": True}).post()
        again = _Req("/approve", {"approval_id": req["approval_id"], "policy_hash": "p" * 64, "granted": False}).post()
        self.assertEqual((ok[0], again[0]), (200, 409))
        self.assertTrue(json.loads((self.run / "approval.json").read_text())["granted"], "the first answer stands")

    def test_approve_against_reject_from_two_processes_is_decided_once(self):
        req = self._pend()
        from ui.approval_api import ApprovalStore
        other_process = ApprovalStore(self.demo)
        a = other_process.decide(req["approval_id"], "p" * 64, False)
        b = _Req("/approve", {"approval_id": req["approval_id"], "policy_hash": "p" * 64, "granted": True}).post()
        self.assertEqual((a[0], b[0]), (200, 409))
        self.assertFalse(json.loads((self.run / "approval.json").read_text())["granted"])

    def test_an_expired_request_is_404_and_nothing_is_recreated(self):
        req = self._pend()
        (self.run / "approval-request.json").unlink()        # the runner's timeout removed it
        code, body = _Req("/approve", {"approval_id": req["approval_id"], "policy_hash": "p" * 64, "granted": True}).post()
        self.assertEqual((code, body["error"]), (404, "expired or no longer pending"))
        self.assertFalse((self.run / "approval-request.json").exists())
        self.assertFalse((self.run / "approval.json").exists())


class CrossSiteRequestsAreRefused(_Base):
    """A POST that is not JSON, or that comes from a foreign origin, changes nothing."""

    def test_text_plain_cannot_approve_or_reply_or_start(self):
        self._waiting()
        self._busy(True)
        with mock.patch.object(serve.LAUNCHER, "start") as start:
            for path, body in (("/approve", {"granted": True}), ("/chat", {"text": "go"}), ("/run", {"task": "go"})):
                code, _ = _Req(path, body, {"Content-Type": "text/plain"}).post()
                self.assertEqual(code, 403, path)
        start.assert_not_called()
        self.assertFalse((self.run / "chat.json").exists())

    def test_a_foreign_origin_is_refused_and_the_own_is_not(self):
        self._waiting()
        self._busy(True)
        code, _ = _Req("/chat", {"text": "go"}, {"Origin": "http://evil.example"}).post()
        self.assertEqual(code, 403)
        code, _ = _Req("/chat", {"text": "go"}, {"Origin": "http://localhost:8765"}).post()
        self.assertEqual(code, 200)


class AnOrphanedPauseIsRecognisable(_Base):
    """A pause that nobody can answer any more is told apart from a live one."""

    def _paused(self):
        (self.run / "events.json").write_text(json.dumps([{"kind": "start"}, {"kind": "paused"}]))

    def test_dead_controller(self):
        self._paused()
        self._waiting()
        self.assertTrue(is_orphaned(self.run, process_alive=False))
        self.assertFalse(is_orphaned(self.run, process_alive=True))

    def test_unknown_process_but_request_past_its_timeout(self):
        self._paused()
        (self.run / "chat-request.json").write_text(json.dumps(
            {"chat_id": "abc", "requested_at": 1000.0, "timeout": 900.0}))
        self.assertFalse(is_orphaned(self.run, None, now=1500.0))
        self.assertTrue(is_orphaned(self.run, None, now=2000.0))

    def test_a_run_that_is_not_paused_is_never_orphaned(self):
        (self.run / "events.json").write_text(json.dumps([{"kind": "start"}, {"kind": "end"}]))
        self.assertFalse(is_orphaned(self.run, process_alive=False))


if __name__ == "__main__":
    unittest.main()
