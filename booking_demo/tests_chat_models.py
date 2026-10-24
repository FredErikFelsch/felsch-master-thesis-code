"""The chat continuation at the model boundary.

After a stop, the OpenAI client must send each tool result once (a repeated
tool_call_id is refused by the API), keep the results directly after the assistant message
that asked for them, and put the human's reply after them.
"""
from __future__ import annotations

import os
import unittest
from unittest import mock

from .models import ANTHROPIC_PLAN_MAX_TOKENS, AnthropicModel, OpenAIModel, Transcript


def _reply(content=None, calls=None) -> dict:
    msg = {"role": "assistant", "content": content}
    if calls:
        msg["tool_calls"] = [{"id": cid, "type": "function",
                              "function": {"name": name, "arguments": "{}"}} for cid, name in calls]
    return {"choices": [{"message": msg}]}


class TheOpenAIClientContinuesCleanly(unittest.TestCase):
    """The message order the OpenAI client sends after a stop."""

    def setUp(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            self.m = OpenAIModel()
        self.sent: list[list[dict]] = []
        self.answers = [_reply(calls=[("c1", "book")]), _reply(content="ready for payment"),
                        _reply(calls=[("c2", "pay_order")])]

        def post(body):
            self.sent.append([dict(x) for x in body["messages"]])
            return self.answers.pop(0)
        self.m._post = post

    def test_results_once_and_the_reply_after_them(self):
        t = Transcript(task="task", mail="mail")
        call = self.m.next_call(t)
        self.assertEqual(call.name, "book")
        t.record(call, {"order_id": "ord_1"})
        self.assertIsNone(self.m.next_call(t))
        self.assertEqual(self.m.final_message(), "ready for payment")
        self.assertTrue(self.m.add_user_message("Continue with the payment."))
        call = self.m.next_call(t)
        self.assertEqual(call.name, "pay_order")
        last = self.sent[-1]
        tool_msgs = [x for x in last if x["role"] == "tool"]
        self.assertEqual([x["tool_call_id"] for x in tool_msgs], ["c1"], "a tool result was sent twice")
        roles = [x["role"] for x in last]
        self.assertEqual(roles[-2:], ["assistant", "user"])
        self.assertEqual(last[-1]["content"], "Continue with the payment.")
        self.assertLess(roles.index("tool"), len(roles) - 1)

    def test_the_base_model_does_not_continue(self):
        from .models import Model
        self.assertFalse(Model().add_user_message("x"))


class _Block:
    """One text block of an Anthropic answer."""

    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _Response:
    """An Anthropic answer reduced to what the model adapter reads."""

    def __init__(self, text: str, stop_reason: str = "end_turn") -> None:
        self.content, self.stop_reason = [_Block(text)], stop_reason


class TheAnthropicClientKeepsItsAnswersWhole(unittest.TestCase):
    """A plan answer must not be cut at the token cap.

    With a small `max_tokens` the plan ends before its closing brace and the run stops at plan
    formation. Such a run must be reported as a harness error, not counted as a run of the model.
    """

    PLAN = ('{"steps": ["search", "select", "book", "pay_order"], "budget_minor": 100000, '
            '"currency": "EUR", "approval_steps": ["pay_order"]}')

    def _model(self, response: _Response):
        import sys
        import types
        self.calls: list[dict] = []
        outer = self

        class _Messages:
            def create(self, **kwargs):
                outer.calls.append(kwargs)
                return response

        fake = types.SimpleNamespace(Anthropic=lambda: types.SimpleNamespace(messages=_Messages()))
        with mock.patch.dict(sys.modules, {"anthropic": fake}):
            return AnthropicModel(model="claude-test")

    def test_the_plan_is_asked_for_with_room_to_finish(self):
        model = self._model(_Response(self.PLAN))
        model.propose_plan("task", "mail")
        self.assertEqual(self.calls[0]["max_tokens"], ANTHROPIC_PLAN_MAX_TOKENS)
        self.assertGreaterEqual(ANTHROPIC_PLAN_MAX_TOKENS, 2048)

    def test_a_plan_cut_at_the_cap_is_a_harness_error_and_not_a_refused_plan(self):
        model = self._model(_Response(self.PLAN[:90], stop_reason="max_tokens"))
        with self.assertRaises(RuntimeError) as caught:
            model.propose_plan("task", "mail")
        self.assertIn("max_tokens", str(caught.exception))

    def test_a_whole_answer_is_parsed(self):
        model = self._model(_Response(self.PLAN))
        self.assertEqual(model.propose_plan("task", "mail").steps[-1], "pay_order")


if __name__ == "__main__":
    unittest.main()
