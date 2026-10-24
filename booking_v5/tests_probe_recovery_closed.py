"""Offline tests for the pure part of `probe_recovery_closed`, the live probe that the recovery path is closed."""
from __future__ import annotations

import unittest

from booking_v4 import tests_durable as td
from booking_v4 import wire
from booking_v4.durable import DurableProcessDeployment
from booking_v4.services import _call

from . import probe_recovery_closed as probe


class ClassifyTests(unittest.TestCase):
    """The probe counts only an unknown-method reply as proof that the recovery path is closed."""

    def test_only_an_unknown_method_reply_counts_as_closed(self):
        for reply in ("no such method 'gateway.recover_dispatch' on this surface",
                      "unknown method 'gateway.recover_dispatch'"):
            self.assertEqual(probe.classify(f"gateway.recover_dispatch: {reply}", False), "closed")
        self.assertTrue(probe.classify("gateway.recover_dispatch: recover_dispatch is disabled on this gateway",
                                       False).startswith("UNEXPECTED"))

    def test_an_answer_means_the_path_is_open(self):
        self.assertTrue(probe.classify(None, True).startswith("OPEN"))

    def test_a_parameter_error_is_not_closed(self):
        # An enabled gateway fails at token validation, which must not pass as closed.
        self.assertTrue(probe.classify("gateway.recover_dispatch: internal error: param_validation", False)
                        .startswith("UNEXPECTED"))

    def test_a_missing_reply_is_not_closed(self):
        self.assertTrue(probe.classify(None, False).startswith("UNEXPECTED"))

    def test_the_probe_call_gets_an_unknown_method_reply_from_a_real_server(self):
        """The call the probe makes (no token, no fragment), against the shipped server."""
        dep = DurableProcessDeployment(td.FixedClock(td.T0), executor=td.ExternalWorld(idempotent=False).executor,
                                       downstream_idempotent=True)
        with dep:
            with self.assertRaises(wire.WireError) as ctx:
                _call(dep.server.endpoint, "gateway.recover_dispatch", {})
        self.assertEqual(probe.classify(str(ctx.exception), False), "closed")


if __name__ == "__main__":
    unittest.main()
