"""The V5 chain end to end over the production services, offline.

The Authority, the grant logic, the ToolGateway, the durable state machine and the ledger
projection are the ones the cluster runs. Two role-bound `DurableDeploymentServer`s listen on
loopback TCP. The authority role puts the V5 relying party in front of the frozen V3 Authority.
The gateway role holds the verify key and serves the observation port. A runner thread runs
`runner_main.serve` with the frozen V3 `EphemeralRunner` against those two endpoints. The
controller is `AttestedFragmentController` with `RemoteAuthority` and `RemoteLedger`, and its
channel is an `AttachTransport` over pipes.

On the cluster only the transport (attach websocket, peer pod) and the verifier (DCAP instead of
the fake) differ. Evidence here comes from the fake AA with a real RTMR3 replay. The hardware
path is covered by `tests_v5_fixtures` on recorded quotes.
"""
from __future__ import annotations

import json
import os
import pathlib
import tempfile
import threading
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v1.lifecycle import PolicyState
from booking_v3.fragment import honest_fragment
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3
from booking_v3.provisioner import create_deployment
from booking_v4 import wire
from booking_v4.durable import DurableDeploymentServer, DurableStore, _RestoredDeployment
from booking_v4.services import _call

from . import e2e_live, protocol, runner_main, service_v5
from .attach_transport import AttachTransport
from .binding import PROTOCOL_VERSION
from .controller_v5 import AttestedFragmentController, RemoteAuthority
from .evidence import FakeAttestationAgent
from .gateway import COMMITTED, PENDING, RemoteLedger, ledger_delta
from .pool import TdPool
from .profile_v5 import SUBSTRATE_PROFILE, substrate_profile_hash
from .relying_party import AuthorityRelyingParty, FakeVerifier, ReferenceValues
from .rtmr_replay import replay
from .runner_bind import Challenge, RunnerError
from .tests_v5_fixtures import FREEZE, STAMP, needs_measured_freeze
from .tests_v5_protocol import _FakeAA, _PipeStream

T0 = 1_700_000_010
ISSUED, EXPIRES = 1_700_000_000, 1_700_003_600
RUN = "run-1"


class _FakeBackend:
    """TdPool backend whose TDs are names. Every TD is ready at once."""

    def __init__(self):
        self.n = 0
        self.alive = set()
        self.deleted = []
        self.cleanup_mode = {}

    def create(self):
        self.n += 1
        name = f"td-{self.n}"
        self.alive.add(name)
        return name

    def is_ready(self, name):
        return True

    def delete_and_confirm(self, name):
        self.alive.discard(name)
        self.deleted.append(name)
        self.cleanup_mode[name] = "coco_native"

    def list_managed(self):
        return sorted(self.alive)


class ServiceEndToEndTests(unittest.TestCase):
    """One fragment through the real roles: one committed effect, or a refusal with no effect."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v5-e2e-")
        self.base = create_deployment(FixedClock(T0))
        self.policy = default_p3()
        approval = approve(self.policy, approver_id="alice", approval_id=f"A-{RUN}",
                           run_id=RUN, issued_at=ISSUED, expires_at=EXPIRES)
        self.s0 = self.base.authority.create_run(self.policy, approval, RUN)
        self.ref = ReferenceValues(require_rtmr3=True, substrate_profile_hash=substrate_profile_hash())
        self.rp = AuthorityRelyingParty(FakeVerifier(), self.ref)
        self.auth_store = DurableStore(os.path.join(self.tmp, "authority.db"))
        self.gw_store = DurableStore(os.path.join(self.tmp, "gateway.db"))
        self.authority = DurableDeploymentServer(
            _RestoredDeployment(self.base.authority, None, self.rp), self.auth_store,
            tcp=("127.0.0.1", 0), role="authority")
        self.gateway = DurableDeploymentServer(
            _RestoredDeployment(None, self.base.gateway), self.gw_store,
            tcp=("127.0.0.1", 0), role="gateway", observe_tcp=("127.0.0.1", 0))
        self.fragment = honest_fragment(self.policy, RUN, 0, {"to": "FRA"})
        self.frag_octets = protocol.fragment_bytes(self.fragment)
        self.env_octets = protocol.envelope_bytes(self.s0)
        self.threads, self._files, self._ctl_tx = [], [], []
        self.runner_errors: list = []
        self.backend = _FakeBackend()
        self.pool = TdPool(self.backend, size=0)                 # cold path
        self.transport = AttachTransport(
            open_stream=lambda td: self._start_runner(), anchors=self.base.anchors,
            endpoint=self.authority.endpoint, gateway_endpoint=self.gateway.endpoint,
            policy=self.policy)
        self.ledger = RemoteLedger(self.gateway.observe_endpoint)
        self.controller = AttestedFragmentController(
            self.pool, RemoteAuthority(self.authority.endpoint), self.transport, ledger=self.ledger)

    def tearDown(self):
        for f in self._ctl_tx:
            try:
                f.close()
            except Exception:
                pass
        for t in self.threads:
            t.join(timeout=5)
        for f in self._files:
            try:
                f.close()
            except Exception:
                pass
        self.authority.close()
        self.gateway.close()
        self.auth_store.close()
        self.gw_store.close()

    def _attestation_agent(self):
        """The AA a fresh TD of this fixture starts with."""
        return _FakeAA(self.ref.init_data_digest)

    def _start_runner(self, aa=None):
        """Start one runner thread, which plays one TD: the frozen V3 monitor behind the V5 protocol.

        Args:
            aa: The attestation agent of the TD. Defaults to `_attestation_agent()`.

        Returns:
            The controller's end of the pipes to that runner.
        """
        if aa is None:
            aa = self._attestation_agent()
        c2r_r, c2r_w = os.pipe()
        r2c_r, r2c_w = os.pipe()
        rx, tx = os.fdopen(c2r_r, "r"), os.fdopen(r2c_w, "w")
        ctl_tx, ctl_rx = os.fdopen(c2r_w, "w"), os.fdopen(r2c_r, "r")
        self._files += [rx, tx, ctl_rx]
        self._ctl_tx.append(ctl_tx)

        def _run():
            try:
                runner_main.serve(rx, tx, aa=aa)                 # execute runs the real V3 path
            except BaseException as exc:                         # noqa: BLE001
                self.runner_errors.append(exc)
            finally:
                try:
                    tx.close()
                except Exception:
                    pass

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        self.threads.append(t)
        return _PipeStream(ctl_tx, ctl_rx)

    # The result.

    def test_one_cold_fragment_end_to_end_has_exactly_one_committed_effect(self):
        rec = self.controller.execute_fragment(RUN, 0, self.frag_octets, self.env_octets)
        self.assertIsNone(rec.refusal, rec.refusal)
        self.assertEqual(rec.result.status, "STEP_COMPLETED", rec.result)
        self.assertEqual((rec.effects, rec.pending_effects, rec.foreign_effects), (1, 0, 0))
        self.assertEqual(rec.outcome, "ACCEPTED")
        self.assertTrue(rec.accepted)
        self.assertIn(rec.td, self.backend.deleted)
        self.assertEqual(self.runner_errors, [])
        rows = self.ledger.entries_after(0)
        self.assertEqual([r.state for r in rows], [PENDING, COMMITTED])
        self.assertEqual((rows[0].run_id, rows[0].step, rows[0].fragment_hash),
                         (RUN, 0, self.fragment.fragment_hash))
        self.assertGreater(rec.timings.total, 0)
        for phase in ("spawn", "boot_key", "evidence", "verification", "execution", "destroy"):
            self.assertIsNotNone(getattr(rec.timings, phase), phase)

    def test_the_session_and_its_effect_survive_in_the_stores(self):
        """Both sides are durable, each in its own database.

        The authority role keeps the relying party's ledgers, the gateway role keeps the effect
        ledger.
        """
        self.controller.execute_fragment(RUN, 0, self.frag_octets, self.env_octets)
        v5 = self.auth_store.load_v5_state()
        self.assertEqual(len(v5["sessions"]), 1)
        self.assertEqual(v5["sessions"][0]["run_id"], RUN)
        self.assertEqual(len(v5["td_bound_to"]), 1)
        # A stored nonce is [run, step, fragment_hash, state_hash, pk_boot hex, consumed].
        self.assertTrue(all(v[5] for v in v5["nonces"].values()), "the nonce was consumed")
        self.assertEqual(self.gw_store.ledger_watermark(), 2)
        self.assertEqual(self.gw_store.load_states()[0], {}, "the gateway store holds no Authority state")

    # Refusals over the real surface.

    def test_a_foreign_substrate_is_refused_before_any_effect(self):
        self.controller.substrate_profile = dict(SUBSTRATE_PROFILE, podvm_subnet_cidr="10.9.9.0/24")
        rec = self.controller.execute_fragment(RUN, 0, self.frag_octets, self.env_octets)
        self.assertEqual(rec.refusal.rule, "substrate-profile-mismatch")
        self.assertEqual((rec.effects, rec.pending_effects, rec.foreign_effects), (0, 0, 0))
        self.assertEqual(rec.outcome, "REFUSED(substrate-profile-mismatch)")
        self.assertEqual(self.ledger.entries_after(0), ())
        self.assertIn(rec.td, self.backend.deleted)

    def test_A11_a_second_challenge_on_the_live_stream_is_refused_in_the_td(self):
        """Acceptance test A11 on the TD side: a runner binds once.

        Over one live stream the test runs boot_key and attest, then sends a second challenge
        where the runner expects the session. The runner refuses it, no session is established and
        the ledger stays empty. `cmd_negative` drives the same mechanism live. The Authority side
        (`td-already-bound`) is covered by the fixture tests. The A labels are listed in
        `scripts/gke-v5/attack_catalogue.md`.
        """
        auth = RemoteAuthority(self.authority.endpoint)
        cursor = self.ledger.high_watermark()
        td, _ = self.controller.pool.acquire((RUN, 0, self.fragment.fragment_hash, self.s0.state_hash))
        try:
            keys = self.transport.boot_keys(td)
            n1 = auth.issue_nonce(RUN, 0, self.fragment.fragment_hash, self.s0.state_hash, keys.pk_boot)
            self.transport.attest(td, Challenge(RUN, 0, self.fragment.fragment_hash, self.s0.state_hash, n1))
            # The Authority refuses to issue a challenge for step 1 (the run is at step 0), so the
            # second challenge is made up here. The TD must refuse it on its own.
            n2 = os.urandom(32)
            with self.assertRaises(Exception):                        # the runner refuses the second challenge
                self.transport.attest(td, Challenge(RUN, 1, self.fragment.fragment_hash, self.s0.state_hash, n2))
            self.assertEqual(self.ledger.entries_after(cursor), ())   # no session, no effect
        finally:
            self.controller.pool.retire(td)
            self.transport.close(td)
        # The harness calls serve() directly, so the refusal surfaces as one protocol or wire error.
        # Live, runner_main.main wraps it into a RUNNER_ERROR line.
        self.assertLessEqual(len(self.runner_errors), 1)
        if self.runner_errors:
            self.assertIsInstance(self.runner_errors[0], (wire.WireError, RunnerError))

    def test_a_wrong_challenge_leaves_the_run_active_and_the_right_step_still_runs(self):
        """An early refusal consumes nothing.

        The wrong step is refused as `run-not-at-step`. No session and no grant exist, the gateway
        ledger does not move, and the run is still ACTIVE at step 0. The correct step then runs to
        its one committed effect.
        """
        base = self.base.authority
        refused = self.controller.execute_fragment(RUN, 1, self.frag_octets, self.env_octets)
        self.assertEqual(refused.refusal.rule, "run-not-at-step")
        self.assertEqual((refused.effects, refused.pending_effects, refused.foreign_effects), (0, 0, 0))
        self.assertEqual(self.ledger.entries_after(0), ())                     # no grant, no dispatch
        self.assertEqual(self.auth_store.load_v5_state()["sessions"], [])      # no session either
        self.assertIs(base.status(RUN), PolicyState.ACTIVE)
        self.assertTrue(base.run_is_at(RUN, 0, self.s0.state_hash))
        ok = self.controller.execute_fragment(RUN, 0, self.frag_octets, self.env_octets)
        self.assertIsNone(ok.refusal, ok.refusal)
        self.assertEqual(ok.result.status, "STEP_COMPLETED", ok.result)
        self.assertEqual((ok.effects, ok.pending_effects, ok.foreign_effects), (1, 0, 0))
        self.assertEqual([r.state for r in self.ledger.entries_after(0)], [PENDING, COMMITTED])
        self.assertEqual(self.runner_errors, [])

    def test_a_step_the_run_is_not_at_is_refused_before_any_evidence(self):
        """The Authority knows the run stands at step 0 and refuses a challenge for step 1 itself.

        The controller records the refusal instead of raising, no hardware evidence is asked for,
        and the TD is retired.
        """
        rec = self.controller.execute_fragment(RUN, 1, self.frag_octets, self.env_octets)
        self.assertEqual(rec.refusal.rule, "run-not-at-step")
        self.assertEqual(rec.outcome, "REFUSED(run-not-at-step)")
        self.assertIsNone(rec.evidence_blob)
        self.assertEqual((rec.effects, rec.pending_effects, rec.foreign_effects), (0, 0, 0))
        self.assertIn(rec.td, self.backend.deleted)
        self.assertEqual(self.auth_store.load_v5_state()["nonces"], {})   # no challenge was written

    def test_a_refused_run_keeps_its_evidence_blob_for_offline_reappraisal(self):
        """A refusal that reached the evidence stage carries the raw quote on the record.

        `_save_refused_evidence` can then write `evidence-<td>.bin` for
        `scripts/gke-v5/20_verify_evidence_offline.py` and `scripts/gke-v5/21_dcap_verify.sh` to
        re-appraise, which the RTMR0 outlier path needs. Here the relying party refuses after attest, so the blob is present.
        """
        self.controller.substrate_profile = dict(SUBSTRATE_PROFILE, podvm_subnet_cidr="10.9.9.0/24")
        rec = self.controller.execute_fragment(RUN, 0, self.frag_octets, self.env_octets)
        self.assertIsNotNone(rec.refusal)
        self.assertTrue(rec.evidence_blob, "the quote of a run refused after attest must be kept")
        out = pathlib.Path(tempfile.mkdtemp(prefix="v5-refused-"))
        saved = e2e_live._save_refused_evidence(out, rec)
        self.assertEqual(saved, str(out / f"evidence-{rec.td}.bin"))
        self.assertEqual(pathlib.Path(saved).read_bytes(), rec.evidence_blob)

    def test_A14_no_evidence_no_session_and_no_v3_provisioning_on_the_surface(self):
        """Acceptance test A14: the controller's own standing buys nothing.

        Without evidence the Authority refuses, and the legacy provisioning call the controller
        could have used does not exist on this surface.
        """
        auth = RemoteAuthority(self.authority.endpoint)
        state = self.s0.state_hash  # a challenge needs the run's real state
        nonce = auth.issue_nonce(RUN, 0, "f" * 64, state, b"\1" * 32)
        res = auth.establish_session(None, b"\1" * 32, b"\2" * 32, RUN, 0, "f" * 64, state, nonce, substrate_profile_hash())
        self.assertEqual((res.rule, res.stage), ("evidence-missing", "relying-party"))
        with self.assertRaises(wire.WireError) as ctx:
            _call(self.authority.endpoint, "authority.establish_runner_session",
                  {"bootstrap": wire.bootstrap_to_wire(self.base.bootstrap), "run_id": RUN,
                   "fragment_hash": "f" * 64, "state_hash": state, "nonce": "n"})
        self.assertIn("no such method", str(ctx.exception))
        self.assertEqual(self.auth_store.load_v5_state()["sessions"], [])
        self.assertEqual(self.ledger.entries_after(0), ())

    def test_the_durable_boundary_holds_for_v5_calls(self):
        """Server-derived idempotency applies to the V5 surface.

        An identical retry replays the stored reply. A call with other content is a different
        request and is judged on its own merits, so once the nonce is spent every further call
        with it is refused as `nonce-reused`, whatever key it names.
        """
        auth = RemoteAuthority(self.authority.endpoint)
        state = self.s0.state_hash  # a challenge needs the run's real state
        nonce = auth.issue_nonce(RUN, 0, "f" * 64, state, b"\1" * 32)
        self.assertEqual(auth.issue_nonce(RUN, 0, "f" * 64, state, b"\1" * 32), nonce)   # same TD, same challenge
        self.assertNotEqual(auth.issue_nonce(RUN, 0, "f" * 64, state, b"\2" * 32), nonce)  # fresh TD, fresh one
        first = auth.establish_session(None, b"\1" * 32, b"\2" * 32, RUN, 0, "f" * 64, state, nonce, substrate_profile_hash())
        again = auth.establish_session(None, b"\1" * 32, b"\2" * 32, RUN, 0, "f" * 64, state, nonce, substrate_profile_hash())
        self.assertEqual((first.rule, again.rule), ("evidence-missing", "evidence-missing"))   # replayed reply
        # The identity covers the full request, so a call with other content is a different request
        # and not a collision. Here the nonce it carries has already been spent by the two calls
        # above. Refusing it as "identity reused with different content" would fail closed against
        # the honest caller, because whoever spoke first would hold the slot.
        other = auth.establish_session(None, b"\1" * 32, b"\2" * 32, RUN, 0, "f" * 64, state,
                                       nonce, "0" * 64)
        self.assertEqual(other.rule, "nonce-reused")
        # Freshness is decided first, so another key on the same spent nonce is nonce-reused and
        # not evidence-missing. A challenge is spent at its first presentation whatever the outcome.
        other = auth.establish_session(None, b"\3" * 32, b"\4" * 32, RUN, 0, "f" * 64, state,
                                       nonce, substrate_profile_hash())
        self.assertEqual(other.rule, "nonce-reused")

    def test_repeat_runs_produce_one_record_each_and_a_summary(self):
        """The --repeat path runs N cold runs, each with a fresh run_id.

        Each repetition yields one record, and the summary carries mean and spread per phase and
        the cleanup-mode counts. The test drives the `_run_once`, `_create_run` and `_summarize`
        functions the CLI uses.
        """
        env = {"controller": self.controller, "backend": self.backend, "policy": self.policy,
               "authority": self.authority.endpoint, "run_id": RUN, "s0": self.s0,
               "approval_window": lambda: (ISSUED, EXPIRES)}      # the services here run FixedClock(T0)
        out = pathlib.Path(tempfile.mkdtemp(prefix="v5-repeat-"))
        runs = []
        for i in range(2):
            run_id = RUN if i == 0 else f"{RUN}-r{i}"
            s0 = self.s0 if i == 0 else e2e_live._create_run(env, run_id)
            # _run_once also reports whether a refusal was provider RTMR0 variance. Nothing is
            # refused here, so it must be None. A green run carries no tolerance record.
            records, ok, variance = e2e_live._run_once(env, 1, run_id, s0, out)
            self.assertTrue(ok, records)
            self.assertIsNone(variance)
            runs.append({"run_id": run_id, "accepted": ok, "steps": records,
                         "substrate_variance": variance})
        self.assertNotEqual(runs[0]["steps"][0]["td"], runs[1]["steps"][0]["td"])   # cold TD each time
        summ = e2e_live._summarize(runs)
        self.assertEqual((summ["repetitions"], summ["accepted_runs"], summ["accepted_steps"]), (2, 2, 2))
        self.assertEqual(summ["substrate_variance_runs"], 0)
        self.assertEqual(summ["substrate_variance"], [])
        self.assertEqual(summ["phases"]["execution"]["n"], 2)
        self.assertIn("mean", summ["phases"]["verification"])
        for key in ("median", "q1", "q3", "iqr", "p95", "min", "max", "stdev"):
            self.assertIn(key, summ["total_s"])
        self.assertEqual(sum(summ["cleanup_mode_counts"].values()), 2)

    def test_two_fragments_run_in_two_tds_and_each_has_its_own_effect(self):
        a = self.controller.execute_fragment(RUN, 0, self.frag_octets, self.env_octets)
        self.assertTrue(a.accepted, a.refusal)
        s1 = a.result.envelope                                   # the envelope step 0 produced
        f1 = honest_fragment(self.policy, RUN, 1, happy_path_arguments()[1])
        b = self.controller.execute_fragment(RUN, 1, protocol.fragment_bytes(f1), protocol.envelope_bytes(s1))
        self.assertTrue(b.accepted, b.refusal)
        self.assertNotEqual(a.td, b.td)
        rows = self.ledger.entries_after(0)
        self.assertEqual(ledger_delta(rows, RUN, 0).own_committed, 1)
        self.assertEqual(ledger_delta(rows, RUN, 1).own_committed, 1)
        self.assertEqual(ledger_delta(rows, RUN, 1).foreign[0].step, 0)   # the earlier one is "foreign" to step 1


# The seeded artefact: init, then serve --role, as the cluster runs it.

class _FrozenFakeAA(_FakeAA):
    """Fake AA that shows what a correct TD of the frozen image would show, without hardware.

    Its claims (mrtd, rtmr0 to rtmr2, mrseam, tee_tcb_svn, xfam, tdattributes) are the frozen
    image's, and its RTMR3 is the real replay over the frozen init-data digest. The relying party
    it talks to is the seeded one (`from_freeze`).
    """

    def __init__(self, freeze: dict):
        super().__init__(freeze["init_data"]["digest"])
        self._m = freeze["measurement"]

    def evidence(self, runtime_data_32: bytes):
        rtmr3 = replay([f"v5 init-data {self._init}"] + self.lines)
        boot = {k: self._m[k] for k in ("rtmr0", "rtmr1", "rtmr2", "mrseam", "tee_tcb_svn", "xfam", "tdattributes")}
        return FakeAttestationAgent(measurement=self._m["mrtd"], rtmr3=rtmr3,
                                    boot_measurements=boot).get_evidence(runtime_data_32)


@needs_measured_freeze
class SeededServiceTests(ServiceEndToEndTests):
    """The same tests, with the two roles started the way the pods start them.

    `service_v5 init` seeds authority.db (Authority and frozen reference) and gateway.db (gateway
    and verify key) from one minting, then `start_authority` and `start_gateway` restore them. The
    Authority is pinned to the frozen reference, so the fake AA must present the frozen image.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v5-seeded-")
        self.freeze = json.loads((FREEZE / f"freeze-{STAMP}.json").read_text())
        # The archived record may name no `binding_version`, and `ReferenceValues` refuses such a
        # record outside an explicit re-appraisal, so a deployment cannot silently end up on the
        # earlier binding. The runner exercised here is the current one, so the test seeds from a
        # copy that names the current version.
        self.freeze["binding_version"] = PROTOCOL_VERSION.decode()
        freeze_path = os.path.join(self.tmp, f"freeze-{STAMP}.json")
        with open(freeze_path, "w", encoding="utf-8") as fh:
            json.dump(self.freeze, fh)
        a_db, g_db = os.path.join(self.tmp, "authority.db"), os.path.join(self.tmp, "gateway.db")
        # A freeze of the run profile names the runner image whose init-data digest it pins, and the
        # seed refuses a deployment that renders another one. A freeze of an older profile pins the
        # probe's digest and the deployment brings its own, so any image does.
        run_profile = self.freeze["init_data"].get("profile") == "run"
        image = (self.freeze["init_data"]["runner_image"] if run_profile
                 else "eu.gcr.io/x/booking@sha256:" + "ab" * 32)
        config = service_v5.seed(a_db, g_db, freeze_path, FixedClock(T0), runner_image=image)
        self.assertEqual(set(config), {"anchors"}, "the controller config carries only the anchors")
        self.authority, self.auth_store = service_v5.start_authority(
            a_db, ("127.0.0.1", 0), FixedClock(T0), verifier_factory=FakeVerifier)   # injected, not configured
        # The Authority pins the deployment's policy digest, not the probe's.
        self.assertEqual(self.authority._dep.relying_party.reference.init_data_digest,
                         service_v5.deployment_init_data_digest(image))
        if run_profile:
            self.assertEqual(self.authority._dep.relying_party.reference.init_data_digest,
                             self.freeze["init_data"]["digest"], "the deployment reproduces the run digest")
        else:
            self.assertNotEqual(self.authority._dep.relying_party.reference.init_data_digest,
                                self.freeze["init_data"]["digest"])
        self.freeze["init_data"]["digest"] = self.authority._dep.relying_party.reference.init_data_digest
        self.assertEqual(self.authority._dep.relying_party.reference.binding_version,
                         PROTOCOL_VERSION.decode(), "the seeded reference carries the version")
        self.gateway, self.gw_store = service_v5.start_gateway(g_db, ("127.0.0.1", 0), ("127.0.0.1", 0), FixedClock(T0))
        self.base = self.authority._dep                     # authority and relying party, as restored
        self.policy = default_p3()
        approval = approve(self.policy, approver_id="alice", approval_id=f"A-{RUN}",
                           run_id=RUN, issued_at=ISSUED, expires_at=EXPIRES)
        # The run is created through the surface, as the operator does it.
        reply = _call(self.authority.endpoint, "authority.create_run",
                      {"policy": wire.policy_to_wire(self.policy), "approval": wire.approval_to_wire(approval), "run_id": RUN})
        self.s0 = wire.envelope_from_wire(reply["envelope"])
        self.anchors = wire.anchors_from_wire(config["anchors"])
        self.ref = self.base.relying_party.reference
        self.fragment = honest_fragment(self.policy, RUN, 0, {"to": "FRA"})
        self.frag_octets = protocol.fragment_bytes(self.fragment)
        self.env_octets = protocol.envelope_bytes(self.s0)
        self.threads, self._files, self._ctl_tx = [], [], []
        self.runner_errors: list = []
        self.backend = _FakeBackend()
        self.pool = TdPool(self.backend, size=0)
        self.transport = AttachTransport(
            open_stream=lambda td: self._start_runner(), anchors=self.anchors,
            endpoint=self.authority.endpoint, gateway_endpoint=self.gateway.endpoint, policy=self.policy)
        self.ledger = RemoteLedger(self.gateway.observe_endpoint)
        self.controller = AttestedFragmentController(
            self.pool, RemoteAuthority(self.authority.endpoint), self.transport, ledger=self.ledger)

    def _attestation_agent(self):
        """A TD of the frozen image."""
        return _FrozenFakeAA(self.freeze)

    def test_A14_no_evidence_no_session_and_no_v3_provisioning_on_the_surface(self):
        """Acceptance test A14 on the seeded store, which has no bootstrap to hand to anyone.

        The assertions are the same. The bootstrap does not exist outside the process.
        """
        auth = RemoteAuthority(self.authority.endpoint)
        state = self.s0.state_hash  # a challenge needs the run's real state
        nonce = auth.issue_nonce(RUN, 0, "f" * 64, state, b"\1" * 32)
        res = auth.establish_session(None, b"\1" * 32, b"\2" * 32, RUN, 0, "f" * 64, state, nonce, substrate_profile_hash())
        self.assertEqual(res.rule, "evidence-missing")
        with self.assertRaises(wire.WireError) as ctx:
            _call(self.authority.endpoint, "authority.establish_runner_session",
                  {"bootstrap": {"kind": "provisioner-credential", "secret": "guess"}, "run_id": RUN,
                   "fragment_hash": "f" * 64, "state_hash": "s" * 64, "nonce": "n"})
        self.assertIn("no such method", str(ctx.exception))

    def test_the_seeded_human_credential_is_accepted_by_the_restored_authority(self):
        """The human's credential from the seeded store is accepted on the surface.

        The credential is the one published to the admin-only Secret. The controller config still
        carries only the anchors.
        """
        a_db = os.path.join(self.tmp, "authority.db")
        human = wire.human_from_wire(service_v5.human_credential(a_db))
        self.assertTrue(self.base.authority.verify_human(human))
        # The credential is accepted: the refusal names the missing pending record, not the
        # credential. An approval binds only a parked fragment.
        with self.assertRaises(wire.WireError) as ctx:
            _call(self.authority.endpoint, "authority.decide_intervention", {
                "human": wire.human_to_wire(human), "decision_id": "d1", "run_id": RUN, "step_index": 0,
                "fragment_hash": "ab" * 32, "approver_id": "approver:demo-human", "approver_kind": "passkey", "grant": True, "ttl": 600})
        self.assertIn("no pending intervention", str(ctx.exception))
        bad = wire.human_to_wire(wire.human_from_wire({"v": wire.WIRE_VERSION, "kind": "human-credential", "secret": "x"}))
        with self.assertRaises(wire.WireError) as ctx:
            _call(self.authority.endpoint, "authority.decide_intervention", {
                "human": bad, "decision_id": "d2", "run_id": RUN, "step_index": 0, "fragment_hash": "ab" * 32,
                "approver_id": "approver:demo-human", "approver_kind": "passkey", "grant": True, "ttl": 600})
        self.assertIn("invalid", str(ctx.exception))

    def test_a_td_that_is_not_the_frozen_image_is_refused_by_the_seeded_reference(self):
        """The seeded Authority pins the freeze.

        The plain fake AA (measurement 'mrtd-ref') is refused on the reference, before any session
        or effect.
        """
        plain = _FakeAA(self.freeze["init_data"]["digest"])
        self.transport.open_stream = lambda td: self._start_runner(plain)
        rec = self.controller.execute_fragment(RUN, 0, self.frag_octets, self.env_octets)
        self.assertEqual(rec.refusal.rule, "measurement-mismatch")
        self.assertEqual((rec.effects, rec.pending_effects), (0, 0))
        self.assertEqual(self.ledger.entries_after(0), ())


class SummaryStatisticsTests(unittest.TestCase):
    """The order statistics next to mean and stdev, because cold-boot timings are not normal."""

    def test_order_statistics_on_a_known_sample(self):
        st = e2e_live._stat([1, 2, 3, 4, 100])
        self.assertEqual((st["n"], st["min"], st["max"], st["median"]), (5, 1, 100, 3.0))
        self.assertEqual((st["q1"], st["q3"], st["iqr"]), (2.0, 4.0, 2.0))
        self.assertAlmostEqual(st["p95"], 4 + 96 * 0.8)          # linear interpolation at position 3.8
        self.assertAlmostEqual(st["mean"], 22.0)

    def test_single_value_and_empty(self):
        st = e2e_live._stat([7.5])
        self.assertEqual((st["median"], st["p95"], st["iqr"], st["stdev"]), (7.5, 7.5, 0.0, 0.0))
        self.assertIsNone(e2e_live._stat([None, "x"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
