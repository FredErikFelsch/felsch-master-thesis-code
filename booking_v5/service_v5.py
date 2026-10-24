"""The V5 service: a trusted `init` that seeds both stores, and `serve` for the authority and the gateway role.

    python3 -m booking_v5.service_v5 init  --authority-db A --gateway-db G --freeze freeze-<STAMP>.json \
        [--runner-image IMG@sha256:...] [--world W] [--now 1000] \
        [--publish-secret --namespace NS --secret-name NAME [--human-secret-name NAME] | --config-out FILE]
    python3 -m booking_v5.service_v5 serve --role authority --db A --bind 0.0.0.0:8443 \
        --no-approval-gate [--gateway-observe H:P] [--now N]
        (test configuration, a deployment starts booking_approval.service)
    python3 -m booking_v5.service_v5 serve --role gateway   --db G --bind 0.0.0.0:8443 \
        --observe 0.0.0.0:8444 [--world-db W] [--idempotent] [--now N]

`--now`, `--harness-bind` and `--no-approval-gate` are test flags and need V5_TEST_MODE=1.

init is trusted, runs once before any adversarial component exists and is idempotent.
    It mints the V3 authority material once (`Authority.create`) and seeds two stores:
      authority.db   Authority state (signing keys, bootstrap, human secret) and the frozen
                     reference (`freeze-<STAMP>.json`, unchanged, as a setting)
      gateway.db     ToolGateway state and the token verify key as a setting. It holds no
                     Authority state, no signing material and no bootstrap.
    It then publishes the controller config, which carries the trust anchors only. The
    provisioner bootstrap does not exist outside the authority process.
    With --human-secret-name it also publishes the human's approval credential (the V3
    `HumanApprovalCredential`, compared by HMAC) into a second Secret that only the admin
    reads. The controller Role cannot read it. The key that signs an intervention approval
    stays in the Authority and the human never holds it.

serve only restores state and fails closed on an unseeded store.
    authority   V3 Authority plus the V5 relying party (`ReferenceValues.from_freeze` on the
                seeded reference, `TdxVerifier` with the DCAP appraiser) on the authority
                surface. No other verifier is reachable from this CLI. The CLI serves this
                role only as a test configuration. A deployment starts it through
                booking_approval.service, which calls `start_authority`.
    gateway     V3 ToolGateway restored with the seeded verify key. The execution surface
                listens on --bind and the observation surface on --observe. It has its own
                SQLite file and its own PVC.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time

from booking_v1.clock import FixedClock, SystemClock
from booking_v3.authority import Authority
from booking_v3.envelope import VerifyKey
from booking_v3.gateway import ToolGateway
from booking_v4 import wire
from booking_v4.durable import DurableDeploymentServer, DurableStore, ExternalWorld, _RestoredDeployment

from .relying_party import AuthorityRelyingParty, ReferenceValues
from .verifier import TdxVerifier

SETTING_FREEZE = "v5.freeze_json"
SETTING_TOKEN_KEY = "v5.token_verify_key"
SETTING_ROLE = "v5.role"
SETTING_INIT_DATA = "v5.init_data_digest"
#: Which counterparty this deployment reaches. It is seeded into both stores at `init`, so it
#: is a property of the deployment and not of whatever a process was started with.
#: Changing it needs fresh stores, because `seed` refuses to re-seed existing stores for
#: another world. An environment variable could differ between two restarts of the same pod
#: without anyone noticing. "mock" is the V2 catalogue and the default, so a deployment that
#: does not ask for a live world is unaffected.
SETTING_WORLD = "v5.world"
DEFAULT_WORLD = "mock"


# --- init -----------------------------------------------------------------------------------

def deployment_init_data_digest(runner_image: str) -> str:
    """Return the init-data digest the Authority pins for this deployment.

    It is the SHA-256 over the TOML the controller launches every runner with (aa.toml,
    cdh.toml, the genpolicy policy for the fixed profile with `runner_main` as the command,
    the pinned image). The freeze pins the image (MRTD, RTMR0..2). The policy digest belongs
    to the deployment.

    The Authority and the controller agree because both read the same `k8s/v5/init-data`
    files, not because both call this function. The Authority runs it inside the services
    image, which carries its own copy of those files (`Dockerfile.services`), while the
    controller reads them from the working tree. The digest is a function of the checked-in
    sources and the digest-pinned runner image only, so the two copies agree whenever both
    come from the same commit. scripts/gke-v5/40_verify_v5.sh compares them before a run.
    """
    from .profile_v5 import init_data_document, init_data_hash
    return init_data_hash(init_data_document(runner_image))


def _require_deployment_matches_freeze(reference: ReferenceValues, deployed_digest: str | None) -> None:
    """Fail closed when a freeze that names the run digest disagrees with the deployment's own.

    A freeze with `init_data.profile == "run"` carries the run digest, so the deployment must
    reproduce it. A different services image, tree or runner image is refused here
    instead of showing up as rtmr3-mismatch after a full TD boot. For a legacy or probe
    record the deployment digest overrides the freeze.
    """
    if (reference.init_data_profile == "run" and deployed_digest is not None
            and deployed_digest != reference.init_data_digest):
        raise SystemExit(
            f"the freeze pins the run init-data digest {reference.init_data_digest[:12]}, this "
            f"deployment renders {deployed_digest[:12]}: wrong services image, tree or "
            f"runner image (fail-closed)")


def seed(authority_db: str, gateway_db: str, freeze_json: str, clock: FixedClock,
         runner_image: str | None = None, world: str = DEFAULT_WORLD) -> dict:
    """Seed both stores from one minting. Idempotent.

    Args:
        authority_db: path of the authority store.
        gateway_db: path of the gateway store.
        freeze_json: path of `freeze-<STAMP>.json`.
        clock: the clock the V3 material is minted under.
        runner_image: the digest-pinned runner image, which fixes the deployment's init-data
            digest. Without it the freeze's digest stays.
        world: the counterparty, "mock" or a live world of booking_live.startup.WORLDS.

    Returns:
        The controller config (anchors only) reconstructed from the authority store.

    Raises:
        SystemExit: the freeze, the world or the existing stores are refused.
    """
    freeze_text = pathlib.Path(freeze_json).read_text()
    reference = ReferenceValues.from_freeze_text(freeze_text, str(freeze_json))   # validates before seeding
    if world != DEFAULT_WORLD:
        from booking_live.startup import WORLDS
        if world not in WORLDS:
            raise SystemExit(f"unknown world {world!r}, expected {DEFAULT_WORLD} or "
                             f"one of {sorted(WORLDS)} (fail-closed)")
    init_data_digest = deployment_init_data_digest(runner_image) if runner_image else None
    _require_deployment_matches_freeze(reference, init_data_digest)
    a_store, g_store = DurableStore(authority_db), DurableStore(gateway_db)
    try:
        states = a_store.load_states()
        if states is None:
            authority, _bootstrap, _human = Authority.create(clock)
            gateway = ToolGateway(authority.token_key(), clock)
            with a_store.transaction():
                a_store.put_states(json.dumps(authority.export_state(), sort_keys=True), "{}")
                a_store.put_setting(SETTING_FREEZE, freeze_text)
                a_store.put_setting(SETTING_ROLE, "authority")
                a_store.put_setting(SETTING_WORLD, world)
                if init_data_digest:
                    a_store.put_setting(SETTING_INIT_DATA, init_data_digest)
            with g_store.transaction():
                g_store.put_states("{}", json.dumps(gateway.export_state(), sort_keys=True))
                g_store.put_setting(SETTING_TOKEN_KEY, authority.token_key().to_bytes().hex())
                g_store.put_setting(SETTING_ROLE, "gateway")
                g_store.put_setting(SETTING_WORLD, world)
        else:
            if a_store.get_setting(SETTING_ROLE) != "authority" or g_store.get_setting(SETTING_ROLE) != "gateway":
                raise SystemExit("stores exist but are not a V5 authority/gateway pair (refusing to touch them)")
            # A re-seed must not silently move a deployment to another counterparty:
            # the stores already carry runs, facts and a ledger that were produced
            # against the world they were seeded with.
            for store_name, store in (("authority", a_store), ("gateway", g_store)):
                seeded = store.get_setting(SETTING_WORLD) or DEFAULT_WORLD
                if seeded != world:
                    raise SystemExit(
                        f"the {store_name} store was seeded for world {seeded!r}, "
                        f"refusing to re-seed it as {world!r} (fail-closed)")
            authority = Authority.restore(clock, states[0])
            # A re-run does not re-mint, but it may re-pin the deployment's policy digest (a new
            # policy.rego for the same image) and the frozen reference. Both are settings, not state.
            with a_store.transaction():
                a_store.put_setting(SETTING_FREEZE, freeze_text)
                if init_data_digest:
                    a_store.put_setting(SETTING_INIT_DATA, init_data_digest)
        return {"anchors": wire.anchors_to_wire(authority.anchors())}
    finally:
        a_store.close()
        g_store.close()


def human_credential(authority_db: str) -> dict:
    """Return the human's approval credential (wire form) from a seeded authority store.

    The store is opened read-only, so no writer lock is taken and it works beside a live
    Authority.
    """
    from booking_v3.authority import HumanApprovalCredential
    store = DurableStore(authority_db, readonly=True)
    try:
        states = store.load_states()
        if states is None or store.get_setting(SETTING_ROLE) != "authority":
            raise SystemExit(f"{authority_db!r} is not a seeded V5 authority store")
        return wire.human_to_wire(HumanApprovalCredential(secret=states[0]["human_secret"]))
    finally:
        store.close()


def _publish_secret(namespace: str, secret_name: str, key: str, payload: dict) -> None:
    from kubernetes import client, config as kconfig
    kconfig.load_incluster_config()
    client.CoreV1Api().patch_namespaced_secret(
        secret_name, namespace, {"stringData": {key: json.dumps(payload, sort_keys=True)}})


# --- serve ----------------------------------------------------------------------------------

def _verifier(kind: str, freeze: dict | None = None):
    """Return the Authority's verifier.

    `dcap` appraises with Intel's QVL over a validity-bounded collateral cache
    (`collateral_cache.CachedCollateral`), warmed at start with the FMSPC of the frozen
    reference so no verdict waits for DNS or PCS.

    `dcap` is the only kind the service accepts. The offline `FakeVerifier` lives in the
    model (`relying_party.py`, `experiment_v5.py`) and is not reachable from this CLI. A
    deployed Authority cannot be switched to accept unappraised evidence by configuration, so
    a run record whose appraisal names `TdxVerifier` together with a QVL `qv_result` came
    from a service that had no other verifier to offer.

    Raises:
        SystemExit: `kind` is not `dcap`.
    """
    if kind == "dcap":
        from .collateral_cache import CachedCollateral
        from .dcap.local_dcap_collateral import PCSCollateralClient
        from .verifier import dcap_appraiser
        cache = CachedCollateral(PCSCollateralClient())
        fmspc = ((freeze or {}).get("dcap") or {}).get("fmspc")
        report = cache.warm(fmspc)
        sys.stdout.write(f"[v5-authority] collateral cache warmed: {json.dumps(report)} "
                         f"(fmspc={fmspc}, fetches={cache.fetches})\n")
        sys.stdout.flush()
        return TdxVerifier(dcap_appraiser(pcs=cache))
    raise SystemExit(f"unknown verifier {kind!r}")


def start_authority(db: str, bind: tuple[str, int], clock, verifier: str = "dcap",
                    harness: tuple[str, int] | None = None, *,
                    verifier_factory=None,
                    gateway_observe: tuple[str, int] | None = None,
                    closed_methods: frozenset[str] = frozenset(),
                    ) -> tuple[DurableDeploymentServer, DurableStore]:
    """Restore the Authority role and return its server and store.

    Args:
        db: path of the seeded authority store.
        bind: the authority surface's listen address.
        clock: the clock of the restored Authority.
        verifier: the CLI kind (`dcap` only).
        harness: the listen address of the separate harness surface, tests only.
        verifier_factory: dependency injection for the seeded offline suite (a callable
            returning a Verifier). It has no CLI flag and no environment variable, so a
            deployed service cannot reach it.
        gateway_observe: the gateway's observation endpoint. With it the Authority checks
            every reported observation against the digest the gateway recorded for that
            effect, over the only gateway surface it is allowed to reach (read-only, no
            identity, no state mutation). Without it that check does not happen, which is
            the V3 and V4 behaviour.
        closed_methods: refused on every non-harness listener from the moment the listener
            is bound. The approval gate passes `CLOSED_METHODS` here, so `create_run` and
            `decide_intervention` are not served in a window before the gate is installed.
            The default (nothing closed) is the offline and test configuration only.

    Returns:
        (server, store).

    Raises:
        SystemExit: the store is not a seeded authority store, the freeze disagrees with the
            deployment, the dcap verifier gets a freeze whose init-data profile is not
            "run", or the seeded world refuses the policy admission.
    """
    store = DurableStore(db)
    if store.get_setting(SETTING_ROLE) != "authority":
        store.close()
        raise SystemExit(f"{db!r} is not a seeded V5 authority store. Run `service_v5 init` first (fail-closed)")
    states = store.load_states()
    authority = Authority.restore(clock, states[0])
    freeze_text = store.get_setting(SETTING_FREEZE)
    reference = ReferenceValues.from_freeze_text(freeze_text)
    deployed_digest = store.get_setting(SETTING_INIT_DATA)
    _require_deployment_matches_freeze(reference, deployed_digest)
    if verifier_factory is None and reference.init_data_profile != "run":
        # The deployed binary appraises real quotes. Under a probe (or absent) profile the digest
        # pinned here is the probe pod's, whose policy is not the one the runner boots under, and
        # a missing deployment digest would not override it. Offline fixtures inject their own
        # verifier and do not reach this.
        store.close()
        raise SystemExit(
            f"the freeze names init_data.profile {reference.init_data_profile!r}: the Authority with the "
            f"dcap verifier serves only a freeze whose init-data profile is 'run' (fail-closed)")
    if deployed_digest:
        reference.init_data_digest = deployed_digest        # the policy of this deployment
    chosen = verifier_factory() if verifier_factory is not None else _verifier(verifier, json.loads(freeze_text))
    rp = AuthorityRelyingParty(chosen, reference)
    rp.import_state(store.load_v5_state())
    if gateway_observe is not None:
        from booking_v4.endpoint import ServiceEndpoint
        from .gateway import RemoteLedger
        authority.bind_effect_ledger(RemoteLedger(
            ServiceEndpoint(kind="tcp", address=f"{gateway_observe[0]}:{gateway_observe[1]}")))
    world = store.get_setting(SETTING_WORLD) or DEFAULT_WORLD
    if world != DEFAULT_WORLD:
        # Fail-closed, like the gateway: an Authority seeded for a live world activates only
        # policies that world can execute. The catalogue deployment stays unbound.
        from booking_live.startup import ConfigurationRefused, admit_policy
        try:
            authority.bind_policy_admission(admit_policy(world))
        except ConfigurationRefused as refused:
            store.close()
            raise SystemExit(f"authority configured for world {world!r}: {refused}")
        sys.stdout.write(f"[v5-authority] world={world}: policy admission bound\n")
        sys.stdout.flush()
    server = DurableDeploymentServer(_RestoredDeployment(authority, None, rp), store,
                                     tcp=bind, role="authority", harness_tcp=harness,
                                     closed_methods=closed_methods)
    return server, store


def start_gateway(db: str, bind: tuple[str, int], observe: tuple[str, int], clock,
                  world_db: str | None = None, idempotent: bool = False,
                  harness: tuple[str, int] | None = None) -> tuple[DurableDeploymentServer, DurableStore]:
    """Restore the gateway role and return its server and store.

    The execution surface listens on `bind` and the observation surface on `observe`. A store
    seeded for a live world starts with that world's executor or not at all.

    Args:
        db: path of the seeded gateway store.
        bind: the execution surface's listen address.
        observe: the observation surface's listen address.
        clock: the gateway's clock.
        world_db: path of a durable external-world store, if any.
        idempotent: whether the downstream counterparty is idempotent.
        harness: the listen address of the separate harness surface, tests only.

    Returns:
        (server, store).

    Raises:
        SystemExit: the store is not a seeded gateway store, or the seeded live world
            cannot be verified.
    """
    store = DurableStore(db)
    if store.get_setting(SETTING_ROLE) != "gateway":
        store.close()
        raise SystemExit(f"{db!r} is not a seeded V5 gateway store. Run `service_v5 init` first (fail-closed)")
    states = store.load_states()
    token_key = VerifyKey.from_bytes(bytes.fromhex(store.get_setting(SETTING_TOKEN_KEY)))
    configured = store.get_setting(SETTING_WORLD) or DEFAULT_WORLD
    executor = None
    if configured != DEFAULT_WORLD:
        # Fail-closed: a gateway seeded for a live counterparty does not start as the
        # catalogue, because silently serving mock data from a deployment that believes it
        # is live is a failure nobody would notice in time.
        from booking_live.startup import ConfigurationRefused, verify_world
        # Experiment knob of the live evaluation: an injected fault, off by default and
        # announced below. The journey, including a provider scenario route, is part of the
        # approved plan and not of the deployment.
        fault = os.environ.get("WORLD_FAULT", "").strip() or None
        try:
            live = verify_world(configured, fault=fault)
        except ConfigurationRefused as refused:
            store.close()
            raise SystemExit(f"gateway configured for world {configured!r}: {refused}")
        executor = live.executor
        print(f"[gateway] world={configured} flow={'/'.join(live.flow)} "
              f"fault={fault or 'none'}", flush=True)

    if world_db:
        world = (ExternalWorld(db_path=world_db, idempotent=idempotent, executor=executor)
                 if executor else ExternalWorld(db_path=world_db, idempotent=idempotent))
        gateway = ToolGateway(token_key, clock, executor=world.executor)
    elif executor is not None:
        # No durable world store, but a live counterparty: the executor still has to be
        # the live one, otherwise the catalogue would answer.
        gateway = ToolGateway(token_key, clock, executor=executor)
    else:
        gateway = ToolGateway(token_key, clock)
    gateway.restore_state(states[1])
    server = DurableDeploymentServer(_RestoredDeployment(None, gateway), store,
                                     tcp=bind, observe_tcp=observe, role="gateway",
                                     downstream_idempotent=idempotent, harness_tcp=harness)
    return server, store


def _hostport(s: str) -> tuple[str, int]:
    host, port = s.rsplit(":", 1)
    return host, int(port)


#: Set to 1 by a test or an offline fixture. No manifest and no script sets it, and a test
#: checks that, so the flags below cannot be switched on in a deployment by accident.
TEST_MODE_ENV = "V5_TEST_MODE"


def refuse_test_flags(args: argparse.Namespace) -> None:
    """Refuse `--now`, `--harness-bind` and `--no-approval-gate` unless the process says explicitly
    that it is a test.

    `--now` pins the clock, so approval windows and tokens do not expire. `--harness-bind`
    opens a second listener with fault injection and read back. `--no-approval-gate` serves
    create_run and decide_intervention without the approval gate. All three exist for offline
    fixtures, and none belongs in a deployment.
    """
    if os.environ.get(TEST_MODE_ENV) == "1":
        return
    used = [flag for flag, value in (("--now", getattr(args, "now", None)),
                                     ("--harness-bind", getattr(args, "harness_bind", None)),
                                     ("--no-approval-gate", True if getattr(args, "no_approval_gate", False) else None))
            if value is not None]
    if used:
        raise SystemExit(f"{', '.join(used)}: test flag, refused outside a test "
                         f"(set {TEST_MODE_ENV}=1 for an offline fixture)")


def main(argv: list[str] | None = None) -> int:
    """Command line entry point: `init` seeds the stores, `serve` runs one role until killed."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("--authority-db", required=True)
    i.add_argument("--gateway-db", required=True)
    i.add_argument("--freeze", required=True)
    i.add_argument("--now", type=int, default=None, help="pin the clock (offline fixtures only), default: system clock")
    i.add_argument("--runner-image", default=None, help="digest-pinned runner image: fixes the deployment's init-data digest")
    i.add_argument("--world", default=DEFAULT_WORLD,
                   help="which counterparty this deployment reaches: mock (the V2 catalogue, "
                        "default) or a live world. Seeded into both stores, so it is a "
                        "property of the deployment and not of a process's environment. "
                        "A live world needs its credential in the gateway's environment.")
    i.add_argument("--namespace", default="agent-system")
    i.add_argument("--secret-name", default="deployment-bootstrap")
    i.add_argument("--publish-secret", action="store_true")
    i.add_argument("--config-out", default=None)
    i.add_argument("--human-secret-name", default=None,
                   help="with --publish-secret: also publish the human's approval credential into this Secret")
    s = sub.add_parser("serve")
    s.add_argument("--role", required=True, choices=("authority", "gateway"))
    s.add_argument("--db", required=True)
    s.add_argument("--bind", required=True)
    s.add_argument("--observe", default=None)
    s.add_argument("--now", type=int, default=None)
    s.add_argument("--verifier", default="dcap", choices=("dcap",))
    s.add_argument("--gateway-observe", default=None,
                   help="authority role: HOST:PORT of the gateway's observation surface. "
                        "Arms the check of reported observations against the effect ledger")
    s.add_argument("--world-db", default=None)
    s.add_argument("--idempotent", action="store_true")
    s.add_argument("--harness-bind", default=None,
                   help="HOST:PORT of a separate listener for the harness surface (test.*, read.*), not on --bind")
    s.add_argument("--no-approval-gate", action="store_true",
                   help="authority role: test configuration. Serves create_run and decide_intervention without "
                        "the approval gate. A deployment starts `booking_approval.service` instead.")
    args = ap.parse_args(argv)
    refuse_test_flags(args)

    if args.cmd == "init":
        config = seed(args.authority_db, args.gateway_db, args.freeze,
                      FixedClock(args.now) if args.now is not None else SystemClock(),
                      args.runner_image, world=args.world)
        if args.publish_secret:
            _publish_secret(args.namespace, args.secret_name, "controller-config.json", config)
            sys.stderr.write(f"seeded {args.authority_db} and {args.gateway_db}, patched Secret "
                             f"{args.namespace}/{args.secret_name} (anchors only)\n")
            if args.human_secret_name:
                _publish_secret(args.namespace, args.human_secret_name, "human-credential.json",
                                human_credential(args.authority_db))
                sys.stderr.write(f"patched Secret {args.namespace}/{args.human_secret_name} (human credential)\n")
        if args.config_out:
            pathlib.Path(args.config_out).write_text(json.dumps(config, sort_keys=True))
            sys.stderr.write(f"seeded both stores, controller config (anchors only) -> {args.config_out}\n")
        if not args.publish_secret and not args.config_out:
            sys.stderr.write("nothing published: pass --publish-secret or --config-out FILE\n")
            return 2
        return 0

    # The deployed services run the system clock, so approval windows, token TTLs and
    # intervention expiry are live. `--now` pins the clock for offline fixtures only.
    clock = FixedClock(args.now) if args.now is not None else SystemClock()
    if args.role == "authority":
        if not args.no_approval_gate:
            raise SystemExit("authority role without the approval gate is a test configuration: start "
                             "`python3 -m booking_approval.service`, or pass --no-approval-gate explicitly")
        sys.stderr.write("[v5-authority] TEST CONFIGURATION: create_run and decide_intervention are open "
                         "(no approval gate)\n")
        harness = _hostport(args.harness_bind) if args.harness_bind else None
        observe = _hostport(args.gateway_observe) if args.gateway_observe else None
        server, _ = start_authority(args.db, _hostport(args.bind), clock, args.verifier, harness,
                                    gateway_observe=observe)
        out = {"role": "authority", "endpoint": server.endpoint.to_wire(), "verifier": args.verifier,
               "observation_check": args.gateway_observe or "off",
               "clock": "system" if args.now is None else f"fixed:{args.now}"}
    else:
        if not args.observe:
            raise SystemExit("--observe HOST:PORT is required for the gateway role")
        harness = _hostport(args.harness_bind) if args.harness_bind else None
        server, _ = start_gateway(args.db, _hostport(args.bind), _hostport(args.observe), clock,
                                  args.world_db, args.idempotent, harness)
        out = {"role": "gateway", "endpoint": server.endpoint.to_wire(),
               "observe_endpoint": server.observe_endpoint.to_wire(),
               "clock": "system" if args.now is None else f"fixed:{args.now}"}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
