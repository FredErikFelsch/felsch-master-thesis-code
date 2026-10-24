"""The adapter that runs the booking_v3 evaluation on Kubernetes.

This is the deployment factory that runs the same booking_v3 evaluation (scenario matrix,
differential conformance, dispatch safety) with the runner launch backend swapped to Kubernetes
Jobs. It is the Kubernetes analogue of the durable container backend of `container_backend`, and it
is what `experiment_k8s.py` installs.

Scope of this adapter:

  * The evaluation shows semantic equivalence: running each fragment in its own short-lived
    Kubernetes Job keeps every decision, rejection point, fact, lifecycle state, provenance head
    and dispatch outcome. To make that comparison exact, the durable Authority and gateway service
    runs inside the evaluation harness and is reached over TCP. All Authority reads the comparison
    depends on (`status`, `audit`, `gateway.executions`) come from the harness's real objects, so
    the results compare equal to every other backend without a change to the durable service. The
    Job pods reach this Authority over the advertised TCP endpoint.

  * This adapter does not show the enforced launch boundary (RBAC denies the orchestrator
    ServiceAccount Job verbs, a NetworkPolicy confines the runner). `tests_k8s.py` checks that live
    on the full in-cluster topology (Authority pod `service_process_tcp`, controller pod
    `controller_k8s_process`, RBAC, NetworkPolicy). The two are kept apart: the equivalence run
    measures semantics, the enforcement suite measures the boundary.

`create_k8s_deployment` needs a real cluster and the `kubernetes` client, so it is exercised by the
cluster scripts under `scripts/gke`, not offline. The module imports without the client (the import
is inside the factory), so the offline tests still load.

Configuration (environment, set by the security-suite script, no secrets):
    RUNNER_IMAGE               digest-pinned runner image the Jobs run (required)
    K8S_NAMESPACE              namespace for the runner Jobs (default agent-system)
    K8S_AUTHORITY_BIND         harness Authority bind HOST:PORT (default 0.0.0.0:0)
    K8S_AUTHORITY_ADVERTISE    HOST[:PORT] the Job pods use to reach the harness
                               Authority (required live, the port defaults to the
                               bound port)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from booking_v1.clock import Clock

from booking_v3.provisioner import create_deployment

from .durable import (AuthorityFacade, DurableDeploymentServer, DurableStore,
                      GatewayFacade, HumanApprovalClient, RemoteAuthorityHandle,
                      _RestoredDeployment)
from .endpoint import ServiceEndpoint


@dataclass
class KubernetesDeployment:
    """Evaluation deployment whose runners are short-lived Kubernetes Jobs.

    Authority, gateway, anchors, bootstrap and human interface are those of the
    durable in-harness service, reached over TCP and unchanged (only the launch
    substrate differs), so every scenario behaves as on the other backends.
    ``provisioner`` is the Kubernetes launch backend.
    """

    authority: object
    gateway: object
    anchors: object
    provisioner: object
    bootstrap: object
    human_interface: object
    _server: object = field(repr=False, default=None)
    _store: object = field(repr=False, default=None)

    def close(self) -> None:
        """Stop the in-harness service and close its store."""
        try:
            if self._server is not None:
                self._server.close()
        finally:
            if self._store is not None:
                self._store.close()

    def __enter__(self) -> "KubernetesDeployment":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _advertise_endpoint(bound_port: int) -> ServiceEndpoint:
    """Return the endpoint the in-cluster Job pods use to reach the harness Authority.

    It differs from the harness's own local connect endpoint: pods cannot use
    127.0.0.1, so the security-suite script provides a reachable host (a node IP,
    or the address of a `kubectl port-forward` or Service that fronts the harness).

    Raises:
        RuntimeError: K8S_AUTHORITY_ADVERTISE is not set.
    """
    advertise = os.environ.get("K8S_AUTHORITY_ADVERTISE")
    if not advertise:
        raise RuntimeError(
            "K8S_AUTHORITY_ADVERTISE is required: the Job pods need a host:port "
            "at which they can reach the harness Authority (set by the "
            "security-suite script for a live cluster run)")
    host, sep, port = advertise.rpartition(":")
    if not sep:                       # host only: use the bound port
        host, port = advertise, str(bound_port)
    return ServiceEndpoint.tcp(host, int(port))


_LIVE_DEPLOYMENT: list = []   # the one harness deployment currently serving


def _retire_previous_deployment() -> None:
    """Close the previous scenario's harness Authority before opening the next.

    The scenario harness does not close a deployment, and the other backends bind an
    ephemeral port per scenario, so leaked listeners are harmless there. In-cluster
    the harness Authority listens on one fixed port (the runner egress policy and the
    fronting Service pin 8443), so only one listener may exist at a time. Scenarios
    run one after another, so retiring the previous one is safe.
    """
    while _LIVE_DEPLOYMENT:
        _LIVE_DEPLOYMENT.pop().close()


def create_k8s_deployment(clock: Clock, executor=None) -> KubernetesDeployment:
    """Build a deployment on the Kubernetes launch backend (fits the booking_v3 scenario hook).

    Builds the durable Authority and gateway service in this harness process over
    a TCP listener, then the Kubernetes launch backend that runs one short-lived
    Job per fragment against it. Reads come from the real local objects, as in
    every other backend, and runner Jobs reach the Authority over the advertised
    TCP endpoint.
    """
    from .k8s_backend import KubernetesRunnerProvisioner  # lazy: needs the client

    _retire_previous_deployment()
    base = create_deployment(clock, executor=executor)
    authority, gateway = base.authority, base.gateway
    bootstrap, human = base.bootstrap, base.human
    anchors = authority.anchors()

    import tempfile
    store = DurableStore(os.path.join(
        tempfile.mkdtemp(prefix="booking-k8s-"), "deployment.db"))
    bind = os.environ.get("K8S_AUTHORITY_BIND", "0.0.0.0:0")
    bind_host, bind_port = bind.rsplit(":", 1)
    server = DurableDeploymentServer(
        _RestoredDeployment(authority, gateway), store,
        tcp=(bind_host, int(bind_port)))
    bound_port = int(server.endpoint.address.rsplit(":", 1)[1])

    # Harness-side facades connect locally. Reads come from the real objects.
    local = ServiceEndpoint.tcp("127.0.0.1", bound_port)
    authority_facade = AuthorityFacade(authority, local)
    gateway_facade = GatewayFacade(gateway, local)
    human_interface = HumanApprovalClient(local, human)

    # The Job pods reach the harness Authority over the advertised endpoint.
    advertise = _advertise_endpoint(bound_port)
    image = os.environ.get("RUNNER_IMAGE")
    if not image:
        raise RuntimeError("RUNNER_IMAGE (digest-pinned) is required for a live "
                           "Kubernetes evaluation run")
    provisioner = KubernetesRunnerProvisioner(
        namespace=os.environ.get("K8S_NAMESPACE", "agent-system"),
        image=image,
        authority=RemoteAuthorityHandle(advertise),
        anchors=anchors,
        bootstrap=bootstrap,
        authority_endpoint=advertise.to_wire())

    deployment = KubernetesDeployment(
        authority=authority_facade, gateway=gateway_facade, anchors=anchors,
        provisioner=provisioner, bootstrap=bootstrap,
        human_interface=human_interface, _server=server, _store=store)
    _LIVE_DEPLOYMENT.append(deployment)
    return deployment
