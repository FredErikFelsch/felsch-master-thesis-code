"""The measured runner profile: the V5 form of `booking_v4.k8s_backend.FIXED_PROFILE`.

The manifest is a pure function of its arguments (image, namespace, name or generate_name,
policy, interpreter) plus the frozen init-data documents. It takes no fragment, so the Pod
template is the same for every fragment. Compared with V4 it adds
`runtimeClassName: kata-remote` (one confidential VM per pod) and the
`io.katacontainers.config.hypervisor.cc_init_data` annotation carrying aa.toml, cdh.toml and
policy.rego, whose hash is measured into the TD. The hardening that the guest policy enforces
is the same list as in V4 (digest pin, no exec, no privileged, no extra mounts, no env
override).

The runner is a bare Pod here, not a Job, because pool TDs live until they are bound and
the controller manages their lifecycle itself (pool.py).
"""
from __future__ import annotations

import base64
import gzip
import copy
import hashlib
import os

from booking_v4.k8s_backend import FIXED_PROFILE, require_pinned_image

INIT_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "k8s", "v5", "init-data")
RUNTIME_CLASS = "kata-remote"
INIT_DATA_ANNOTATION = "io.katacontainers.config.hypervisor.cc_init_data"

PROFILE_V5 = dict(FIXED_PROFILE, runtime_class=RUNTIME_CLASS, managed_by="trusted-runner-controller-v5")

# The Fixed Execution Profile has two halves with different evidence:
#   guest half     -> measured by the hardware and appraised by the Authority (local
#                     DCAP): pod-VM MRTD/RTMR0-2, the init-data digest in RTMR3
#                     (policy.rego, aa.toml, cdh.toml), the image digest (enforced in
#                     the guest by the policy).
#   substrate half -> established by the trusted controller on the substrate and
#                     asserted to the Authority as a hash: RuntimeClass, pod-VM
#                     machine and TEE type, pod-VM subnet and firewall policy, and the
#                     NetworkPolicy set. Attacks A5 and A5b of
#                     scripts/gke-v5/attack_catalogue.md probe the last two.
#                     Attestation proves the TD, the controller produces the
#                     environment, and the Authority accepts only the combination
#                     (reference pins for both halves).
SUBSTRATE_PROFILE = {
    "runtime_class": RUNTIME_CLASS,
    "podvm_machine": "c3-standard-4",
    "podvm_tee": "TDX",
    "podvm_subnet_cidr": "192.168.200.0/24",
    "firewall_rules": ("v5-allow-peerpod-tunnel", "v5-runner-td-policy:65000-deny-egress"),
    "network_policies": ("default-deny-all", "runner-egress"),
}


def substrate_profile_hash(profile: dict = SUBSTRATE_PROFILE) -> str:
    """Return the canonical SHA-256 of the substrate half.

    The deploy step pins it, the controller asserts it at session establishment and the
    Authority compares the two.
    """
    import json
    return hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()


def init_data_document(image_digest_ref: str, policy_rego: str | None = None) -> str:
    """Render the init-data TOML from the frozen templates.

    The image digest is substituted into policy.rego, so the guest enforces the same pin as
    the controller.

    Args:
        image_digest_ref: the runner image pinned by digest.
        policy_rego: replaces the policy.rego on disk, typically a policy genpolicy produced
            for the manifest being launched (see scripts/gke-v5/_genpolicy.sh).

    Returns:
        The init-data TOML document.
    """
    parts = []
    for fn in ("aa.toml", "cdh.toml", "policy.rego"):
        if fn == "policy.rego" and policy_rego is not None:
            body = policy_rego.replace("${RUNNER_IMAGE}", image_digest_ref)
        else:
            with open(os.path.join(INIT_DATA_DIR, fn)) as fh:
                body = fh.read().replace("${RUNNER_IMAGE}", image_digest_ref)
        parts.append(f'"{fn}" = \'\'\'\n{body}\n\'\'\'')
    return "algorithm = \"sha256\"\nversion = \"0.1.0\"\n\n[data]\n" + "\n".join(parts) + "\n"


def init_data_hash(doc: str) -> str:
    """Return the digest the guest measures: SHA-256 over the uncompressed TOML document."""
    return hashlib.sha256(doc.encode()).hexdigest()


def init_data_annotation_value(doc: str) -> str:
    """Return the annotation value the kata shim expects, base64(gzip(TOML)).

    The gzip mtime is fixed to 0, so the value is deterministic.
    """
    return base64.b64encode(gzip.compress(doc.encode(), mtime=0)).decode()


#: The interpreter inside the runner image (python:3.11-slim has no /usr/bin/python3).
#: Scripts read it from .digests (RUNNER_PYTHON) and pass it here instead of guessing a path.
DEFAULT_RUNNER_PYTHON = "/usr/local/bin/python3"
#: The V5 runner entry point: the line protocol over stdin/stdout (booking_v5.runner_main).
RUNNER_MODULE = "booking_v5.runner_main"
#: The guest-pull credential the controller mints per spawn (a short-lived registry token).
PULL_SECRET = "ar-pull"


#: The controller's pods are created with generateName, so one policy (genpolicy pins the
#: sandbox name as the regex ^runner-td-[bcdfghjklmnpqrstvwxz2456789]+$) covers every TD.
#: A fixed `name` pins that one name (the probe pods do this, each with its own policy).
RUNNER_GENERATE_NAME = "runner-td-"


def build_runner_pod_manifest(*, image: str, namespace: str, name: str | None = None,
                              policy_rego: str | None = None, python: str = DEFAULT_RUNNER_PYTHON,
                              generate_name: str | None = None) -> dict:
    """Build the runner Pod manifest. It takes no fragment, envelope, V3 policy or credential.

    The container command is part of what the measured policy pins, so it is fixed here
    (`python -m booking_v5.runner_main`) and not left to the image's ENTRYPOINT (the V4
    runner).

    Args:
        image: the runner image, pinned by digest.
        namespace: the namespace of the pod.
        name: a fixed pod name (probes). Give either this or `generate_name`.
        policy_rego: the agent policy to embed, the frozen policy.rego when None.
        python: the interpreter inside the image.
        generate_name: the generateName prefix (the controller).

    Returns:
        The Pod manifest as a dict.

    Raises:
        ValueError: both or neither of `name` and `generate_name` are given, or the image
            is not pinned by digest.
    """
    if (name is None) == (generate_name is None):
        raise ValueError("give exactly one of name or generate_name")
    image = require_pinned_image(image)
    p = PROFILE_V5
    doc = init_data_document(image, policy_rego)
    identity = {"name": name} if name is not None else {"generateName": generate_name}
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            **identity, "namespace": namespace,
            "labels": {"app": "runner", "managed-by": p["managed_by"]},
            "annotations": {INIT_DATA_ANNOTATION: init_data_annotation_value(doc),
                            "v5/init-data-sha256": init_data_hash(doc)},
        },
        "spec": {
            "runtimeClassName": p["runtime_class"],
            "restartPolicy": "Never",
            "serviceAccountName": p["service_account"],
            "automountServiceAccountToken": False,
            "activeDeadlineSeconds": p["active_deadline_seconds"],
            "imagePullSecrets": [{"name": PULL_SECRET}],
            "securityContext": {"runAsNonRoot": True, "runAsUser": p["uid"], "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "runner", "image": image,
                "command": [python, "-m", RUNNER_MODULE],
                "stdin": True, "stdinOnce": True, "tty": False,
                "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"limits": {"memory": p["memory_limit"]},
                              "requests": {"memory": p["memory_limit"], "cpu": p["cpu_request"]}},
                "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
            }],
            "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": p["tmp_size"]}}],
        },
    }


def manifest_without_identity(m: dict) -> dict:
    """Return the manifest with `name`, its only per-instance field, removed.

    The result must be identical for every fragment. The function expects a manifest built
    with `name`. A manifest built with `generate_name` has no per-instance field.
    """
    m = copy.deepcopy(m)
    m["metadata"].pop("name")
    return m
