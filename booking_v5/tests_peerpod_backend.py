"""`PeerPodBackend.delete_and_confirm` against fake Kubernetes and GCE.

  * A PeerPod CR is found by `spec.instanceID` (`podvm-<pod>-<hash>`), not by the pod name,
    because the CRs are named `<pod>-resource-<random>`.
  * The finalizer is removed only after GCE reports the instance gone
    (gce_confirmed_finalizer_cleanup).
  * A VM that does not disappear keeps its finalizer and fails the run (fail closed).

Run:  python3 -m booking_v5.tests_peerpod_backend
"""
from __future__ import annotations

import sys
import types
import unittest
from unittest import mock


# A minimal fake `kubernetes` package so the module's lazy imports resolve.
class _ApiException(Exception):
    """The shape of `kubernetes.client.rest.ApiException`: an exception with a status."""

    def __init__(self, status):
        super().__init__(status)
        self.status = status


_k8s = types.ModuleType("kubernetes")
_client = types.ModuleType("kubernetes.client")
_rest = types.ModuleType("kubernetes.client.rest")
_rest.ApiException = _ApiException
_client.rest = _rest
_client.V1DeleteOptions = lambda **kw: kw
_k8s.client = _client
sys.modules.setdefault("kubernetes", _k8s)
sys.modules.setdefault("kubernetes.client", _client)
sys.modules.setdefault("kubernetes.client.rest", _rest)

from .controller_v5 import PeerPodBackend  # noqa: E402


class _FakeCore:
    """The core API with one runner pod. A deleted pod reads as 404."""

    def __init__(self):
        self.pods = {"runner-td-1": True}
        self.deleted = []

    def delete_namespaced_pod(self, name, ns, body=None):
        self.deleted.append(name)
        self.pods.pop(name, None)

    def read_namespaced_pod(self, name, ns):
        if name not in self.pods:
            raise _ApiException(404)
        return object()


class _FakeCustom:
    """The custom-objects API that lists the given PeerPod CRs and records patches."""

    def __init__(self, items):
        self.items = items
        self.patched = []

    def list_namespaced_custom_object(self, g, v, ns, plural):
        return {"items": self.items}

    def patch_namespaced_custom_object(self, g, v, ns, plural, name, body):
        self.patched.append((name, body))


class _Probe:
    """A cloud probe whose instance exists for the first `alive_polls` calls and is gone afterwards."""

    def __init__(self, alive_polls):
        self.alive_polls = alive_polls
        self.calls = 0

    def exists(self, instance_id):
        self.calls += 1
        return self.calls <= self.alive_polls


def _backend(items, probe, cr_grace=0.0):
    """Return a PeerPodBackend over the fakes, with the fakes themselves."""
    b = PeerPodBackend(namespace="agent-system", image="img@sha256:0", instances=probe, cr_grace=cr_grace)
    core, custom = _FakeCore(), _FakeCustom(items)
    b._api = lambda: (core, custom)                      # noqa: SLF001 (test seam)
    return b, core, custom


CRS = [
    {"metadata": {"name": "runner-td-1-resource-6v2wk"}, "spec": {"instanceID": "podvm-runner-td-1-d2277bd9"}},
    {"metadata": {"name": "runner-td-2-resource-j8n24"}, "spec": {"instanceID": "podvm-runner-td-2-b58d525c"}},
]


class Cleanup(unittest.TestCase):
    """Teardown matches the CR by instance ID and clears it only once the VM is gone."""

    def test_cr_is_matched_by_instance_id_and_cleared_after_vm_is_gone(self):
        probe = _Probe(alive_polls=2)
        with mock.patch("booking_v5.controller_v5.time.sleep", lambda s: None):
            b, core, custom = _backend(CRS, probe)
            b.delete_and_confirm("runner-td-1")
        self.assertEqual(core.deleted, ["runner-td-1"])
        self.assertEqual([n for n, _ in custom.patched], ["runner-td-1-resource-6v2wk"])   # not td-2, not the pod name
        self.assertEqual(custom.patched[0][1], {"metadata": {"finalizers": None}})
        self.assertEqual(probe.calls, 3, "finalizer cleared only once GCE answered 'gone'")
        self.assertIn("runner-td-1", b.destroyed_at)
        self.assertEqual(b.cleanup_mode.get("runner-td-1"), "gce_confirmed_finalizer_cleanup",
                         "the finalizer was dropped after the cloud confirmed the VM gone")

    def test_a_cr_coco_removes_itself_takes_the_normal_path(self):
        """Within the grace period CoCo cleans up on its own.

        No finalizer is touched, the cloud is not asked and cleanup_mode is coco_native.
        """
        probe = _Probe(alive_polls=0)
        b, core, custom = _backend(list(CRS), probe, cr_grace=5.0)
        polls = {"n": 0}
        original = custom.list_namespaced_custom_object

        def vanishing(*a, **kw):                      # the CR disappears on the second poll
            polls["n"] += 1
            return original(*a, **kw) if polls["n"] < 2 else {"items": []}
        custom.list_namespaced_custom_object = vanishing
        with mock.patch("booking_v5.controller_v5.time.sleep", lambda s: None):
            b.delete_and_confirm("runner-td-1")
        self.assertEqual(custom.patched, [])
        self.assertEqual(probe.calls, 0)
        self.assertEqual(b.cleanup_mode.get("runner-td-1"), "coco_native")
        self.assertIn("runner-td-1", b.destroyed_at)

    def test_a_vm_that_does_not_disappear_keeps_its_finalizer(self):
        probe = _Probe(alive_polls=10**9)
        with mock.patch("booking_v5.controller_v5.time.sleep", lambda s: None), \
             mock.patch("booking_v5.controller_v5._DELETE_TIMEOUT", 0.01):
            b, core, custom = _backend(CRS, probe)
            with self.assertRaises(RuntimeError):
                b.delete_and_confirm("runner-td-1")
        self.assertEqual(custom.patched, [])
        self.assertEqual(b.cleanup_mode.get("runner-td-1"), "leaked_vm_failure")
        self.assertNotIn("runner-td-1", b.destroyed_at)

    def test_the_gcp_default_grace_is_zero_and_the_confirmed_path_is_expected(self):
        """On GCP the default grace is 0 and the confirmed-finalizer cleanup is the normal path.

        CAA 0.21.1 peerpod-ctrl has no gcp provider, so CoCo does not clear the CR on GCP. The
        confirmed cleanup is therefore not a recovery. With a CR present and the VM already gone,
        no grace is waited.
        """
        b, core, custom = _backend(CRS, _Probe(alive_polls=0))          # default cr_grace
        self.assertEqual(b.cr_grace, 0.0)
        with mock.patch("booking_v5.controller_v5.time.sleep", lambda s: None):
            b.delete_and_confirm("runner-td-1")
        self.assertEqual(b.cleanup_mode.get("runner-td-1"), "gce_confirmed_finalizer_cleanup")
        self.assertEqual([n for n, _ in custom.patched], ["runner-td-1-resource-6v2wk"])

    def test_no_cr_means_nothing_to_clear(self):
        b, core, custom = _backend([], _Probe(0))
        with mock.patch("booking_v5.controller_v5.time.sleep", lambda s: None):
            b.delete_and_confirm("runner-td-1")
        self.assertEqual(custom.patched, [])
        self.assertEqual(b.cleanup_mode.get("runner-td-1"), "coco_native")   # no CR to clear
        self.assertIn("runner-td-1", b.destroyed_at)


if __name__ == "__main__":
    unittest.main(verbosity=1)
