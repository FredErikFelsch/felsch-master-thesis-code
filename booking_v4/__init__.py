"""Deployment backends for the booking protocol.

Nothing here changes what the protocol computes, only where it runs. The package holds the wire
contract (canonical JSON, versioned, strict, no pickle), the Authority and gateway service boundary,
and the backends that run one runner per fragment: an OS process, a hardened container or a
Kubernetes Job. The untrusted execution input (fragment, envelope, policy) and the trusted
provisioning input (anchors, endpoints, session credential) travel on separate channels. The
booking_v3 scenario matrix runs unchanged against each backend through
booking_v3.scenarios.set_deployment_factory.
"""

__all__ = ["wire", "services", "runner_process", "process_backend", "experiment"]
