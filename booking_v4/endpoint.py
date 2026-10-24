"""ServiceEndpoint: a transport-neutral address for the deployment service.

The process and container backends reach the deployment service by a bare Unix-socket path, which
is fine while runner and service share a host. The Kubernetes runner reaches the Authority and
gateway over a ClusterIP service on TCP. This type is the small abstraction between the two: the
provisioning message carries a ServiceEndpoint {kind, address}, and the runner connects the same
way whether the transport is a UDS or TCP.

It changes how the runner reaches the service, not what the service computes. An attested TLS
channel would attach here, but none is implemented.

`coerce` accepts a bare path string and treats it as a UDS endpoint, so callers that pass a socket
path keep working unchanged.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

from . import wire

_KINDS = ("uds", "tcp")


@dataclass(frozen=True)
class ServiceEndpoint:
    """Where and how to reach the deployment service.

    uds: ``address`` is the socket path. tcp: ``address`` is ``host:port``.
    """

    kind: str
    address: str

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise wire.WireError(f"unknown service endpoint kind {self.kind!r}")
        if not isinstance(self.address, str) or not self.address:
            raise wire.WireError("service endpoint address must be a non-empty string")
        if self.kind == "tcp":
            self._validate_tcp(self.address)

    @staticmethod
    def _validate_tcp(address: str) -> None:
        """Validate host:port at construction rather than at connect().

        Invalid wire input is rejected at once instead of surfacing later as a
        transport failure. Rejects a missing port, an empty host, a port that is
        not ASCII digits and a port outside 1..65535.

        Raises:
            WireError: The address is not a valid host:port.
        """
        host, sep, port = address.rpartition(":")
        if not sep:
            raise wire.WireError("tcp endpoint address must be host:port")
        if not host:
            raise wire.WireError("tcp endpoint host must be non-empty")
        if not (port.isascii() and port.isdigit()):
            raise wire.WireError(f"tcp endpoint port must be an integer, got {port!r}")
        p = int(port)
        if not (1 <= p <= 65535):
            raise wire.WireError(f"tcp endpoint port out of range 1..65535: {p}")

    @classmethod
    def uds(cls, path: str) -> "ServiceEndpoint":
        """Return an endpoint on a Unix domain socket path."""
        return cls("uds", path)

    @classmethod
    def tcp(cls, host: str, port: int) -> "ServiceEndpoint":
        """Return an endpoint on a TCP host and port."""
        return cls("tcp", f"{host}:{port}")

    @classmethod
    def coerce(cls, value) -> "ServiceEndpoint":
        """Return `value` as a ServiceEndpoint. A bare path string becomes a UDS endpoint.

        Raises:
            TypeError: `value` is neither a ServiceEndpoint nor a string.
        """
        if isinstance(value, ServiceEndpoint):
            return value
        if isinstance(value, str):
            return cls("uds", value)
        raise TypeError(f"cannot coerce {type(value).__name__} to ServiceEndpoint")

    def connect(self, timeout: float | None = None) -> socket.socket:
        """Open a connected stream socket to this endpoint."""
        if self.kind == "uds":
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(self.address)
            return sock
        # tcp
        host, port = self.address.rsplit(":", 1)
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        return sock

    def to_wire(self) -> dict:
        """Return the wire form {kind, address}."""
        return {"kind": self.kind, "address": self.address}

    @classmethod
    def from_wire(cls, data) -> "ServiceEndpoint":
        """Decode the wire form, rejecting unknown or missing keys."""
        d = wire.expect_keys(data, {"kind", "address"}, "service endpoint")
        return cls(d["kind"], d["address"])
