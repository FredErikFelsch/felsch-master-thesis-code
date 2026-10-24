"""The production `TdTransport`: the V5 protocol over the Kubernetes `pods/attach` stream.

The controller needs a bidirectional channel into a peer pod whose guest policy forbids
`exec` (`ExecProcessRequest := false`), so the only way in is the container's own
stdin/stdout: `pods/attach` with `stdin: true`. V4 used the same channel for its runner Jobs.
Here it runs through kata-remote and the agent-protocol-forwarder.

The transport carries lines. It cannot read the credential (sealed to the TD's boot key),
cannot forge evidence and cannot substitute the fragment after attestation (the TD re-hashes
the octets). It could replace the sealed session package, because sealing does not
authenticate the sender, but the Authority's re-checks at the grant refuse such a package (see
booking_v4.wire.session_package_to_wire). Within that limit it can be untrusted plumbing
between the controller and the attested guest.

`LineStream` keeps the protocol testable without a cluster: `PipeStream` in the tests speaks
the same three methods as the live websocket.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from booking_v4 import wire

from . import protocol
from .evidence import Evidence
from .runner_bind import Challenge

_ATTACH_TIMEOUT = 120      # seconds to wait for one line from the guest
_POLL = 0.2


class LineStream(Protocol):
    """One newline-delimited duplex channel to a container's stdin/stdout."""

    def write_line(self, line: str) -> None:
        """Send one line to the container's stdin."""
        ...

    def read_line(self) -> str:
        """Block until one line arrives from the container's stdout and return it."""
        ...

    def close(self) -> None:
        """Close the channel."""
        ...


class TransportError(Exception):
    """The channel failed. The run fails with it and no protocol step is skipped."""


@dataclass
class KubernetesAttachStream:
    """`pods/attach` with stdin, through the kubernetes client's websocket helper.

    The production path uses the API the controller itself speaks rather than `kubectl attach`.
    The stream stays open for the whole protocol, because attaching twice would give the runner
    a second stdin and the phase guard would refuse the second challenge.
    """

    namespace: str
    pod: str
    container: str = "runner"
    _stream: object = field(default=None, repr=False)
    _buffer: str = field(default="", repr=False)

    def open(self) -> "KubernetesAttachStream":
        """Attach to the pod's container and keep the stream open."""
        from kubernetes import client
        from kubernetes.stream import stream          # the function, which shares its module's name
        self._stream = stream(client.CoreV1Api().connect_get_namespaced_pod_attach,
                              self.pod, self.namespace, container=self.container,
                              stderr=True, stdin=True, stdout=True, tty=False,
                              _preload_content=False)
        return self

    def write_line(self, line: str) -> None:
        """Write one line to the container's stdin."""
        if self._stream is None:
            raise TransportError("attach stream is not open")
        self._stream.write_stdin(line + "\n")

    def read_line(self) -> str:
        """Block until one complete line arrives on stdout, or time out.

        The websocket delivers arbitrary chunks, so lines are reassembled here. Stderr is
        drained separately and printed on the controller's stdout, outside the line buffer.

        Raises:
            TransportError: no line within `_ATTACH_TIMEOUT` seconds, or the stream closed.
        """
        deadline = time.monotonic() + _ATTACH_TIMEOUT
        while "\n" not in self._buffer:
            if time.monotonic() > deadline:
                raise TransportError(f"no line from {self.pod} within {_ATTACH_TIMEOUT} s")
            self._stream.update(timeout=1)
            if self._stream.peek_stdout():
                self._buffer += self._stream.read_stdout()
            if self._stream.peek_stderr():
                for row in self._stream.read_stderr().splitlines():
                    print(f"[runner-stderr {self.pod}] {row}")
            if not self._stream.is_open() and "\n" not in self._buffer:
                raise TransportError(f"{self.pod} closed its stream before answering")
            time.sleep(_POLL)
        line, _, self._buffer = self._buffer.partition("\n")
        return line

    def close(self) -> None:
        """Close the stream. Teardown is best effort."""
        try:
            if self._stream is not None:
                self._stream.close()
        except Exception:                                   # noqa: BLE001 (teardown is best effort)
            pass


@dataclass
class AttachTransport:
    """`TdTransport` over one `LineStream` per TD.

    `endpoint` and `policy` are deployment-level inputs, not per-fragment ones, and the TD
    receives them in the clear. An endpoint the controller substitutes only misroutes a request
    no real gateway would honour, and the policy is pinned by the digest in the signed envelope
    the TD already holds.

    The trust anchors are not carried here. They are the keys the monitor verifies a state
    envelope and a human approval with. The Authority seals them together with the credential,
    which keeps them from being read or altered in transit but does not authenticate the
    sender. This transport neither holds nor sends them. The `anchors` field is kept for the
    deployment wiring and is not read on this path.
    """

    open_stream: Callable[[str], LineStream]   # td name -> an open LineStream
    anchors: object                        # deployment wiring only, not sent to the TD
    endpoint: object                       # the Authority (V3 grant path)
    policy: object
    intervention: object = None
    gateway_endpoint: object = None        # the gateway's execution surface, None means `endpoint`
    _streams: dict = field(default_factory=dict, repr=False)

    def _stream(self, td: str) -> LineStream:
        if td not in self._streams:
            self._streams[td] = self.open_stream(td)
        return self._streams[td]

    # --- TdTransport ---------------------------------------------------------
    def boot_keys(self, td: str):
        """Open the channel and read the TD's first line, its two public keys.

        The runner speaks only after v5-open, because anything it wrote before the attach went
        to the container log.

        Returns:
            The TD's `binding.RunnerKeys` (pk_boot, pk_sig).
        """
        s = self._stream(td)
        s.write_line(protocol.open_line())
        return protocol.parse_hello(s.read_line())

    def attest(self, td: str, challenge: Challenge) -> Evidence:
        """Send the challenge and read back the TD's evidence."""
        s = self._stream(td)
        s.write_line(protocol.challenge(challenge))
        return protocol.parse_evidence(s.read_line())

    def deliver(self, td: str, sealed: dict, fragment_bytes: bytes, envelope_bytes: bytes):
        """Send the session and the attested octets, then read the one result line.

        Args:
            td: the TD's pod name.
            sealed: the sealed session package.
            fragment_bytes: the attested fragment octets.
            envelope_bytes: the attested envelope octets.

        Returns:
            The runner's result.
        """
        s = self._stream(td)
        s.write_line(protocol.session(sealed, self.endpoint, self.gateway_endpoint))
        s.write_line(protocol.execution(fragment_bytes, envelope_bytes, self.policy, self.intervention))
        result_line = s.read_line()
        return wire.result_from_wire(wire.decode_line(result_line))

    def close(self, td: Optional[str] = None) -> None:
        """Close the stream of one TD, or of all of them."""
        for name in ([td] if td else list(self._streams)):
            stream = self._streams.pop(name, None)
            if stream is not None:
                stream.close()


def kubernetes_attach(namespace: str, container: str = "runner") -> Callable[[str], LineStream]:
    """Return the `open_stream` function of the live path, which opens one attach stream per pod."""
    def _open(td: str) -> LineStream:
        return KubernetesAttachStream(namespace, td, container).open()
    return _open
