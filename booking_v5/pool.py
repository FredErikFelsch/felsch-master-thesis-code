"""Pool: controller-side set of pre-booted, unbound TDs, none of which is used twice.

The pool is substrate-agnostic. A `TdBackend` creates and deletes TDs (peer pods via the
Kubernetes API in V5). The pool hands out no TD twice and does not re-add a bound one. After
a controller restart no handle survives, so `sweep_on_start` deletes every managed TD.

Cold and warm operation share one code path, and the warm pool's idle cost is reported:

    size = 0   cold:  `acquire` creates a TD and waits until it is READY. The wait is
                      returned as `ready_seconds` and lands in `Timings.ready`.
    size = N   warm:  `fill()` pre-boots N unbound TDs. `acquire` hands one out with
                      `ready_seconds = 0.0` (the boot happened before the fragment existed).
                      When the pool is exhausted, `acquire` falls back to a cold create,
                      so a burst does not fail and shows up in the measurements instead.

A binding is identified by (run_id, step, fragment_hash, state_hash), not by the fragment
bytes alone, because the same fragment content may legitimately recur in another run or step.
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Protocol

READY_TIMEOUT = 300.0      # seconds for a cold pod VM to reach READY (85 to 131 s observed)
READY_POLL = 2.0

BindingKey = tuple  # (run_id, step, fragment_hash, state_hash)


class TdBackend(Protocol):
    """The substrate a pool runs on: creates, probes and deletes TDs by name."""

    def create(self) -> str:
        """Ask for a new TD and return its name (the pod name) without waiting for it."""
        ...

    def is_ready(self, name: str) -> bool:
        """Whether the TD has reached READY.

        Raises:
            Exception: the TD is in a terminal failure state.
        """
        ...

    def delete_and_confirm(self, name: str) -> None:
        """Delete the TD and return only once it is gone."""
        ...

    def list_managed(self) -> list:
        """Return the names of the TDs this controller owns (label managed-by)."""
        ...


class PoolError(RuntimeError):
    """A pool invariant would be violated (double binding) or a TD never became ready."""


@dataclass
class TdPool:
    """Pre-booted unbound TDs plus the registry of bound ones."""

    backend: TdBackend
    size: int = 0                                  # 0 = cold path
    ready_timeout: float = READY_TIMEOUT
    _idle: list = field(default_factory=list)
    _bound: dict = field(default_factory=dict)     # name -> BindingKey
    _retired: set = field(default_factory=set)

    # --- lifecycle -----------------------------------------------------------
    def sweep_on_start(self) -> None:
        """Delete every managed TD, because the pool holds no binding state after a restart.

        Raises:
            Exception: the first failed delete, after all others were attempted.
        """
        failed = None
        for name in self.backend.list_managed():
            try:
                self.backend.delete_and_confirm(name)
            except Exception as exc:                      # noqa: BLE001 (one stuck TD must not hide the others)
                failed = failed or exc
        self._idle.clear()
        self._bound.clear()
        if failed is not None:
            raise failed

    def fill(self) -> None:
        """Warm pool: pre-boot up to `size` unbound TDs (no-op for the cold pool).

        Called once at start, by `acquire` on every warm hand-out, and by a caller that wants
        to top the pool up between runs. `backend.create()` does not wait for the machine, it
        only asks for it, so a refill costs the hand-out nothing and the replacement boots
        while the current fragment runs.
        """
        while len(self._idle) < self.size:
            self._idle.append(self.backend.create())

    def drain(self) -> int:
        """Delete every idle (pre-booted, never bound) TD and return how many.

        The controller destroys the warm pool's idle TDs at the end, as it does a bound one.

        Raises:
            Exception: the first failed delete. That TD stays in the idle list.
        """
        n, failed = 0, None
        for name in list(reversed(self._idle)):
            try:
                self.backend.delete_and_confirm(name)
            except Exception as exc:                      # noqa: BLE001 (keep it tracked, go on with the rest)
                failed = failed or exc
                continue
            self._idle.remove(name)
            self._retired.add(name)
            n += 1
        if failed is not None:
            raise failed
        return n

    # --- hand-out ------------------------------------------------------------
    def acquire(self, key: BindingKey) -> tuple[str, float]:
        """Hand out a never-used TD for this binding.

        A warm hand-out takes a READY idle TD with ready_seconds = 0.0. Otherwise (cold pool,
        or warm pool exhausted or none ready yet) a TD is created and awaited.

        A warm hand-out starts its replacement at once, so the replacement boots while the
        current fragment runs. With an acquire every T_warm and a boot time T_boot, a pool of
        ceil(T_boot / T_warm) machines then suffices.

        Returns:
            (name, ready_seconds).

        Raises:
            PoolError: the binding key is already bound, or the TD did not become ready.
        """
        if key in self._bound.values():
            raise PoolError(f"binding already has a TD: {key}")
        for name in list(self._idle):
            try:
                ready = self.backend.is_ready(name)
            except Exception:                             # noqa: BLE001 (a terminal state of an idle TD)
                # A warm TD can hit its activeDeadlineSeconds while the human decides (pod
                # Failed: DeadlineExceeded). Left in the idle list it would fail every later
                # acquire. Evict it, keep looking, and let fill() replace it. A failed delete
                # aborts the acquire.
                self._idle.remove(name)
                try:
                    self.backend.delete_and_confirm(name)
                finally:
                    self._retired.add(name)
                continue
            if ready:
                self._idle.remove(name)
                self._bound[name] = key
                try:
                    self.fill()            # the replacement boots from this moment on
                except Exception as exc:   # noqa: BLE001 (the hand-out stands, the next acquire tops up)
                    # The machine is bound and must reach its caller. Losing it here would leave a
                    # TD that nobody retires. A failed replacement only means a smaller pool.
                    sys.stderr.write(f"[pool] replacement not created: {type(exc).__name__}\n")
                return name, 0.0
        name = self.backend.create()
        t0 = time.monotonic()
        while True:
            try:
                if self.backend.is_ready(name):
                    break
            except Exception as exc:                      # noqa: BLE001 (a terminal boot state, stop waiting)
                self.backend.delete_and_confirm(name)
                self._retired.add(name)
                raise PoolError(f"TD {name} failed to boot after {time.monotonic() - t0:.0f} s (destroyed): {exc}") from exc
            if time.monotonic() - t0 > self.ready_timeout:
                self.backend.delete_and_confirm(name)
                self._retired.add(name)
                raise PoolError(f"TD {name} not READY after {self.ready_timeout:.0f} s (destroyed)")
            time.sleep(READY_POLL)
        self._bound[name] = key
        return name, time.monotonic() - t0

    def retire(self, name: str) -> None:
        """Delete a bound TD after its fragment. It does not return to idle."""
        self._bound.pop(name, None)
        self.backend.delete_and_confirm(name)
        self._retired.add(name)

    def bound_key(self, name: str) -> BindingKey | None:
        """Return the binding a TD is bound to, or None if it is not bound."""
        return self._bound.get(name)

    @property
    def idle(self) -> int:
        """Return the number of pre-booted, unbound TDs, which is the warm pool's idle cost."""
        return len(self._idle)
