"""Which counterparty a booking_v4 service process reaches, decided in one function.

Both process entry points of this package (`service_process`, `service_process_tcp`) read the
world from the command line and wire it through `gateway_executor`. A world that is not the
catalogue either produces a live executor or the process refuses to start, so a process
configured for a real counterparty does not come up serving recorded data. The in-cluster
service `booking_v5.service_v5` reads its world from the seeded store and wires it itself
with `booking_live.startup.verify_world`, under the same rule.
"""
from __future__ import annotations

from typing import Any, Callable

from .durable import ExternalWorld

#: The recorded counterparty, the booking_v2 catalogue. Anything else is a live world.
DEFAULT_WORLD = "mock"


class WorldRefused(RuntimeError):
    """The configured world cannot be served, and the caller does not start."""


def live_executor_for(world: str, source: Any = None, transport: Any = None) -> Callable:
    """Return the executor of a live world, without falling back to the catalogue.

    Args:
        world: The counterparty, as named in `booking_live.startup.WORLDS`.
        source: Where the credential comes from, the environment by default and OpenBao in
            the cluster. Tests pass one so they need no credential.
        transport: Tests pass one so the function runs without a network.

    Returns:
        The executor of the live provider.

    Raises:
        WorldRefused: The world is the catalogue or unknown, the credential is missing, or
            `booking_live` is not importable.
    """
    if world == DEFAULT_WORLD:
        raise WorldRefused(f"{world!r} is the catalogue, not a live world")
    try:
        from booking_live.startup import ConfigurationRefused, verify_world
    except ImportError as exc:                       # the services image carries it, a lean one may not
        raise WorldRefused(f"world {world!r} needs booking_live, which is not importable: {exc}") from exc
    try:
        return verify_world(world, source, transport).executor
    except ConfigurationRefused as refused:
        raise WorldRefused(f"world {world!r}: {refused}") from refused


def gateway_executor(world: str, world_db: str | None = None, idempotent: bool = False,
                     source: Any = None, transport: Any = None) -> Callable | None:
    """Return the executor for a `ToolGateway`, or None for the plain catalogue.

    Args:
        world: The counterparty, `DEFAULT_WORLD` for the booking_v2 catalogue.
        world_db: Gives the counterparty its own durable state, so an experiment can
            observe whether an external effect happened even when the service died
            mid-dispatch. The `ExternalWorld` wraps whatever reaches the counterparty,
            live or recorded, and does not replace it.
        idempotent: Let the `ExternalWorld` deduplicate on `durable.idempotency_key`.
        source: Passed to `live_executor_for`.
        transport: Passed to `live_executor_for`.

    Returns:
        The executor, or None when the gateway's default catalogue executor applies.

    Raises:
        WorldRefused: From `live_executor_for`, before anything is opened or served.
    """
    live = None if world == DEFAULT_WORLD else live_executor_for(world, source, transport)
    if world_db:
        durable = (ExternalWorld(db_path=world_db, idempotent=idempotent, executor=live)
                   if live else ExternalWorld(db_path=world_db, idempotent=idempotent))
        return durable.executor
    return live
