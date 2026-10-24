"""Attack harnesses that are kept out of every measured artefact.

Dockerfile.k8s builds the runner image and copies `booking_v0` to `booking_v5` only. Nothing
in this package reaches a confidential machine, and a change here does not move
`RUNNER_SOURCE_SHA256` or force a guest rebuild. Dockerfile.services copies it, because the
transport proxy of `transport_proxy.py` runs beside the gateway, in the network position the
attacker model grants a host beneath a runner.

The attacker stays out of the measured image for a reason. A harness hook inside the gateway
would build the very capability the observation check is meant to catch, and the result would
then say nothing about an outside attacker.
"""
