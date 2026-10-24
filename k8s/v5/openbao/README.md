# The live world in the cluster: credential store, network, evidence

Everything here is additive. Without it the deployment uses the V2 catalogue behind the
same gateway, and every recorded run stays valid. Applying it changes one thing: which
counterparty the gateway reaches.

## The order

The whole run is unchanged up to the deploy. The live path is two scripts after it, and
the numbering says so: `37` and `38` come after `30`.

```
  00 preflight → 12 cluster → 15 caa values → 14 coco → 40 verify
     → 13 genpolicy → 41 a19 → 23 services image → 30 deploy
       → 37 credential store        <- live world only
       → 38 negative evidence       <- live world only
         → 40 verify → 36 observation → 31 run → 32 negative → …
```

`37` has to come after `30` for two reasons: the seeder writes the world into both
stores during the deploy, and `37` patches a gateway that must already exist. Both scripts
are idempotent.

The simplest way is the full run, which skips the live path entirely when
`BOOKING_WORLD` is unset:

    export BOOKING_WORLD=duffel
    export DUFFEL_TOKEN=duffel_test_…          # never written to a file by these scripts
    export PCS_API_KEY=…                       # as always
    caffeinate -ims ./scripts/gke-v5/99_full_run_v5.sh

On one line, the assignments go before `caffeinate`. It runs its first argument as a
command, so anything between it and the script is taken for a program name:

    BOOKING_WORLD=duffel DUFFEL_TOKEN=duffel_test_… KEEP_CLUSTER=1 \
        caffeinate -ims ./scripts/gke-v5/99_full_run_v5.sh

Or by hand, against a cluster that is already up:

    export BOOKING_WORLD=duffel DUFFEL_TOKEN=duffel_test_…
    scripts/gke-v5/30_deploy_v5.sh
    scripts/gke-v5/37_install_openbao.sh
    scripts/gke-v5/38_negative_live_v5.sh

To go back, seed a fresh pair of stores with `BOOKING_WORLD=mock` and delete
`gateway-live-egress`. The world cannot be changed on existing stores: they already
carry runs, facts and a ledger that were produced against the world they were seeded
with, and `service_v5 init` refuses to move them.

## The files

| file | what it is |
|---|---|
| `openbao.yaml` | the store, its ServiceAccount, and the TokenReview binding |
| `networkpolicy-live.yaml` | the gateway's egress and the store's own edge |
| `gateway-live-patch.yaml` | the projected token and the `BAO_*` variables |

`k8s/v5/services/networkpolicy.yaml` is untouched. NetworkPolicies are additive, so the
network diff between the mock deployment and the live one is `networkpolicy-live.yaml`, and
the evaluation can point at that one file.

## Three precise statements

**The gateway still has `automountServiceAccountToken: false`.** It receives no
general-purpose Kubernetes API credential. What it receives is one projected token, bound
to the audience `openbao` and valid for an hour. A token issued for one audience cannot
be replayed against the Kubernetes API, so this grants strictly less than switching
automounting back on.

**The network cannot name a provider.** A NetworkPolicy selects pods, namespaces and CIDR
blocks. `api.duffel.com` is not expressible. So the network grants HTTPS in general, with
every private range carved out by `except`, and which provider may be reached is the
gateway's own allow-list in `booking_live.world`. The network layer is not described as
confining the provider.

**OpenBao is storage, not a mediator.** The gateway reads its credential once, at
start-up, and holds it. A provider call therefore does not appear as a secret read in the
audit log.

## Dev mode

The server runs in development mode: in memory, unsealed at start, root token from a
Secret. Restart it and the stored secrets are gone. Re-run `37` and they are back. That
is enough to demonstrate where a credential lives, and not suitable for anything else.

## What is not here

The runner. It has no ServiceAccount token, no OpenBao role and no egress to OpenBao or to
the internet (its only routes are the Authority, the gateway's execution port and DNS), so
there is nothing to deny it and no rule to maintain. `38_negative_live_v5.sh` shows this from
the runner's own network position, with the runner's own identity.
