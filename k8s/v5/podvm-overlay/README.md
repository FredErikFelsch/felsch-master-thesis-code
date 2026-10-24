# V5 pod-VM overlay

`11_build_podvm_image.sh` copies this overlay into mkosi's `resources/binaries-tree` (on top of
CAA's `podvm/files`) before `make image`, so the result is still a function of (CAA tag, this
overlay, the patches in `k8s/v5/podvm-patches/`). The sha256 of the overlay (all files, sorted,
README.md excluded) and of the patches is recorded in the image provenance and in the image
description. A change here is a change to what the image measures.

    usr/local/bin/initdata-measure                       measures /run/peerpod/initdata.digest into RTMR3 (AAEL encoding)
    etc/systemd/system/initdata-measure.service          oneshot, after process-user-data, before every agent
    etc/systemd/system/multi-user.target.wants/initdata-measure.service
                                                         shipped enablement symlink
    usr/lib/systemd/system-preset/20-v5.preset           `enable initdata-measure.service`: survives the build's preset-all
    etc/systemd/system/{attestation-agent,kata-agent}.service.d/10-v5-measure.conf
                                                         Wants=/After= initdata-measure (no Requires=): the agents
                                                         pull the measurement in and wait for it
    apply-hardening.sh (build-time only, not in the image: 11 runs it against
                        resources/binaries-tree and excludes it from what gets extracted there)
                                                         A5c: keeps the metadata server away from the workload.
                                                         B1:  removes run-kata-containers.mount and every hard dependency
                                                         on it. Behaviour covered by booking_v5/tests_podvm_overlay.py.

Expected RTMR3 history that the Authority replays:
`[ "v5 init-data <digest>", "v5 boot-key <…>", "v5 bind <…>" ]`.

The revision in the image name (`podvm-fedora-tdx-caa-0-21-1-ov<rev>`) is `PODVM_OVERLAY_REV`
in `scripts/gke-v5/_config.sh`. Every change to the overlay, to the hardening defaults or to the
patches bumps it, so the image name and the reference values change together. An image name is
not reused for different content (11 builds nothing when the image already exists). To build a differently named image on demand, set
`PODVM_IMAGE_BUILD` when calling 11.

## Hardening switches

`apply-hardening.sh` reads two switches, exported by `_config.sh` with these defaults:

    V5_HARDEN_A5C=noop   neutralise setup-nat-for-imds.sh  (A5c)
    V5_HARDEN_B1=1       remove run-kata-containers.mount  (B1)

`11_build_podvm_image.sh` refuses any other combination unless `V5_ALLOW_UNHARDENED=1` is set.
Without a default, an image could be built without the hardening unnoticed, and A5c (the pod
VM's metadata server reachable from the TD) would be open again.

## Why the overlay looks like this

**The guest does not gate itself.** The overlay is minimal: one measurement unit and ordering
edges, with `Wants=` and `After=` on the agents and no `Requires=` on any of them. A missing
measurement is supposed to fail closed in the Authority (RTMR3 does not replay, the evidence is
refused with `V5_RTMR3_MISMATCH`), not in the guest's unit graph. Gating the agent stack could
only break the boot, without making the claim stronger.

**A unit that is present but never started is invisible.** A TD that measured nothing passes
P2 and P3 and looks healthy. Only the Authority's replay notices. This is the failure mode the
design has to survive, and it is why three independent anchors pull the unit in.

1. `usr/lib/systemd/system-preset/20-v5.preset` survives the build's `preset-all`. Fedora's
   `99-default-disable.preset` (`disable *`) removes the `multi-user.target.wants` symlink of
   every unit with an `[Install]` section that no preset enables.
2. The `multi-user.target.wants/initdata-measure.service` symlink is shipped in the overlay.
   `systemctl preset` cannot repair it at boot, because the root is squashfs under dm-verity
   and the preset run fails with "Read-only file system".
3. The `Wants=`/`After=` drop-ins on `attestation-agent` and `kata-agent` are untouched by
   presets and cannot break the boot.

11 gates on the tree before `make image` and on the built image. For the built image it mounts
`build/system.raw` and checks the script, the unit, the enablement symlink, the preset and the
drop-ins. The `wants` listing of the image goes into the provenance.

**A5c needs a durable mechanism.** GCP peer pods need the metadata server only in the VM root
network namespace (`process-user-data`), not inside the container. The service
`setup-nat-for-imds.service` sets up NAT and proxy ARP into the pod network namespace. Two
mechanisms that look obvious do not work. Removing its enablement symlink does not hold,
because mkosi's own preset (`podvm-mkosi/.../system-preset/30-coco.preset`:
`enable setup-nat-for-imds.service`, the only preset entry for this unit) re-creates the
symlink during `make image`, after the overlay step. Masking the unit (a symlink to `/dev/null`
at its own path, `V5_HARDEN_A5C=1`) beats every preset, but an image built that way did not
boot: `agent-protocol-forwarder` never listened on 15150. The default `noop` mode therefore
replaces the body of `/usr/local/bin/setup-nat-for-imds.sh` with a script that logs and exits
0. Unit file, preset and enablement stay as CAA ships them, the oneshot runs and succeeds, and
the NAT and proxy-ARP path into the pod network namespace is not created. Nothing re-derives
a script body, so this is durable. 11 checks the built image: the script is ours and the unit
is not masked. The expected result in `19_probe_network.sh` is BLOCKED
`169.254.169.254:80` in the peer-pod group, the same as in the regular-pod group.

**B1: a mount unit that blocks the sandbox boot.** CAA v0.21.1 ships a mount unit for
`/run/kata-containers`, but its source directory does not exist in the immutable mkosi image.
systemd fails the mount, so `kata-agent` does not start, `/run/kata-containers` is not created,
`agent.sock` does not appear, `agent-protocol-forwarder` does not listen, and the CAA's connect
to `:15150` times out. On the Kubernetes side this arrives as
`FailedCreatePodSandBox: DeadlineExceeded`, which is indistinguishable from a TDX, VXLAN,
firewall or A5c fault. `kata-agent` creates the directory itself, so the unit has no work to do
here. The unit is deleted, not masked. A mask keeps the dependency edges, so every `Requires=`
on a masked unit still fails, while a preset cannot re-enable a unit that no longer exists.
Hard dependencies (`Requires=`, `Requisite=`, `BindsTo=`, `RequiresMountsFor=/run/kata-containers`)
are stripped from the units that declared them. `After=` and `Wants=` are left, since an absent
unit satisfies both. The removal has four traps, and `apply-hardening.sh` handles each of them.

- CAA ships the file as `podvm/files/etc/systemd/system/run-kata\x2dcontainers.mount`, with four
  literal characters `\x2d` where systemd unescapes a hyphen. The unit that systemd loads is
  `run-kata-containers.mount`, so a search for that exact name matches nothing and reports
  "nothing to remove" while shipping the defect. The search is by glob over both spellings, and
  directives are matched by the unescaped unit name, which is what other units reference.
- `grep -R` follows symlinks, and `/etc/systemd/system/*.wants/` is nothing but symlinks into
  `../`. A search for `/run/kata-containers` then matches
  `agent-protocol-forwarder.path`, whose `PathExists=/run/kata-containers/agent.sock` is not
  a dependency to remove. The removal step uses `grep -r`. (The final check for remaining hard
  dependencies still uses `grep -R`. That changes only with the next overlay revision.)
- `sed -i` replaces a symlink with a regular file. systemd then logs "Wants dependency dropin
  … is not a symlink, ignoring" and drops the unit. The forwarder's path unit would never
  become active and nothing would listen on 15150. So enablement directories are skipped
  outright, a symlink is not written to, and a gate fails the build if any `.wants/` or
  `.requires/` entry has stopped being a symlink.
- `find` and `grep` return non-zero for a missing path, and under `set -e` a command
  substitution inherits that status. Only existing directories are searched, and every search
  ends in `|| true`.

**The RTMR3 extend is one 48-byte write.** The RTMR3 attribute accepts 48 bytes at offset 0
and nothing shorter. bash writes its builtin `printf` through line-buffered stdio, so a `0x0a` byte
inside the digest flushes the buffer and the single logical write becomes two `write()`
syscalls. The first, short write is refused with `EINVAL`, and the second never gets a chance.
The byte count is right, so counting bytes does not find the defect. Across the recorded
boots, every failure and only the failures had an event digest with a `0x0a` before its last
byte. `initdata-measure` therefore assembles the 48 bytes in a file on tmpfs,
asserts the size and lets `dd bs=48 count=1` perform one read and one write. The extend is
retried (`INITDATA_MEASURE_EXTEND_ATTEMPTS`, default 20, `INITDATA_MEASURE_EXTEND_DELAY`,
default 0.2 s), because `TDG.MR.RTMR.EXTEND` is serialised by the TDX module and a concurrent
RTMR operation can return BUSY.

**The producer of the digest is patched.** `process-user-data` used to discard a transient
metadata-provider failure, skip the cloud config and still report success for a run that wrote
nothing. `k8s/v5/podvm-patches/0001-bounded-provider-retry.patch` makes it retry the provider
detection until the context deadline (`--user-data-fetch-timeout`, 180 s by default). As defence
in depth, `initdata-measure` waits up to `INITDATA_MEASURE_WAIT` seconds (default 30) for both
preconditions, a writable RTMR3 attribute and a non-empty digest file. A timeout still refuses:
an unmeasured TD stays unusable for the Authority.

**A refusal always has a reason.** The journal of a pod VM cannot be reached from anywhere.
Exec is denied by the measured policy, a hostPath on a peer pod is the worker's filesystem, and
kata passes no `kernel_params` to a peer pod, so the journal cannot be mirrored to the console
from the host. `initdata-measure` therefore also writes to `/dev/kmsg` with the `<3>` (KERN_ERR)
prefix, so the message survives the default console loglevel and lands on the serial console,
which `18_probe_peer_pod.sh` records for every boot.
