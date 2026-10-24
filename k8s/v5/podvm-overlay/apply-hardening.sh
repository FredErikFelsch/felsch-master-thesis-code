#!/usr/bin/env bash
# V5 build-time hardening of the pod-VM rootfs. Two independent fixes, both applied against
# the builder's resources/binaries-tree before `make image`, both with their own gate:
#
#   A5c (ov2)  mask setup-nat-for-imds.service
#   B1  (ov3)  remove the CAA 0.21.1 run-kata-containers.mount, which blocks the sandbox boot
#
# --- A5c: mask setup-nat-for-imds.service so no systemd preset and no unit
# dependency can re-activate the workload-facing IMDS NAT/proxy-ARP path into the pod
# netns. Runs against the builder's resources/binaries-tree, before `make image`.
#
# ov1 only removed the multi-user.target.wants/ enablement symlink. That did not survive:
# the mkosi build (podvm-mkosi/mkosi.images/system/mkosi.skeleton/usr/lib/systemd/
# system-preset/30-coco.preset) carries `enable setup-nat-for-imds.service`, and it is the
# only preset entry for this unit in the whole podvm-mkosi tree. mkosi re-derives .wants/
# symlinks from that preset during `make image`, after this script would have run, which
# is exactly what put the enablement symlink back — a plain "remove the enable symlink" is
# not durable against a preset that says the opposite. A mask (the unit's own definition
# path replaced by a symlink to /dev/null) is systemd's mechanism for this: masked beats
# any preset or dependency, unconditionally.
#
# Only the workload path is affected. setup-nat-for-imds.sh sets up networking for one pod
# netns at a time (After=agent-protocol-forwarder.service); the VM's own root-netns
# bootstrap (process-user-data) never runs through this unit, so it keeps its own IMDS
# access.
set -euo pipefail
ROOT="${1:?rootfs path required}"

# Both fixes are OPTIONAL and OFF by default (ov5). The reason is a bisect, not a change of
# mind: the pre-overlay image boots and runs the full V5 sequence, every overlay image so far
# does not, and the difference has to be narrowed to one change at a time. ov5 is therefore
# the known-good image plus initdata-measure.service and nothing else. Turn a fix on with
#   V5_HARDEN_A5C=1     mask setup-nat-for-imds.service            (A5c, ov8: did not boot)
#   V5_HARDEN_A5C=noop  neutralise setup-nat-for-imds.sh instead   (A5c, ov9)
#   V5_HARDEN_B1=1    remove run-kata-containers.mount  (B1)
# and rebuild under a new PODVM_OVERLAY_REV, so image name and reference values follow.
HARDEN_A5C="${V5_HARDEN_A5C:-0}"
HARDEN_B1="${V5_HARDEN_B1:-0}"
say_skip() { echo "SKIPPED ($1=0): $2"; }

# --- A5c, ov9: V5_HARDEN_A5C=noop — neutralise the SCRIPT, leave the UNIT GRAPH untouched -----
# ov8 (= ov7 + the mask below, nothing else: same CAA commit, same package set) did not boot:
# agent-protocol-forwarder never listened on 15150, the same symptom as ov1..ov4. The unit
# graph does not explain it (nothing Requires= the unit, the build's preset-all only reports
# "is masked, ignoring"), and the guest console is not observable on this image. So this mode
# changes exactly one thing that systemd never sees: /usr/local/bin/setup-nat-for-imds.sh
# becomes a no-op that logs and exits 0. Unit file, preset and enablement stay as CAA ships
# them, the oneshot runs and succeeds, and the NAT/proxy-ARP path into the pod netns is never
# created. Durable for the same reason as the mask: nothing re-derives a script body.
if [ "${HARDEN_A5C}" = "noop" ]; then
  script="${ROOT}/usr/local/bin/setup-nat-for-imds.sh"
  mkdir -p "$(dirname "${script}")"
  rm -f "${script}"
  cat > "${script}" <<'NOOP'
#!/bin/bash
# V5 A5c (ov9): the IMDS NAT/proxy-ARP path into the pod netns is deliberately never set up.
# Unit, preset and enablement are unchanged; only this body is. Exits 0 so the oneshot
# succeeds and the unit graph behaves exactly as on the unhardened image.
echo "setup-nat-for-imds: disabled by the V5 overlay (A5c), nothing to do"
exit 0
NOOP
  chmod 0755 "${script}"
  [ -x "${script}" ] && ! grep -q "iptables" "${script}" && grep -q "V5 A5c" "${script}" || {
    echo "ERROR: setup-nat-for-imds.sh was not neutralised" >&2; exit 1; }
  [ ! -L "${ROOT}/etc/systemd/system/setup-nat-for-imds.service" ] || {
    echo "ERROR: noop mode expects the unit file untouched, found a mask" >&2; exit 1; }
  echo "setup-nat-for-imds.sh neutralised (A5c noop): unit graph unchanged, NAT/proxy-ARP path never set up"
elif [ "${HARDEN_A5C}" = "1" ]; then
service="${ROOT}/etc/systemd/system/setup-nat-for-imds.service"
wants="${ROOT}/etc/systemd/system/multi-user.target.wants/setup-nat-for-imds.service"

# A plain enablement symlink, if present: harmless once masked below, removed for clarity.
rm -f "${wants}"

# The actual fix: mask the unit itself. No preset, no unit dependency, can re-enable a
# masked unit. (`rm` then `ln -s` rather than `ln -sfn`: the flag combination differs
# between GNU and BSD, and this script is also executed by the offline test suite on a Mac.)
rm -f "${service}"
ln -s /dev/null "${service}"

# Informational only, not a gate: other mentions of the unit already present in the tree
# at this point in the build. The systemd preset that enables it (30-coco.preset) is NOT
# part of resources/binaries-tree yet here — mkosi merges its own skeleton, presets
# included, later during `make image` — so finding nothing here is expected, not a sign
# the search missed something.
grep -RIn "setup-nat-for-imds" "${ROOT}/etc/systemd" "${ROOT}/usr/lib/systemd" 2>/dev/null || true

# Build-time postcondition: the mask must have taken. This is the actual gate.
target="$(readlink "${service}" 2>&1 || true)"
[ "${target}" = "/dev/null" ] || {
  echo "ERROR: setup-nat-for-imds.service is not masked (readlink: ${target:-<not a symlink>})" >&2
  exit 1
}
echo "setup-nat-for-imds.service masked (A5c): ${service} -> /dev/null"
else
  say_skip V5_HARDEN_A5C "setup-nat-for-imds.service left as the image ships it"
fi

# --- B1 (ov3): remove run-kata-containers.mount ----------------------------------------
# CAA v0.21.1 ships etc/systemd/system/run-kata-containers.mount, a mount unit whose SOURCE
# directory does not exist in the immutable mkosi image that is actually produced. systemd
# fails the mount, so kata-agent never starts, /run/kata-containers is never created,
# agent.sock never appears, agent-protocol-forwarder never listens, and the CAA's connect to
# 192.168.200.x:15150 runs into its timeout. On the Kubernetes side that arrives as
#     FailedCreatePodSandBox: rpc error: code = DeadlineExceeded
# which is indistinguishable, from the outside, from a TDX, firewall, VXLAN or A5c problem —
# and cost us exactly that search. kata-agent creates /run/kata-containers itself, so the
# unit has no work to do in this image.
#
# DELETED, not masked. A mask keeps the dependency edges alive and every `Requires=` on a
# masked unit still fails; and a preset cannot re-enable a unit that no longer exists, so
# deletion is durable here in a way it was not for setup-nat-for-imds (which mkosi's own
# preset re-enables). Hard dependencies other units declare on it are stripped below, so
# nothing is left requiring a unit that is gone.
# The FILE is not named the way the UNIT is. CAA ships it as
#     podvm/files/etc/systemd/system/run-kata\x2dcontainers.mount
# — four literal characters \x2d where systemd unescapes a hyphen — plus a
# multi-user.target.wants/ symlink under the same escaped name. The unit systemd loads is
# therefore `run-kata-containers.mount`, while `find -name run-kata-containers.mount` matches
# NOTHING. The first ov3 build ran into exactly that and reported "nothing to remove", so the
# search is by glob over both spellings, and directives are matched by the UNESCAPED unit name
# because that is what other units reference.
if [ "${HARDEN_B1}" != "1" ]; then
  say_skip V5_HARDEN_B1 "run-kata-containers.mount left as the image ships it"
  exit 0
fi

mount_unit="run-kata-containers.mount"
mount_glob="run-kata*containers.mount"
mount_esc="run-kata(-|\\\\x2d)containers\\.mount"

# Only search directories that EXIST. `find` and `grep` return non-zero for a missing path,
# and under `set -e` a command substitution assignment inherits that status — which killed
# the first ov4 build silently, right after the two removals, before `make image` ever ran.
# (`resources/binaries-tree` carries etc/systemd but no usr/lib/systemd.) Every assignment
# below additionally ends in `|| true`, so a non-zero search can never abort the build again.
sysd_dirs=()
for d in "${ROOT}/etc/systemd" "${ROOT}/usr/lib/systemd" "${ROOT}/lib/systemd"; do
  [ -d "${d}" ] && sysd_dirs+=("${d}")
done
[ "${#sysd_dirs[@]}" -gt 0 ] || { echo "ERROR: no systemd directory under ${ROOT}" >&2; exit 1; }

removed=0
while IFS= read -r f; do
  rm -f "${f}"
  echo "removed ${f#"${ROOT}"} (${mount_unit})"
  removed=$((removed + 1))
done < <(find "${sysd_dirs[@]}" -name "${mount_glob}" 2>/dev/null || true)
[ "${removed}" -gt 0 ] || echo "NOTE: no ${mount_unit} in this tree (CAA version changed?) — nothing to remove"

# Strip HARD dependencies on the unit and on the mount point. After= and Wants= are left
# alone: both are satisfied trivially by an absent unit, and After= still documents intent.
#
# THREE rules here, each of which cost us a cluster day on 4 September:
#   * `grep -r`, never `-R`: -R FOLLOWS symlinks, and /etc/systemd/system/*.wants/ is nothing
#     but symlinks into ../. The search for "/run/kata-containers" therefore matched
#     multi-user.target.wants/agent-protocol-forwarder.path — whose target contains
#     PathExists=/run/kata-containers/agent.sock.
#   * enablement directories are skipped outright. Nothing in a .wants/ or .requires/ is ever
#     a unit we need to edit; it is systemd's own bookkeeping.
#   * a symlink is never written to. `sed -i` replaces a symlink with a REGULAR FILE, and
#     systemd then says "Wants dependency dropin ... is not a symlink, ignoring" and drops the
#     unit. That is exactly how ov4 lost agent-protocol-forwarder.path, so nothing listened on
#     15150 and every peer pod died in FailedCreatePodSandBox — the symptom B1 was meant to fix.
while IFS= read -r f; do
  case "${f}" in *.wants/*|*.requires/*) continue ;; esac
  if [ -L "${f}" ]; then
    echo "NOTE: ${f#"${ROOT}"} is a symlink — not touching it (systemd bookkeeping)"
    continue
  fi
  before="$(cat "${f}")"
  # No `sed -i`: GNU takes the suffix as an optional argument, BSD requires one, so
  # `sed -i -E` silently means "-E is the backup suffix" on a Mac. Write through a temporary
  # file, which behaves the same everywhere and cannot replace the file's identity.
  tmp="$(mktemp)"
  sed -E \
    -e "/^(Requires|Requisite|BindsTo)=/ s/([=[:space:]])${mount_esc}([[:space:]]|\$)/\1/g" \
    -e "/^RequiresMountsFor=/ s#([=[:space:]])/run/kata-containers(/[^[:space:]]*)?([[:space:]]|\$)#\1#g" \
    -e "/^(Requires|Requisite|BindsTo|RequiresMountsFor)=/ s/=[[:space:]]+/=/" \
    -e "/^(Requires|Requisite|BindsTo|RequiresMountsFor)=[[:space:]]*\$/d" \
    "${f}" > "${tmp}"
  if cmp -s "${f}" "${tmp}"; then
    rm -f "${tmp}"
  else
    cat "${tmp}" > "${f}"      # keep the original inode, owner and mode
    rm -f "${tmp}"
    echo "stripped hard dependency on ${mount_unit} from ${f#"${ROOT}"}"
  fi
done < <(grep -rIl -e "run-kata-containers.mount" -e 'run-kata\\x2dcontainers.mount' -e "/run/kata-containers" \
           "${sysd_dirs[@]}" 2>/dev/null || true)

# Nothing in an enablement directory may have stopped being a symlink.
broken="$(find "${sysd_dirs[@]}" \( -path "*.wants/*" -o -path "*.requires/*" \) -type f 2>/dev/null || true)"
[ -z "${broken}" ] || {
  echo "ERROR: enablement entries are regular files, systemd will ignore them: ${broken}" >&2
  exit 1
}

# Build-time postconditions: the unit is gone and nothing hard-requires it any more.
still="$(find "${sysd_dirs[@]}" -name "${mount_glob}" 2>/dev/null || true)"
[ -z "${still}" ] || { echo "ERROR: ${mount_unit} still present: ${still}" >&2; exit 1; }
dangling="$(grep -RIl -E "^(Requires|Requisite|BindsTo)=.*${mount_esc}" "${sysd_dirs[@]}" 2>/dev/null || true)"
[ -z "${dangling}" ] || { echo "ERROR: units still hard-require ${mount_unit}: ${dangling}" >&2; exit 1; }
echo "${mount_unit} removed (B1): sandbox boot no longer waits on a mount whose source does not exist"
