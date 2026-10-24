#!/usr/bin/env bash
# _peerpod_cleanup.sh: shared cleanup for peer pods that an earlier run left behind.
#
# Needs:  _config.sh already sourced (say, die, PROJECT), kubectl and gcloud.
# Usage:  Sourced by 14 and 91. Call clear_stale_peer_pods.
# Result: Terminal kata-remote pods deleted, and the finalizers of PeerPod CRs without a pod and
#         without a VM removed. Live peer pods are reported and not touched.
#
# Why this is its own file: the CAA's startup probe is node-wide. It walks every
# kata-remote pod on the node and answers HTTP 500 while a single one of them is not
# Ready, so one pod in PodFailed keeps the DaemonSet out of Ready for as long as the
# object exists, and `rollout status` in 14 then burns its full 600 s timeout without
# saying why. Eleven stale probe CRs, or one failed runner-td in agent-system, are enough.
# The probe-namespace cleanup in 14 does not cover the second case, because it only knows
# v5-probe, v5-netprobe and v5-netprobe-open.
#
# The rule below is the one booking_v5/controller_v5.py already applies, not a second one:
#   * a PeerPod CR belongs to the pod named in its `spec.instanceID` (podvm-<pod>-<hash>),
#     not to the CR's own name, which is <pod>-resource-<random>,
#   * a finalizer is ballast only once GCE confirms the instance is gone. While a VM still
#     exists the finalizer is doing its job, and removing it orphans a running c3 TDX
#     instance that nobody will clean up.
#
# Only pods in a terminal phase are removed. A Running or Pending peer pod belongs to a
# live run and is not touched. It is reported instead, because it is the one case in
# which waiting is the correct answer.

peerpod_terminal_pods() {
    # "<namespace> <name>" per line, for every kata-remote pod in a terminal phase.
    { kubectl get pods -A -o jsonpath='{range .items[?(@.spec.runtimeClassName=="kata-remote")]}{.metadata.namespace}{" "}{.metadata.name}{" "}{.status.phase}{"\n"}{end}' 2>/dev/null || true; } |
        awk '$3=="Failed" || $3=="Succeeded" {print $1" "$2}'
}

peerpod_live_pods() {
    # "<namespace> <name>" per line, for every kata-remote pod that is not terminal.
    { kubectl get pods -A -o jsonpath='{range .items[?(@.spec.runtimeClassName=="kata-remote")]}{.metadata.namespace}{" "}{.metadata.name}{" "}{.status.phase}{"\n"}{end}' 2>/dev/null || true; } |
        awk '$3!="Failed" && $3!="Succeeded" {print $1" "$2}'
}

peerpod_all_crs() {
    # "<namespace> <cr name> <instanceID>" per line, across every namespace.
    { kubectl get peerpods.confidentialcontainers.org -A \
        -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{.spec.instanceID}{"\n"}{end}' 2>/dev/null || true; }
}

clear_stale_peer_pods() {
    local ns name crname inst pod left

    say "cleanup: kata-remote pods an earlier run left in a terminal phase"
    while read -r ns name; do
        [ -n "${name}" ] || continue
        say "  ${ns}/${name}: terminal, deleting (it holds the CAA startup probe at 500)"
        kubectl -n "${ns}" delete pod "${name}" --wait=false >/dev/null 2>&1 || true
    done < <(peerpod_terminal_pods)

    # A peer pod whose sandbox never came up has nothing to unwind and stays Terminating,
    # so wait a bounded 60 s and then force what is left. Its VM is picked up below.
    for _ in $(seq 1 30); do
        [ -z "$(peerpod_terminal_pods)" ] && break
        sleep 2
    done
    while read -r ns name; do
        [ -n "${name}" ] || continue
        say "  ${ns}/${name}: still Terminating after 60 s, force-removing"
        kubectl -n "${ns}" delete pod "${name}" --grace-period=0 --force >/dev/null 2>&1 || true
    done < <(peerpod_terminal_pods)

    say "cleanup: PeerPod CRs with no pod and no VM"
    while read -r ns crname inst; do
        [ -n "${crname}" ] || continue
        pod="${inst#podvm-}"; pod="${pod%-*}"
        if [ -n "${pod}" ] && kubectl -n "${ns}" get pod "${pod}" >/dev/null 2>&1; then
            continue                                   # the owning pod is still there
        fi
        if [ -n "${inst}" ] && gcloud compute instances list --project "${PROJECT}" \
              --filter="id=${inst} OR name=${inst}" --format='value(name)' 2>/dev/null | grep -q .; then
            say "  ${ns}/${crname}: pod VM ${inst} still exists, leaving the finalizer alone"
            continue
        fi
        say "  ${ns}/${crname}: no pod, no VM for ${inst:-<none>}, removing the finalizer"
        kubectl -n "${ns}" patch peerpods.confidentialcontainers.org "${crname}" \
            --type=merge -p '{"metadata":{"finalizers":null}}' >/dev/null 2>&1 || true
        kubectl -n "${ns}" delete peerpods.confidentialcontainers.org "${crname}" \
            --wait=false >/dev/null 2>&1 || true
    done < <(peerpod_all_crs)

    # Anything left is a live peer pod. If the CAA rollout still hangs afterwards, these pods
    # are the reason, and deleting them here would kill a run.
    left="$(peerpod_live_pods)"
    if [ -n "${left}" ]; then
        say "note: live peer pods remain (not touched), the CAA probe waits for them:"
        printf '%s\n' "${left}" | sed 's/^/  /'
    fi
}
