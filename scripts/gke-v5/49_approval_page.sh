#!/usr/bin/env bash
# 49_approval_page.sh: forwards the Authority's approval page to the person who approves.
#
# Needs:  kubectl with the admin context as the current context (or ADMIN_CONTEXT), and an Authority
#         running behind the approval gate.
# Usage:  scripts/gke-v5/49_approval_page.sh          # keep it running, open http://localhost:8450/
# Result: A port-forward to the Authority's approval surface (8450) until Ctrl-C. It runs under the
#         admin context and refuses v5-controller. The page is served by the Authority and the
#         passkey is scoped to this origin (http://localhost:8450, rp id localhost).
#
# It refuses to start when 8450 is already taken. Whoever holds that port serves the page on
# the passkey's origin: a process of the operator machine that got there first could show
# one object and fetch the challenge for another, and the passkey could not tell the two
# apart. This check is the operational half of that residual risk of the approval design.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
PORT=8450
CTX="${ADMIN_CONTEXT:-$(kubectl config current-context)}"
[ "${CTX}" != "v5-controller" ] || die "the current context is the controller. The approval page runs under the admin context"
if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
    lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN || true
    die "port ${PORT} is already taken. Stop that process first (it would serve the approval origin)"
fi
kubectl --context "${CTX}" -n agent-system rollout status deployment/authority --timeout=60s >/dev/null \
    || die "the Authority is not ready"
kubectl --context "${CTX}" -n agent-system logs deployment/authority | grep "approval-gate\] installed" >/dev/null \
    || die "the Authority runs without the approval gate"
say "approval page: http://localhost:${PORT}/   (context ${CTX}, Ctrl-C closes it)"
exec kubectl --context "${CTX}" -n agent-system port-forward --address 127.0.0.1 deployment/authority "${PORT}:${PORT}"
