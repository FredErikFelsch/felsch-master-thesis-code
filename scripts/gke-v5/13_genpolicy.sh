#!/usr/bin/env bash
# 13_genpolicy.sh: generates the freeze policy for the runner pod.
#
# Needs:  The image digest file (DIGEST_FILE, written by ../gke/20_build_push_images.sh), python3
#         with pyyaml and the booking_v5 package, and genpolicy through _genpolicy.sh.
# Usage:  ./scripts/gke-v5/13_genpolicy.sh
# Result: k8s/v5/init-data/policy.rego with the placeholder ${RUNNER_IMAGE} in place of the pinned
#         digest. The last output line is the init-data sha256 of the freeze.
#
# The policy is generated for the runner pod as the controller launches it (namespace
# agent-system, fixed profile). Its sha256 flows into the init-data hash the relying party pins.
# Probe runs (18) generate their own policy for their own manifest via _genpolicy.sh.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
[ -f "${DIGEST_FILE}" ] || die "no ${DIGEST_FILE}: build the image first (../gke/20_build_push_images.sh)"
source "${DIGEST_FILE}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
python3 - "${RUNNER_IMAGE}" "${tmp}/runner-pod.yaml" <<'PY'
import sys, yaml
from booking_v5.profile_v5 import build_runner_pod_manifest
from booking_v5.profile_v5 import RUNNER_GENERATE_NAME
# generateName, as the controller creates its pods: genpolicy then pins the sandbox name as
# ^runner-td-[...]+$ and one policy covers every TD (a fixed name would pin that name).
m = build_runner_pod_manifest(image=sys.argv[1], namespace="agent-system", generate_name=RUNNER_GENERATE_NAME)
m["metadata"]["annotations"] = {}          # the policy travels in init-data, not as an annotation
yaml.safe_dump(m, open(sys.argv[2], "w"))
PY
"$(dirname "${BASH_SOURCE[0]}")/_genpolicy.sh" "${tmp}/runner-pod.yaml" "${V5_K8S_DIR}/init-data/policy.rego"
# The template keeps the placeholder. profile_v5.init_data_document renders the pinned digest
# back in, byte for byte, so the digest printed below is the one the guest measures.
python3 - "${V5_K8S_DIR}/init-data/policy.rego" "${RUNNER_IMAGE}" <<'PYX'
import sys
path, image = sys.argv[1], sys.argv[2]
s = open(path).read()
n = s.count(image)
open(path, "w").write(s.replace(image, "${RUNNER_IMAGE}"))
print(f"[v5] policy template: {n} image reference(s) replaced by ${{RUNNER_IMAGE}}")
PYX
grep -n 'io.kubernetes.cri.sandbox-name' "${V5_K8S_DIR}/init-data/policy.rego" | head -2
say "init-data sha256 for the freeze = $(python3 -c "
from booking_v5.profile_v5 import init_data_document, init_data_hash; import sys
print(init_data_hash(init_data_document(sys.argv[1])))" "${RUNNER_IMAGE}")"
