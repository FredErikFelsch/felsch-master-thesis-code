#!/usr/bin/env python3
"""A fake `gcloud` and `kubectl` for the offline tests of scripts/gke-v5/12_create_cluster_v5.sh.

It dispatches on argv[0] and on the command words, logs every invocation to $FAKE_LOG (one
tab-separated line each, in order) and answers from the scenario in $FAKE_STATE. It knows
only the calls 12_create_cluster_v5.sh makes. Anything else is answered "ok" and shows up in
the log, so a new call in the script cannot pass unnoticed, because the tests assert on the
log.

This is not a cloud simulator. It answers three questions that would otherwise cost real
money and cluster time: in which order the script touches things, whether it reconciles what
already exists, and whether it aborts on a drift it cannot repair.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

# The node version the frozen policy pins (scripts/gke-v5/_node_pin.sh). The fake pool runs it by default.
NODE_VERSION = os.environ.get("V5_NODE_VERSION", "1.35.8-gke.1225000")

STATE = json.loads(pathlib.Path(os.environ["FAKE_STATE"]).read_text())
LOG = pathlib.Path(os.environ["FAKE_LOG"])


def log(argv: list[str]) -> None:
    """Append one invocation to $FAKE_LOG as a tab-separated line."""
    with LOG.open("a") as fh:
        fh.write("\t".join(argv) + "\n")


def out(text: str = "") -> None:
    """Print `text` (if any) and exit 0, as a successful call."""
    if text:
        print(text)
    sys.exit(0)


def missing() -> None:
    """Exit 1 with gcloud's not-found shape, as for a resource that does not exist."""
    print("ERROR: (fake) resource not found", file=sys.stderr)
    sys.exit(1)


def fmt(args: list[str]) -> str:
    """Return the `--format...` argument, or an empty string."""
    for a in args:
        if a.startswith("--format"):
            return a
    return ""


def main() -> None:
    """Log the call and answer it from $FAKE_STATE. Every branch ends the process."""
    argv = sys.argv
    log([pathlib.Path(argv[0]).name] + argv[1:])
    tool = pathlib.Path(argv[0]).name
    a = argv[1:]
    if tool == "kubectl":
        out("node-1" if "jsonpath={.items[*].metadata.name}" in " ".join(a) else "")
    w = [x for x in a if not x.startswith("--")]
    f = fmt(a)

    if w[:3] == ["config", "get-value", "project"]:
        out(STATE.get("project", "test-project"))
    if w[:1] == ["services"] or w[:1] == ["projects"]:
        out()
    if w[:2] == ["iam", "service-accounts"]:
        out()

    if w[:2] == ["container", "clusters"]:
        if w[2] == "describe":
            if "json" in f:
                out(json.dumps(STATE.get("cluster_json", {})))
            if "status" in f:
                out("RUNNING")
            if "value(network)" in f:
                out(STATE.get("network", "default"))
            if "subnetwork" in f:
                out("projects/p/regions/r/subnetworks/" + STATE.get("node_subnet", "default"))
            out()
        out()
    if w[:2] == ["container", "get-server-config"]:
        # The pinned node version is offered in the REGULAR channel. _node_pin.sh reads both
        # the channel lists and the top-level list, and a test may narrow either.
        out(json.dumps({
            "validNodeVersions": STATE.get("valid_node_versions", ["1.35.9-gke.100000"]),
            "channels": [{"channel": "REGULAR",
                          "validVersions": STATE.get("channel_node_versions", [NODE_VERSION])}]}))
    if w[:2] == ["container", "node-pools"]:
        if w[2] == "describe":
            if "default-pool" in w:
                missing()
            if "serviceAccount" in f:
                out(STATE.get("pool_sa", "peerpods@test-project.iam.gserviceaccount.com"))
            if "oauthScopes" in f:
                out("https://www.googleapis.com/auth/cloud-platform")
            if "value(version)" in f:
                out(STATE.get("pool_version", NODE_VERSION))
            out()
        out()

    if w[:3] == ["compute", "networks", "subnets"]:
        # compute networks subnets <verb> <name>
        name = w[4] if len(w) > 4 else ""
        if w[3] == "describe":
            if name == STATE.get("node_subnet", "default"):
                out(STATE.get("node_cidr", "10.164.0.0/20"))
            sn = STATE.get("subnet")
            if sn is None:
                missing()
            out(f"{sn['cidr']} {sn['network']} {sn['pga']}")
        out()

    if w[:2] == ["compute", "ssh"]:
        out()

    if w[:2] == ["compute", "firewall-rules"]:
        # compute firewall-rules <verb> <name>
        name = w[3] if len(w) > 3 else ""
        if w[2] == "describe":
            rule = STATE.get("fw_rules", {}).get(name)
            if rule is None:
                missing()
            out(rule.get("direction", "INGRESS") if "direction" in f else "")
        out()

    if w[:2] == ["compute", "network-firewall-policies"]:
        if w[2] == "describe":
            if not STATE.get("policy"):
                missing()
            # The real `gcloud ... describe` shows existing associations as fields of the
            # firewall policy. The script uses this to decide whether an association already
            # exists, because `associations list` is not a supported command.
            if "yaml" in f:
                associations = STATE.get("associations", [])
                if not associations:
                    out("associations: []")
                lines = ["associations:"]
                for assoc in associations:
                    # Scenarios may store only the association name.
                    if isinstance(assoc, str):
                        name = assoc
                        network = STATE.get("network", "default")
                        project = STATE.get("project", "test-project")
                        target = ("https://www.googleapis.com/compute/v1/"
                                  f"projects/{project}/global/networks/{network}")
                    else:
                        name = assoc["name"]
                        target = assoc["attachmentTarget"]
                    lines.append(f"- attachmentTarget: {target}")
                    lines.append(f"  name: {name}")
                out("\n".join(lines))
            out()
        if w[2] == "rules":
            # ... rules <verb> <priority>
            prio = w[4] if len(w) > 4 else ""
            if w[3] == "describe":
                rule = STATE.get("policy_rules", {}).get(prio)
                if rule is None:
                    missing()
                out(rule.get("direction", "EGRESS") if "direction" in f else "")
            out()
        if w[2] == "associations":
            # There is no fake `associations list`, so the script has to detect existing
            # associations through the policy describe.
            out()
        out()

    if w[:2] == ["dns", "managed-zones"]:
        if w[2] == "describe":
            z = STATE.get("zones", {}).get(w[3])
            if z is None:
                missing()
            out(",".join(z.get("networks", [])))
        out()

    if w[:2] == ["dns", "record-sets"]:
        if w[2] == "describe":
            rtype = argv[argv.index("--type") + 1] if "--type" in argv else ""
            rec = STATE.get("records", {}).get(f"{w[3]}|{rtype}")
            if rec is None:
                missing()
            out(rec)
        out()

    out()


if __name__ == "__main__":
    main()
