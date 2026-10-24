#!/usr/bin/env python3
"""_rules_backport.py: backports the genpolicy mount-source fix onto the rules.rego of Kata 3.31.0 and adds our image-source binding.

Needs:  The upstream rules.rego of Kata 3.31.0, and python3.
Usage:  _rules_backport.py <upstream rules.rego> <patched rules.rego>
Result: The patched rules.rego, and its sha256 on stdout. Exit code 1 with BACKPORT_FAIL on stderr
        if any anchor is missing or matches more than once, so a different upstream release cannot
        be silently mis-patched.

The fix is GHSA-fmg6-v47x-52wr (CVE-2026-77176), fixed in Kata 4.1.0 (commit 788e2df4).

Why not rules.rego from 4.1.0 as a whole: the agent inside our pod-VM image is 3.31.0, and the
policy input schema moves between releases. The minimal patch keeps the 3.31 rules and only
closes the hole. Three edits, all quoted from the 4.1.0 rules:

  allow_mount 1   requires p_mount.source != ""   (image-pull storages can no longer match a
                  policy mount that has a source)
  allow_mount 2   requires p_mount.source == "" and i_storage.driver in {"blk", "scsi"}
                  (a host-supplied storage may only back a mount the policy left source-less,
                  and only as a block device)
  allow_storage   image_guest_pull storages must mount at the container rootfs
  (image_guest_pull)   (expect_root_path == i_storage.mount_point) instead of anywhere

Two further edits are not part of that advisory. They are additions of this work.
Upstream leaves the source of an image_guest_pull storage and the CRI image-name annotation
unchecked ("TODO: Check Mount Point, Source, Driver Options, etc."), so the digest the policy
names was only text. The kata-agent 3.31.0 pulls `storage.source` for an application container
(image_pull_handler.rs) and, when the pull metadata in the single `image_guest_pull=<json>` driver
option carries a container-type of "sandbox", unpacks the pause bundle of the guest image instead
(confidential_data_hub/image.rs, is_sandbox). So the rule binds all three:

  allow_image_source (call)   CreateContainerRequest requires allow_image_source(...)
  allow_image_source (rule)   three cases
    application container     the policy entry names an image, which must end in
                              @sha256:<64 hex>. There is one image_guest_pull storage, its
                              `source` and the io.kubernetes.cri.image-name annotation equal that
                              reference, and its metadata does not say "sandbox" (no switch to
                              the pause unpack).
    pause container           policy and request are the sandbox: one pull with source "pause"
                              whose metadata says "sandbox" (the shape is taken from the pause
                              requests the host sent in a recorded probe).
    any other container       no image_guest_pull storage at all.
  Exactly one driver option of the form image_guest_pull=<json> is accepted.
"""
import hashlib
import pathlib
import sys

EDITS = [
    (
        'allow_mount 1: p_mount.source != ""',
        '''    print("allow_mount 1: p_mount =", p_mount)
    check_mount(p_mount, i_mount, bundle_id, sandbox_id)
''',
        '''    print("allow_mount 1: p_mount =", p_mount)
    p_mount.source != ""
    check_mount(p_mount, i_mount, bundle_id, sandbox_id)
''',
    ),
    (
        'allow_mount 2: source-less policy mount, blk/scsi storage only',
        '''    p_mount.options == i_mount.options

    some i_storage in i_storages
    print("allow_mount 2: i_storage =", i_storage)

    i_storage.mount_point == i_mount.source
''',
        '''    p_mount.options == i_mount.options
    p_mount.source == ""

    some i_storage in i_storages
    print("allow_mount 2: i_storage =", i_storage)

    i_storage.driver in {"blk", "scsi"}
    i_storage.mount_point == i_mount.source
''',
    ),
    (
        'allow_storage image_guest_pull: mount point must be the rootfs',
        '''    count(i_storage.options) == 0
    # TODO: Check Mount Point, Source, Driver Options, etc.
    print("allow_storage with image_guest_pull: true")
''',
        '''    count(i_storage.options) == 0
    expect_root_path := replace(policy_data.common.root_path, "$(bundle-id)", bundle_id)
    print("allow_storage with image_guest_pull: expect_root_path =", expect_root_path)
    expect_root_path == i_storage.mount_point
    print("allow_storage with image_guest_pull: true")
''',
    ),
    (
        'allow_image_source: call in CreateContainerRequest',
        '''    allow_anno(p_container, i_oci)

    p_storages := p_container.storages
''',
        '''    allow_anno(p_container, i_oci)
    allow_image_source(p_container, i_oci, i_storages)

    p_storages := p_container.storages
''',
    ),
    (
        'allow_image_source: rule',
        '''allow_anno_key_value(i_key, i_value, p_container) if {
    print("allow_anno_key_value 1: i key =", i_key)
''',
        '''# What a guest pull loads (audit F-039). The agent pulls `storage.source` for an application
# container and, when the pull metadata says "sandbox", unpacks the pause bundle of the guest
# image instead (kata-agent 3.31.0, image_pull_handler.rs and confidential_data_hub/image.rs).
# So the rule binds the source, the sandbox flag in the metadata, and the number of pulls.
image_pulls(i_storages) := [s | some s in i_storages; s.driver == "image_guest_pull"]

# Container-type values the agent would read from the single `image_guest_pull=<json>` option.
pull_container_types(i_storage) := types if {
    count(i_storage.driver_options) == 1
    option := i_storage.driver_options[0]
    startswith(option, "image_guest_pull=")
    metadata := json.unmarshal(substring(option, count("image_guest_pull="), -1)).metadata
    types := {v |
        some k in {"io.kubernetes.cri.container-type", "io.kubernetes.cri-o.ContainerType"}
        v := metadata[k]
    }
}

# An application container that names an image: exactly one pull, its source and the CRI
# image-name annotation equal the digest-pinned reference of the policy, the metadata does
# not turn the pull into the pause unpack.
allow_image_source(p_container, i_oci, i_storages) if {
    p_image := p_container.OCI.Annotations["io.kubernetes.cri.image-name"]
    print("allow_image_source: p_image =", p_image)
    regex.match("@sha256:[0-9a-f]{64}$", p_image)
    i_oci.Annotations["io.kubernetes.cri.image-name"] == p_image
    pulls := image_pulls(i_storages)
    count(pulls) == 1
    pulls[0].source == p_image
    types := pull_container_types(pulls[0])
    not "sandbox" in types
    print("allow_image_source: true")
}
# The pause container: exactly one pull that the agent resolves to the guest's pause bundle.
allow_image_source(p_container, i_oci, i_storages) if {
    p_container.OCI.Annotations["io.kubernetes.cri.container-type"] == "sandbox"
    i_oci.Annotations["io.kubernetes.cri.container-type"] == "sandbox"
    pulls := image_pulls(i_storages)
    count(pulls) == 1
    pulls[0].source == "pause"
    "sandbox" in pull_container_types(pulls[0])
    print("allow_image_source: pause bundle of the guest image")
}
# Any other container: no pull at all.
allow_image_source(p_container, i_oci, i_storages) if {
    not p_container.OCI.Annotations["io.kubernetes.cri.image-name"]
    p_container.OCI.Annotations["io.kubernetes.cri.container-type"] != "sandbox"
    count(image_pulls(i_storages)) == 0
    print("allow_image_source: no image to pull, none requested")
}

allow_anno_key_value(i_key, i_value, p_container) if {
    print("allow_anno_key_value 1: i key =", i_key)
''',
    ),
]


def main(src: str, dst: str) -> int:
    """Apply every edit of EDITS to `src`, write the result to `dst` and print its sha256.

    The header written above the rules is part of the hashed output, and through policy.rego
    of the measured init-data, so its text changes only together with a new freeze.

    Args:
        src: the upstream rules.rego of Kata 3.31.0.
        dst: where the patched rules.rego is written.

    Returns:
        0 on success, 1 if an anchor is missing or not unique (reported as BACKPORT_FAIL).
    """
    text = pathlib.Path(src).read_text()
    for name, old, new in EDITS:
        n = text.count(old)
        if n != 1:
            print(f"BACKPORT_FAIL {name}: anchor found {n} times (expected 1)", file=sys.stderr)
            return 1
        text = text.replace(old, new)
    header = ("# rules.rego from Kata 3.31.0 with the GHSA-fmg6-v47x-52wr (CVE-2026-77176) mount-source\n"
              "# fix backported by scripts/gke-v5/_rules_backport.py (three edits) plus the image-source\n# binding of audit F-039 (two edits), see that file.\n")
    pathlib.Path(dst).write_text(header + text)
    print(hashlib.sha256((header + text).encode()).hexdigest())
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    sys.exit(main(*sys.argv[1:3]))
