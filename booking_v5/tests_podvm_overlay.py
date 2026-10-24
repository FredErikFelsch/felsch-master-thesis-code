"""Behaviour tests for `k8s/v5/podvm-overlay/apply-hardening.sh` against a synthetic rootfs.

The script runs once per pod-VM image build, on a remote builder, inside a 30 to 60 minute
`make image`. A mistake there is expensive to find and expensive to redo, so it is exercised
here against a tree that carries the units of the real CAA 0.21.1 tree that the script touches.
The other classes check what the overlay ships, the producer patch and the measurement script.

The script applies two independent fixes:

    A5c    setup-nat-for-imds.service must be neutralised. Either it ends up masked (symlink to
           /dev/null, because mkosi's own preset re-enables it after the overlay step) or, in
           `noop` mode, the unit stays as shipped and its script body does nothing. A5c is the
           acceptance label of `scripts/gke-v5/attack_catalogue.md`.
    mount  run-kata-containers.mount must be removed with its enablement symlinks, and no unit
           may be left hard-requiring it (`V5_HARDEN_B1`). It binds /kata-containers, which does
           not exist in the mkosi image, so systemd fails the mount, kata-agent does not start
           and the sandbox boot ends in FailedCreatePodSandBox/DeadlineExceeded.

The tree below uses the file name CAA ships, `run-kata\\x2dcontainers.mount`: four literal
characters \\x2d where systemd unescapes a hyphen. The unit systemd loads is
`run-kata-containers.mount`, so a `find -name run-kata-containers.mount` matches nothing. That
would report "nothing to remove" and ship the defect.

Run:  python3 -m booking_v5.tests_podvm_overlay
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

MOCKS = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = MOCKS / "k8s" / "v5" / "podvm-overlay" / "apply-hardening.sh"

KATA_AGENT = """[Unit]
Description=Kata Containers Agent
After=run-kata-containers.mount network.target
Requires=run-kata-containers.mount
RequiresMountsFor=/run/kata-containers

[Service]
ExecStart=/usr/bin/kata-agent
"""

# A unit whose enablement symlink must survive. Its target mentions /run/kata-containers, so a
# dependency-strip search finds it through the symlink.
FORWARDER_PATH = """[Unit]
Description=Watch for the kata-agent socket

[Path]
PathExists=/run/kata-containers/agent.sock

[Install]
WantedBy=multi-user.target
"""

FORWARDER = """[Unit]
Description=agent-protocol-forwarder
BindsTo=run-kata-containers.mount
Wants=run-kata-containers.mount
After=kata-agent.service
"""

#: as CAA 0.21.1 ships it (podvm/files/etc/systemd/system/), escaped file name included
MOUNT_FILE = "run-kata\\x2dcontainers.mount"
MOUNT_UNIT = """[Unit]
Description=Mount unit for /run/kata-containers
Before=kata-agent.service

[Mount]
What=/kata-containers
Where=/run/kata-containers
Type=none
Options=bind

[Install]
WantedBy=multi-user.target
"""


OVERLAY = MOCKS / "k8s" / "v5" / "podvm-overlay"


class OverlayContentsTests(unittest.TestCase):
    """What the overlay must ship, checked in the repository without a build.

    The measurement unit needs its enablement symlink. Without it nothing pulls the unit in, RTMR3
    stays at zero and the evidence still passes: a TD that measured nothing looks like one that
    did, until the replay is compared. `systemctl preset` cannot enable it at boot, because the
    root is squashfs under dm-verity, so /etc is read-only then ("Failed to populate /etc with
    preset unit settings").
    """

    def test_the_unit_is_shipped_enabled(self):
        link = OVERLAY / "etc/systemd/system/multi-user.target.wants/initdata-measure.service"
        self.assertTrue(link.is_symlink(), "the enablement must be a symlink, not a regular file")
        self.assertEqual(str(link.readlink()), "../initdata-measure.service")
        self.assertTrue((link.parent.parent / "initdata-measure.service").is_file())

    def test_the_measurement_script_is_executable(self):
        script = OVERLAY / "usr/local/bin/initdata-measure"
        self.assertTrue(script.is_file())
        self.assertTrue(script.stat().st_mode & 0o111, "must be executable in the image")

    def test_the_unit_does_not_gate_any_agent(self):
        """The fail-closed property belongs to the Authority, not to the guest's unit graph.

        Drop-ins on the agents are allowed but may only carry Wants= and After=. They pull the
        measurement in and order after it, and they do not make an agent depend on it.
        """
        unit = (OVERLAY / "etc/systemd/system/initdata-measure.service").read_text()
        self.assertIn("Before=attestation-agent.service", unit)
        self.assertNotIn("Requires=attestation-agent", unit)
        for dropin in (OVERLAY / "etc/systemd/system").glob("*.service.d/*.conf"):
            for line in dropin.read_text().splitlines():
                key = line.split("=", 1)[0].strip()
                self.assertNotIn(key, ("Requires", "Requisite", "BindsTo", "PartOf"),
                                 f"{dropin.name} must not gate an agent on the measurement unit: {line}")

    def test_the_agents_pull_the_measurement_in(self):
        """The enablement must not rest on a single build step."""
        for agent in ("attestation-agent", "kata-agent"):
            conf = (OVERLAY / f"etc/systemd/system/{agent}.service.d/10-v5-measure.conf").read_text()
            self.assertIn("Wants=initdata-measure.service", conf)
            self.assertIn("After=initdata-measure.service", conf)

    def test_the_preset_enables_the_unit(self):
        """`preset-all` during the build must enable, not disable, the unit."""
        preset = (OVERLAY / "usr/lib/systemd/system-preset/20-v5.preset").read_text()
        lines = [l.strip() for l in preset.splitlines() if l.strip() and not l.startswith("#")]
        self.assertEqual(["enable initdata-measure.service"], lines)


class ProducerPatchTests(unittest.TestCase):
    """The patch repairs the producer of /run/peerpod/initdata, not only its consumer.

    Upstream `ProvisionFiles` discards the `newProvider` error, skips the whole cloud config and
    still returns nil. `process-user-data.service` is Type=oneshot with RemainAfterExit, so
    systemd records a clean completion for a run that wrote nothing, the guest falls back to the
    allow-all policy of tmpfiles.d/policy.conf, and initdata-measure has no digest.
    """

    PATCH_DIR = MOCKS / "k8s" / "v5" / "podvm-patches"
    BUILD = MOCKS / "scripts" / "gke-v5" / "11_build_podvm_image.sh"
    CONFIG = MOCKS / "scripts" / "gke-v5" / "_config.sh"

    def patches(self):
        """Return the patch files of the pod-VM source patch directory, sorted by name."""
        return sorted(self.PATCH_DIR.glob("*.patch"))

    def test_the_producer_patch_exists_and_repairs_the_discarded_error(self):
        self.assertTrue(self.patches(), "the producer fix is defined by its source patch")
        text = "\n".join(p.read_text() for p in self.patches())
        # The defect.
        self.assertIn("-\tprovider, _ := newProvider(ctx)", text)
        self.assertIn("unsupported user data provider, we extract and calculate initdata hash only",
                      text)
        # The repair is a bounded retry, not a fail-closed single attempt.
        self.assertIn("newProviderWithRetry", text)
        self.assertIn("retry.Context(ctx)", text)
        self.assertIn("retry.Attempts(0)", text)
        # A postcondition makes "the unit completed" mean "the files are there".
        self.assertIn("provisioning finished but %s is missing", text)
        self.assertIn("provisioning finished but %s is empty", text)

    def test_the_build_applies_the_patch_before_it_compiles(self):
        """The build applies the patch, so a patch that stops being applied fails here."""
        sh = self.BUILD.read_text()
        self.assertIn("git -C \"\\$WORK\" apply --check -p1", sh)
        self.assertIn("git -C \"\\$WORK\" apply -p1", sh)
        compile_cmd = "sudo -E env TEE_PLATFORM=tdx PODVM_DISTRO=fedora make binaries"
        self.assertLess(sh.index("apply -p1"), sh.index(compile_cmd),
                        "the patch must be applied before the compile step")
        # The built tree is checked as well, not just the patch file.
        self.assertIn("newProviderWithRetry", sh)

    def test_an_unapplied_or_empty_patch_set_stops_the_build(self):
        sh = self.BUILD.read_text()
        self.assertIn("no *.patch in", sh)          # empty directory is refused
        self.assertIn("patch does not apply", sh)   # --check failure is refused
        self.assertIn("exit 8", sh)

    def test_the_caa_source_is_pinned_to_a_commit_not_only_a_tag(self):
        """A tag can be moved, and an image whose source can change gives no reference value."""
        cfg = self.CONFIG.read_text()
        self.assertRegex(cfg, r'CAA_COMMIT="\$\{CAA_COMMIT:-[0-9a-f]{40}\}"')
        sh = self.BUILD.read_text()
        self.assertIn("expected ${CAA_COMMIT}", sh)
        self.assertIn("exit 7", sh)

    def test_the_remote_build_heredoc_has_no_unescaped_backticks(self):
        """Backticks in the remote build heredoc must be escaped.

        The heredoc is unquoted so that ${CAA_COMMIT} and the other settings are substituted. Bash
        therefore also runs backticks on the operator's machine while writing the script. A
        backtick in a comment line prints errors such as `--check: command not found` before the
        remote build starts, in the part of the log that needs to be readable.
        """
        sh = self.BUILD.read_text().splitlines()
        start = next(i for i, l in enumerate(sh) if l.startswith('cat > "${OUT}/remote-build.sh" <<REMOTE'))
        end = next(i for i in range(start + 1, len(sh)) if sh[i] == "REMOTE")
        bad = [(i + 1, l) for i, l in enumerate(sh[start + 1:end], start + 1)
               if "`" in l and "\\`" not in l]
        self.assertEqual([], bad, f"unescaped backticks run locally: {bad}")

    def test_the_provenance_records_the_commit_and_the_patch_hash(self):
        sh = self.BUILD.read_text()
        self.assertIn("caa_commit=${CAA_COMMIT} patch_sha256=${PATCH_SHA256}", sh)
        self.assertIn("patches-applied.txt", sh)

    def test_the_overlay_revision_moved_with_the_change(self):
        cfg = self.CONFIG.read_text()
        self.assertIn('PODVM_OVERLAY_REV="${PODVM_OVERLAY_REV:-14}"', cfg)

    def test_the_ov9_hardening_is_the_default_and_the_build_refuses_less(self):
        """The hardening of overlay revision 9 (ov9) is the build default.

        A5c in noop mode and the mount fix are on, and the build refuses anything less unless
        `V5_ALLOW_UNHARDENED` says so.
        """
        cfg = self.CONFIG.read_text()
        self.assertIn('export V5_HARDEN_A5C="${V5_HARDEN_A5C:-noop}"', cfg)
        self.assertIn('export V5_HARDEN_B1="${V5_HARDEN_B1:-1}"', cfg)
        sh = self.BUILD.read_text()
        self.assertIn('V5_ALLOW_UNHARDENED', sh)
        gate = sh.index("V5_ALLOW_UNHARDENED")
        self.assertLess(gate, sh.index('say "builder VM'), "the gate must run before anything is built")


class MeasurementWaitTests(unittest.TestCase):
    """The wait in initdata-measure is a second line, and it stays fail-closed."""

    SCRIPT = OVERLAY / "usr" / "local" / "bin" / "initdata-measure"

    def test_the_wait_is_bounded_and_overridable(self):
        s = self.SCRIPT.read_text()
        self.assertIn('WAIT_SECONDS="${INITDATA_MEASURE_WAIT:-30}"', s)
        self.assertIn('[ "${waited}" -lt "${WAIT_SECONDS}" ]', s)

    def test_the_wait_covers_the_rtmr3_attribute_too(self):
        """The wait covers the RTMR3 attribute as well as the digest.

        The attribute itself can be the missing precondition even when the digest is on disk, so
        waiting only for the digest would not help.
        """
        s = self.SCRIPT.read_text()
        self.assertIn('ready() { [ -w "${RTMR3_SYSFS}" ] && [ -s "${DIGEST_FILE}" ]; }', s)
        self.assertIn("while ! ready &&", s)

    def test_either_precondition_missing_after_the_wait_fails_closed(self):
        """There is no `exit 0` path without a measurement, so the TD stays unusable instead of booting on."""
        s = self.SCRIPT.read_text()
        self.assertIn('[ -w "${RTMR3_SYSFS}" ] || die', s)
        self.assertIn('[ -s "${DIGEST_FILE}" ] || die', s)
        self.assertEqual(2, s.count("after ${WAIT_SECONDS}s"))

    def test_the_48_bytes_reach_the_kernel_in_one_write(self):
        """The 48 bytes of the digest reach the RTMR3 attribute in one write() call.

        Bash writes its builtin printf through line-buffered stdio, so a 0x0a inside the digest
        splits one logical write into two write() calls. The RTMR3 attribute takes 48 bytes at
        offset 0 and refuses a short first write with EINVAL. The script therefore assembles the
        bytes in a file and lets dd perform the single 48-byte write.
        """
        s = self.SCRIPT.read_text()
        self.assertIn('dd if="${RAW}" of="${RTMR3_SYSFS}" bs=48 count=1', s)
        # The size is asserted before the write, so a broken encoder says so instead of EINVAL.
        self.assertIn('[ "${raw_size}" -eq 48 ] || die', s)
        self.assertLess(s.index("raw_size"), s.index("extend_rtmr3 ||"))
        # The sysfs attribute is not the target of a shell redirect.
        self.assertNotIn('> "${RTMR3_SYSFS}"', s)
        self.assertIn('RAW="/run/peerpod/initdata-measure.raw"', s)

    def test_the_extend_is_retried_bounded_and_reported(self):
        """The extend is retried a bounded number of times, and each rejection is reported.

        The TDX module serialises TDG.MR.RTMR.EXTEND, so a concurrent RTMR operation returns BUSY
        even when both preconditions are ready.
        """
        s = self.SCRIPT.read_text()
        self.assertIn('EXTEND_ATTEMPTS="${INITDATA_MEASURE_EXTEND_ATTEMPTS:-20}"', s)
        self.assertIn("extend_rtmr3()", s)
        self.assertIn('[ "${attempt}" -lt "${EXTEND_ATTEMPTS}" ]', s)
        # The kernel's own message is reported per attempt, so a refusal keeps its reason.
        self.assertIn("RTMR3 extend attempt ${attempt}/${EXTEND_ATTEMPTS} rejected", s)

    def test_an_extend_that_never_succeeds_still_fails_closed(self):
        s = self.SCRIPT.read_text()
        self.assertIn('|| die "RTMR3 extend rejected by the kernel on all ${EXTEND_ATTEMPTS} attempts"', s)
        self.assertNotIn("|| true\nprintf '%s\\n%s\\n'", s)

    def test_every_refusal_reaches_the_serial_console(self):
        """Every refusal is written to /dev/kmsg, because the guest journal is unreachable.

        <3> is KERN_ERR, which survives the default console loglevel.
        """
        s = self.SCRIPT.read_text()
        self.assertIn('kmsg() { echo "<3>initdata-measure: $*" > /dev/kmsg 2>/dev/null || true; }', s)
        self.assertIn('die() { echo "initdata-measure: $*" >&2; kmsg "$*"; exit 1; }', s)
        # The successful path reports as well, so a boot log answers the question either way.
        self.assertIn('kmsg "RTMR3 extended', s)

    def test_the_wait_is_documented_as_a_second_line_not_as_the_fix(self):
        """The script names the wait a second line and points to the patch that is the repair.

        The asserted text is quoted from the measured script, which keeps its own spelling.
        """
        s = self.SCRIPT.read_text()
        self.assertIn("defense in depth and NOT the fix for the 23.09.2026 defect", s)
        self.assertIn("0001-bounded-provider-retry.patch", s)


class ApplyHardeningTests(unittest.TestCase):
    """The hardening script on a synthetic rootfs neutralises the IMDS NAT and removes the kata mount."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        sysd = self.root / "etc/systemd/system"
        (sysd / "multi-user.target.wants").mkdir(parents=True)
        (sysd / "local-fs.target.requires").mkdir(parents=True)
        (self.root / "usr/lib/systemd/system").mkdir(parents=True)
        (sysd / "setup-nat-for-imds.service").write_text("[Unit]\nDescription=IMDS NAT\n")
        (sysd / "multi-user.target.wants/setup-nat-for-imds.service").symlink_to(
            "../setup-nat-for-imds.service")
        (self.root / "usr/local/bin").mkdir(parents=True)
        (self.root / "usr/local/bin/setup-nat-for-imds.sh").write_text(
            "#!/bin/bash\niptables -t nat -A POSTROUTING -j MASQUERADE\n")
        (sysd / MOUNT_FILE).write_text(MOUNT_UNIT)
        (sysd / "multi-user.target.wants" / MOUNT_FILE).symlink_to(f"../{MOUNT_FILE}")
        (sysd / "local-fs.target.requires" / MOUNT_FILE).symlink_to(f"../{MOUNT_FILE}")
        (sysd / "kata-agent.service").write_text(KATA_AGENT)
        (sysd / "agent-protocol-forwarder.service").write_text(FORWARDER)
        (sysd / "agent-protocol-forwarder.path").write_text(FORWARDER_PATH)
        (sysd / "multi-user.target.wants/agent-protocol-forwarder.path").symlink_to(
            "../agent-protocol-forwarder.path")
        self.sysd = sysd

    def tearDown(self):
        self._tmp.cleanup()

    def run_script(self, defaults: bool = False, **flags) -> subprocess.CompletedProcess:
        """Run the hardening script on the synthetic tree.

        Args:
            defaults: Run without any `V5_HARDEN_*` variable, so the script's own defaults apply.
            **flags: Environment variables that override the defaults of this harness, which turn
                both fixes on.

        Returns:
            The completed process.
        """
        env = {k: v for k, v in os.environ.items() if not k.startswith("V5_HARDEN_")}
        if not defaults:
            env.update(V5_HARDEN_A5C="1", V5_HARDEN_B1="1")
        env.update({k: str(v) for k, v in flags.items()})
        return subprocess.run(["bash", str(SCRIPT), str(self.root)],
                              capture_output=True, text=True, env=env)

    def _snapshot(self):
        """Return every path of the tree with its kind and content, sorted."""
        return sorted((str(p.relative_to(self.root)), p.is_symlink(),
                       str(p.readlink()) if p.is_symlink() else (p.read_text() if p.is_file() else ""))
                      for p in self.root.rglob("*"))

    def test_both_fixes_are_off_by_default(self):
        """Without the flags the tree stays untouched, so the baseline image plus the measurement unit can still be built."""
        before = self._snapshot()
        proc = self.run_script(defaults=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("SKIPPED (V5_HARDEN_A5C=0)", proc.stdout)
        self.assertIn("SKIPPED (V5_HARDEN_B1=0)", proc.stdout)
        self.assertEqual(self._snapshot(), before)

    def test_both_fixes_at_zero_leave_the_tree_untouched(self):
        before = self._snapshot()
        proc = self.run_script(V5_HARDEN_A5C="0", V5_HARDEN_B1="0")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self._snapshot(), before)

    def test_the_script_succeeds_and_reports_both_fixes(self):
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("setup-nat-for-imds.service masked", proc.stdout)
        self.assertIn("run-kata-containers.mount removed", proc.stdout,
                      "the final line is missing: the script exited early")

    def test_it_runs_on_a_tree_that_has_only_etc_systemd(self):
        """The script runs on `resources/binaries-tree`, which has no usr/lib/systemd.

        `find` and `grep` return non-zero for a missing path, and under `set -e` an assignment
        inherits that. The script would stop silently right after the removals, before
        `make image` started.
        """
        shutil.rmtree(self.root / "usr")
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("run-kata-containers.mount removed", proc.stdout,
                      "the script stopped before its last step")
        self.assertEqual([p for p in self.root.rglob("*") if "containers.mount" in p.name], [])

    def test_A5c_the_imds_unit_is_masked_not_merely_disabled(self):
        self.run_script()
        unit = self.sysd / "setup-nat-for-imds.service"
        self.assertTrue(unit.is_symlink())
        self.assertEqual(str(unit.readlink()), "/dev/null")
        self.assertFalse((self.sysd / "multi-user.target.wants/setup-nat-for-imds.service").exists())

    def test_A5c_noop_neutralises_the_script_and_leaves_the_unit_graph_alone(self):
        """In noop mode A5c is a no-op script body, because a masked unit breaks the peer-pod boot.

        The unit file and the enablement symlink stay as shipped. The script stays executable,
        carries no iptables call and exits 0.
        """
        proc = self.run_script(V5_HARDEN_A5C="noop")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("setup-nat-for-imds.sh neutralised (A5c noop)", proc.stdout)
        unit = self.sysd / "setup-nat-for-imds.service"
        self.assertFalse(unit.is_symlink())
        self.assertEqual(unit.read_text(), "[Unit]\nDescription=IMDS NAT\n")
        self.assertTrue((self.sysd / "multi-user.target.wants/setup-nat-for-imds.service").is_symlink())
        script = self.root / "usr/local/bin/setup-nat-for-imds.sh"
        self.assertTrue(os.access(script, os.X_OK))
        self.assertNotIn("iptables", script.read_text())
        run = subprocess.run(["bash", str(script)], capture_output=True, text=True)
        self.assertEqual((run.returncode, "disabled by the V5 overlay" in run.stdout), (0, True))

    def test_A5c_noop_refuses_a_masked_unit(self):
        """The two realisations are exclusive.

        Noop on a tree that already carries the mask is a configuration error, not a silent double
        fix.
        """
        self.run_script(V5_HARDEN_A5C="1")
        proc = self.run_script(V5_HARDEN_A5C="noop")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("expects the unit file untouched", proc.stderr)

    def test_the_mount_unit_and_its_enablement_symlinks_are_gone(self):
        """The escaped file name is matched.

        The file carries the systemd escape \\x2d, so an exact-name search finds nothing and
        reports success.
        """
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("nothing to remove", proc.stdout,
                         "the escaped file name was not matched")
        found = [p for p in self.root.rglob("*") if "containers.mount" in p.name]
        self.assertEqual(found, [], f"still present: {found}")

    def test_a_plainly_named_mount_unit_is_removed_too(self):
        """A future CAA may ship the unescaped name, so both spellings are covered."""
        (self.sysd / MOUNT_FILE).unlink()
        (self.sysd / "multi-user.target.wants" / MOUNT_FILE).unlink()
        (self.sysd / "local-fs.target.requires" / MOUNT_FILE).unlink()
        (self.sysd / "run-kata-containers.mount").write_text(MOUNT_UNIT)
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse((self.sysd / "run-kata-containers.mount").exists())

    def test_hard_dependencies_on_the_mount_are_stripped_but_ordering_is_kept(self):
        """`Requires=` on a missing unit fails the requiring unit. `After=` does not."""
        self.run_script()
        agent = (self.sysd / "kata-agent.service").read_text()
        self.assertNotIn("Requires=run-kata-containers.mount", agent)
        self.assertNotIn("RequiresMountsFor=/run/kata-containers", agent)
        self.assertIn("After=run-kata-containers.mount network.target", agent,
                      "ordering documents intent and is harmless for an absent unit")
        self.assertIn("ExecStart=/usr/bin/kata-agent", agent)
        fwd = (self.sysd / "agent-protocol-forwarder.service").read_text()
        self.assertNotIn("BindsTo=run-kata-containers.mount", fwd)
        self.assertIn("Wants=run-kata-containers.mount", fwd)

    def test_enablement_symlinks_survive_as_symlinks(self):
        """Enablement symlinks stay symlinks.

        `grep -R` follows symlinks, so a search for /run/kata-containers reaches
        multi-user.target.wants/agent-protocol-forwarder.path, and `sed -i` would replace that
        symlink with a regular file. Systemd then ignores it ("Wants dependency dropin ... is not
        a symlink"), the forwarder does not start, nothing listens on 15150, and every peer pod
        ends in FailedCreatePodSandBox.
        """
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        link = self.sysd / "multi-user.target.wants/agent-protocol-forwarder.path"
        self.assertTrue(link.is_symlink(), "systemd ignores a .wants entry that is a plain file")
        self.assertEqual(str(link.readlink()), "../agent-protocol-forwarder.path")
        self.assertIn("PathExists=/run/kata-containers/agent.sock",
                      (self.sysd / "agent-protocol-forwarder.path").read_text(),
                      "the path unit's own content must not be rewritten either")

    def test_no_empty_directive_lines_are_left_behind(self):
        self.run_script()
        for unit in ("kata-agent.service", "agent-protocol-forwarder.service"):
            for line in (self.sysd / unit).read_text().splitlines():
                self.assertFalse(line.rstrip().endswith("="), f"{unit}: empty directive {line!r}")

    def test_a_tree_without_the_mount_unit_is_not_an_error(self):
        """A later CAA release may not ship the mount unit. That is a note, not a build failure."""
        (self.sysd / MOUNT_FILE).unlink()
        (self.sysd / "multi-user.target.wants" / MOUNT_FILE).unlink()
        (self.sysd / "local-fs.target.requires" / MOUNT_FILE).unlink()
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("nothing to remove", proc.stdout)

    def test_it_is_idempotent(self):
        self.assertEqual(self.run_script().returncode, 0)
        after_first = self._snapshot()
        second = self.run_script()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(self._snapshot(), after_first)
        unit = self.sysd / "setup-nat-for-imds.service"
        self.assertEqual(str(unit.readlink()), "/dev/null")


if __name__ == "__main__":
    unittest.main(verbosity=2)
