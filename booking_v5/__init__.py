"""V5: attested fragment execution (one TDX pod VM per fragment, CoCo peer pods).

The model and the fixture tests run offline, the model with fakes and the fixture tests with
recorded evidence of a probe run. The live adapters (`e2e_live.py`, the `probe_*.py` modules,
`service_v5.py` and `controller_v5.PeerPodBackend`) run against a cluster. Inside the guest
they are thin clients over the Attestation Agent's loopback endpoints and one Intel library.

Module map:

    binding.py        runner side of the bind step: boot keys, canonical binding, the RTMR3
                      hook and the sealed box that carries the session credential.
    rtmr_replay.py    the AAEL encoding and the expected RTMR3 history
                      [init-data, boot-key, bind]. The Authority replays it, the guest
                      sends no event log.
    tdx_quote.py      the TDX quote v4 layout (read-only parsing).
    evidence.py       the evidence document, a fake producer, and the recorded probe
                      evidence used as a fixture.
    verifier.py       checks whether the evidence is genuine (structure, DCAP appraisal,
                      REPORTDATA binding). Judges no policy.
    collateral_cache.py  validity-bounded cache of the DCAP collateral, so a verdict does
                      not depend on the network.
    relying_party.py  checks whether it is the right evidence: reference values, canonical
                      binding, one-TD-one-fragment ledger, substrate profile, session scope.
                      This is where the Authority's attestation policy lives.
    runner_bind.py    the sequence inside the TD: boot, bind, attest, open, execute.
    runner_main.py    the runner entrypoint: that sequence over stdin and stdout.
    protocol.py       the seven-line attach protocol between controller and TD.
    attach_transport.py  the protocol over the Kubernetes `pods/attach` stream.
    controller_v5.py  trusted launch and relay (pool, challenge, evidence, session,
                      delivery, destroy), with the timings of the evaluation.
    pool.py           controller-side pool of unbound TDs, which never hands a TD out twice.
    profile_v5.py     the measured runner profile: a pure function that yields the Pod
                      manifest with runtimeClassName kata-remote and the init-data
                      annotation, plus the substrate half of the Fixed Execution Profile.
    gateway.py        the reading side of the effect ledger.
    freeze_record.py  the machine-readable record of the Authority's reference values.
    substrate_variance.py  classifies a refused RTMR0 outlier as provider variance.
    service_v5.py     the trusted init and the authority and gateway serve roles.
    e2e_live.py       the live end-to-end run and the live negative cases, run from the
                      operator machine.
    experiment_v5.py  the frozen scenario matrix on the attested path, with the
                      equivalence check.
    report_v5.py      regenerates the evaluation tables from results_v5/.
    dcap/             the vendored Intel QVL binding and PCS client (see dcap/PROVENANCE.md).
    probe_*.py, permissive_policy.py  probes that run in peer pods or against a cluster.
    testdata/         a fake `gcloud` and `kubectl` for the tests of
                      scripts/gke-v5/12_create_cluster_v5.sh.

    tests_v5_offline.py   the model: attacks A10, A11 and A13 to A18 with fakes (labels
                          from scripts/gke-v5/attack_catalogue.md).
    tests_v5_fixtures.py  the same path on real recorded TDX evidence, plus the offline
                          end-to-end with an effect count of one.
    tests_rtmr_replay.py  the measurement maths against live recorded values.

The property this package establishes: no Execution Grant unless the Authority holds evidence
that the measured monitor runs for this fragment on this state, in an instance bound to no
other fragment, and the credential to ask for that grant is readable only inside that
instance.
"""
