# k8s/v5: manifests for attested fragment execution (CoCo peer pods, TDX)

    init-data/      aa.toml, cdh.toml, policy.rego: rendered into the runner Pod's
                    io.katacontainers.config.hypervisor.cc_init_data annotation by
                    booking_v5.profile_v5. Its sha256 is a pinned reference value.
    caa/            Helm values of cloud-api-adaptor for GCP (values-gcp.yaml, rendered by
                    scripts/gke-v5/15_render_caa_values.sh)
    services/       Authority, Gateway, trusted init, controller identity and NetworkPolicies
    openbao/        optional credential store for a live world (see openbao/README.md)
    podvm-overlay/  files added to the pod-VM image (see podvm-overlay/README.md)
    podvm-patches/  source patches applied to cloud-api-adaptor before the pod-VM build
    genpolicy-settings.json  the genpolicy settings behind the measured policy
    approver-credentials.json       the approvers the demo deployment pins (passkeys, public keys only)
    approver-credentials.eval.json  the set an unattended evaluation pins (a passkey and the harness key)

The V4.4c manifests in k8s/apply/ are frozen. V5 adds the namespace
`confidential-containers-system` and, in agent-system, the gateway, the approval gate, the
controller identity and the optional OpenBao. On the runner side it changes the
runtimeClassName (kata-remote), adds init-data, and uses a Pod (pool) instead of a Job.
