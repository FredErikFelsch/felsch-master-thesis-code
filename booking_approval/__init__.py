"""Human approval over WebAuthn, served by the Authority.

An approval must not travel through the controller. A controller that relays or mints
approvals can be compromised and then approve on the human's behalf. This package moves the
decision behind the Authority, which applies it only after a verified WebAuthn assertion:

    webauthn     verification of a WebAuthn assertion (ES256, EdDSA), no third-party library
    credentials  the pinned approver credentials (public keys only) and their pinning
    objects      what is approved (a plan, one payment fragment) and how it is displayed
    store        pending objects, issued challenges and decisions, durable (SQLite)
    gate         the Authority-side gate: closes create_run and decide_intervention on the
                 RPC surface and applies a decision only after a verified assertion
    surface      the HTTP approval surface the browser talks to (page, challenge, assertion)
    softauthn    a software authenticator (tests and the unattended evaluation harness)
    client       the controller's view: propose, poll, and the harness approver
    enroll       one-time registration of a passkey (or a harness key)
    service      the Authority entry point with the gate installed

Nothing here is imported by the runner. The packages the runner image carries
(`booking_v0` to `booking_v5`) do not depend on it.
"""
