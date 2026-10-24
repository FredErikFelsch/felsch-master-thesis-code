# Demo: an agent reads an injected e-mail, three chains decide

Two terminals, from the repository root:

    python3 -m booking_demo.serve                 # dashboard on http://localhost:8765/
    python3 -m booking_demo.run --mode v0 --mail fraud                    # act 1: the damage (5349 EUR to the wrong payee)
    python3 -m booking_demo.run --mode v3 --mail fraud --approve wait     # act 2: the fraudulent payment is denied
    python3 -m booking_demo.run --mode v3 --mail eager                    # act 2b: fail-closed variant
    python3 -m booking_demo.run --mode v5-local --mail fraud --attack a16,a10,a18   # act 3 rehearsal, no cluster

The agent proposes the plan, and its freedom ends at approval:

    python3 -m booking_demo.run --mode v3 --mail fraud --model openai --plan agent --approve wait

Before it acts, the model answers with one JSON plan (steps, budget, approval steps). The
dashboard shows the plan next to the mail, with what the compiled policy can and cannot
enforce. A plan without `search` gives up the offer bindings and says so. You approve or
reject. The approved plan is compiled into the frozen V2/V3 policy language (`plan.py`) and
enforced like the fixed one. With the fraud mail the agent typically proposes 5349 EUR as
budget. The review flags it. Even an approved bad budget cannot pay the attacker, because
`pay` stays bound to the amount and payee of the booking.

    python3 -m booking_demo.run --mode v3 --mail fraud-payee    # the isolating case, see below

## The second application: an on-call agent in a Kubernetes cluster

It uses the same session, the same compiler, the same monitor, Authority and gateway, and the
same attested path. What changes is the application profile (`profile.py`, `devops.py`): the
task, the step library, the world the gateway executes against, and the untrusted input. Pick
it in the dashboard's demo selector ("DevOps cluster") and run:

    python3 -m booking_demo.run --app devops --mode v0 --alert fraud                       # the damage
    python3 -m booking_demo.run --app devops --mode v3 --alert clean --plan agent --approve wait    # the legitimate restart, one human decision
    python3 -m booking_demo.run --app devops --mode v3 --alert subtle --plan agent --approve wait   # the cluster twin of fraud-payee
    python3 -m booking_demo.run --app devops --mode v3 --alert fraud --plan agent               # the blatant runbook, refused by name
    python3 -m booking_demo.run --app devops --mode v5-local --alert subtle                   # inside fake TDs

The step library has two entries. `list_deployments` is a read whose reply (through the
gateway) produces the facts `observed_failing` and `observed_deployments`.
`restart_deployment` binds its `name` to `observed_failing` and always requires approval, even
when the plan says `approval_steps: []` (the compiler repairs that and adds a note).

A plan admits the effects it lists, once each. With `subtle`, the fooled agent first restarts
the healthy `payments`. Its one planned restart is therefore refused by the binding, and the
run terminates with zero effects, like the swapped payee in booking. With `fraud`, the
legitimate restart runs and the second restart is refused as off-plan, whatever its target.
`http_post`, `exec_pod` and `delete_namespace` have no schema in the tool registry, and
`read_secret` is not a step of any plan. All four are refused before anything executes.

`--mode v5` (the cluster) runs the booking application only, because the deployed gateway
image executes the booking world. Putting the cluster world behind the deployed gateway needs
a rebuild of the services image and a new freeze of the reference values
(`scripts/gke-v5/98a_freeze_prepare.sh`, see `scripts/gke-v5/README.md`).

    python3 -m booking_demo.explain_policy --app devops --plan restart_deployment    # what a plan without the read gives up

Nothing in the manipulated mails announces itself. They come from the same sender as the real
invoice and name `airline:LH-collections`, which reads like a second account of the same
airline. A payee called "attacker" would have measured the label rather than the behaviour.

`fraud-payee` is the sharpest case for the contribution. The fare is the real 349.00 EUR and
only the bank details are swapped, which is how business e-mail compromise typically looks.
Budget, scope and capability all pass. The refusal is
`cross-step binding violated at step 3: recipient must equal fact booking_recipient`. What
stops the payment is therefore the binding to the fact the booking step produced, not a
ceiling. A static capability cannot express this, because the payee is unknown before the run.

`fraud-labelled` and `fraud-payee-labelled` are the same two mails with the disguise removed.
The payee is called `attacker:acct-666` and the sender is a visible lookalike domain. The rest
of the text is identical, which a test enforces. Running the pair measures how much of the
attack rate comes from the disguise rather than from the defence.

Options: `--mail clean|fraud|fraud-payee|fraud-labelled|fraud-payee-labelled|injected|eager`
(default `fraud`, which is invoice fraud and the realistic case. `injected` and `eager` are the
blatant prompt injections, which current models tend to ignore), `--model scripted|openai|anthropic`,
`--approve auto|wait|deny`.

Real agent with OpenAI (no SDK, plain HTTPS from the standard library):

    export OPENAI_API_KEY=sk-...            # not on the command line of a shared screen
    export DEMO_OPENAI_MODEL=gpt-5.4-mini   # optional, this is the default. OPENAI_BASE_URL selects a compatible server
    python3 -m booking_demo.run --mode v3 --mail injected --model openai --approve wait

If the demo machine cannot reach the model APIs, run `python3 -m booking_demo.relay` on a
machine that can (for example a Raspberry Pi in the LAN, which holds the keys `OPENAI_API_KEY`
and/or `ANTHROPIC_API_KEY`). Point the demo machine at it with
`OPENAI_BASE_URL=http://<pi>:8787/v1` for OpenAI and `ANTHROPIC_BASE_URL=http://<pi>:8787` for
Anthropic (no `/v1`, the SDK adds it), each with any non-empty key.

The dashboard accepts POSTs (run, chat, approval) only from the origins `http://localhost:<port>`
and `http://127.0.0.1:<port>`, whatever `--host` it binds. To use it from another machine, keep
the default loopback bind and open an SSH tunnel to it, for example
`ssh -L 8765:localhost:8765 <demo-machine>`, then browse to `http://localhost:8765/`. With
`--host 0.0.0.0` another machine can view the page, but its POSTs are refused.

Requirements on any machine (laptop, Raspberry Pi): Python 3.10+ and `pip install cryptography`
(Ed25519 for envelopes and tokens). The Anthropic adapter needs `pip install anthropic`. The
OpenAI adapter keeps the token usage per API call on the model object (`usage`).

Every run is recorded under `results_v5/demo/<stamp>-<mode>-<mail>-<model>/events.json`. The
dashboard's run picker replays any of them without a model and without a cluster. The tests
(`python3 -m booking_demo.tests_demo`, also run by `scripts/gke-v5/40_verify_v5.sh --offline`)
pin the three acts.

## Act 3: the cluster (every step in a fresh attested TD)

It uses the same session and the same adapter. The chain is `AttestedChain.cluster`, the
plumbing of `e2e_live`: narrow controller identity, peer pods, `pods/attach`, and the ledger
read through the observation port. The cluster must be up with the services deployed, in this
order of `scripts/gke-v5/`: `12_create_cluster_v5.sh`, `15_render_caa_values.sh`,
`14_install_coco.sh`, `23_build_services_image.sh`, `30_deploy_v5.sh`,
`40_verify_v5.sh` and `31_run_fragment_v5.sh` as a smoke test. `30_deploy_v5.sh` also publishes
the human's approval credential into the Secret `human-approver`, which is readable by the admin
only. The controller Role cannot read it.

    source scripts/gke-v5/_config.sh   # sets PROJECT, ZONE and AR_HOST (the registry host)
    python3 -m booking_demo.run --mode v5 --mail fraud --model openai --approve wait \
        --project "$PROJECT" --zone "$ZONE" --registry "$AR_HOST" \
        --impersonate "v5-controller@$PROJECT.iam.gserviceaccount.com" \
        --admin-context "$(kubectl config current-context)" --pool 5 --attack a16

`scripts/gke-v5/33_demo_v5.sh` makes this call with project, zone, registry, controller identity
and admin context filled in, and passes its own arguments on.

On top of act 2, the dashboard shows the attack cards. a16 runs as a throwaway run, while a10
and a18 attack step 0 of the approved run itself before the honest attempt. Each card shows the
refusal, a ledger delta of 0 and where it was blocked: inside the TD for a16, at the relying
party for a10 and a18. The dashboard also shows one row per attested TD with its phases (spawn,
evidence, verification, execution, destroy) and outcome. With the approval gate, the person
approves the payment at step 4 on the Authority's page (port 8450, forwarded by
`scripts/gke-v5/49_approval_page.sh`). Older deployments without the gate use
`authority.decide_intervention` with the human's credential. The approved retry runs in a new
TD that the continuation gate admits (same fragment, same state, pending intervention).

Budget: one TD per fragment, plus one per attack, plus one for the continuation. A step takes
about 110 s on a cold TD and about 23 s on a warm one from the pool (`--pool 5`), the medians
of `total_s` over the attested steps of the cluster runs recorded under `results_v5/demo/`.
Give the pool about 90 s after start before the first step. `--mode v5-local` is the same code
over fake TDs in threads for rehearsals.

## Layout

- `mail.py` the e-mails, `world.py` catalogue, secret store and outbound sink.
- `profile.py` the application profile (what differs between booking and devops), `devops.py`
  the on-call cluster application, `live.py` the booking profile retargeted at a live world
  (Duffel, SerpApi).
- `models.py` scripted, Anthropic and OpenAI agents over the tools of the profile (plus
  `propose_plan`), `forge.py` wrappers that forge one argument or retry an uncertain payment.
- `plan.py` the agent's plan compiled into the frozen policy language, with the review,
  `explain_policy.py` a policy in plain English.
- `chains.py` the decision chains behind a common interface (`InProcessChain` V3,
  `AttestedChain` V5 local or cluster), `attacks.py` the three live attacks as switches,
  `expiry.py` the live expiry of an intervention approval.
- `session.py` the adapter (tool call to ActionFragment) and the loop, `run.py` the CLI.
- `serve.py` and `dashboard.html` the display, `http_guard.py` the request rules of the local
  servers, `approval_record.py` the approval request and its id, `continuation.py` the chat
  reply to a paused run, `relay.py` the model API relay.
- `report_llm.py` the classification of the recorded agent runs for the evaluation tables.
- `cluster-config.md` the cluster configuration of the V5 deployment, block by block.
