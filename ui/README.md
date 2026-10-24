# ui: Open WebUI in front of the agent, an approval panel beside it

Chat and approval share only the browser. A chat message reaches `agent_api.py`,
which starts one run through the dashboard's launcher and streams the run record back. A
decision in the local panel reaches `approval_api.py`, which shows the pending record (built from the compiled
policy and the monitor's fragment) and writes the answer with the request's `approval_id` and
`policy_hash`. The runner (`booking_demo/run.py`) accepts only an answer that names its request
(`booking_demo/approval_record.py`).

    ui/
    ├── agent_api.py          OpenAI-compatible facade → booking_demo.run (port 8767)
    ├── approval_api.py       facade over approval-request.json and approval.json (port 8766)
    ├── approval-ui/          shell.html: Open WebUI in an iframe and the approval drawer (one view)
    │                         index.html: the local panel alone (/panel), polls pending every 1.5 s
    ├── docker-compose.yml    Open WebUI, pointed at the facade
    ├── tests_ui.py           a chat message cannot approve, the panel accepts only the pending request
    └── tests_session_edges.py  pause and resume, cross-conversation, pending approval, CSRF, orphan

An answer is bound to one request, but that does not make its sender an approver.
`approval_id` and `policy_hash` tie an answer to one pending request. Both must match, the
request must be unused and current, and what is approved is the server's stored record. Amount,
tool and order in the body are ignored. Locally the panel counts as the trusted human channel,
because it listens on loopback and one person uses it. Over a network, set `APPROVAL_TOKEN` and
open the panel as `http://host:8766/#token=<token>`. The token is a proof-of-concept
placeholder for an approver identity.

"Trusted" on the approval path means trusted against the conversation: nothing there comes from
the chat. It does not mean attested. The request file is written by the controller, which the
threat model treats as untrusted. In the local panel the human signs the digest and reads what
the page renders from that file, outside the TCB. With the WebAuthn gate on the cluster path
the Authority renders its own approval page (`booking_approval.surface`), and the shell only
embeds it.

The injection comes from the demo controls, not from a second model. They switch the external
input of the next run between benign and indirect prompt injection
(`results_v5/demo/demo-controls.json`, read by `agent_api.py` when it starts the run). The
request, the agent, the policy and the deployment stay the same. Only the untrusted observation
differs.

The second demo control is the attacker on the node beneath the runner (`a10` forged boot key,
`a16` tampered fragment, `a18` wrong substrate, from `booking_demo/attacks.py`, catalogued in
`scripts/gke-v5/attack_catalogue.md`). It works on the attested modes only. `a16` runs as a
throwaway run before the real one, while `a10` and `a18` are an extra attempt at the first step
of the real run. The chat narrates the refusal with the ledger delta. This shows what the
attested path adds over the monitor, because the refusal comes from the TD or the relying
party and not from a policy check.

Run, from the repository root:

    export OPENAI_API_KEY=sk-...             # the agent's brain (AGENT_BRAIN=openai|anthropic|scripted)
    export DUFFEL_TOKEN=duffel_test_...      # only for the duffel worlds
    python3 -m ui.approval_api               # http://localhost:8766/
    python3 -m ui.agent_api --host 0.0.0.0   # http://localhost:8767/v1
    docker compose -f ui/docker-compose.yml up   # Open WebUI on http://localhost:3000/
    open http://localhost:8766/                  # the one view: chat and approval drawer. Pick the model v3-duffel

The one view is a shell on the approval origin. Open WebUI is an iframe with its own origin and
backend, reaching only the agent facade. The drawer beside it shows one of two pages. By
default it is the local panel, which is the case on the local path. On the cluster path start
the facade with `--authority-url http://localhost:8450/`, the port-forward of
`scripts/gke-v5/49_approval_page.sh`, and the drawer embeds the Authority's approval page. The
choice is explicit, so a foreign process on that port is never embedded by accident.

With the local panel, only the drawer talks to the approval API. The drawer opens itself when
the API reports a pending request and closes when it is answered. With the Authority's page,
the only message the shell accepts is a count of pending approvals from that frame and origin.
The shell ignores anything the chat frame sends. `?chat=<url>` points the shell at another
Open WebUI, and `#token=` passes to the local panel.

The "models" Open WebUI offers are the run configurations: `v0-mock`, `v3-mock`, `v3-duffel`,
`v5-local-mock`, `v5-local-duffel` and `v5-duffel`. The last is the CoCo cluster, through
`scripts/gke-v5/33_demo_v5.sh`. It needs the kube context `v5-controller`, the admin context as
the current one and a gcloud project. The facade checks that before it starts anything and says
in the chat what is missing. On the cluster the credential stays in OpenBao behind the gateway,
and the v5 runs start without `DUFFEL_TOKEN`. The local duffel modes take `DUFFEL_TOKEN` from
the environment of `agent_api.py`. A second message while a run waits is answered with "no
effect". The words `approve`, `already approved` and the like are a task like any other and not
an answer. The dashboard (`booking_demo.serve`, port 8765) still works next to it and writes the
same bound answer.

    python3 -m unittest ui.tests_ui ui.tests_session_edges

Continuation. When the agent stops before the approved plan is done, the run pauses in
`WAITING_FOR_USER_CONTINUATION` and the chat turn ends with a fixed answer built from the signed
state ("The order ord_… (50.11 EUR) has been created and is ready for payment. Tell me when you
want to continue with the payment."). The next message of the same conversation resumes that
run. It does not plan again, does not change the policy and is not an approval, so the payment
still asks in the panel. The facade finds the run by its launch id, not by `latest`, and binds
it to the conversation (`X-OpenWebUI-Chat-Id`, forwarded because the compose file sets
`ENABLE_FORWARD_USER_INFO_HEADERS`). Without that header the demo assumes one local operator.
A pause takes one reply, and a second reply to it is refused. A pause whose controller is gone
is named `PAUSED_ORPHANED`. The run stays ACTIVE at the Authority without a grant and cannot be
resumed. A run that ended COMPLETED, TERMINATED or EFFECT_UNCERTAIN is not resumed. A new
message starts a new run with a new plan, and an uncertain payment is reconciled instead of
being retried from the chat.

Hygiene. Every POST of the three servers must be `application/json`. A browser cannot send that
cross-origin without a preflight nobody answers. When a browser names an Origin, it must be one
of the server's own (`booking_demo/http_guard.py`). Answers are written with O_EXCL, so two
tabs, a double click or approve against reject from two processes decide once. The panel lists
pending requests of every run, not only of `latest`. Identity is out of scope. There is a single
local operator, and `APPROVAL_TOKEN` is the placeholder. In the local panel what the human
reads is rendered outside the Authority, which is a known limit. The chat history is not
runtime state, because the facade keeps the run binding in its own memory.

Edges to know when running it live:

- Stopping the stream in Open WebUI does not stop the run. It keeps waiting for the panel.
- A repeated or regenerated message is a new run, and live runs are budgeted per server start.
  The first line of the stream counts them.
- A second message while a run is in progress (and not paused for a continuation) is answered
  with what that run is waiting for and has no effect.
- A request without a decision within the runner's timeout (300 s by default) counts as not
  approved, and the card shows the time left.
- Two windows may both show a request. The first decision wins and the other window sees
  "already decided".
- A card whose request expired or was replaced says "Expired or no longer pending" and stays
  disabled.
- A page reload shows a pending request again under the same id.
