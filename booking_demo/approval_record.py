"""The approval record: what a pending request is, and the id an answer must carry.

The runner writes `approval-request.json` and waits for `approval.json`. Every request has
an `approval_id` derived from the run and from the object being approved (the policy digest
of a plan, the fragment hash of a step). The answer must repeat that id, and the runner
ignores an answer that names another request. A bare `{"granted": bool}` would let any file
of that shape, written at any time, count as an approval. A trusted front end
(ui/approval_api.py) shows the record and checks the id and the policy hash before it writes
the answer. The chat never sees these files.
"""
from __future__ import annotations

import hashlib
from typing import Any


def approval_id(run_id: str, req: dict) -> str:
    """Return the id of one request: sha256 over the run and the approved object.

    Args:
        run_id: The run the request belongs to (`demo-<stamp>`).
        req: The request the session hands to its hook (kind "plan", or a step request
            with `fragment_hash` and `seq`).

    Returns:
        A hex digest. Two requests of one run for the same object get the same id, which
        is intended: the answer is bound to the object, not to a counter.
    """
    if req.get("kind") == "plan":
        subject = f"plan|{req['policy']['digest']}"
    else:
        subject = f"step|{req['seq']}|{req['fragment_hash']}"
    return hashlib.sha256(f"{run_id}|{subject}".encode()).hexdigest()


def policy_hash(req: dict) -> str:
    """Return the policy digest a request is bound to.

    For a plan this is the compiled policy. For a step it is the policy the run executes
    under, put there by the session.
    """
    if req.get("kind") == "plan":
        return str(req["policy"]["digest"])
    return str(req.get("policy_hash", ""))


def pending_record(run: str, req: dict) -> dict[str, Any]:
    """Build the trusted view of a request for a front end.

    Everything in it comes from the compiled policy or from the monitor's fragment, not
    from a model message: the parameters, budget and effects of a task approval are the
    `approved_policy` view (session.approved_policy_view), the order and amount of a
    payment approval are the arguments of the fragment the Authority will sign.

    Args:
        run: The run directory name (the front end answers by run).
        req: The request as written to `approval-request.json`.

    Returns:
        A JSON-serialisable record with `approval_id`, `kind` ("task" or "step"),
        `policy_hash` and the fields to display.
    """
    rec: dict[str, Any] = {"approval_id": req["approval_id"], "run": run,
                           "policy_hash": policy_hash(req),
                           "requested_at": req.get("requested_at"), "timeout": req.get("timeout")}
    if req.get("kind") == "plan":
        ap = req.get("approved_policy") or {}
        rec.update(kind="task", parameters=ap.get("parameters", {}),
                   budget_minor=ap.get("budget_minor"), currency=ap.get("currency"),
                   steps=ap.get("steps", []), trusted_config=req.get("trusted_config", {}),
                   planning_context=req.get("planning_context", {}),
                   # What the compiled policy cannot check in this plan (compile_plan's review).
                   # The human is the check for a plan's shape, so the human must see this.
                   review={"notes": list((req.get("review") or {}).get("notes", [])),
                           "unsourced_steps": list((req.get("review") or {}).get("unsourced_steps", []))})
    else:
        rec.update(kind="step", seq=req["seq"], step=req["step"], tool=req["tool"],
                   arguments=dict(req.get("arguments", {})), fragment_hash=req["fragment_hash"])
    return rec


def answer_matches(req: dict, answer: dict) -> bool:
    """Return whether `approval.json` answers this request.

    The answer must carry this request's `approval_id`. A `policy_hash`, when present, must
    equal the request's. An answer without one is not checked on the hash.

    Args:
        req: The pending request.
        answer: The parsed `approval.json`.

    Returns:
        True when the answer belongs to the request.
    """
    return (bool(answer.get("approval_id"))
            and answer.get("approval_id") == req.get("approval_id")
            and answer.get("policy_hash", policy_hash(req)) == policy_hash(req))
