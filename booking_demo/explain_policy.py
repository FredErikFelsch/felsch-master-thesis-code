"""Make a policy readable: what each step of a plan is allowed to do, and why.

A policy is hard to read as data. This module renders any policy in plain English, step by
step, showing for each step the local limits, the cross-step bindings (which argument must
match which observed fact), the facts it records for later steps, the post-conditions on its
reply, and whether a human must approve it.

It also shows plan compilation. Given a plan (a subset of steps in some order, a budget, and
which steps a human approves), it prints the compiled policy and the review, so a person sees
which checks survive and which are dropped because the fact they rely on is no longer
produced by an earlier step. A dropped check becomes a human approval at that step, and the
review says so.

    python3 -m booking_demo.explain_policy
        the fixed policy the demo enforces (search, select, book, pay), in plain English

    python3 -m booking_demo.explain_policy --plan search,select,book,pay --budget 40000
        the same flow, compiled from a plan, with the review

    python3 -m booking_demo.explain_policy --plan book,pay --budget 40000
        a shorter plan: see which checks it gives up and where it now needs a human

    python3 -m booking_demo.explain_policy --json
        the compiled policy as canonical JSON (what the digest is taken over)

    python3 -m booking_demo.explain_policy --app devops --plan list_deployments,restart_deployment
        the on-call cluster application, same compiler, its own step library
"""
from __future__ import annotations

import argparse
import json

from booking_v2.policy import Policy

from .plan import Plan, compile_plan
from .profile import APPLICATIONS, profile as load_profile


# --- plain-English renderers, one per registered kind ------------------------------------
# Each returns a sentence a person approving the policy can act on. The wording matches what
# the monitor checks. The renderers only read the policy data.

def _minor(v: int) -> str:
    return f"{v / 100:.2f}"


def render_binding(kind: str, p: dict) -> str:
    """Render one cross-step binding as a sentence."""
    if kind == "arg_equals_fact":
        return f"its `{p['arg']}` must equal the observed fact `{p['fact']}`"
    if kind == "arg_in_fact_set":
        return f"its `{p['arg']}` must be one of the observed `{p['fact']}`"
    if kind == "arg_affordable":
        return (f"the observed price of `{p['arg']}` (from `{p['price_fact']}`) must be at most "
                f"{_minor(p['ceiling'])} (budget)")
    if kind == "arg_affordable_bounded":
        bound = f" and at most {_minor(p['ceiling'])} (budget)" if "ceiling" in p else ""
        return f"the observed price of `{p['arg']}` (from `{p['price_fact']}`) must be non-negative{bound}"
    if kind == "arg_maps_to_const":
        return f"the observed `{p['map_fact']}` of `{p['arg']}` must equal {p['expected']!r}"
    if kind == "arg_equals_const":
        return f"`{p['arg']}` must be the approved {p['expected']!r}"
    return f"{kind} {p}"


def render_producer(kind: str, p: dict) -> str:
    """Render one recorded fact as a sentence."""
    if kind == "field":
        return f"records `{p['name']}` = the reply's `{p['payload_key']}` ({p['ftype']})"
    if kind == "arg_field":
        return f"records `{p['name']}` = the argument `{p['arg']}` it was called with ({p['ftype']})"
    if kind == "set_of_field":
        return f"records the set `{p['name']}` = every `{p['item_key']}` in the reply's `{p['payload_list_key']}`"
    if kind == "map_of_fields":
        return f"records the map `{p['name']}` = `{p['key_field']}` -> `{p['value_field']}` from the reply's `{p['payload_list_key']}`"
    return f"{kind} {p}"


def render_post(kind: str, p: dict) -> str:
    """Render one post-condition on a reply as a sentence."""
    if kind == "produced_equals_fact":
        return f"the recorded `{p['produced']}` must equal the earlier fact `{p['fact']}`"
    if kind == "produced_equals_map_lookup":
        return f"the recorded `{p['produced']}` must equal `{p['map_fact']}`[`{p['key_fact']}`]"
    if kind == "produced_equals_const":
        return f"the reply must confirm `{p['produced']}` == {p['expected']!r}"
    return f"{kind} {p}"


def render_local(spec, budget_minor: int, currency: str) -> str:
    """Render one local limit as a sentence."""
    c = spec.canonical()
    if c.get("kind") == "budget_ceiling":
        p = c.get("params", {})
        return (f"its `{p.get('amount_param', 'amount')}` must be within the budget "
                f"of {_minor(budget_minor)} {currency}")
    p = c.get("params", {})
    return c.get("kind", "local") + (": " + "; ".join(f"{k}={v}" for k, v in p.items()) if p else "")


def step_rules(policy) -> list[dict]:
    """Return the rules of a policy per step, as data for the dashboard.

    Each row says what the monitor checks before the step runs, what must hold after its
    reply, what it records, and whether a person decides. The policy is a Policy or a
    Policy3 (approval marks are read from the latter). Step numbers in the rows are 0-based.
    """
    base = getattr(policy, "base", policy)
    approvals = set(getattr(policy, "approval_required_steps", ()))
    rows = []
    for i, tool in enumerate(base.allowed_flow):
        local = base.local_at(i)
        rows.append({
            "step": i, "tool": tool, "approval": i in approvals,
            "before": ([render_local(local, base.budget_minor, base.currency)] if local else [])
                      + [render_binding(b.kind, dict(b.params)) for b in base.bindings_at(i)],
            "after": [render_post(q.kind, dict(q.params)) for q in base.postconditions_at(i)],
            "records": [render_producer(p.kind, dict(p.params)) for p in base.producers_at(i)],
        })
    return rows


def explain(policy: Policy, approval_steps: set[int]) -> str:
    """Render the policy as a numbered walk over its steps.

    Args:
        policy: The policy to render.
        approval_steps: The 0-based indices of the steps a human approves.

    Returns:
        The text, with steps numbered from 1.
    """
    out = []
    out.append(f"Task     : {policy.task}")
    out.append(f"Flow     : {' -> '.join(policy.allowed_flow)}")
    if policy.budget_minor:
        out.append(f"Budget   : {_minor(policy.budget_minor)} {policy.currency} (ceiling on the payment)")
    out.append(f"Digest   : {policy.digest()[:16]}...  (any change to the policy changes this)")
    out.append("")
    for i, tool in enumerate(policy.allowed_flow):
        head = f"Step {i + 1}: {tool}"
        if i in approval_steps:
            head += "   [a human must approve before this runs]"
        out.append(head)
        local = policy.local_at(i)
        if local:
            out.append(f"    before it runs, local limit : {render_local(local, policy.budget_minor, policy.currency)}")
        binds = policy.bindings_at(i)
        for b in binds:
            out.append(f"    before it runs, binding     : {render_binding(b.kind, dict(b.params))}")
        if not local and not binds:
            out.append("    before it runs              : nothing to check (no argument is security-relevant here)")
        posts = policy.postconditions_at(i)
        for q in posts:
            out.append(f"    after the reply, must hold  : {render_post(q.kind, dict(q.params))}")
        prods = policy.producers_at(i)
        for pr in prods:
            out.append(f"    on success, {render_producer(pr.kind, dict(pr.params))}")
        out.append("")
    return "\n".join(out)


def explain_review(review) -> str:
    """Render the review of a compiled plan: which checks were kept and which were given up."""
    out = ["Plan review (what compiling this plan kept and gave up):"]
    if review.grounded:
        out.append(f"  kept {len(review.grounded)} check(s) whose fact an earlier step produces")
    if review.ungrounded:
        out.append("  dropped, because the fact they need is not produced earlier in this plan:")
        for (i, tool, kind, facts) in review.ungrounded:
            out.append(f"    step {i + 1} ({tool}): {kind} on {', '.join(facts)}")
    for (i, tool, lost) in review.unsourced_steps:
        out.append(f"  -> step {i + 1} ({tool}) now needs a human decision, because it lost: {', '.join(lost)}")
    for note in review.notes:
        out.append(f"  note: {note}")
    if not review.ungrounded and not review.notes:
        out.append("  nothing dropped: every check is grounded in an earlier step.")
    return "\n".join(out)


def main(argv=None) -> int:
    """Run the command line (see the module docstring for the invocations). Returns 0."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app", choices=APPLICATIONS, default="booking", help="the application profile")
    ap.add_argument("--plan", default=None,
                    help="comma list of the application's tools to compile and explain (default: the fixed policy)")
    ap.add_argument("--budget", type=int, default=40000, help="budget ceiling in minor units (default 40000 = 400.00)")
    ap.add_argument("--approve", default=None, help="comma list of steps a human approves (default: the application's)")
    ap.add_argument("--json", action="store_true", help="print the compiled policy as canonical JSON instead")
    args = ap.parse_args(argv)
    app = load_profile(args.app)

    if args.plan is None:
        policy3 = app.fixed_policy()
        policy, approval = policy3.base, set(policy3.approval_required_steps)
        if args.json:
            print(json.dumps(policy._canonical(), indent=2))
            return 0
        print(explain(policy, approval))
        print("This is the fixed policy. In `--plan agent` mode the agent proposes the plan and a")
        print("human approves it. The approved plan compiles into a policy of this shape.")
        return 0

    steps = tuple(s.strip() for s in args.plan.split(",") if s.strip())
    approve = (tuple(s.strip() for s in args.approve.split(",") if s.strip()) if args.approve is not None
               else tuple(a for a in app.default_approvals if a in steps))
    plan = Plan(steps=steps, budget_minor=args.budget if app.has_budget else 0, approval_steps=approve)
    policy3, review = compile_plan(plan, app)
    base = policy3.base
    approval = set(policy3.approval_required_steps)
    if args.json:
        print(json.dumps(base._canonical(), indent=2))
        return 0
    print("PROPOSED PLAN")
    print(f"  steps  : {' -> '.join(plan.steps)}")
    print(f"  budget : {_minor(plan.budget_minor)} {plan.currency}")
    print(f"  approve: {', '.join(plan.approval_steps) or 'none'}")
    print()
    print("COMPILED POLICY")
    print(explain(base, approval))
    print(explain_review(review))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
