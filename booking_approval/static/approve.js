/* The approval page of the Authority. Everything it shows comes from /api/pending and
   /api/object/<id>, that is from the policy and the fragment the Authority itself holds. A
   decision is a WebAuthn assertion over a challenge the Authority issued for this object and
   this decision. Embedded as the shell's side panel, it tells the shell only how many
   approvals are pending (postMessage), so the shell can open its drawer. */
"use strict";

const main = document.getElementById("main");
const POLL_MS = 2000;
let current = null;          // object id on screen, null = the list
let busy = false;            // a passkey ceremony is running, so the page is not re-rendered under it

/** Base64url <-> bytes, the encoding WebAuthn fields travel in. */
const b64u = {
  toBytes(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
               return Uint8Array.from(atob(s), c => c.charCodeAt(0)); },
  fromBytes(buf) { let s = ""; new Uint8Array(buf).forEach(b => { s += String.fromCharCode(b); });
                   return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); },
};

/** Create an element with text content only (no HTML from any field). */
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  for (const k of kids) if (k !== null && k !== undefined && k !== "") e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}

// --- display:begin (evaluated on its own by booking_v5/tests_code_closure.py) ----------------

const INVALID_AMOUNT = "invalid amount, do not approve";
// An integer up to 10^13 has at most 13 significant digits, well within the 15 to 16 a double
// holds, so minor / 10 ** digits rounded to `digits` decimals gives the exact decimal.
const MAX_MINOR = 10 ** 13;
let invalidShown = 0;                // how many amounts the current card could not show

/** An amount in minor units, shown exactly or flagged. A value that is not a plain integer, a
 *  currency that is not three capital ASCII letters, or an amount out of range is not rendered
 *  as a number. The card says so instead and the approve button stays disabled. The number of
 *  decimals comes from the currency (JPY has none). The live adapters always count two decimals
 *  (`booking_live.normalize.minor_units`), so a JPY amount from them would be shown 100 times
 *  too large. Only two-decimal currencies such as EUR are consistent end to end. */
function money(minor, currency) {
  try {
    if (!Number.isSafeInteger(minor) || minor < 0 || minor > MAX_MINOR) throw new Error("amount");
    if (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency)) throw new Error("currency");
    const digits = new Intl.NumberFormat("en", { style: "currency", currency }).resolvedOptions().maximumFractionDigits;
    return (minor / 10 ** digits).toLocaleString("en-GB", { minimumFractionDigits: digits, maximumFractionDigits: digits }) + " " + currency;
  } catch (e) {
    invalidShown += 1;
    return INVALID_AMOUNT;
  }
}

/** The arguments every step that fixes them agrees on. A key fixed to different values at
 *  different steps is left out, because one merged object would let the last step win silently. */
function agreedFixed(steps) {
  const seen = {};
  for (const s of steps) for (const [k, v] of Object.entries(s.fixed)) (seen[k] = seen[k] || new Set()).add(JSON.stringify(v));
  return Object.fromEntries(Object.entries(seen).filter(([, vs]) => vs.size === 1).map(([k, vs]) => [k, JSON.parse([...vs][0])]));
}

// --- display:end -------------------------------------------------------------------------------

async function api(path, body) {
  const init = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
                    : { cache: "no-store" };
  const r = await fetch(path, init);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data;
}

// "*" as the target origin is acceptable because the page's CSP frame-ancestors decides who
// may embed it, and the message carries only the number of pending approvals.
function tellShell(count) {
  if (window.parent !== window) window.parent.postMessage({ type: "authority-approvals", pending: count }, "*");
}

// --- views ------------------------------------------------------------------------------

function planCard(v) {
  const fixed = agreedFixed(v.steps);
  const route = fixed.origin && (fixed.to || fixed.destination) ? `${fixed.origin} → ${fixed.to || fixed.destination}` : "Plan";
  const detail = [fixed.date, fixed.cabin].filter(Boolean).join(" · ");
  const steps = v.steps.map(s => el("li", {},
    el("span", { class: "num" }, String(s.index + 1)),
    el("div", {},
      el("span", { class: "tool" }, s.tool), s.approval ? el("span", { class: "badge" }, "asks you again") : "",
      Object.keys(s.fixed).length ? el("div", { class: "rule" }, "fixed: " + Object.entries(s.fixed).map(([k, x]) => k + "=" + (typeof x === "string" ? x : JSON.stringify(x))).join(", ")) : "",
      s.checks.length ? el("details", {}, el("summary", {}, `${s.checks.length} check${s.checks.length > 1 ? "s" : ""} the monitor enforces`),
                           ...s.checks.map(c => el("div", { class: "rule" }, c))) : "")));
  return el("div", { class: "card" },
    el("div", { class: "kicker" }, "Plan approval"),
    el("h1", {}, route), detail ? el("div", { class: "sub" }, detail) : "",
    v.budget_minor != null ? el("div", { class: "chips" }, el("span", { class: "chip" }, "Budget ≤ " + money(v.budget_minor, v.currency))) : "",
    el("ol", { class: "steps" }, ...steps),
    el("div", { class: "foot" }, "Run ", el("code", {}, v.run_id), el("br"), "Policy digest ", el("code", { title: v.digest }, v.digest.slice(0, 24) + "…")));
}

function stepCard(v) {
  const a = v.arguments || {};
  const pay = /pay/.test(v.tool);
  const keys = Object.keys(a).filter(k => !(pay && (k === "amount_minor" || k === "currency"))).sort();
  return el("div", { class: "card" },
    el("div", { class: "kicker" }, pay ? "Payment approval" : `Step ${v.step + 1} approval`),
    pay && "amount_minor" in a ? el("div", { class: "amount" }, money(a.amount_minor, a.currency)) : el("h1", {}, v.tool),
    el("div", { class: "sub" }, `${v.tool} · step ${v.step + 1}` + (v.attempt ? ` · attempt ${v.attempt + 1}` : "")),
    el("dl", { class: "kv" }, ...keys.flatMap(k => [el("dt", {}, k), el("dd", {}, typeof a[k] === "string" ? a[k] : JSON.stringify(a[k]))])),
    el("div", { class: "foot" }, "Run ", el("code", {}, v.run_id), el("br"), "Fragment ", el("code", { title: v.fragment_hash }, v.fragment_hash.slice(0, 24) + "…"),
       el("br"), "The signature binds these arguments."));
}

function idle() {
  return el("div", { class: "card idle" }, el("div", { class: "dot" }), el("div", {}, "Nothing to approve."),
            el("div", { class: "sub" }, "Requests appear here as soon as the Authority records them."));
}

function listView(items) {
  return el("div", { class: "list" }, ...items.map(o => el("a", { href: "/approve/" + o.object_id },
    el("b", {}, o.view.kind === "plan" ? "Plan approval" : (/pay/.test(o.view.tool) ? "Payment approval" : `Step ${o.view.step + 1} approval`)),
    el("span", { class: "sub" }, "run " + o.view.run_id))));
}

// --- decisions --------------------------------------------------------------------------

async function decide(oid, decision, buttons, status) {
  busy = true;
  buttons.forEach(b => { b.disabled = true; });
  status.className = "status show"; status.textContent = "Confirm with your passkey…";
  try {
    const ch = await api("/api/challenge", { object_id: oid, decision });
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: b64u.toBytes(ch.challenge), rpId: ch.rp_id, timeout: ch.timeout_ms, userVerification: "required",
      allowCredentials: ch.allow.map(id => ({ type: "public-key", id: b64u.toBytes(id) })) } });
    const r = cred.response;
    const out = await api("/api/decide", { object_id: oid, decision, assertion: {
      challenge: ch.challenge, credential_id: b64u.fromBytes(cred.rawId),
      client_data_json: b64u.fromBytes(r.clientDataJSON), authenticator_data: b64u.fromBytes(r.authenticatorData),
      signature: b64u.fromBytes(r.signature) } });
    const ok = out.state === "approved";
    status.className = "status show " + (ok ? "ok" : "bad");
    status.textContent = (ok ? "Approved" : out.state === "rejected" ? "Rejected" : "Not applied") +
      ` by ${out.approver_id} (${out.approver_kind}).` + (out.state === "failed" && out.result && out.result.reason ? " " + out.result.reason : "");
    setTimeout(() => { busy = false; current = null; history.replaceState(null, "", "/"); refresh(); }, 2500);
  } catch (e) {
    status.className = "status show bad";
    status.textContent = "Nothing was recorded: " + e.message;
    buttons.forEach(b => { b.disabled = b.dataset.locked === "1"; });   // a locked approve stays locked
    busy = false;
  }
}

async function showObject(oid) {
  let o;
  try { o = await api("/api/object/" + oid); }
  catch (e) { current = null; return refresh(); }
  if (o.state !== "pending") { current = null; history.replaceState(null, "", "/"); return refresh(); }
  current = oid;
  invalidShown = 0;
  const card = o.view.kind === "plan" ? planCard(o.view) : stepCard(o.view);
  const status = el("div", { class: "status" });
  const ok = el("button", { class: "primary" }, "Approve with passkey");
  const no = el("button", {}, "Reject");
  if (invalidShown > 0) {          // a card that cannot show its amounts cannot be approved
    ok.disabled = true; ok.dataset.locked = "1";
    status.className = "status show bad";
    status.textContent = "This request carries an amount the page cannot show exactly. Reject it.";
  }
  ok.addEventListener("click", () => decide(oid, "approve", [ok, no], status));
  no.addEventListener("click", () => decide(oid, "reject", [ok, no], status));
  card.append(el("div", { class: "actions" }, ok, no), status);
  main.replaceChildren(card);
}

async function refresh() {
  if (busy) return;
  let pending = [];
  try { pending = await api("/api/pending"); } catch (e) { return; }
  tellShell(pending.length);
  if (current) {
    if (!pending.some(o => o.object_id === current)) { current = null; history.replaceState(null, "", "/"); }
    else return;                                                   // keep the page under the reader's eyes
  }
  if (pending.length === 1) return showObject(pending[0].object_id);
  main.replaceChildren(pending.length ? listView(pending) : idle());
}

// --- start --------------------------------------------------------------------------------

document.getElementById("origin").textContent = location.host;
if (!window.PublicKeyCredential) {
  main.replaceChildren(el("div", { class: "card" }, el("h1", {}, "Passkeys unavailable"),
    el("p", { class: "sub" }, "This browser offers no WebAuthn here. Open http://localhost:8450 directly.")));
} else {
  const m = location.pathname.match(/^\/approve\/([0-9a-f]{64})$/);
  if (m) showObject(m[1]); else refresh();
  setInterval(refresh, POLL_MS);
}
