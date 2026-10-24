/* Enrolment: navigator.credentials.create on the approval origin, and the public key back to
   the enrolment listener. getPublicKey() gives the SPKI the Authority pins (Firefox 119+,
   Chrome, Safari). The one-time code comes from the URL fragment, is sent only as a header and
   is removed from the address bar. The key's fingerprint is shown before the key is sent, so
   the operator can compare it with the terminal prompt that decides whether it is pinned. */
"use strict";

const b64u = {
  toBytes(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
               return Uint8Array.from(atob(s), c => c.charCodeAt(0)); },
  fromBytes(buf) { let s = ""; new Uint8Array(buf).forEach(b => { s += String.fromCharCode(b); });
                   return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); },
};
const status = document.getElementById("status");
const go = document.getElementById("go");
const code = new URLSearchParams(location.hash.slice(1)).get("code") || "";
history.replaceState(null, "", location.pathname);

/** First 24 hex digits of SHA-256 over the SPKI, in groups of four (same as the terminal). */
async function fingerprint(spki) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
  const hex = Array.from(d, b => b.toString(16).padStart(2, "0")).join("").slice(0, 24);
  return hex.match(/.{4}/g).join("-");
}

async function register() {
  go.disabled = true;
  status.className = "status show"; status.textContent = "Waiting for your authenticator…";
  try {
    const headers = { "X-Enroll-Code": code };
    const optRes = await fetch("/api/options", { headers });
    if (!optRes.ok) throw new Error("enrolment code missing or wrong, open the link from the terminal");
    const opt = await optRes.json();
    document.getElementById("who").textContent = "Register a passkey for " + opt.approver;
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: b64u.toBytes(opt.challenge),
      rp: { id: opt.rp_id, name: "Thesis V5 Authority" },
      user: { id: b64u.toBytes(opt.user_id), name: opt.approver, displayName: opt.approver },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }],
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      attestation: "none", timeout: 120000 } });
    const r = cred.response;
    if (typeof r.getPublicKey !== "function" || typeof r.getAuthenticatorData !== "function")
      throw new Error("this browser does not expose getPublicKey() and getAuthenticatorData()");
    const spki = r.getPublicKey();
    status.textContent = "Key " + await fingerprint(spki) + ". Confirm it in the terminal…";
    const res = await fetch("/api/register", { method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify({ credential_id: b64u.fromBytes(cred.rawId), public_key: b64u.fromBytes(spki),
        algorithm: r.getPublicKeyAlgorithm(), client_data_json: b64u.fromBytes(r.clientDataJSON),
        authenticator_data: b64u.fromBytes(r.getAuthenticatorData()) }) });
    const out = await res.json();
    if (!res.ok) throw new Error(out.error || res.status);
    status.className = "status show ok"; status.textContent = "Registered for " + out.approver_id + ". You can close this tab.";
  } catch (e) {
    status.className = "status show bad"; status.textContent = "Not registered: " + e.message;
    go.disabled = false;
  }
}
go.addEventListener("click", register);
