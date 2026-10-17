"use strict";

/* Tab 4: Diffie-Hellman handshake, optional man-in-the-middle, optional signatures. */
(() => {
  const { h, api, showError, spacedHex } = CL;
  const form = document.getElementById("hs-form");
  const out = document.getElementById("hs-out");
  const errorEl = document.getElementById("hs-error");

  const NAMES = { alice: "Alice", bob: "Bob", mallory: "Mallory" };
  const KIND_LABEL = { key: "Public key", cipher: "Encrypted", check: "Check", alert: "Alert" };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showError(errorEl, "");
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const res = await api("/api/handshake", {
        attacker: document.getElementById("hs-attacker").checked,
        authenticated: document.getElementById("hs-auth").checked,
        message: document.getElementById("hs-msg").value,
      });
      render(res);
    } catch (err) {
      showError(errorEl, err.message);
    } finally {
      button.disabled = false;
    }
  });

  function party(id, active) {
    return h("div", { class: `party ${id}${active ? "" : " absent"}` }, h("b", {}, NAMES[id]));
  }

  function badge(step) {
    if (step.ok === true) return h("span", { class: "tag good" }, step.kind === "alert" ? "Bad for Alice and Bob" : "Passed");
    if (step.ok === false) return h("span", { class: "tag bad" }, step.kind === "alert" ? "Bad for Alice and Bob" : "Failed");
    return null;
  }

  function stepNode(step, index) {
    const talk = step.from === step.to;
    const direction = talk
      ? h("span", { class: "dir" }, NAMES[step.from], " computes")
      : h("span", { class: "dir" }, NAMES[step.from], " ", h("span", { "aria-label": "to" }, "→"), " ", NAMES[step.to]);
    // A step that Mallory performs and that helps her is not a pass or a fail for the victims.
    const tag =
      step.from === "mallory" && step.kind === "alert" ? h("span", { class: "tag bad" }, "Mallory succeeds") :
      step.from === "mallory" && step.kind === "check" && step.ok === true ? null : badge(step);
    return h("li", { class: `step ${step.kind} from-${step.from}`, style: `--i:${index}` },
      h("div", { class: "head" }, direction, tag),
      h("p", { class: "title" }, step.title),
      h("p", { class: "detail" }, step.detail),
      step.values.length
        ? h("dl", { class: "vals" }, step.values.map((v) =>
            h("div", {}, h("dt", {}, v.label), h("dd", { class: "mono wrap" }, v.label === "Plaintext" ? textOf(v.hex) : spacedHex(v.hex)))))
        : null
    );
  }

  function textOf(hex) {
    const bytes = new Uint8Array(hex.match(/../g).map((b) => parseInt(b, 16)));
    return new TextDecoder().decode(bytes);
  }

  function outcomeBox(res) {
    const o = res.outcome;
    const cls = !res.attacker ? "good" : o.detected ? "good" : "bad";
    const rows = [];
    rows.push(h("div", {}, h("dt", {}, "What Bob received"), h("dd", {}, o.bob_received === null ? "Nothing. The connection was refused." : h("q", {}, o.bob_received))));
    if (res.attacker) rows.push(h("div", {}, h("dt", {}, "What Mallory read"), h("dd", {}, o.mallory_read === null ? "Nothing." : h("q", {}, o.mallory_read))));
    const prints = res.fingerprints && res.fingerprints.alice
      ? h("p", { class: "small" }, `Identity fingerprints Bob and Alice trust: Alice ${res.fingerprints.alice}, Bob ${res.fingerprints.bob}.`)
      : null;
    return h("div", { class: `result ${cls}` }, h("p", { class: "verdict" }, o.verdict), h("dl", { class: "outcome" }, rows), prints);
  }

  function render(res) {
    const withMallory = res.attacker;
    const stage = h("div", { class: `stage${withMallory ? " three" : ""}`, role: "img",
      "aria-label": withMallory ? "Alice talks to Bob through Mallory" : "Alice talks directly to Bob" },
      party("alice", true),
      h("div", { class: "wire" }),
      party("mallory", withMallory),
      h("div", { class: "wire" }),
      party("bob", true));

    out.replaceChildren(
      h("h3", { class: "first" }, withMallory ? (res.authenticated ? "With an attacker, signatures on" : "With an attacker, no signatures") : (res.authenticated ? "No attacker, signatures on" : "No attacker, no signatures")),
      stage,
      h("ol", { class: "steps" }, res.steps.map(stepNode)),
      outcomeBox(res)
    );
  }
})();
