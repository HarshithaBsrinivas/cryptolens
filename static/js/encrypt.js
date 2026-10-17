"use strict";

/* Tab 1: encrypt a message and show every intermediate value. */
(() => {
  const { h, fill, api, showError, cells, copyButton, scramble } = CL;
  const form = document.getElementById("enc-form");
  const out = document.getElementById("enc-out");
  const errorEl = document.getElementById("enc-error");
  const MAX_BLOCKS = 8;

  const algo = () => form.elements.algo.value;

  function syncFields() {
    const a = algo();
    document.getElementById("enc-key-field").hidden = a === "rsa-oaep";
    document.getElementById("enc-bits-field").hidden = a === "rsa-oaep" || a === "chacha20";
  }
  form.addEventListener("change", syncFields);
  syncFields();

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showError(errorEl, "");
    const payload = {
      algo: algo(),
      plaintext: form.elements.plaintext.value,
      key_bits: Number(form.elements.bits.value),
    };
    const key = form.elements.key.value.replace(/\s+/g, "");
    if (key) payload.key_hex = key;
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      render(await api("/api/encrypt", payload));
    } catch (err) {
      showError(errorEl, err.message);
    } finally {
      button.disabled = false;
    }
  });

  function line(label, node) {
    return h("div", { class: "line" }, h("span", { class: "lbl" }, label), node);
  }

  function blockCard(enc, block) {
    const isRsa = enc.algo === "rsa-oaep";
    const isCbc = enc.algo === "aes-cbc";
    const isStream = enc.algo === "aes-gcm" || enc.algo === "chacha20";
    const lines = [];
    const padFrom = block.pad_bytes ? 16 - block.pad_bytes : null;

    lines.push(line("Plaintext", cells(block.plaintext_hex, { chars: true, padFrom, max: 24 })));
    if (isCbc) lines.push(line(block.index === 0 ? "XOR with IV" : "XOR with previous ciphertext", cells(block.xor_with_hex)));
    if (isCbc) lines.push(line("AES input", cells(block.input_hex)));
    if (enc.algo === "aes-gcm") lines.push(line("Counter", cells(block.counter_hex)));
    if (isStream) lines.push(line(enc.algo === "aes-gcm" ? "AES of counter (keystream)" : "Keystream", cells(block.keystream_hex)));
    lines.push(
      line(
        isStream ? "Plaintext XOR keystream" : isRsa ? "Ciphertext" : "AES output",
        cells(block.ciphertext_hex, { cls: "cipher", max: isRsa ? 32 : 24 })
      )
    );

    const title = isRsa ? "Whole message" : `Block ${block.index + 1}`;
    return h("article", { class: "blockcard" }, h("h4", {}, title), lines);
  }

  function render(enc) {
    const blocks = enc.blocks.slice(0, MAX_BLOCKS);
    const hiddenBlocks = enc.blocks.length - blocks.length;
    const isRsa = enc.algo === "rsa-oaep";

    const keyLabel = isRsa ? `Public key (n, ${enc.key_bits} bits, e = ${enc.exponent})` : `Key (${enc.key_bits} bits)`;
    const facts = [
      h("div", {}, h("dt", {}, keyLabel), h("dd", { class: "mono wrap" }, isRsa ? enc.key_hex.slice(0, 64) + "..." : enc.key_hex)),
    ];
    if (enc.iv_hex) facts.push(h("div", {}, h("dt", {}, enc.iv_label), h("dd", { class: "mono wrap" }, enc.iv_hex)));
    if (enc.tag_hex) facts.push(h("div", {}, h("dt", {}, "Authentication tag"), h("dd", { class: "mono wrap" }, enc.tag_hex)));

    const cipherNode = cells(enc.ciphertext_hex, { cls: "cipher", max: 64 });
    const decryptBox = h("div", { class: "result", hidden: true, "aria-live": "polite" });

    const run = async (tamper) => {
      const payload = {
        algo: enc.algo,
        key_hex: isRsa ? undefined : enc.key_hex,
        iv_hex: enc.iv_hex || undefined,
        tag_hex: enc.tag_hex || undefined,
        ciphertext_hex: enc.ciphertext_hex,
      };
      let index = null;
      if (tamper) {
        index = Math.floor(Math.random() * (enc.ciphertext_hex.length / 2));
        payload.tamper_index = index;
      }
      try {
        const res = await api("/api/decrypt", payload);
        const good = tamper ? res.detected : res.ok;
        const bad = tamper && !res.detected;
        decryptBox.className = `result ${good ? "good" : bad ? "bad" : "warn"}`;
        decryptBox.hidden = false;
        fill(
          decryptBox,
          h("p", { class: "verdict" },
            tamper ? `One bit changed in byte ${index + 1}. ` : "",
            res.message),
          res.plaintext_hex
            ? h("p", { class: "recovered" }, h("span", { class: "lbl" }, "Result"), h("q", {}, res.plaintext))
            : null
        );
      } catch (err) {
        decryptBox.className = "result bad";
        decryptBox.hidden = false;
        decryptBox.replaceChildren(h("p", { class: "verdict" }, err.message));
      }
    };

    fill(
      out,
      h("h3", { class: "first" }, enc.label),
      h("dl", { class: "facts" }, facts),
      h("h3", {}, "Message as bytes"),
      line("Plaintext", cells(enc.plaintext_hex, { chars: true, max: 64 })),
      enc.padded_hex ? h("p", { class: "small" }, "Shaded bytes are padding added so the message fills whole 16-byte blocks.") : null,
      h("h3", {}, isRsa ? "Encryption" : "Block by block"),
      h("div", { class: "blocks" }, blocks.map((b) => blockCard(enc, b))),
      hiddenBlocks > 0 ? h("p", { class: "small" }, `${hiddenBlocks} more block${hiddenBlocks > 1 ? "s" : ""} not shown.`) : null,
      h("h3", {}, "Ciphertext"),
      h("div", { class: "cipherrow" }, cipherNode, copyButton(() => enc.ciphertext_hex, "Copy hex")),
      h("ul", { class: "notes-list" }, enc.notes.map((n) => h("li", {}, n))),
      h("h3", {}, "Try to break it"),
      h("div", { class: "actions" },
        h("button", { class: "btn secondary", type: "button", onclick: () => run(false) }, "Decrypt"),
        h("button", { class: "btn secondary", type: "button", onclick: () => run(true) }, "Change one bit, then decrypt")),
      decryptBox
    );
    scramble(cipherNode.querySelectorAll(".b i"));
  }
})();
