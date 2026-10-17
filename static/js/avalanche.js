"use strict";

/* Tab 2: avalanche effect heatmap and histogram of every possible single-bit flip. */
(() => {
  const { h, api, showError, cells, debounce, cssVar, number } = CL;
  const prim = document.getElementById("av-prim");
  const msg = document.getElementById("av-msg");
  const bit = document.getElementById("av-bit");
  const bitLabel = document.getElementById("av-bit-label");
  const errorEl = document.getElementById("av-error");
  const hist = document.getElementById("av-hist");
  let lastSweep = null;
  let started = false;

  function paintGrid(el, bits, kind, diff) {
    const cols = 16;
    el.style.setProperty("--cols", cols);
    el.replaceChildren(
      ...bits.map((value, i) =>
        h("span", { class: kind === "diff" ? (value ? "cell on" : "cell") : value ? "cell one" : "cell zero", title: `bit ${i + 1}: ${value}` })
      )
    );
    if (diff) el.classList.add("diff");
  }

  function sizeAxes() {
    const isKey = prim.value === "aes-key";
    const isHash = prim.value === "sha256";
    const maxBit = isHash ? Math.max(0, new TextEncoder().encode(msg.value.slice(0, 64)).length * 8 - 1) : 127;
    bit.max = String(maxBit);
    if (Number(bit.value) > maxBit) bit.value = String(maxBit);
    document.getElementById("av-msg-hint").textContent = isKey
      ? "This text is the block being encrypted. The flipped bit is in the key."
      : isHash
      ? "SHA-256 accepts any length. Only the first 64 characters are used here."
      : "AES works on 16-byte blocks, so only the first 16 characters are used.";
  }

  async function update() {
    sizeAxes();
    showError(errorEl, "");
    try {
      const d = await api("/api/avalanche", { primitive: prim.value, message: msg.value, bit: Number(bit.value) });
      bitLabel.textContent = `Flip bit ${d.bit + 1} of ${d.input_bits}`;
      document.getElementById("av-input-note").textContent =
        prim.value === "aes-key" ? "The key below has one bit flipped. Changed bit is highlighted." : "The input below has one bit flipped. Changed bit is highlighted.";
      renderInput(d);
      paintGrid(document.getElementById("av-before"), d.original_bits, "plain");
      paintGrid(document.getElementById("av-after"), d.flipped_bits, "plain");
      paintGrid(document.getElementById("av-diff"), d.diff_bits, "diff");
      document.getElementById("av-stat").innerHTML = "";
      document.getElementById("av-stat").append(
        h("b", {}, `${d.changed} of ${d.output_bits} output bits changed (${d.percent}%).`),
        " A perfect avalanche is 50%."
      );
      lastSweep = d;
      drawHist(d);
    } catch (err) {
      showError(errorEl, err.message);
    }
  }

  function renderInput(d) {
    const wrap = document.getElementById("av-input");
    const original = d.input_hex;
    const flipped = d.flipped_input_hex;
    const byteIndex = Math.floor(d.bit / 8);
    const make = (hex, label) => {
      const row = h("div", { class: "line" }, h("span", { class: "lbl" }, label), cells(hex, { max: 32 }));
      const target = row.querySelectorAll(".b")[byteIndex];
      if (target) target.classList.add("hit");
      return row;
    };
    wrap.replaceChildren(make(original, "Before"), make(flipped, "After"));
  }

  function drawHist(d) {
    const dpr = window.devicePixelRatio || 1;
    const cssW = hist.clientWidth || 600;
    const cssH = 150;
    hist.width = cssW * dpr;
    hist.height = cssH * dpr;
    hist.style.height = cssH + "px";
    const ctx = hist.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);

    const n = d.output_bits;
    const counts = new Array(n + 1).fill(0);
    d.sweep.forEach((v) => counts[v]++);
    const lo = Math.max(0, Math.floor(n * 0.25));
    const hi = Math.min(n, Math.ceil(n * 0.75));
    const peak = Math.max(...counts.slice(lo, hi + 1), 1);
    const padL = 28, padB = 24, padT = 8, padR = 6;
    const plotW = cssW - padL - padR;
    const plotH = cssH - padB - padT;
    const barW = plotW / (hi - lo + 1);
    const ink = cssVar("--ink"), muted = cssVar("--muted"), bar = cssVar("--flip"), line = cssVar("--line");

    ctx.font = "11px system-ui, sans-serif";
    ctx.fillStyle = muted;
    ctx.strokeStyle = line;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padL, padT + plotH + 0.5);
    ctx.lineTo(cssW - padR, padT + plotH + 0.5);
    ctx.stroke();

    for (let v = lo; v <= hi; v++) {
      const x = padL + (v - lo) * barW;
      const height = (counts[v] / peak) * plotH;
      ctx.fillStyle = v === d.changed ? ink : bar;
      ctx.fillRect(x + 0.5, padT + plotH - height, Math.max(1, barW - 1), height);
    }

    ctx.fillStyle = muted;
    ctx.textAlign = "center";
    const mid = n / 2;
    const midX = padL + (mid - lo + 0.5) * barW;
    ctx.fillText(`${mid} (half)`, midX, cssH - 8);
    ctx.textAlign = "left";
    ctx.fillText(String(lo), padL, cssH - 8);
    ctx.textAlign = "right";
    ctx.fillText(String(hi), cssW - padR, cssH - 8);
    ctx.save();
    ctx.setLineDash([3, 3]);
    ctx.strokeStyle = ink;
    ctx.beginPath();
    ctx.moveTo(midX, padT);
    ctx.lineTo(midX, padT + plotH);
    ctx.stroke();
    ctx.restore();

    document.getElementById("av-hist-note").textContent =
      `Each bar counts how many of the ${number(d.input_bits)} possible single-bit flips changed that many output bits. ` +
      `The average is ${d.sweep_mean} of ${n}. The dark bar is the flip you chose.`;
  }

  const refresh = debounce(update, 120);
  prim.addEventListener("change", () => { bit.value = "0"; update(); });
  msg.addEventListener("input", refresh);
  bit.addEventListener("input", refresh);
  document.getElementById("av-random").addEventListener("click", () => {
    bit.value = String(Math.floor(Math.random() * (Number(bit.max) + 1)));
    update();
  });
  window.addEventListener("resize", debounce(() => lastSweep && drawHist(lastSweep), 150));

  CL.start.avalanche = () => {
    if (started) { lastSweep && drawHist(lastSweep); return; }
    started = true;
    update();
  };
})();
