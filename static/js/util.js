"use strict";

/* Shared helpers, exposed as window.CL. */
window.CL = (() => {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const start = {}; // each tab registers a function here that runs the first time it is opened

  /* ---- DOM ---------------------------------------------------------- */
  function append(node, children) {
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
  }

  function h(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") node.className = value;
      else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : value);
    }
    append(node, children);
    return node;
  }

  /* Replace a node's children. Unlike replaceChildren(), null/false entries are skipped, not printed as "null". */
  function fill(node, ...children) {
    node.replaceChildren();
    append(node, children);
  }

  function showError(el, message) {
    el.textContent = message || "";
    el.hidden = !message;
  }

  /* ---- Server calls ------------------------------------------------- */
  async function api(path, payload) {
    let res;
    try {
      res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch {
      throw new Error("Could not reach the server. Make sure app.py is running.");
    }
    let data = {};
    try {
      data = await res.json();
    } catch {
      /* non-JSON error body */
    }
    if (!res.ok) throw new Error(data.error || `The server returned an error (${res.status}).`);
    return data;
  }

  /* ---- Bytes -------------------------------------------------------- */
  function spacedHex(hex) {
    return hex.replace(/(..)/g, "$1 ").trim();
  }

  function bytesToB64(bytes) {
    let binary = "";
    const step = 0x8000;
    for (let i = 0; i < bytes.length; i += step) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
    }
    return btoa(binary);
  }

  function b64ToBytes(b64) {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  /* One cell per byte: hex on top, the matching character underneath (optional). */
  function cells(hex, opts = {}) {
    const { chars = false, padFrom = null, cls = "", max = Infinity } = opts;
    const total = hex.length / 2;
    const shown = Math.min(total, max);
    const wrap = h("span", { class: `bytes ${cls}`.trim(), role: "img", "aria-label": spacedHex(hex.slice(0, 96)) + (total > 48 ? " and more" : "") });
    for (let i = 0; i < shown; i++) {
      const pair = hex.slice(i * 2, i * 2 + 2);
      const code = parseInt(pair, 16);
      const printable = code >= 0x20 && code < 0x7f;
      wrap.append(
        h("span", { class: padFrom !== null && i >= padFrom ? "b pad" : "b", "aria-hidden": "true" },
          h("i", {}, pair),
          chars ? h("u", {}, printable ? String.fromCharCode(code) : "·") : null)
      );
    }
    if (total > shown) wrap.append(h("span", { class: "more" }, `+${total - shown} more bytes`));
    return wrap;
  }

  /* ---- Small utilities --------------------------------------------- */
  async function copyText(text, button) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = h("textarea", { style: "position:fixed;opacity:0" });
      area.value = text;
      document.body.append(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    const label = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = label), 1200);
  }

  function copyButton(getText, label = "Copy") {
    return h("button", { class: "copy", type: "button", onclick: (e) => copyText(getText(), e.currentTarget) }, label);
  }

  function debounce(fn, wait) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), wait);
    };
  }

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  const number = (n) => Number(n).toLocaleString("en-US");

  /* Random hex flicker that settles on the real value, left to right. */
  function scramble(nodes) {
    if (reduceMotion) return;
    const hex = "0123456789abcdef";
    const startedAt = performance.now();
    const items = [...nodes].slice(0, 600).map((node, i) => ({
      node,
      final: node.textContent,
      settle: 300 + (i % 40) * 16 + Math.random() * 260,
    }));
    function tick(now) {
      const elapsed = now - startedAt;
      let running = false;
      for (const item of items) {
        if (elapsed < item.settle) {
          item.node.textContent = hex[(Math.random() * 16) | 0] + hex[(Math.random() * 16) | 0];
          running = true;
        } else if (item.node.textContent !== item.final) {
          item.node.textContent = item.final;
        }
      }
      if (running) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  return { reduceMotion, start, h, fill, showError, api, spacedHex, bytesToB64, b64ToBytes, cells, copyButton, debounce, cssVar, number, scramble };
})();
