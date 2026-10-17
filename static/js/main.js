"use strict";

/* Tabs: show one panel at a time, support arrow keys, remember the choice in the URL hash. */
(() => {
  const tabs = [...document.querySelectorAll('[role="tab"]')];

  function select(tab, focus) {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    }
    if (focus) tab.focus();
    const key = tab.dataset.panel;
    if (typeof CL.start[key] === "function") CL.start[key]();
    try { history.replaceState(null, "", "#" + key); } catch { /* file:// or sandbox */ }
  }

  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => select(tab, false));
    tab.addEventListener("keydown", (event) => {
      const keys = { ArrowRight: 1, ArrowLeft: -1 };
      if (event.key in keys) {
        event.preventDefault();
        select(tabs[(i + keys[event.key] + tabs.length) % tabs.length], true);
      } else if (event.key === "Home") { event.preventDefault(); select(tabs[0], true); }
      else if (event.key === "End") { event.preventDefault(); select(tabs[tabs.length - 1], true); }
    });
  });

  const wanted = tabs.find((t) => "#" + t.dataset.panel === location.hash);
  if (wanted) select(wanted, false);
})();
