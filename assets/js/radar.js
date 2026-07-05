(() => {
  const root = document.documentElement;
  const storageKey = "secpath-radar-ui-v1";
  const state = loadState();
  let activePanel = null;

  root.dataset.radarRuntime = "production-static";
  root.dataset.density = state.density || "normal";

  const chips = Array.from(document.querySelectorAll("[data-ui-action]"));
  const panels = Array.from(document.querySelectorAll(".panel"));

  panels.forEach((panel) => {
    const head = panel.querySelector(".compact-head");
    if (!head) return;
    head.setAttribute("tabindex", "0");
    head.setAttribute("role", "button");
    head.setAttribute("aria-expanded", state.collapsed?.includes(panel.id) ? "false" : "true");
    if (state.collapsed?.includes(panel.id)) panel.classList.add("is-collapsed");

    const activate = () => setActivePanel(panel);
    panel.addEventListener("pointerdown", activate);
    head.addEventListener("click", () => togglePanel(panel));
    head.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        togglePanel(panel);
      }
    });
  });

  chips.forEach((chip) => {
    chip.addEventListener("click", () => runAction(chip.dataset.uiAction));
    chip.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        runAction(chip.dataset.uiAction);
      }
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.target && ["INPUT", "TEXTAREA", "SELECT"].includes(event.target.tagName)) return;
    const key = event.key.toLowerCase();
    if (key === "d") runAction("density");
    if (key === "f") runAction("focus");
    if (event.key === "Escape") exitFocusMode();
  });

  refreshControls();

  function runAction(action) {
    if (action === "density") toggleDensity();
    if (action === "collapse") toggleCollapseAll();
    if (action === "focus") toggleFocusMode();
  }

  function toggleDensity() {
    root.dataset.density = root.dataset.density === "dense" ? "normal" : "dense";
    state.density = root.dataset.density;
    saveState();
    refreshControls();
  }

  function togglePanel(panel) {
    panel.classList.toggle("is-collapsed");
    const collapsed = panel.classList.contains("is-collapsed");
    const head = panel.querySelector(".compact-head");
    if (head) head.setAttribute("aria-expanded", String(!collapsed));
    state.collapsed = panels.filter((item) => item.id && item.classList.contains("is-collapsed")).map((item) => item.id);
    saveState();
  }

  function toggleCollapseAll() {
    const shouldCollapse = panels.some((panel) => !panel.classList.contains("is-collapsed"));
    panels.forEach((panel) => {
      panel.classList.toggle("is-collapsed", shouldCollapse);
      const head = panel.querySelector(".compact-head");
      if (head) head.setAttribute("aria-expanded", String(!shouldCollapse));
    });
    state.collapsed = shouldCollapse ? panels.map((panel) => panel.id).filter(Boolean) : [];
    saveState();
    refreshControls();
  }

  function setActivePanel(panel) {
    if (!panel || !panel.id) return;
    activePanel = panel;
    panels.forEach((item) => item.classList.toggle("is-active-panel", item === panel));
  }

  function toggleFocusMode() {
    if (root.classList.contains("radar-focus-mode")) {
      exitFocusMode();
      return;
    }
    const panel = activePanel || panels.find((item) => !item.classList.contains("is-collapsed")) || panels[0];
    if (!panel) return;
    setActivePanel(panel);
    panels.forEach((item) => item.classList.toggle("is-focused", item === panel));
    root.classList.add("radar-focus-mode");
    document.body.dataset.radarMode = "focus";
    showFocusNote(panel);
    refreshControls();
  }

  function exitFocusMode() {
    root.classList.remove("radar-focus-mode");
    document.body.dataset.radarMode = "overview";
    panels.forEach((item) => item.classList.remove("is-focused"));
    document.querySelector(".focus-note")?.remove();
    refreshControls();
  }

  function showFocusNote(panel) {
    document.querySelector(".focus-note")?.remove();
    const note = document.createElement("div");
    note.className = "focus-note";
    note.textContent = "Focus Mode محلی فعال است؛ Esc برای بازگشت به نمای کامل.";
    panel.insertBefore(note, panel.children[1] || null);
  }

  function refreshControls() {
    chips.forEach((chip) => {
      const action = chip.dataset.uiAction;
      chip.classList.toggle("is-active", action === "density" && root.dataset.density === "dense");
      chip.classList.toggle("is-active", action === "focus" && root.classList.contains("radar-focus-mode"));
      if (action === "collapse") {
        chip.textContent = panels.some((panel) => !panel.classList.contains("is-collapsed")) ? "جمع‌کردن" : "بازکردن";
      }
    });
  }

  function loadState() {
    try {
      return JSON.parse(localStorage.getItem(storageKey) || "{}");
    } catch (_) {
      return {};
    }
  }

  function saveState() {
    try {
      localStorage.setItem(storageKey, JSON.stringify(state));
    } catch (_) {
      // Local storage may be disabled; the dashboard remains read-only and usable.
    }
  }
})();
