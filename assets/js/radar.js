// SecPath Radar — local-only display helpers.
// Read-only dashboard: no data collection, no requests, no forms.
(function () {
  "use strict";

  var body = document.body;

  // --- Local display chips (density / collapse-all) ---
  function setChipState(chip, on) {
    chip.classList.toggle("is-on", on);
  }

  function toggleDensity(chip) {
    var on = body.classList.toggle("is-compact");
    if (chip) setChipState(chip, on);
  }

  function toggleCollapseAll(chip) {
    var panels = document.querySelectorAll(".panel");
    var anyOpen = Array.prototype.some.call(panels, function (p) {
      return !p.classList.contains("is-collapsed");
    });
    panels.forEach(function (p) {
      p.classList.toggle("is-collapsed", anyOpen);
    });
    if (chip) setChipState(chip, anyOpen);
  }

  document.querySelectorAll("[data-ui-action]").forEach(function (chip) {
    var action = chip.getAttribute("data-ui-action");
    function run() {
      if (action === "density") toggleDensity(chip);
      if (action === "collapse") toggleCollapseAll(chip);
    }
    chip.addEventListener("click", run);
    chip.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        run();
      }
    });
  });

  // --- Per-panel collapse on header click ---
  document.querySelectorAll(".panel-head").forEach(function (head) {
    head.addEventListener("click", function (ev) {
      if (ev.target.closest("a")) return;
      var panel = head.closest(".panel");
      if (panel) panel.classList.toggle("is-collapsed");
    });
  });

  // --- Keyboard shortcuts (local only) ---
  document.addEventListener("keydown", function (ev) {
    if (ev.target !== document.body) return;
    if (ev.key === "d" || ev.key === "D") {
      toggleDensity(document.querySelector('[data-ui-action="density"]'));
    }
    if (ev.key === "Escape") {
      body.classList.remove("is-compact");
      document.querySelectorAll(".panel.is-collapsed").forEach(function (p) {
        p.classList.remove("is-collapsed");
      });
      document.querySelectorAll(".ui-chip.is-on").forEach(function (c) {
        c.classList.remove("is-on");
      });
    }
  });

  // --- Scroll spy for anchor nav ---
  var nav = document.querySelector(".anchor-nav");
  if (nav && "IntersectionObserver" in window) {
    var links = Array.prototype.slice.call(nav.querySelectorAll("a[href^='#']"));
    var targets = links
      .map(function (a) {
        return document.querySelector(a.getAttribute("href"));
      })
      .filter(Boolean);

    var activeId = targets.length ? targets[0].id : null;
    var visible = {};

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          visible[entry.target.id] = entry.isIntersecting;
        });
        var current = null;
        targets.forEach(function (t) {
          if (current === null && visible[t.id]) current = t.id;
        });
        if (current && current !== activeId) {
          activeId = current;
          links.forEach(function (a) {
            a.classList.toggle("is-active", a.getAttribute("href") === "#" + current);
          });
        }
      },
      { rootMargin: "-100px 0px -55% 0px" }
    );
    targets.forEach(function (t) {
      observer.observe(t);
    });
  }
})();
