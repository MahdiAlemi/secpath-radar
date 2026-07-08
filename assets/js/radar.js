// SecPath Radar — local-only display helpers.
// Read-only dashboard: no data collection, no requests, no forms.
(function () {
  "use strict";

  var body = document.body;

  // --- Scroll spy for anchor nav ---
  var nav = document.querySelector(".anchor-nav");
  if (nav && "IntersectionObserver" in window) {
    var links = Array.prototype.slice.call(nav.querySelectorAll("a[href^='#']"));
    var targets = links
      .map(function (a) {
        return document.querySelector(a.getAttribute("href"));
      })
      .filter(Boolean);

    var activeId = null;
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


// SecPath Radar — theme, interactive charts (local-only, no requests).
(function () {
  "use strict";

  var body = document.body;

  function chipFor(action) {
    return document.querySelector('[data-ui-action="' + action + '"]');
  }
  function store(key, value) {
    try { window.localStorage.setItem(key, value); } catch (e) {}
  }
  function load(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function bind(chip, run) {
    if (!chip) return;
    chip.addEventListener("click", run);
    chip.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); run(); }
    });
  }

  // --- Theme toggle (radar-theme) ---
  function applyTheme(light) {
    body.classList.toggle("theme-light", light);
    var chip = chipFor("theme");
    if (chip) chip.classList.toggle("is-on", light);
  }
  applyTheme(load("radar-theme") === "light");

  bind(chipFor("theme"), function () {
    var light = !body.classList.contains("theme-light");
    applyTheme(light);
    store("radar-theme", light ? "light" : "dark");
  });

  // --- Interactive charts: click a bar for exact value + share ---
  document.querySelectorAll("[data-chart-name]").forEach(function (row) {
    function toggleDetail() {
      var next = row.nextElementSibling;
      if (next && next.classList.contains("bar-detail")) {
        next.remove();
        row.classList.remove("is-active");
        return;
      }
      row.classList.add("is-active");
      var chart = row.parentElement;
      var siblings = chart ? chart.querySelectorAll("[data-chart-name]") : [];
      var total = 0;
      Array.prototype.forEach.call(siblings, function (r) {
        total += parseFloat(r.getAttribute("data-chart-count")) || 0;
      });
      var rawCount = row.getAttribute("data-chart-count") || "";
      var count = parseFloat(rawCount);
      var text = row.getAttribute("data-chart-name") + " — " + rawCount;
      if (!isNaN(count) && total > 0) {
        var share = Math.round((count / total) * 100);
        text += " · " + share + "% of this chart";
      }
      var detail = document.createElement("div");
      detail.className = "bar-detail";
      detail.textContent = text;
      row.insertAdjacentElement("afterend", detail);
    }
    row.addEventListener("click", toggleDetail);
    row.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggleDetail(); }
    });
  });
})();
