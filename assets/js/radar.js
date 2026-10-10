// SecPath Radar — local-only display helpers.
// Static/read-only dashboard: no data collection, no requests, no forms.
(function () {
  "use strict";

  // Scroll spy for anchor navigation. This only updates local presentation state.
  var nav = document.querySelector(".anchor-nav");
  if (!nav || !("IntersectionObserver" in window)) return;

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
      targets.forEach(function (target) {
        if (current === null && visible[target.id]) current = target.id;
      });
      if (current && current !== activeId) {
        activeId = current;
        links.forEach(function (anchor) {
          anchor.classList.toggle("is-active", anchor.getAttribute("href") === "#" + current);
        });
      }
    },
    { rootMargin: "-100px 0px -55% 0px" }
  );

  targets.forEach(function (target) {
    observer.observe(target);
  });
})();

// Phase 470: data-aware column balancing (local-only, no data collection).
// Evens the bottom edge of the 4-column top layout by revealing hidden
// scrollable list content in shorter columns. Panels without extra data
// keep their natural height and are never stretched.
(function () {
  "use strict";

  var layout = document.querySelector(".top-layout.top-layout-columns.top-layout-balanced");
  if (!layout) return;

  function columns() {
    return Array.prototype.slice.call(layout.children).filter(function (el) {
      return el.classList && el.classList.contains("top-column");
    });
  }

  function resetColumn(col) {
    Array.prototype.slice.call(col.querySelectorAll("[data-balanced]")).forEach(function (el) {
      el.style.removeProperty("max-height");
      el.removeAttribute("data-balanced");
    });
  }

  // Natural content height: bottom edge of the lowest panel, not the
  // stretched column box.
  function contentHeight(col) {
    var top = col.getBoundingClientRect().top;
    var bottom = top;
    Array.prototype.slice.call(col.children).forEach(function (child) {
      var r = child.getBoundingClientRect();
      if (r.bottom > bottom) bottom = r.bottom;
    });
    return bottom - top;
  }

  // Scroll wells that actually hide content behind a scrollbar.
  function scrollWells(col) {
    return Array.prototype.slice.call(col.querySelectorAll("*")).filter(function (el) {
      if (el.clientHeight < 60) return false;
      var overflowY = window.getComputedStyle(el).overflowY;
      if (overflowY !== "auto" && overflowY !== "scroll") return false;
      return el.scrollHeight - el.clientHeight > 16;
    });
  }

  function balance() {
    var cols = columns();
    cols.forEach(resetColumn);
    if (cols.length < 3 || window.innerWidth <= 1500) return;

    var target = 0;
    cols.forEach(function (col) {
      var h = contentHeight(col);
      if (h > target) target = h;
    });

    cols.forEach(function (col) {
      var spare = target - contentHeight(col);
      if (spare < 32) return;
      var wells = scrollWells(col).sort(function (a, b) {
        return (b.scrollHeight - b.clientHeight) - (a.scrollHeight - a.clientHeight);
      });
      wells.forEach(function (well) {
        if (spare < 16) return;
        var hidden = well.scrollHeight - well.clientHeight;
        // Cap growth so a single list (e.g. the CVE queue) never balloons;
        // a well may grow by at most half its natural height.
        var cap = Math.max(160, Math.round(well.clientHeight * 0.5));
        var grow = Math.min(hidden, spare, cap);
        // Inline important wins over stylesheet !important caps.
        well.style.setProperty("max-height", (well.clientHeight + grow) + "px", "important");
        well.setAttribute("data-balanced", "1");
        spare -= grow;
      });
    });
  }

  var timer = null;
  function schedule() {
    if (timer) window.clearTimeout(timer);
    timer = window.setTimeout(balance, 120);
  }

  if (document.readyState === "complete") schedule();
  else window.addEventListener("load", schedule);
  window.addEventListener("resize", schedule);
})();
