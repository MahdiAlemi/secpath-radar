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
