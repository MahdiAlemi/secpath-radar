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


// SecPath Radar — E5: theme, language, interactive charts (local-only, no requests).
(function () {
  "use strict";

  var body = document.body;
  var docEl = document.documentElement;

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

  // --- Language switch (radar-lang) ---
  var I18N = {
    "رصد غیرفعال امنیت سایبری": "Passive cyber security watch",
    "نمای کلی": "Overview",
    "آسیب‌پذیری": "Vulnerabilities",
    "خبر و تحلیل": "News & Research",
    "تله‌متری تهدید": "Threat Telemetry",
    "منابع": "Sources",
    "مهم‌ترین سیگنال‌های امروز": "Top Signals Today",
    "خلاصه ۶۰ ثانیه‌ای": "60-Second Summary",
    "سیگنال اولویت‌دار امروز": "Today's Priority Signal",
    "تغییرات نسبت به اجرای قبل": "Changes Since Last Run",
    "روند چند اجرای اخیر": "Recent Run Trend",
    "اولویت وصله": "Patch Priority",
    "پوشش Template": "Template Coverage",
    "PoCهای عمومی تازه": "Fresh Public PoCs",
    "زنجیره تأمین": "Supply Chain",
    "رصد وندورها": "Vendor Watchlist",
    "خبر فوری": "Breaking News",
    "رصد ایران": "Iran Radar",
    "خبر امروز": "Today's News",
    "تحلیل‌های تازه": "Fresh Research",
    "تهدید فعال": "Active Threats",
    "فشار حمله": "Attack Pressure",
    "الگوهای حمله": "Attack Patterns",
    "زمینه زیرساخت": "Infrastructure Context",
    "زیرساخت C2": "C2 Infrastructure",
    "فیشینگ": "Phishing",
    "نمونه‌های بدافزار": "Malware Samples",
    "رنج‌های IP خصمانه": "Hostile IP Ranges",
    "اطلاعیه‌های وندور": "Vendor Advisories",
    "صنعتی و OT": "ICS / OT",
    "زیرساخت مشکوک": "Suspicious Infrastructure",
    "باج‌افزار": "Ransomware",
    "منابع و سلامت اجرا": "Sources & Run Health",
    "منابع داده": "Data Feeds",
    "لایه تحلیلی": "AI Layer",
    "یادداشت اجرا": "Run Notes",
    "آسیب‌پذیری و بهره‌برداری": "Vulnerability & Exploitation",
    "امتیاز ریسک": "Risk Score",
    "CVE بحرانی": "Critical CVEs",
    "بهره‌برداری": "Exploitation",
    "پوشش Nuclei": "Nuclei Coverage",
    "جمع‌بندی هفتگی": "Weekly Digest",
    "نمای فشرده": "Compact View",
    "جمع‌کردن همه": "Collapse All",
    "روشن/تیره": "Light/Dark",
    "احتمال اثر مستقیم روی تداوم کسب‌وکار و بازیابی سرویس‌ها وجود دارد.": "Potential direct impact on business continuity and service recovery.",
    "نشانه بهره‌برداری فعال دیده شده و باید از backlog عادی جدا شود.": "Signs of active exploitation observed; keep it out of the normal backlog.",
    "اگر محصول مرتبط در محیط وجود داشته باشد، اولویت patch و کنترل exposure بالاست.": "If the related product exists in your environment, patching and exposure control are high priority.",
    "برای تصمیم روزانه SOC و تیم زیرساخت، ارزش triage و ثبت وضعیت دارد.": "Worth triaging and tracking for daily SOC and infrastructure decisions.",
    "ارتباط این آیتم با ایران را با دامنه، برند، vendor و زیرساخت خودت جداگانه triage کن.": "Triage this item's Iran relevance against your own domains, brands, vendors and infrastructure.",
    "برای دارایی‌های public-facing مرتبط، وضعیت exposure و لاگ‌های ۲۴ تا ۴۸ ساعت اخیر را بررسی کن.": "For related public-facing assets, review exposure and logs from the last 24-48 hours.",
    "نام vendor یا محصول را با inventory و backlog patch مقایسه کن.": "Compare the vendor or product name against your inventory and patch backlog.",
    "چون در KEV دیده شده، وضعیت affected/not affected را همان‌روز مشخص و mitigation را پیگیری کن.": "Listed in KEV: determine affected/not-affected the same day and track mitigation.",
    "ابتدا assetهای اینترنتی و سرویس‌های حساس مرتبط را بررسی و برای patch اولویت بالا تعیین کن.": "Review internet-facing assets and sensitive services first and set a high patch priority.",
    "با inventory تطبیق بده و در چرخه patch عادی یا accelerated پیگیری کن.": "Match against inventory and track in the normal or accelerated patch cycle.",
    "اول exposure و دارایی‌های مرتبط را مشخص کن، سپس وضعیت patch یا mitigation را ثبت کن.": "Identify exposure and related assets first, then record patch or mitigation status.",
    "در این اجرا CVE تازه‌ای در بازه انتخابی ثبت نشد.": "No new CVEs were recorded in the selected window this run.",
    "خبر فوری تازه‌ای در پنجره امروز ثبت نشده است.": "No new breaking news in today's window.",
    "آیتم مرتبط با ایران در این اجرا دیده نشد.": "No Iran-related items were seen in this run.",
    "خبر تازه‌ای در پنجره امروز نمایش داده نشده است.": "No new news items in today's window.",
    "تغییر معناداری ثبت نشده است.": "No meaningful changes recorded.",
    "بدون داده در این اجرا": "No data in this run",
    "خروجی بدون AI هم کامل است": "Output is complete even without AI",
    "SecPath Radar · رصد غیرفعال و read-only · بدون اسکن فعال": "SecPath Radar \u00b7 passive & read-only \u00b7 no active scanning",
    "تعامل‌ها فقط محلی و نمایشی هستند": "All interactions are local and display-only",
    "جدید": "New",
    "ردیابی": "Tracked",
    "افزایش": "Increased",
    "کاهش": "Decreased",
    "مدل": "Model",
    "فراخوانی": "Calls",
    "خطا": "Errors",
    "تله‌متری": "Telemetry",
    "فعال": "Active",
    "غیرفعال": "Disabled",
  };
  var LANG_SELECTORS = "h2, .anchor-nav a, .kpi > span, .brand-sub, .ui-chip, .footer span, .note, .ops, .tag, .chip, .empty-note, .stat-row span, .meta span";

  function applyLang(en) {
    body.classList.toggle("lang-en", en);
    docEl.setAttribute("lang", en ? "en" : "fa");
    docEl.setAttribute("dir", en ? "ltr" : "rtl");
    document.querySelectorAll(LANG_SELECTORS).forEach(function (el) {
      if (!el.getAttribute("data-fa")) {
        var txt = el.textContent.trim();
        if (I18N[txt]) {
          el.setAttribute("data-fa", txt);
          el.setAttribute("data-en", I18N[txt]);
        }
      }
      var fa = el.getAttribute("data-fa");
      if (fa) el.textContent = en ? el.getAttribute("data-en") : fa;
    });
    var chip = chipFor("lang");
    if (chip) {
      chip.textContent = en ? "فا" : "EN";
      chip.classList.toggle("is-on", en);
    }
  }
  if (load("radar-lang") === "en") applyLang(true);
  bind(chipFor("lang"), function () {
    var en = !body.classList.contains("lang-en");
    applyLang(en);
    store("radar-lang", en ? "en" : "fa");
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
      var en = body.classList.contains("lang-en");
      var text = row.getAttribute("data-chart-name") + " — " + rawCount;
      if (!isNaN(count) && total > 0) {
        var share = Math.round((count / total) * 100);
        text += en ? " · " + share + "% of this chart" : " · " + share + "٪ از این نمودار";
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
