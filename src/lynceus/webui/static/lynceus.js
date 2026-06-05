(function () {
  "use strict";

  var DAY = 86400;
  var WEEK = 7 * DAY;
  var YEAR = 365 * DAY;

  function days(n) {
    return n === 1 ? "1 day ago" : n + " days ago";
  }
  function weeks(n) {
    return n === 1 ? "1 week ago" : n + " weeks ago";
  }
  function months(n) {
    return n === 1 ? "1 month ago" : n + " months ago";
  }
  function years(n) {
    return n === 1 ? "1 year ago" : n + " years ago";
  }

  // Locale-aware absolute formatters. Use Intl.DateTimeFormat so month/day
  // ordering follows the user's locale (manual "May 4" strings break for
  // locales that put day before month).
  var sameYearFmt = new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  var otherYearFmt = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  var titleFmt = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  });

  function formatAbsolute(then, now) {
    var fmt = then.getFullYear() === now.getFullYear() ? sameYearFmt : otherYearFmt;
    return fmt.format(then);
  }

  // Threshold convention: comparisons use strict < on the upper bound, so
  // delta exactly equal to a boundary (e.g. 60s, 7*86400s) falls into the
  // *next* (coarser) bucket. delta == 60 → not "just now", delta == WEEK
  // → coarse-relative not absolute.
  function formatStamp(then, now) {
    var delta = Math.floor((now.getTime() - then.getTime()) / 1000);

    if (delta < 0) {
      // Future timestamps: render as fully-qualified absolute (don't say
      // "in 3 hours"). Always include the year for unambiguity.
      return otherYearFmt.format(then);
    }
    if (delta < 60) {
      return "just now";
    }
    if (delta < WEEK) {
      return formatAbsolute(then, now);
    }
    if (delta < 14 * DAY) {
      return days(Math.floor(delta / DAY));
    }
    if (delta < 60 * DAY) {
      return weeks(Math.floor(delta / WEEK));
    }
    if (delta < 365 * DAY) {
      return months(Math.floor(delta / (30 * DAY)));
    }
    if (delta < 730 * DAY) {
      return "1 year ago";
    }
    return years(Math.floor(delta / YEAR));
  }

  function formatOne(el, now) {
    var iso = el.getAttribute("datetime");
    if (!iso) {
      console.warn("lynceus.js: missing datetime attribute", el);
      return;
    }
    var then = new Date(iso);
    if (isNaN(then.getTime())) {
      console.warn("lynceus.js: cannot parse datetime", iso, el);
      return;
    }
    el.textContent = formatStamp(then, now);
    el.setAttribute("title", titleFmt.format(then));
  }

  function formatAll(root) {
    var now = new Date();
    var nodes = (root || document).querySelectorAll("time[datetime]");
    for (var i = 0; i < nodes.length; i++) {
      formatOne(nodes[i], now);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      formatAll(document);
    });
  } else {
    formatAll(document);
  }

  document.addEventListener("htmx:afterSwap", function (evt) {
    formatAll(evt.target || document);
  });
})();

// Theme toggle: cycles auto → light → dark → auto and persists the
// choice to localStorage. "auto" leaves <html> with no data-theme
// attribute so Pico's own @media (prefers-color-scheme: dark) block
// (and our matching one in lynceus.css) decide. The two forced modes
// set data-theme on <html>, which Pico and our overrides both honor.
//
// FOUC mitigation: base.html has a tiny inline <head> script that
// applies the stored "light"/"dark" choice synchronously before the
// stylesheet loads, so the forced-theme case never flashes the OS
// default. This deferred script still runs to keep "auto" behaviour
// (clear attribute → fall back to @media) and to wire the toggle.
(function () {
  "use strict";

  var THEME_KEY = "lynceus-theme";
  var THEME_CYCLE = ["auto", "light", "dark"];

  function readStoredTheme() {
    try {
      var v = localStorage.getItem(THEME_KEY);
      return THEME_CYCLE.indexOf(v) >= 0 ? v : "auto";
    } catch (_) {
      // localStorage may throw under strict privacy settings or in
      // sandboxed contexts; degrade to auto silently.
      return "auto";
    }
  }

  function writeStoredTheme(t) {
    try { localStorage.setItem(THEME_KEY, t); } catch (_) { /* swallow */ }
  }

  function applyTheme(theme) {
    var html = document.documentElement;
    if (theme === "auto") {
      html.removeAttribute("data-theme");
    } else {
      html.setAttribute("data-theme", theme);
    }
    var btn = document.querySelector("[data-theme-toggle]");
    if (btn) {
      btn.textContent = "theme: " + theme;
      btn.setAttribute("aria-pressed", theme === "auto" ? "false" : "true");
    }
  }

  function cycleTheme() {
    var current = readStoredTheme();
    var next = THEME_CYCLE[(THEME_CYCLE.indexOf(current) + 1) % THEME_CYCLE.length];
    writeStoredTheme(next);
    applyTheme(next);
  }

  // Apply stored theme immediately so the DOM is in the right state by
  // the time the button is wired up below.
  applyTheme(readStoredTheme());

  function bindToggle() {
    var btn = document.querySelector("[data-theme-toggle]");
    if (!btn) return;
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      cycleTheme();
    });
    // Re-apply once the button is in the DOM so its label reflects the
    // stored theme (applyTheme above ran before bindToggle when the
    // script first loads on a page where the topnav hadn't parsed yet).
    applyTheme(readStoredTheme());
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindToggle);
  } else {
    bindToggle();
  }
})();

// Client-side data-table column resize + reorder with per-table
// persistence (v0.9.2). Opt-in: only tables carrying [data-table-id] (set by
// the data_table macro's table_id) are enhanced. State persists to
// localStorage["lynceus-table:<id>"] as {order:[colKey...], widths:{colKey:px}}.
//
// The inline head helper window.__lynTableApply applies persisted state
// pre-paint (called by the macro right after each table) and is reused here
// to perform the DOM moves after an interactive reorder. This script adds
// the interactive layer:
//   - first-load width freeze: measure the current content-fit widths into
//     the colgroup and switch to table-layout:fixed so columns are
//     resizable (measured == rendered, so the flip is visually a no-op).
//   - drag-to-resize via the per-th grip.
//   - drag-to-reorder, coexisting with the Touch-1 server-side sort <a>: a
//     header press only becomes a reorder once the pointer moves past a
//     small threshold; under the threshold the click falls through and the
//     sort link navigates. After a real drag the trailing click is
//     swallowed so the drag never also sorts.
//   - the "reset columns" control (clears the table's key, reloads).
(function () {
  "use strict";

  var PREFIX = "lynceus-table:";
  var MIN_W = 72;      // px floor for a resized column; clears the 12px grip + 2px
                       // separator bar against the column label. Raised 64->72 after
                       // the widest table (/devices, 12 cols) still showed a live
                       // label/grip overlap at the old floor.
  var DRAG_SLOP = 5;   // px a header press must move before it is a reorder

  function readState(id) {
    try {
      var raw = localStorage.getItem(PREFIX + id);
      if (!raw) return {};
      var st = JSON.parse(raw);
      return (st && typeof st === "object") ? st : {};
    } catch (_) { return {}; }
  }
  function writeState(id, st) {
    try { localStorage.setItem(PREFIX + id, JSON.stringify(st)); } catch (_) { /* swallow */ }
  }
  function clearState(id) {
    try { localStorage.removeItem(PREFIX + id); } catch (_) { /* swallow */ }
  }

  function headKeys(table) {
    var keys = [];
    var row = table.tHead && table.tHead.rows[0];
    if (row) {
      for (var i = 0; i < row.cells.length; i++) {
        var k = row.cells[i].getAttribute("data-col-key");
        if (k) keys.push(k);
      }
    }
    return keys;
  }
  function colFor(table, key) {
    return table.querySelector('colgroup col[data-col-key="' + key + '"]');
  }

  // First visit (no widths persisted yet): freeze the content-fit widths
  // into the colgroup and switch to fixed layout. Persisting them means the
  // next load applies them pre-paint with no jump (the accepted tradeoff:
  // widths are frozen at first-load measurement until "reset columns").
  function freezeWidths(table, id, st) {
    var row = table.tHead && table.tHead.rows[0];
    if (!row) return;
    var hidden = st.hidden || [];
    var widths = {};
    for (var i = 0; i < row.cells.length; i++) {
      var th = row.cells[i];
      var key = th.getAttribute("data-col-key");
      if (!key) continue;
      // A hidden column's th measures ~0 (its <col> is collapsed to width:0), so
      // never freeze that as its width -- that would lose the real width and make
      // un-hide restore a 0-width column. Carry over any previously-stored real
      // width instead.
      if (hidden.indexOf(key) >= 0) {
        if (st.widths && st.widths[key] > 0) widths[key] = st.widths[key];
        continue;
      }
      var w = Math.round(th.getBoundingClientRect().width);
      var col = colFor(table, key);
      if (col && w > 0) { col.style.width = w + "px"; widths[key] = w; }
    }
    table.style.tableLayout = "fixed";
    st.widths = widths;
    writeState(id, st);
  }

  // Defensive re-apply of the hidden state after first paint (the base.html
  // pre-paint applier normally does this; this keeps lynceus.js correct on its
  // own if that applier was absent). Idempotent: zeroing an already-0 col is a
  // no-op. See the hide-pass comment in base.html for the mechanism.
  function applyHidden(table, st) {
    if (!st.hidden || !st.hidden.length) return;
    for (var i = 0; i < st.hidden.length; i++) {
      var col = colFor(table, st.hidden[i]);
      if (col) col.style.width = "0px";
    }
    table.style.tableLayout = "fixed";
  }

  // Hide/show ONE column by collapsing (or restoring) only its <col> width under
  // table-layout:fixed -- never touching cells, so the col<->cell positional
  // mapping stays exact. State: add/remove the key in st.hidden; the real width
  // is kept in st.widths[key] so un-hide restores the right size.
  function setColHidden(table, id, key, hide) {
    var col = colFor(table, key);
    if (!col) return;
    table.style.tableLayout = "fixed";
    var st = readState(id);
    st.hidden = st.hidden || [];
    var at = st.hidden.indexOf(key);
    if (hide) {
      col.style.width = "0px";
      if (at < 0) st.hidden.push(key);
    } else {
      var w = st.widths && st.widths[key];
      col.style.width = (typeof w === "number" && w > 0) ? (w + "px") : "";
      if (at >= 0) st.hidden.splice(at, 1);
    }
    writeState(id, st);
  }

  function bindResize(table, id) {
    var grips = table.querySelectorAll("th .col-resizer");
    for (var i = 0; i < grips.length; i++) {
      (function (grip) {
        var th = grip.parentNode;
        var key = th.getAttribute("data-col-key");
        var startX = 0, startW = 0, col = null;
        function move(e) {
          var w = Math.max(MIN_W, Math.round(startW + (e.clientX - startX)));
          if (col) col.style.width = w + "px";
        }
        function end(e) {
          grip.removeEventListener("pointermove", move);
          grip.removeEventListener("pointerup", end);
          grip.removeEventListener("pointercancel", end);
          th.classList.remove("lyn-resizing");
          try { grip.releasePointerCapture(e.pointerId); } catch (_) {}
          if (col) {
            var st = readState(id);
            st.widths = st.widths || {};
            st.widths[key] = parseInt(col.style.width, 10) || st.widths[key];
            writeState(id, st);
          }
        }
        grip.addEventListener("pointerdown", function (e) {
          if (e.button !== undefined && e.button !== 0) return;
          e.preventDefault();
          e.stopPropagation();          // never let the grip start a reorder
          col = colFor(table, key);
          startX = e.clientX;
          startW = th.getBoundingClientRect().width;
          th.classList.add("lyn-resizing");
          try { grip.setPointerCapture(e.pointerId); } catch (_) {}
          grip.addEventListener("pointermove", move);
          grip.addEventListener("pointerup", end);
          grip.addEventListener("pointercancel", end);
        });
      })(grips[i]);
    }
  }

  function bindReorder(table, id) {
    var row = table.tHead && table.tHead.rows[0];
    if (!row) return;
    var ths = row.cells;
    var dragKey = null, startX = 0, startY = 0, dragging = false;
    var dragTh = null, dropTarget = null, dropBefore = false;

    function clearMarks() {
      for (var i = 0; i < ths.length; i++) {
        ths[i].classList.remove("lyn-drop-before", "lyn-drop-after");
      }
    }
    function onMove(e) {
      if (!dragKey) return;
      if (!dragging) {
        if (Math.abs(e.clientX - startX) < DRAG_SLOP && Math.abs(e.clientY - startY) < DRAG_SLOP) return;
        dragging = true;
        dragTh.classList.add("lyn-dragging");
      }
      e.preventDefault();
      var el = document.elementFromPoint(e.clientX, e.clientY);
      var over = (el && el.closest) ? el.closest("th[data-col-key]") : null;
      clearMarks();
      dropTarget = null;
      if (over && over !== dragTh && over.parentNode === row) {
        var r = over.getBoundingClientRect();
        dropBefore = e.clientX < r.left + r.width / 2;
        over.classList.add(dropBefore ? "lyn-drop-before" : "lyn-drop-after");
        dropTarget = over;
      }
    }
    function teardown() {
      document.removeEventListener("pointermove", onMove, true);
      document.removeEventListener("pointerup", onUp, true);
      document.removeEventListener("pointercancel", onCancel, true);
    }
    function onUp() {
      teardown();
      var didDrag = dragging;
      if (dragTh) dragTh.classList.remove("lyn-dragging");
      clearMarks();
      if (dragging && dropTarget) {
        var keys = headKeys(table);
        keys.splice(keys.indexOf(dragKey), 1);
        var ti = keys.indexOf(dropTarget.getAttribute("data-col-key"));
        keys.splice(dropBefore ? ti : ti + 1, 0, dragKey);
        var st = readState(id);
        st.order = keys;
        writeState(id, st);
        if (window.__lynTableApply) window.__lynTableApply(id);
      }
      dragKey = null; dragging = false; dragTh = null; dropTarget = null;
      // Swallow the click that trails a real drag so the sort link beneath
      // the pointer does not also fire.
      if (didDrag) {
        var swallow = function (ev) {
          ev.preventDefault();
          ev.stopPropagation();
          table.removeEventListener("click", swallow, true);
        };
        table.addEventListener("click", swallow, true);
        setTimeout(function () { table.removeEventListener("click", swallow, true); }, 0);
      }
    }
    function onCancel() {
      teardown();
      if (dragTh) dragTh.classList.remove("lyn-dragging");
      clearMarks();
      dragKey = null; dragging = false; dragTh = null; dropTarget = null;
    }
    for (var i = 0; i < ths.length; i++) {
      ths[i].addEventListener("pointerdown", function (e) {
        if (e.button !== undefined && e.button !== 0) return;     // primary button only
        if (e.target.closest(".col-resizer")) return;             // that is a resize, not a reorder
        var th = e.currentTarget;
        var key = th.getAttribute("data-col-key");
        if (!key) return;
        dragKey = key; dragTh = th; startX = e.clientX; startY = e.clientY;
        dragging = false; dropTarget = null;
        document.addEventListener("pointermove", onMove, true);
        document.addEventListener("pointerup", onUp, true);
        document.addEventListener("pointercancel", onCancel, true);
      });
    }
  }

  function bindReset(id) {
    var btns = document.querySelectorAll('[data-table-reset="' + id + '"]');
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener("click", function (e) {
        e.preventDefault();
        clearState(id);
        location.reload();
      });
    }
  }

  // Columns show/hide menu: one checkbox per column (checked == visible). The
  // macro emits the menu under [data-cols-for="<id>"]; toggling a box collapses
  // or restores that column live via setColHidden (no reload). A guard refuses
  // to hide the last visible column (an all-hidden table is a dead end). On load
  // each checkbox is synced to the persisted hidden state.
  function bindColumnsMenu(table, id) {
    var boxes = document.querySelectorAll('[data-cols-for="' + id + '"] input.col-toggle');
    if (!boxes.length) return;
    function visibleCount() {
      var st = readState(id);
      return boxes.length - (st.hidden || []).length;
    }
    for (var i = 0; i < boxes.length; i++) {
      (function (box) {
        var key = box.getAttribute("data-col-toggle");
        var st = readState(id);
        box.checked = !(st.hidden && st.hidden.indexOf(key) >= 0);
        box.addEventListener("change", function () {
          if (!box.checked) {
            // Hiding would remove a column; never let it remove the last one.
            if (visibleCount() <= 1) { box.checked = true; return; }
            setColHidden(table, id, key, true);
          } else {
            setColHidden(table, id, key, false);
          }
        });
      })(boxes[i]);
    }
  }

  function init() {
    var tables = document.querySelectorAll("table[data-table-id]");
    for (var i = 0; i < tables.length; i++) {
      var table = tables[i];
      var id = table.getAttribute("data-table-id");
      var st = readState(id);
      // __lynTableApply already applied persisted state pre-paint. If no
      // usable widths are stored yet (first visit, or a corrupt/empty
      // widths value), freeze the current content-fit widths now; otherwise
      // just ensure fixed layout is in effect.
      var haveWidths = st.widths && typeof st.widths === "object" && Object.keys(st.widths).length;
      if (!haveWidths) freezeWidths(table, id, st);
      else table.style.tableLayout = "fixed";
      applyHidden(table, st);
      bindResize(table, id);
      bindReorder(table, id);
      bindReset(id);
      bindColumnsMenu(table, id);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
