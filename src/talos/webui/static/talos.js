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
      console.warn("talos.js: missing datetime attribute", el);
      return;
    }
    var then = new Date(iso);
    if (isNaN(then.getTime())) {
      console.warn("talos.js: cannot parse datetime", iso, el);
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
