(function () {
  "use strict";

  var MINUTE = 60;
  var HOUR = 3600;
  var DAY = 86400;
  var WEEK = 7 * DAY;

  function pluralize(n, singular) {
    return n === 1 ? "1 " + singular : n + " " + singular + "s";
  }

  function formatRelative(then, now) {
    var diff = Math.floor((now - then) / 1000);
    if (diff < 0) diff = 0;
    if (diff < MINUTE) return "just now";
    if (diff < HOUR) return pluralize(Math.floor(diff / MINUTE), "minute") + " ago";
    if (diff < DAY) return pluralize(Math.floor(diff / HOUR), "hour") + " ago";
    if (diff < WEEK) return pluralize(Math.floor(diff / DAY), "day") + " ago";
    return null;
  }

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

  function formatOne(el, now) {
    var iso = el.getAttribute("datetime");
    if (!iso) return;
    var then = new Date(iso);
    if (isNaN(then.getTime())) {
      console.warn("talos.js: cannot parse datetime", iso);
      return;
    }
    var rel = formatRelative(then, now.getTime());
    el.textContent = rel !== null ? rel : formatAbsolute(then, now);
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
