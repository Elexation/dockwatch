(function () {
	"use strict";

	var root = document.documentElement;

	// The server pre-renders data-theme from the cookie (flash-free); stale
	// values, including the removed "auto", fall back to dark.
	function readTheme() {
		var m = document.cookie.match(/(?:^|;\s*)dw_theme=(light|dark)/);
		return m ? m[1] : "dark";
	}
	function persistTheme(v) {
		try { document.cookie = "dw_theme=" + v + "; path=/; max-age=31536000; samesite=strict"; } catch (e) {}
	}

	var theme = readTheme();
	root.setAttribute("data-theme", theme);

	var themeBtn = document.querySelector("[data-dw-theme]");
	function labelThemeBtn() {
		var to = "Switch to " + (theme === "light" ? "dark" : "light") + " theme";
		themeBtn.setAttribute("aria-label", to);
		themeBtn.title = to;
	}
	if (themeBtn) {
		labelThemeBtn();
		themeBtn.addEventListener("click", function () {
			theme = theme === "dark" ? "light" : "dark";
			persistTheme(theme);
			root.setAttribute("data-theme", theme);
			labelThemeBtn();
		});
	}

	// View toggle: grouped/flat is a persisted client pref; both subtrees render, CSS shows one.
	// Persisted like the theme, in a cookie the server pre-renders from, so the first
	// paint already shows the chosen view.
	function persistLayout(v) {
		try { document.cookie = "dw_layout=" + v + "; path=/; max-age=31536000; samesite=strict"; } catch (e) {}
	}

	var layouts = document.querySelector("[data-dw-layouts]");
	var seg = document.querySelector("[data-dw-seg]");
	function applyLayout(v) {
		if (layouts) layouts.setAttribute("data-layout", v);
		if (!seg) return;
		var buttons = seg.querySelectorAll("[data-dw-layout]");
		for (var i = 0; i < buttons.length; i++) {
			var on = buttons[i].getAttribute("data-dw-layout") === v;
			buttons[i].classList.toggle("on", on);
			buttons[i].setAttribute("aria-pressed", on ? "true" : "false");
		}
	}
	if (seg && layouts) {
		var segButtons = seg.querySelectorAll("[data-dw-layout]");
		for (var j = 0; j < segButtons.length; j++) {
			segButtons[j].addEventListener("click", function () {
				var v = this.getAttribute("data-dw-layout");
				persistLayout(v);
				applyLayout(v);
			});
		}
	}

	// Host/status filtering. Grouped and flat subtrees both stay in the DOM,
	// so rows hide in both and counts read the flat tree only.
	var statusGroups = {
		update: { update: true, republished: true },
		current: { current: true },
		notcheckable: { local: true, auth: true, rate: true, error: true, pending: true }
	};
	var hostSel = document.querySelector("[data-dw-host]");
	var statusSel = document.querySelector("[data-dw-status]");
	// The inner node, not .dw-count itself: updateCount overwrites textContent, and
	// the wrapper also carries the mobile-only cycle stamp as a sibling.
	var countEl = document.querySelector(".dw-countnum");
	var noResults = document.querySelector("[data-dw-noresults]");
	// Seeded from the server's flag so the load-time count keeps its "checking…" tail.
	var checking = root.hasAttribute("data-checking");

	function rowVisible(row, host, status) {
		if (host !== "all" && row.getAttribute("data-host") !== host) return false;
		if (status !== "all" && !statusGroups[status][row.getAttribute("data-state")]) return false;
		return true;
	}

	function updateCount() {
		if (!countEl || !layouts) return;
		var flat = layouts.querySelectorAll(".dw-flatwrap .dw-row");
		var visible = 0, updates = 0;
		for (var i = 0; i < flat.length; i++) {
			if (!flat[i].hidden) visible++;
			if (flat[i].getAttribute("data-state") === "update") updates++;
		}
		var tail = checking ? "checking…" : updates + (updates === 1 ? " update" : " updates");
		countEl.textContent = visible + " of " + flat.length + " containers · " + tail;
	}

	function applyFilters() {
		if (!layouts) return;
		var host = hostSel ? hostSel.value : "all";
		var status = statusSel ? statusSel.value : "all";
		var rows = layouts.querySelectorAll(".dw-row");
		for (var i = 0; i < rows.length; i++) {
			rows[i].hidden = !rowVisible(rows[i], host, status);
		}
		var groups = layouts.querySelectorAll(".dw-groupedwrap .dw-group");
		for (var g = 0; g < groups.length; g++) {
			groups[g].hidden = groups[g].querySelector(".dw-row:not([hidden])") === null;
		}
		var anyVisible = layouts.querySelector(".dw-flatwrap .dw-row:not([hidden])") !== null;
		layouts.hidden = !anyVisible;
		if (noResults) noResults.hidden = anyVisible;
		updateCount();
	}
	if (hostSel) hostSel.addEventListener("change", applyFilters);
	if (statusSel) statusSel.addEventListener("change", applyFilters);
	// Browsers restore select state across the check-now reload, so re-apply on
	// load or the controls would show a filter the rows no longer reflect.
	applyFilters();

	// Check now: POST, then poll /check and reload once the cycle completes.
	var checkBtn = document.querySelector("[data-dw-check]");

	function setCheckingUI() {
		checking = true;
		root.setAttribute("data-checking", "");
		if (checkBtn) checkBtn.disabled = true;
		// Stale rows belong to an unreachable host: the cycle cannot refresh them,
		// and their time cell is a last-seen stamp, so leave both alone.
		var vers = document.querySelectorAll(".dw-row:not(.stale) .dw-ver");
		for (var i = 0; i < vers.length; i++) {
			vers[i].className = "dw-ver dw-checking";
			vers[i].removeAttribute("title"); // a previous check's error, stale once rechecking
			vers[i].setAttribute("aria-live", "polite");
			vers[i].textContent = "checking…";
		}
		var times = document.querySelectorAll(".dw-row:not(.stale) .dw-time");
		for (var j = 0; j < times.length; j++) times[j].textContent = "…";
		var hups = document.querySelectorAll(".hup");
		for (var k = 0; k < hups.length; k++) hups[k].hidden = true;
		updateCount();
	}

	// usable is the shared "this response carries data" test; a redirect means the
	// session gate bounced us, so the body is a login page rather than JSON.
	function usable(r) { return r.ok && !r.redirected; }

	// Give a stalled cycle plenty of room before declaring it lost: a cycle can
	// legitimately outrun any fixed timeout, so only consecutive failures count.
	var maxPollFailures = 15;

	// Undo the busy state after giving up. setCheckingUI overwrote the row values,
	// so they cannot be restored here; say the check failed rather than leave every
	// row reading "checking…" with nothing still checking. Only rows it swapped are
	// touched: a page loaded mid-cycle never ran it and still shows real values.
	function checkFailedUI() {
		checking = false;
		root.removeAttribute("data-checking");
		if (checkBtn) { checkBtn.disabled = false; }
		var rows = document.querySelectorAll(".dw-row:not(.stale)");
		for (var i = 0; i < rows.length; i++) {
			var ver = rows[i].querySelector(".dw-ver.dw-checking");
			if (!ver) continue;
			ver.className = "dw-ver dw-mut";
			ver.textContent = "check failed";
			var times = rows[i].querySelectorAll(".dw-time");
			for (var j = 0; j < times.length; j++) times[j].textContent = "-";
		}
		var hups = document.querySelectorAll(".hup");
		for (var k = 0; k < hups.length; k++) hups[k].hidden = false;
		updateCount();
	}

	// pollStatus reloads once done(status) holds; a redirect means the session is
	// gone (reload lands on login). Single failures are ignored so a blip cannot
	// abort a running cycle, but they are counted: without a ceiling an unreachable
	// hub leaves this interval running forever behind a permanently disabled button.
	function pollStatus(done) {
		var fails = 0;
		var timer = setInterval(function () {
			fetch("/check").then(function (r) {
				if (r.redirected) { location.reload(); return null; }
				return usable(r) ? r.json() : null;
			}).then(function (s) {
				if (!s) { giveUp(); return; }
				fails = 0;
				if (done(s)) {
					clearInterval(timer);
					location.reload();
				}
			}).catch(giveUp);
		}, 1000);

		function giveUp() {
			if (++fails < maxPollFailures) { return; }
			clearInterval(timer);
			checkFailedUI();
		}
	}

	if (checkBtn) {
		checkBtn.addEventListener("click", function () {
			if (checking) return;
			checking = true; // block re-entry while the POST is in flight
			fetch("/check").then(function (r) {
				return usable(r) ? r.json() : null;
			}).then(function (pre) {
				var last = pre ? pre.lastCycle : "";
				return fetch("/check", { method: "POST" }).then(function (r) {
					if (!usable(r)) throw new Error("check rejected");
					setCheckingUI();
					pollStatus(function (s) { return s.lastCycle !== last; });
				});
			}).catch(function () { location.reload(); });
		});
		// A page rendered mid-cycle arrives with the busy button; resolve it.
		if (checkBtn.hasAttribute("data-dw-checking")) {
			checking = true;
			pollStatus(function (s) { return !s.running; });
		}
	}
})();
