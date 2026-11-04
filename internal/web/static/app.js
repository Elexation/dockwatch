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

	// markPressed shows which button of a segmented control holds value v.
	function markPressed(buttons, attr, v) {
		for (var i = 0; i < buttons.length; i++) {
			var on = buttons[i].getAttribute(attr) === v;
			buttons[i].classList.toggle("on", on);
			buttons[i].setAttribute("aria-pressed", on ? "true" : "false");
		}
	}

	var theme = readTheme();

	// The Settings page control sets the theme.
	var themeSet = document.querySelectorAll("[data-dw-themeset]");
	function showTheme() {
		root.setAttribute("data-theme", theme);
		markPressed(themeSet, "data-dw-themeset", theme);
	}
	function setTheme(v) {
		theme = v;
		persistTheme(v);
		showTheme();
	}
	showTheme();
	for (var t = 0; t < themeSet.length; t++) {
		themeSet[t].addEventListener("click", function () {
			setTheme(this.getAttribute("data-dw-themeset"));
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
		if (seg) markPressed(seg.querySelectorAll("[data-dw-layout]"), "data-dw-layout", v);
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

	// Check now: POST, then poll /check and reload once the cycle completes.
	// The header and the dashboard status row each carry a button; CSS shows one.
	var checking = false;
	var checkBtns = document.querySelectorAll("[data-dw-check]");
	function disableCheck(v) {
		for (var i = 0; i < checkBtns.length; i++) checkBtns[i].disabled = v;
	}

	function setCheckingUI() {
		checking = true;
		root.setAttribute("data-checking", "");
		disableCheck(true);
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
		disableCheck(false);
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

	function startCheck() {
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
	}
	for (var c = 0; c < checkBtns.length; c++) checkBtns[c].addEventListener("click", startCheck);
	// A page rendered mid-cycle arrives with busy buttons; resolve them with one poll.
	if (checkBtns.length && checkBtns[0].hasAttribute("data-dw-checking")) {
		checking = true;
		pollStatus(function (s) { return !s.running; });
	}
})();
