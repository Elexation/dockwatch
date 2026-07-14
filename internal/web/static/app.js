(function () {
	"use strict";

	var root = document.documentElement;

	// server renders data-theme from the dw_theme cookie for a flash-free
	function readTheme() {
		var m = document.cookie.match(/(?:^|;\s*)dw_theme=(auto|light|dark)/);
		if (m) return m[1];
		try { return localStorage.getItem("dw_theme") || "auto"; } catch (e) { return "auto"; }
	}
	function persistTheme(v) {
		try { localStorage.setItem("dw_theme", v); } catch (e) {}
		try { document.cookie = "dw_theme=" + v + "; path=/; max-age=31536000; samesite=strict"; } catch (e) {}
	}

	var theme = readTheme();
	root.setAttribute("data-theme", theme);

	var themeSel = document.querySelector("[data-dw-theme]");
	if (themeSel) {
		themeSel.value = theme;
		themeSel.addEventListener("change", function () {
			theme = themeSel.value;
			persistTheme(theme);
			root.setAttribute("data-theme", theme);
		});
	}
	try {
		window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
			if (theme === "auto") root.setAttribute("data-theme", "auto");
		});
	} catch (e) {}

	// View toggle: grouped/flat is a persisted client pref; both subtrees render, CSS shows one.
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
		var saved;
		try { saved = localStorage.getItem("dw_layout"); } catch (e) {}
		if (saved) applyLayout(saved);
		var segButtons = seg.querySelectorAll("[data-dw-layout]");
		for (var j = 0; j < segButtons.length; j++) {
			segButtons[j].addEventListener("click", function () {
				var v = this.getAttribute("data-dw-layout");
				try { localStorage.setItem("dw_layout", v); } catch (e) {}
				applyLayout(v);
			});
		}
	}

	// Host/status filtering. Grouped and flat subtrees both stay in the DOM,
	// so rows hide in both and counts read the flat tree only.
	var statusGroups = {
		update: { update: true, republished: true },
		current: { current: true },
		notcheckable: { local: true, auth: true, rate: true }
	};
	var hostSel = document.querySelector("[data-dw-host]");
	var statusSel = document.querySelector("[data-dw-status]");
	var countEl = document.querySelector(".dw-count");
	var noResults = document.querySelector("[data-dw-noresults]");
	var checking = false;

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

	// Check now: POST, then poll /check and reload once the cycle completes.
	var checkBtn = document.querySelector("[data-dw-check]");

	function setCheckingUI() {
		checking = true;
		if (checkBtn) {
			checkBtn.disabled = true;
			checkBtn.textContent = "";
			var spin = document.createElement("span");
			spin.className = "dw-spin";
			spin.setAttribute("aria-hidden", "true");
			checkBtn.appendChild(spin);
			checkBtn.appendChild(document.createTextNode("Checking…"));
		}
		var cycle = document.querySelector(".dw-cycle");
		if (cycle) cycle.textContent = "last cycle: running…";
		var vers = document.querySelectorAll(".dw-ver");
		for (var i = 0; i < vers.length; i++) {
			vers[i].className = "dw-ver dw-checking";
			vers[i].setAttribute("aria-live", "polite");
			vers[i].textContent = "checking…";
		}
		var times = document.querySelectorAll(".dw-time");
		for (var j = 0; j < times.length; j++) times[j].textContent = "…";
		var hups = document.querySelectorAll(".hup");
		for (var k = 0; k < hups.length; k++) hups[k].hidden = true;
		updateCount();
	}

	// pollStatus reloads once done(status) holds; a redirect means the session
	// is gone (reload lands on login), a network error keeps polling.
	function pollStatus(done) {
		var timer = setInterval(function () {
			fetch("/check").then(function (r) {
				if (r.redirected) { location.reload(); return null; }
				if (!r.ok) return null;
				return r.json();
			}).then(function (s) {
				if (s && done(s)) {
					clearInterval(timer);
					location.reload();
				}
			}).catch(function () {});
		}, 1000);
	}

	if (checkBtn) {
		checkBtn.addEventListener("click", function () {
			if (checking) return;
			checking = true; // block re-entry while the POST is in flight
			fetch("/check").then(function (r) {
				return r.ok && !r.redirected ? r.json() : null;
			}).then(function (pre) {
				var last = pre ? pre.lastCycle : "";
				return fetch("/check", { method: "POST" }).then(function (r) {
					if (!r.ok || r.redirected) throw new Error("check rejected");
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
