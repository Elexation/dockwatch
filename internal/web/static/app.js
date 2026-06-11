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

	var checkBtn = document.querySelector("[data-dw-check]");
	if (checkBtn) {
		checkBtn.addEventListener("click", function () {
			
		});
	}
})();
