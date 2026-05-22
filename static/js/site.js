document.documentElement.classList.add("js");

window.addEventListener("DOMContentLoaded", () => {
  document.body.classList.add("is-ready");

  const toc = document.querySelector(".inline-toc");
  if (toc && !toc.open) {
    toc.open = true;
  }

  const key = "site-theme";
  const root = document.documentElement;
  const toggle = document.querySelector(".theme-toggle");

  const applyTheme = (theme) => {
    root.dataset.theme = theme;
    localStorage.setItem(key, theme);

    if (!toggle) return;
    const isDark = theme === "dark";
    toggle.setAttribute("aria-pressed", String(isDark));
    toggle.querySelector(".theme-toggle__icon").textContent = isDark ? "☀" : "☾";
    toggle.querySelector(".theme-toggle__text").textContent = isDark ? "Light" : "Dark";
  };

  applyTheme(root.dataset.theme || "light");

  toggle?.addEventListener("click", () => {
    applyTheme(root.dataset.theme === "dark" ? "light" : "dark");
  });

  const panelToggles = Array.from(document.querySelectorAll("[data-reading-panel-toggle]"));
  const panelBackdrop = document.querySelector("[data-reading-panel-close]");

  if (panelToggles.length > 0) {
    const compactPanels = window.matchMedia("(max-width: 1240px)");
    const panelNames = ["article-index", "content-index"];
    const panels = Object.fromEntries(
      panelNames.map((name) => [name, document.querySelector(`[data-reading-panel="${name}"]`)])
    );

    const hiddenClass = (name) => `is-${name}-hidden`;
    const openClass = (name) => `is-${name}-open`;
    const storageKey = (name) => `reading-panel-${name}`;

    const getPreference = (name) => {
      try {
        return localStorage.getItem(storageKey(name));
      } catch {
        return null;
      }
    };

    const setPreference = (name, value) => {
      try {
        localStorage.setItem(storageKey(name), value);
      } catch {
        // The toggle should still work even when storage is unavailable.
      }
    };

    const isCompact = () => compactPanels.matches;
    const isPanelOpen = (name) => root.classList.contains(openClass(name));
    const isPanelVisible = (name) => !root.classList.contains(hiddenClass(name));

    const closePanels = () => {
      panelNames.forEach((name) => root.classList.remove(openClass(name)));
      updatePanelControls();
    };

    const applyWidePreferences = () => {
      panelNames.forEach((name) => {
        root.classList.toggle(hiddenClass(name), getPreference(name) === "hidden");
      });
    };

    function updatePanelControls() {
      const compact = isCompact();
      const overlayOpen = compact && panelNames.some(isPanelOpen);

      root.classList.toggle("is-sidebar-overlay-open", overlayOpen);
      if (panelBackdrop) {
        panelBackdrop.hidden = !overlayOpen;
      }

      panelToggles.forEach((button) => {
        const name = button.dataset.readingPanelToggle;
        const expanded = compact ? isPanelOpen(name) : isPanelVisible(name);
        const state = button.querySelector(".sidebar-toggle__state");

        button.setAttribute("aria-expanded", String(expanded));
        if (state) {
          state.textContent = compact ? (expanded ? "关闭" : "打开") : expanded ? "隐藏" : "显示";
        }

        panels[name]?.setAttribute("aria-hidden", String(!expanded));
      });
    }

    const handlePanelModeChange = () => {
      closePanels();
      if (!isCompact()) {
        applyWidePreferences();
      }
      updatePanelControls();
    };

    applyWidePreferences();
    updatePanelControls();

    panelToggles.forEach((button) => {
      button.addEventListener("click", () => {
        const name = button.dataset.readingPanelToggle;

        if (isCompact()) {
          const shouldOpen = !isPanelOpen(name);
          panelNames.forEach((panelName) => root.classList.remove(openClass(panelName)));
          if (shouldOpen) {
            root.classList.add(openClass(name));
          }
        } else {
          const shouldHide = isPanelVisible(name);
          root.classList.toggle(hiddenClass(name), shouldHide);
          setPreference(name, shouldHide ? "hidden" : "visible");
        }

        updatePanelControls();
      });
    });

    panelBackdrop?.addEventListener("click", closePanels);

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && isCompact() && panelNames.some(isPanelOpen)) {
        closePanels();
      }
    });

    Object.values(panels).forEach((panel) => {
      panel?.addEventListener("click", (event) => {
        if (isCompact() && event.target.closest("a")) {
          closePanels();
        }
      });
    });

    if (compactPanels.addEventListener) {
      compactPanels.addEventListener("change", handlePanelModeChange);
    } else {
      compactPanels.addListener(handlePanelModeChange);
    }
  }
});
