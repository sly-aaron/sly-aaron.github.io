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
});
