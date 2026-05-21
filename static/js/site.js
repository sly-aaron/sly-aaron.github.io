document.documentElement.classList.add("js");

window.addEventListener("DOMContentLoaded", () => {
  document.body.classList.add("is-ready");

  const toc = document.querySelector(".inline-toc");
  if (toc && !toc.open) {
    toc.open = true;
  }
});
