(function () {
  function applyTheme(theme) {
    if (theme === "dark") {
      document.body.classList.add("dark");
    } else {
      document.body.classList.remove("dark");
    }
  }

  // Apply saved theme immediately
  const savedTheme = localStorage.getItem("app_theme") || "light";
  applyTheme(savedTheme);

  // Make it available globally
  window.toggleTheme = function () {
    const isDark = document.body.classList.contains("dark");
    const newTheme = isDark ? "light" : "dark";

    localStorage.setItem("app_theme", newTheme);
    applyTheme(newTheme);
  };
})();