(function () {

  const THEME_KEY = "funsub_theme";


  function loadTheme() {

    const saved = localStorage.getItem(THEME_KEY);

    if (saved === "dark") {
      document.body.classList.add("dark");
    } else {
      document.body.classList.remove("dark");
    }

  }


  window.toggleDarkMode = function () {

    const darkEnabled = document.body.classList.toggle("dark");


    localStorage.setItem(
      THEME_KEY,
      darkEnabled ? "dark" : "light"
    );


  };


  // Apply automatically when every page opens
  loadTheme();


})();