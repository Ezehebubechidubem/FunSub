(function(){

  const themeKey = "funsub_theme";


  function applyTheme(){

    const savedTheme = localStorage.getItem(themeKey);

    if(savedTheme === "dark"){
      document.body.classList.add("dark");
    }else{
      document.body.classList.remove("dark");
    }

  }


  window.toggleDarkMode = function(){

    const isDark = document.body.classList.toggle("dark");

    localStorage.setItem(
      themeKey,
      isDark ? "dark" : "light"
    );

  };


  // Run automatically on every page
  applyTheme();


})();