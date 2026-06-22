const themeKey = 'funsub_theme';

function setTheme(theme) {
  const isDark = theme === 'dark';
  document.body.classList.toggle('dark', isDark);
  localStorage.setItem(themeKey, isDark ? 'dark' : 'light');
}

function loadTheme() {
  const saved = localStorage.getItem(themeKey);
  setTheme(saved === 'dark' ? 'dark' : 'light');
}

function toggleTheme() {
  const isDarkNow = document.body.classList.contains('dark');
  setTheme(isDarkNow ? 'light' : 'dark');
}

document.addEventListener('DOMContentLoaded', loadTheme);