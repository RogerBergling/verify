(() => {
  'use strict';
  const root = document.documentElement;
  const THEME_KEY = 'verify-theme';

  let storedTheme = null;
  try {
    storedTheme = localStorage.getItem(THEME_KEY);
  } catch (e) {
    // Storage can be disabled; defaults still apply.
  }

  let theme = storedTheme === 'light' || storedTheme === 'dark' ? storedTheme : null;
  if (!theme) {
    const configured = root.dataset.themeDefault;
    if (configured === 'light' || configured === 'dark') {
      theme = configured;
    } else if (configured === 'system') {
      theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    } else {
      theme = 'dark';
    }
  }
  root.dataset.theme = theme;

  function updateThemeColor() {
    const meta = document.getElementById('theme-color');
    if (meta) meta.setAttribute('content', root.dataset.theme === 'light' ? '#f4f7fc' : '#070b14');
  }

  function updateThemeButton(button) {
    const isDark = root.dataset.theme === 'dark';
    const label = isDark
      ? (button.dataset.darkLabel || 'Switch to light theme')
      : (button.dataset.lightLabel || 'Switch to dark theme');
    button.setAttribute('aria-label', label);
    button.setAttribute('title', label);
  }

  document.addEventListener('DOMContentLoaded', () => {
    updateThemeColor();

    const themeButton = document.getElementById('theme-toggle');
    if (themeButton) {
      updateThemeButton(themeButton);
      themeButton.addEventListener('click', () => {
        root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
        try { localStorage.setItem(THEME_KEY, root.dataset.theme); } catch (e) {}
        updateThemeColor();
        updateThemeButton(themeButton);
      });
    }

    const menuButton = document.getElementById('menu-toggle');
    const mobileNav = document.getElementById('mobile-nav');
    if (menuButton && mobileNav) {
      const close = () => {
        menuButton.setAttribute('aria-expanded', 'false');
        mobileNav.hidden = true;
      };
      menuButton.addEventListener('click', () => {
        const expanded = menuButton.getAttribute('aria-expanded') === 'true';
        menuButton.setAttribute('aria-expanded', expanded ? 'false' : 'true');
        mobileNav.hidden = expanded;
      });
      mobileNav.addEventListener('click', (event) => {
        if (event.target.closest('a')) close();
      });
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') close();
      });
    }
  });
})();
