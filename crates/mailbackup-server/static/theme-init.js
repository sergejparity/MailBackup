// Applies the saved theme before first paint. Kept in a file (not inline) so the
// Content-Security-Policy can forbid inline scripts.
(function() {
  try {
    const savedTheme = localStorage.getItem('mailbackup_theme') || 'system';
    let effective = savedTheme;
    if (savedTheme === 'system') {
      effective = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    document.documentElement.setAttribute('data-theme', effective);
    document.documentElement.setAttribute('data-theme-preference', savedTheme);
  } catch (e) {}
})();
