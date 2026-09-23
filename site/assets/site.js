// VSAT site: progressive enhancement only. No network calls, no storage, no tracking.
(function () {
  'use strict';
  document.documentElement.classList.add('js');

  function ready(fn) {
    if (document.readyState !== 'loading') { fn(); } else { document.addEventListener('DOMContentLoaded', fn); }
  }

  ready(function () {
    // Header border once the page scrolls.
    var top = document.querySelector('.top');
    if (top) {
      var onScroll = function () { top.classList.toggle('is-scrolled', window.scrollY > 8); };
      window.addEventListener('scroll', onScroll, { passive: true });
      onScroll();
    }

    // Copy buttons: copy commands, dropping comment lines and trailing comments.
    document.querySelectorAll('button.copy[data-copy]').forEach(function (btn) {
      if (!navigator.clipboard || !window.isSecureContext) { btn.hidden = true; return; }
      var label = btn.textContent;
      var timer;
      btn.addEventListener('click', function () {
        var el = document.getElementById(btn.getAttribute('data-copy'));
        if (!el) { return; }
        var text = el.textContent.split('\n')
          .filter(function (line) { var t = line.trim(); return t !== '' && t.charAt(0) !== '#'; })
          .map(function (line) { return line.replace(/\s+#.*$/, ''); })
          .join('\n');
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = 'Copied';
          btn.classList.add('is-done');
          clearTimeout(timer);
          timer = setTimeout(function () { btn.textContent = label; btn.classList.remove('is-done'); }, 1600);
        });
      });
    });

    // Report viewer tabs (WAI-ARIA tabs pattern, automatic activation).
    document.querySelectorAll('[data-tabs]').forEach(function (root) {
      var tabs = Array.prototype.slice.call(root.querySelectorAll('[role="tab"]'));
      var caption = root.querySelector('.viewer-caption');
      function select(tab, focus) {
        tabs.forEach(function (t) {
          var on = t === tab;
          t.setAttribute('aria-selected', on ? 'true' : 'false');
          t.tabIndex = on ? 0 : -1;
          var panel = document.getElementById(t.getAttribute('aria-controls'));
          if (!panel) { return; }
          if (on) {
            if (panel.hidden) {
              panel.hidden = false;
              panel.classList.remove('is-entering');
              void panel.offsetWidth;
              panel.classList.add('is-entering');
            }
          } else {
            panel.hidden = true;
          }
        });
        if (caption) {
          var d = tab.querySelector('.vt-desc');
          caption.textContent = d ? d.textContent : '';
        }
        if (focus) { tab.focus(); }
      }
      tabs.forEach(function (tab, i) {
        tab.addEventListener('click', function () { select(tab, false); });
        tab.addEventListener('keydown', function (e) {
          var n = null;
          if (e.key === 'ArrowDown' || e.key === 'ArrowRight') { n = (i + 1) % tabs.length; }
          else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') { n = (i - 1 + tabs.length) % tabs.length; }
          else if (e.key === 'Home') { n = 0; }
          else if (e.key === 'End') { n = tabs.length - 1; }
          if (n !== null) { e.preventDefault(); select(tabs[n], true); }
        });
      });
    });
  });
})();
