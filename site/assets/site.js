// Copy-to-clipboard for code blocks. Progressive enhancement only; no external calls.
(function () {
  'use strict';
  document.querySelectorAll('button.copy[data-copy]').forEach(function (btn) {
    if (!navigator.clipboard) { btn.hidden = true; return; }
    btn.addEventListener('click', function () {
      var el = document.getElementById(btn.getAttribute('data-copy'));
      if (!el) { return; }
      var text = el.textContent.split('\n')
        .filter(function (line) { return line.trim() !== '' && line.trim().charAt(0) !== '#'; })
        .map(function (line) { return line.replace(/\s+#.*$/, ''); })
        .join('\n');
      navigator.clipboard.writeText(text).then(function () {
        var label = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(function () { btn.textContent = label; }, 1600);
      });
    });
  });
})();
