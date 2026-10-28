// The interface works without JavaScript; this file only makes it smoother.

// Confirmation for destructive forms.
document.addEventListener('submit', function (e) {
  var f = e.target;
  if (f.dataset && f.dataset.confirm && !window.confirm(f.dataset.confirm)) {
    e.preventDefault();
  }
});

// Logs: always open at the newest line. While you read further up it stays put and offers a jump back;
// Live reloads the log every two seconds.
var log = document.getElementById('log');
if (log) {
  var atBottom = function () { return log.scrollHeight - log.scrollTop - log.clientHeight < 40; };
  var toBottom = function () { log.scrollTop = log.scrollHeight; };
  toBottom();
  window.addEventListener('load', toBottom);
  var jump = document.getElementById('log-jump');
  if (jump) {
    log.addEventListener('scroll', function () { jump.hidden = atBottom(); });
    jump.addEventListener('click', function () { toBottom(); jump.hidden = true; });
  }
  var live = document.getElementById('log-live');
  var status = document.getElementById('log-status');
  if (live && log.dataset.src) {
    live.hidden = false;
    var timer = null;
    var poll = function () {
      fetch(log.dataset.src, { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
        var type = r.headers.get('content-type') || '';
        if (!r.ok || r.redirected || type.indexOf('text/plain') !== 0) { throw new Error('not signed in or server error'); }
        return r.text();
      }).then(function (text) {
        var stick = atBottom();
        if (text !== log.textContent) { log.textContent = text; }
        if (stick) { toBottom(); }
        if (status) { status.textContent = 'Live, updated ' + new Date().toLocaleTimeString(); }
      }).catch(function (e) {
        setLive(false);
        if (status) { status.textContent = 'Live stopped: ' + e.message; }
      });
    };
    var setLive = function (on) {
      live.setAttribute('aria-pressed', on ? 'true' : 'false');
      clearInterval(timer);
      timer = null;
      if (on) { poll(); timer = setInterval(poll, 2000); }
      else if (status) { status.textContent = 'Newest lines at the bottom.'; }
      try { localStorage.setItem('pc-log-live', on ? '1' : ''); } catch (e) { /* storage blocked */ }
    };
    live.addEventListener('click', function () { setLive(live.getAttribute('aria-pressed') !== 'true'); });
    document.addEventListener('visibilitychange', function () {
      if (live.getAttribute('aria-pressed') === 'true') { if (document.hidden) { clearInterval(timer); timer = null; } else { setLive(true); } }
    });
    var remembered = false;
    try { remembered = localStorage.getItem('pc-log-live') === '1'; } catch (e) { /* storage blocked */ }
    if (remembered) { setLive(true); }
  }
}

// Dialogs and menus are <details>. One open at a time; Escape, Cancel and a click outside a menu close them;
// an opened dialog focuses its first field.
function closeAll(except) {
  document.querySelectorAll('details.dialog[open], details.menu[open]').forEach(function (d) {
    if (d !== except && !d.contains(except)) { d.open = false; }
  });
}
document.addEventListener('toggle', function (e) {
  var d = e.target;
  if (!(d instanceof HTMLDetailsElement) || !d.open) { return; }
  if (d.classList.contains('dialog') || d.classList.contains('menu')) { closeAll(d); }
  if (d.classList.contains('dialog')) {
    var f = d.querySelector('.dialog-panel [autofocus], .dialog-panel textarea:not([readonly]), .dialog-panel input:not([type=hidden]):not([type=checkbox]), .dialog-panel select');
    if (f) { setTimeout(function () { f.focus(); }, 30); }
  }
}, true);
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') { closeAll(null); }
});
document.addEventListener('click', function (e) {
  var c = e.target.closest('[data-close]');
  if (c) { e.preventDefault(); var d = c.closest('details'); if (d) { d.open = false; } return; }
  var open = document.querySelector('details.menu[open]');
  if (open && !open.contains(e.target)) { open.open = false; }
});

// The success toast goes away on its own.
var flash = document.querySelector('.flash');
if (flash) { setTimeout(function () { flash.hidden = true; }, 5000); }

// Secret fields are one-line textareas (no autofill); Enter submits instead of adding a line.
document.addEventListener('keydown', function (e) {
  var t = e.target;
  if (t.tagName === 'TEXTAREA' && t.classList.contains('secret') && !t.classList.contains('multi') && e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (t.form && t.form.requestSubmit) { t.form.requestSubmit(); } else if (t.form) { t.form.submit(); }
  }
});

// Secrets tab: filter by name and by service; empty groups hide.
var secretSearch = document.getElementById('secret-search');
var secretService = document.getElementById('secret-service');
function filterSecrets() {
  var q = secretSearch ? secretSearch.value.trim().toUpperCase() : '';
  var svc = secretService ? secretService.value : '';
  var shown = 0;
  document.querySelectorAll('[data-secret]').forEach(function (row) {
    var services = row.dataset.services ? row.dataset.services.split(',') : [];
    var ok = (!q || row.dataset.secret.indexOf(q) !== -1) && (!svc || services.length === 0 || services.indexOf(svc) !== -1);
    row.hidden = !ok;
    if (ok) { shown++; }
  });
  document.querySelectorAll('[data-secret-group]').forEach(function (g) {
    g.hidden = !g.querySelector('[data-secret]:not([hidden])');
  });
  var none = document.getElementById('secret-none');
  if (none) { none.hidden = shown !== 0; }
}
if (secretSearch) { secretSearch.addEventListener('input', filterSecrets); }
if (secretService) { secretService.addEventListener('change', filterSecrets); }

// Egress form: the port list only matters for "only TCP ports".
var egressMode = document.getElementById('egress-mode');
if (egressMode) {
  var syncEgress = function () {
    document.getElementById('egress-ports-field').hidden = egressMode.value !== 'ports';
  };
  egressMode.addEventListener('change', syncEgress);
}

// Route form: the chosen service brings its container port and a host suggestion from the compose file.
var routeService = document.getElementById('route-service');
if (routeService) {
  routeService.addEventListener('change', function () {
    var opt = routeService.options[routeService.selectedIndex];
    var port = document.getElementById('route-port');
    var host = document.getElementById('route-host');
    if (opt.dataset.port) { port.value = opt.dataset.port; }
    if (!host.value || host.value === host.dataset.suggested) {
      host.value = opt.dataset.host || '';
      host.dataset.suggested = host.value;
    }
  });
}
