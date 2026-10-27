// Confirmation for destructive forms. The interface works without JavaScript; this only adds the question.
document.addEventListener('submit', function (e) {
  var f = e.target;
  if (f.dataset && f.dataset.confirm && !window.confirm(f.dataset.confirm)) {
    e.preventDefault();
  }
});
var log = document.getElementById('log');
if (log) { log.scrollTop = log.scrollHeight; }

// Secret fields are one-line textareas (no autofill); Enter submits instead of adding a line.
document.addEventListener('keydown', function (e) {
  var t = e.target;
  if (t.tagName === 'TEXTAREA' && t.classList.contains('secret') && e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (t.form && t.form.requestSubmit) { t.form.requestSubmit(); } else if (t.form) { t.form.submit(); }
  }
});

// Egress form: the port list only matters for "only TCP ports".
var egressMode = document.getElementById('egress-mode');
if (egressMode) {
  egressMode.addEventListener('change', function () {
    document.getElementById('egress-ports-field').hidden = egressMode.value !== 'ports';
  });
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
