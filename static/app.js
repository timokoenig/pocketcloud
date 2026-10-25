// Confirmation for destructive forms. The interface works without JavaScript; this only adds the question.
document.addEventListener('submit', function (e) {
  var f = e.target;
  if (f.dataset && f.dataset.confirm && !window.confirm(f.dataset.confirm)) {
    e.preventDefault();
  }
});
var log = document.getElementById('log');
if (log) { log.scrollTop = log.scrollHeight; }

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
