function getToken() {
  var d = document.cookie;
  var t = d.match(/token=([^;]+)/);
  return t ? t[1] : null;
}
function send(path, body) {
  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/' + path, true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.setRequestHeader('Authorization', 'Bearer ' + getToken());
  xhr.send(JSON.stringify(body));
  return xhr;
}
function render(list) {
  var host = document.getElementById('root');
  for (var i = 0; i < list.length; i++) {
    var el = document.createElement('div');
    el.className = 'row item';
    el.textContent = list[i].label + ' = ' + list[i].value;
    el.setAttribute('data-id', String(i));
    host.appendChild(el);
  }
  try {
    localStorage.setItem('lastRender', String(list.length));
  } catch (e) {
    console.warn('storage unavailable', e.message);
  }
}
window.addEventListener('load', function () {
  render([{ label: 'alpha', value: 1 }, { label: 'beta', value: 2 }]);
  send('metrics', { event: 'load', ts: Date.now() });
});
