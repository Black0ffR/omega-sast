// Synthetic vulnerable bundle — patterns that any decent SAST MUST catch.
// Used to verify omega-sast produces true positives on real-looking code.

// 1. CWE-79: Reflected XSS via innerHTML using location.hash
function renderComment() {
  var hash = location.hash.substring(1);
  document.getElementById('out').innerHTML = decodeURIComponent(hash);
  return hash;
}

// 2. CWE-79: innerHTML with document.referrer
function renderReferrer() {
  document.body.innerHTML = document.referrer;
}

// 3. CWE-95: Direct eval of user input
function runUserCode() {
  var code = location.search.split('code=')[1] || '';
  eval(decodeURIComponent(code));
}

// 4. CWE-95: Function() constructor from input
function compileExpr() {
  var expr = document.getElementById('expr').value;
  return new Function('x', 'return ' + expr);
}

// 5. CWE-78: Command injection via child_process
const cp = require('child_process');
function runCmd() {
  var host = document.getElementById('host').value;
  cp.exec('ping -c 1 ' + host);
  cp.execSync('nslookup ' + host);
}

// 6. CWE-798: Hardcoded credentials (general)
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";
const JWT_SECRET = "super-secret-jwt-key-do-not-commit-2024";
const STRIPE_KEY = "FAKE_STRIPE_KEY_REDACTED_FOR_REPO_POLICY";

// 7. CWE-327: Weak crypto (MD5/SHA1 for passwords)
function hashPassword(pw) {
  return CryptoJS.MD5(pw).toString();
}

// 8. CWE-22: Path traversal via fs.readFile
const fs = require('fs');
function readUserFile() {
  var name = document.location.search.split('file=')[1];
  return fs.readFileSync('/var/data/' + name, 'utf8');
}

// 9. CWE-601: open redirect
function go() {
  var url = new URL(location.href).searchParams.get('next');
  window.location = url;
}

// 10. CWE-94: Code injection via Function constructor
function dynamicModule() {
  var src = atob(localStorage.getItem('plugin_src'));
  return new Function(src)();
}

// 11. CWE-79: document.write with user input
document.write('<h1>' + location.search + '</h1>');

// 12. CWE-1321: Prototype pollution
function merge(target, source) {
  for (var k in source) {
    target[k] = source[k];
  }
}

// 13. CWE-352: CSRF token bypass
function submitForm() {
  fetch('/api/transfer', { method: 'POST', body: JSON.stringify({amount: 1000}) });
}

// 14. CWE-319: Cleartext HTTP in production code
fetch('http://api.example.com/users', { credentials: 'include' });
