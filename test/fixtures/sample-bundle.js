// ───────────────────────────────────────────────────────────────────────────
//  Sample minified-style bundle fixture for OMEGA-5.0 AST test harness.
//  Exercises: tokenizer, classes, functions, call sites, member access,
//  Angular Ivy (ɵcmp/ɵprov/ɵmod), Vue (createElementVNode), React (jsx),
//  webpack 5 module layout, taint flows (location.search → innerHTML),
//  JWT literals, WebCrypto, network surface, RFC1918 / cloud metadata.
//  Hand-written — not extracted from a real bundle.
// ───────────────────────────────────────────────────────────────────────────
(self.webpackChunk_app = self.webpackChunk_app || []).push([[1234], {
  101: (Q, H, d) => {
    class AppComponent {
      constructor() {
        this.title = "app";
      }
      static ɵcmp = (() => {
        // Angular component definition
        return { selector: "app-root", template: "<h1>Hello</h1>" };
      })();
    }
    class AuthService {
      constructor(http) { this.http = http; }
      static ɵprov = { providedIn: "root" };
    }
    class AppModule {
      static ɵmod = { declarations: [AppComponent], bootstrap: [AppComponent] };
    }
    class FormatPipe {
      transform(v) { return String(v); }
      static ɵpipe = { name: "format" };
    }
    class TooltipDirective {
      static ɵdir = { selector: "[tooltip]" };
    }
    // Export them so the bundle has top-level references
    Q.AppComponent = AppComponent;
    Q.AuthService = AuthService;
    Q.AppModule = AppModule;
    Q.FormatPipe = FormatPipe;
    Q.TooltipDirective = TooltipDirective;
  },

  202: (Q, H, d) => {
    // Vue 3 component shape
    const VueComp = { __vccOpts: { setup() {
      return () => createElementVNode("div", null, "Hello");
    }}};
    Q.VueComp = VueComp;
  },

  303: (Q, H, d) => {
    // React component shape
    function ReactComp(props) {
      return jsx("div", { children: props.label });
    }
    const Forwarded = forwardRef(ReactComp);
    Q.ReactComp = ReactComp;
    Q.Forwarded = Forwarded;
  },

  404: (Q, H, d) => {
    // ── Taint flow: location.search → innerHTML ──
    function renderSearch() {
      const params = new URLSearchParams(window.location.search);
      const q = params.get("q");
      document.getElementById("out").innerHTML = q;  // CWE-79 source→sink
      return q;
    }
    // ── Direct DOM XSS sink with location.hash ──
    function renderHash() {
      const h = location.hash;
      document.body.innerHTML = h;
    }
    // ── eval sink ──
    function dangerEval() {
      const src = localStorage.getItem("eval_src");
      eval(src);
    }
    Q.renderSearch = renderSearch;
    Q.renderHash = renderHash;
    Q.dangerEval = dangerEval;
  },

  505: (Q, H, d) => {
    // ── Crypto patterns ──
    // Hardcoded JWT literal (3 base64url segments, starts with eyJ)
    const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    // WebCrypto subtle.importKey with 'raw'
    crypto.subtle.importKey("raw", new Uint8Array(32), { name: "AES-GCM" }, false, ["encrypt"]);
    // WebCrypto subtle.exportKey exposing key material
    crypto.subtle.exportKey("raw", keyHandle);
    // Node-style weak hash
    crypto.createHash("md5").update("secret").digest();
    // bcrypt with literal hash
    bcrypt.compare(userInput, "$2b$12$KIXxr5K5LHknQ5K5LHknQ5K5LHknQ5K5LHknQ5K5LHknQ5");
    Q.token = token;
  },

  606: (Q, H, d) => {
    // ── Network surface ──
    const apiUrl = `https://api.example.com/v1/users`;  // template literal
    fetch(apiUrl);
    fetch("https://api.example.com/v1/users/123");
    fetch("https://api.example.com/v1/users/456");
    fetch("https://cdn.cloudflare.com/lib.js");
    // Cloud metadata endpoint
    fetch("http://169.254.169.254/latest/meta-data/");
    // RFC1918 internal IP
    const internal = "10.0.0.5";
    const office = "192.168.1.1";
    Q.internal = internal;
    Q.office = office;
  },

  707: (Q, H, d) => {
    // ── PostMessage wildcard origin ──
    window.addEventListener("message", (e) => {
      document.getElementById("out").innerHTML = e.data;
    });
    window.postMessage({ secret: "leaked" }, "*");
  },

  808: (Q, H, d) => {
    // Cross-module webpack require: 808 → 101, 808 → 404
    d(101);
    d(404);
    // Arrow function callback (exercises AST arrow detection)
    const init = () => { console.log("initialized"); };
    const handler = (event) => { return event.type; };
    const asyncOp = async (id) => { return await fetch("/api/" + id); };
    Q.init = init;
    Q.handler = handler;
    Q.asyncOp = asyncOp;
  },
}]);
//# sourceMappingURL=app.bundle.js.map
