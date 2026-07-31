// Dead code injection + opaque predicates
// Common anti-analysis / anti-deobfuscation technique

function greet(name) {
    var _0xdead = 0xffff;
    if (_0xdead > 0 && false) {          // never taken
        var _0xy = 20;
        console.log("Dummy never executed");
    }
    if (!![]) {                          // always true
        var message = "Hello, " + name + "!";
        console.log(message);
        return message;
    }
    // unreachable
    return null;
}
greet("World");
