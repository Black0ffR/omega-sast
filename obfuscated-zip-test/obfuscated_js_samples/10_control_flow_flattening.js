// Control-flow flattening example (switch dispatcher style)
// Typical of javascript-obfuscator with controlFlowFlattening enabled

(function(){
    var _0xstate = '0';
    while (true) {
        switch (_0xstate) {
            case '0':
                var _0xmsg = "Hello";
                _0xstate = '1';
                break;
            case '1':
                _0xmsg += ", World!";
                _0xstate = '2';
                break;
            case '2':
                console.log(_0xmsg);
                _0xstate = '3';
                break;
            case '3':
                return;
        }
    }
})();
