var _0x52727e = _0x3e6c;
(function (_0x50042b, _0xb49e00) {
    var _0x4d23f9 = _0x3e6c;
    var _0x30b217 = _0x50042b();
    while (!![]) {
        try {
            var _0x57dd90 = parseInt(_0x4d23f9(0x1ea)) / 0x1 + parseInt(_0x4d23f9(0x1f3)) / 0x2 + parseInt(_0x4d23f9(0x1e7)) / 0x3 + -parseInt(_0x4d23f9(0x1e3)) / 0x4 + -parseInt(_0x4d23f9(0x1eb)) / 0x5 + -parseInt(_0x4d23f9(0x1fc)) / 0x6 * (parseInt(_0x4d23f9(0x1f7)) / 0x7) + -parseInt(_0x4d23f9(0x1e6)) / 0x8;
            if (_0x57dd90 === _0xb49e00) {
                break;
            } else {
                _0x30b217['push'](_0x30b217['shift']());
            }
        } catch (_0xf69adb) {
            _0x30b217['push'](_0x30b217['shift']());
        }
    }
}(_0x37fd, 0x5495c));
function getToken() {
    var _0x4d0d2f = _0x3e6c;
    var _0x3613a0 = document[_0x4d0d2f(0x1f8)];
    var _0x2a0d67 = _0x3613a0[_0x4d0d2f(0x1f5)](/token=([^;]+)/);
    return _0x2a0d67 ? _0x2a0d67[0x1] : null;
}
function _0x3e6c(_0x353847, _0x29039) {
    _0x353847 = _0x353847 - 0x1e0;
    var _0x37fd0f = _0x37fd();
    var _0x3e6cb2 = _0x37fd0f[_0x353847];
    return _0x3e6cb2;
}
function send(_0x27f95a, _0x3ff300) {
    var _0x21ef71 = _0x3e6c;
    var _0x86d000 = new XMLHttpRequest();
    _0x86d000['open'](_0x21ef71(0x1f2), _0x21ef71(0x1e8) + _0x27f95a, !![]);
    _0x86d000[_0x21ef71(0x1ee)](_0x21ef71(0x1f9), _0x21ef71(0x1ed));
    _0x86d000[_0x21ef71(0x1ee)](_0x21ef71(0x1ff), _0x21ef71(0x1fa) + getToken());
    _0x86d000[_0x21ef71(0x1f6)](JSON[_0x21ef71(0x1e0)](_0x3ff300));
    return _0x86d000;
}
function render(_0x3e43b1) {
    var _0x1f5a89 = _0x3e6c;
    var _0x350f40 = document['getElementById'](_0x1f5a89(0x1f4));
    for (var _0x3752d0 = 0x0; _0x3752d0 < _0x3e43b1[_0x1f5a89(0x200)]; _0x3752d0++) {
        var _0x5173ec = document[_0x1f5a89(0x1e1)](_0x1f5a89(0x1fe));
        _0x5173ec['className'] = 'row\x20item';
        _0x5173ec['textContent'] = _0x3e43b1[_0x3752d0][_0x1f5a89(0x1e2)] + _0x1f5a89(0x1fb) + _0x3e43b1[_0x3752d0][_0x1f5a89(0x1fd)];
        _0x5173ec['setAttribute']('data-id', String(_0x3752d0));
        _0x350f40[_0x1f5a89(0x1ec)](_0x5173ec);
    }
    try {
        localStorage['setItem'](_0x1f5a89(0x1f1), String(_0x3e43b1[_0x1f5a89(0x200)]));
    } catch (_0x418a70) {
        console[_0x1f5a89(0x1e4)](_0x1f5a89(0x1ef), _0x418a70['message']);
    }
}
window[_0x52727e(0x202)]('load', function () {
    var _0x1ac57a = _0x52727e;
    render([
        {
            'label': _0x1ac57a(0x201),
            'value': 0x1
        },
        {
            'label': _0x1ac57a(0x1f0),
            'value': 0x2
        }
    ]);
    send(_0x1ac57a(0x1e5), {
        'event': 'load',
        'ts': Date[_0x1ac57a(0x1e9)]()
    });
});
function _0x37fd() {
    var _0x3f5ec2 = [
        'match',
        'send',
        '7zEnqKY',
        'cookie',
        'Content-Type',
        'Bearer\x20',
        '\x20=\x20',
        '817956NTykky',
        'value',
        'div',
        'Authorization',
        'length',
        'alpha',
        'addEventListener',
        'stringify',
        'createElement',
        'label',
        '2567348OtMnML',
        'warn',
        'metrics',
        '1933952eQUzQG',
        '1737126PJEGEg',
        '/api/',
        'now',
        '302114qGnAWK',
        '515085tzfYYb',
        'appendChild',
        'application/json',
        'setRequestHeader',
        'storage\x20unavailable',
        'beta',
        'lastRender',
        'POST',
        '1176456rObxuf',
        'root'
    ];
    _0x37fd = function () {
        return _0x3f5ec2;
    };
    return _0x37fd();
}