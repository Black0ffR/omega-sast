function b(c, d) {
    c = c - 0x184;
    var e = a();
    var f = e[c];
    if (b['eQFNOB'] === undefined) {
        var g = function (l) {
            var m = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
            var n = '';
            var o = '';
            for (var p = 0x0, q, r, s = 0x0; r = l['charAt'](s++); ~r && (q = p % 0x4 ? q * 0x40 + r : r, p++ % 0x4) ? n += String['fromCharCode'](0xff & q >> (-0x2 * p & 0x6)) : 0x0) {
                r = m['indexOf'](r);
            }
            for (var t = 0x0, u = n['length']; t < u; t++) {
                o += '%' + ('00' + n['charCodeAt'](t)['toString'](0x10))['slice'](-0x2);
            }
            return decodeURIComponent(o);
        };
        var j = function (k, l) {
            var m = [], n = 0x0, o, p = '';
            k = g(k);
            var q;
            for (q = 0x0; q < 0x100; q++) {
                m[q] = q;
            }
            for (q = 0x0; q < 0x100; q++) {
                n = (n + m[q] + l['charCodeAt'](q % l['length'])) % 0x100;
                o = m[q];
                m[q] = m[n];
                m[n] = o;
            }
            q = 0x0;
            n = 0x0;
            for (var r = 0x0; r < k['length']; r++) {
                q = (q + 0x1) % 0x100;
                n = (n + m[q]) % 0x100;
                o = m[q];
                m[q] = m[n];
                m[n] = o;
                p += String['fromCharCode'](k['charCodeAt'](r) ^ m[(m[q] + m[n]) % 0x100]);
            }
            return p;
        };
        b['nUchyl'] = j;
        b['TvYEgN'] = {};
        b['eQFNOB'] = !![];
    }
    var h = e[0x0];
    if (b['oBVLfu'] !== h) {
        b['TvYEgN'] = {};
        b['oBVLfu'] = h;
    }
    var i = b['TvYEgN'][c];
    if (i === undefined) {
        if (b['lWgWJp'] === undefined) {
            b['lWgWJp'] = !![];
        }
        f = b['nUchyl'](f, d);
        b['TvYEgN'][c] = f;
    } else {
        f = i;
    }
    return f;
}
var m = b;
(function (c, d) {
    var i = b;
    var e = c();
    while (!![]) {
        try {
            var f = parseInt(i(0x184, '(j55')) / 0x1 + -parseInt(i(0x19b, ']U2D')) / 0x2 * (parseInt(i(0x1a1, ']U2D')) / 0x3) + parseInt(i(0x1aa, 'd8Zh')) / 0x4 + parseInt(i(0x1a5, 'n6(3')) / 0x5 + -parseInt(i(0x18e, 'HM*)')) / 0x6 + parseInt(i(0x18b, 'MPFw')) / 0x7 + parseInt(i(0x19e, '3pwO')) / 0x8 * (parseInt(i(0x1ae, 'E[]6')) / 0x9);
            if (f === d) {
                break;
            } else {
                e['push'](e['shift']());
            }
        } catch (g) {
            e['push'](e['shift']());
        }
    }
}(a, 0x7163b));
function getToken() {
    var j = b;
    var c = document[j(0x18c, '6^fM')];
    var e = c[j(0x19c, ')h05')](/token=([^;]+)/);
    return e ? e[0x1] : null;
}
function send(c, d) {
    var k = b;
    var e = new XMLHttpRequest();
    e['open'](k(0x18f, 'BwaI'), k(0x188, 'JoO$') + c, !![]);
    e[k(0x19d, 'HM*)')](k(0x19a, 'tpn5'), 'application/json');
    e[k(0x1a4, 'eHZ^')](k(0x186, 'eq2e'), 'Bearer\x20' + getToken());
    e[k(0x1a9, 'n6(3')](JSON[k(0x195, 'vDr6')](d));
    return e;
}
function render(c) {
    var l = b;
    var d = document[l(0x1a6, ']M)2')](l(0x1a0, 'G2aX'));
    for (var f = 0x0; f < c[l(0x1ad, 'HM*)')]; f++) {
        var g = document[l(0x1ab, 'bWtc')](l(0x196, ']U2D'));
        g[l(0x1a3, ']Mg$')] = l(0x19f, 'aY67');
        g[l(0x194, 'r8Dk')] = c[f][l(0x198, 'mdBD')] + l(0x185, 'wvH9') + c[f]['value'];
        g['setAttribute'](l(0x190, '3pwO'), String(f));
        d[l(0x1a8, 'd8Zh')](g);
    }
    try {
        localStorage[l(0x197, 'n6(3')](l(0x1a7, ']Mg$'), String(c['length']));
    } catch (h) {
        console['warn']('storage\x20unavailable', h[l(0x193, 'zHmm')]);
    }
}
window['addEventListener'](m(0x187, 'I!T0'), function () {
    var n = m;
    render([
        {
            'label': 'alpha',
            'value': 0x1
        },
        {
            'label': 'beta',
            'value': 0x2
        }
    ]);
    send(n(0x191, '*a%@'), {
        'event': n(0x1a2, '(j55'),
        'ts': Date['now']()
    });
});
function a() {
    var o = [
        'e8k4lvC',
        'WOpdHCkvgba',
        'nqfrDv/dMIJcQ8k+W4hcJ8oGnW',
        'WR9Dm8ksW57dRCkWW6pcT0dcPJ7dSW',
        'WOZcN8ocWRSRD8kefY51WOLnW4m',
        'WO9KWRpcV8kdtW',
        'iCoByGJdSwRcNr8DW4nvWQKJ',
        'WRLuoCkuW53dQmk1W4hcOLFcQrxdKG',
        'WQqjbmoQ',
        'WQ/dQv/cG1FcR2e',
        'WPanW5LrWO7cLCkG',
        'qcfBWP0cF8kEoCkluCkeda',
        'qCkNW7fpwmkRW5e',
        'wGuJcmknWQXzW4RdQ3bL',
        'WQxcP8o8nmoHohpdRmob',
        'bSozlW',
        'etLVC8k8sCoo',
        'aevxW7bt',
        'W5K2esTuWOBdP3/dRqTj',
        'x37cIYKTyCozmSoaWPnmW7G',
        'umoNphKKW5X5',
        'bef8WPeV',
        'W74iF8oYWO/cRSoWW6pcQ2FcUYhdMM4CEW',
        'W7JcVb3dLHBcLhueW6VdQq',
        'W63dJmk2sSowW5vpwW',
        'W4hcGcddMG',
        'u8kaBXH/WOytWR1NW6Dco8kG',
        'Dq7dJmkW',
        'uMddLSklzLJdGmkrWRW',
        'W4NcLZ7dHtVcI8oylgTNFCoJdbpcLhu',
        'ugWJcmo8hSkwD1ZdUSkXW78w',
        'W4FdRSoPimoHymoZWQWKgaKXf8on',
        'xw3dHmkmr3pdJ8kyWRZcHG',
        'z8kNDSo+W51TceXwld0',
        'etL1xG',
        'mmoGmCkVWOTZaNr7lHe',
        'W5BdIWZcUSk3jrOluMLhW6RcPa',
        'WRvDmSkrWPJcQCocW5BcR38',
        'W6eizCohWP7cTW',
        'WOm1WPVcNJ/cHmoXWPOCya',
        'fJX3xCooW4zSWPtdOmoQ',
        'k1JcNSoIdSkoW4tdOL3cP8o2WRy',
        'btvH',
        'fmkgD8k4DdVcLdDLmSkuvum'
    ];
    a = function () {
        return o;
    };
    return a();
}