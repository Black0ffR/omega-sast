// Webpack-style / module-bundler output appearance
// (IIFE module wrapper + require-like map + minified body)

(function(modules) {
    var installedModules = {};
    function __webpack_require__(moduleId) {
        if (installedModules[moduleId]) {
            return installedModules[moduleId].exports;
        }
        var module = installedModules[moduleId] = {
            i: moduleId,
            l: false,
            exports: {}
        };
        modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
        module.l = true;
        return module.exports;
    }
    __webpack_require__.m = modules;
    __webpack_require__.c = installedModules;
    __webpack_require__.d = function(exports, name, getter) {
        if (!__webpack_require__.o(exports, name)) {
            Object.defineProperty(exports, name, { enumerable: true, get: getter });
        }
    };
    __webpack_require__.o = function(object, property) {
        return Object.prototype.hasOwnProperty.call(object, property);
    };
    return __webpack_require__(__webpack_require__.s = 0);
})([
    /* 0 */
    function(module, exports, __webpack_require__) {
        "use strict";
        function greet(name) {
            var message = "Hello, " + name + "!";
            console.log(message);
            return message;
        }
        greet("World");
    }
]);
