/*
 *  ┌─────────────────────────────────────────────────────┐
 *  │                                                     │
 *  │   w0rmers RIPTLS                                    │
 *  │                                                     │
 *  │   Universal Android SSL / TLS Pinning Bypass        │
 *  │   Java + ART + Conscrypt + Native OpenSSL            │
 *  │                                                     │
 *  │   "The cert is valid if I say it's valid."           │
 *  └─────────────────────────────────────────────────────┘
 */

setTimeout(function () {
    Java.perform(function () {

        const TAG = "[RIPTLS]//>";
        const VERBOSE = true;
        const STACKTRACE = false;
        const stats = {};

        function log(hook, msg = "") {
            stats[hook] = (stats[hook] || 0) + 1;
            try {
                const tid = Java.use('java.lang.Thread').currentThread().getId();
                console.log(`${TAG} [${hook}] (#${stats[hook]}) [T:${tid}] ${msg}`);
            } catch (_) {
                console.log(`${TAG} [${hook}] ${msg}`);
            }
        }

        function traceIfNeeded() {
            if (!STACKTRACE) return;
            try {
                Java.use("android.util.Log")
                    .getStackTraceString(Java.use("java.lang.Exception").$new())
                    .split("\n")
                    .slice(0, 8)
                    .forEach(l => console.log(`${TAG} | ${l}`));
            } catch (_) {}
        }

        function dumpCert(cert) {
            try {
                const X509 = Java.use("java.security.cert.X509Certificate");
                const c = Java.cast(cert, X509);
                log("CERT", `Subject=${c.getSubjectDN()} Issuer=${c.getIssuerDN()}`);
            } catch (_) {}
        }

        console.log("RIPTLS by w0rmer [LOADED]");

        function now() {
            const d = new Date();
            return d.toISOString().replace("T", " ").replace("Z", "");
        }

        try {
            const ActivityThread = Java.use("android.app.ActivityThread");
            const app = ActivityThread.currentApplication();
            const ctx = app.getApplicationContext();

            console.log("--------------------------------------------------");
            console.log(`RIPTLS [ATTACHED] ${now()}`);
            console.log(`[APP] Package : ${ctx.getPackageName()}`);
            console.log(`[APP] Process : ${ActivityThread.currentProcessName()}`);
            console.log(`[APP] PID     : ${Java.use("android.os.Process").myPid()}`);
            console.log(`[APP] UID     : ${Java.use("android.os.Process").myUid()}`);
            console.log(`[APP] SDK     : ${Java.use("android.os.Build$VERSION").SDK_INT.value}`);
            console.log(`[APP] Device  : ${Java.use("android.os.Build").MODEL.value}`);
            console.log("--------------------------------------------------");
        } catch (_) {}

        /* ============================
           DNS RESOLUTION
           ============================ */
        try {
            const InetAddress = Java.use("java.net.InetAddress");

            InetAddress.getByName.implementation = function (host) {
                log("DNS.getByName", host);
                return this.getByName(host);
            };

            InetAddress.getAllByName.implementation = function (host) {
                log("DNS.getAllByName", host);
                return this.getAllByName(host);
            };
        } catch (_) {}

        /* ============================
           SOCKET CONNECTIONS (IP:PORT)
           ============================ */
        try {
            const Socket = Java.use("java.net.Socket");

            Socket.connect.overload('java.net.SocketAddress').implementation = function (addr) {
                log("Socket.connect", addr.toString());
                return this.connect(addr);
            };

            Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, timeout) {
                log("Socket.connect", `${addr.toString()} timeout=${timeout}`);
                return this.connect(addr, timeout);
            };
        } catch (_) {}

        /* ============================
           SSLContext / TrustManager
           ============================ */
        try {
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');

            const TrustManager = Java.registerClass({
                name: 'dev.w0rmers.deSSL.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted() {},
                    checkServerTrusted(chain) {
                        if (chain && chain.length) dumpCert(chain[0]);
                    },
                    getAcceptedIssuers() { return []; }
                }
            });

            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                log("SSLContext.init", "TrustManager override");
                this.init(km, [TrustManager.$new()], sr);
            };
        } catch (_) {}

        /* ============================
           Conscrypt (Android >= 7)
           ============================ */
        try {
            const ArrayList = Java.use("java.util.ArrayList");
            const TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');

            TMI.checkTrustedRecursive.implementation = function () {
                let host = "<unknown>";
                try {
                    if (arguments.length >= 4 && arguments[3]) {
                        host = arguments[3];
                    }
                } catch (_) {}
                log("TrustManagerImpl.checkTrustedRecursive", `host=${host}`);
                traceIfNeeded();
                return ArrayList.$new();
            };

            TMI.verifyChain.implementation = function (chain, anchors, host) {
                log("TrustManagerImpl.verifyChain", `host=${host}`);
                if (chain && chain.length) dumpCert(chain[0]);
                return chain;
            };
        } catch (_) {}

        /* ============================
           OkHTTP v3
           ============================ */
        try {
            const CP = Java.use('okhttp3.CertificatePinner');

            CP.check.overload('java.lang.String', 'java.util.List')
                .implementation = function (h) { log("OkHTTP.check(list)", h); };

            CP.check.overload('java.lang.String', 'java.security.cert.Certificate')
                .implementation = function (h) { log("OkHTTP.check(cert)", h); };

            CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
                .implementation = function (h) { log("OkHTTP.check(cert[])", h); };

            CP['check$okhttp'].implementation = function (h) {
                log("OkHTTP.check$okhttp", h);
            };

            Java.use("okhttp3.OkHttpClient$Builder")
                .certificatePinner.implementation = function () {
                    log("OkHTTP.Builder.certificatePinner", "nulled");
                    return this;
                };
        } catch (_) {}

        /* ============================
           WebView
           ============================ */
        try {
            Java.use('android.webkit.WebViewClient')
                .onReceivedSslError.overload(
                    'android.webkit.WebView',
                    'android.webkit.SslErrorHandler',
                    'android.net.http.SslError'
                ).implementation = function (v, h) {
                    log("WebViewClient.onReceivedSslError");
                    h.proceed();
                };
        } catch (_) {}

        /* ============================
           Native OpenSSL
           ============================ */
        try {
            const addr = Module.findExportByName("libssl.so", "SSL_verify_cert");
            if (addr) {
                Interceptor.replace(addr, new NativeCallback(function () {
                    console.log(`${TAG} [native] SSL_verify_cert => OK`);
                    return 1;
                }, 'int', ['pointer']));
            }
        } catch (_) {}

        /* ============================
           Anti-Kill
           ============================ */
        try {
            Java.use("java.lang.System").exit.implementation = function (c) {
                log("System.exit", c);
            };
        } catch (_) {}

        try {
            Java.use("android.os.Process").killProcess.implementation = function (p) {
                log("Process.killProcess", p);
            };
        } catch (_) {}

        console.log("--------------------------------------------------");
        console.log(`${TAG} All hooks deployed`);
        console.log(`${TAG} TLS trust is non-existent`);
        console.log("--------------------------------------------------");

        setTimeout(() => {
            console.log(`${TAG} ==== HOOK STATS ====`);
            Object.keys(stats).forEach(k =>
                console.log(`${TAG} ${k}: ${stats[k]}`)
            );
        }, 5000);

    });
}, 0);
