RIPTLS

Universal Android SSL / TLS Pinning Bypass
“The cert is valid if I say it’s valid.”

RIPTLS is a runtime Android TLS unpinning killchain built on Frida.
It targets every major trust decision point in modern Android apps—Java, ART, Conscrypt, third‑party networking libraries, and native OpenSSL—without modifying or resigning the APK.

Attach. Hook. Observe plaintext.

Features
✔ Universal SSL/TLS pinning bypass
✔ Java + ART + Conscrypt + native OpenSSL coverage
✔ Works pre‑ and post‑Android 7
✔ No APK patching or resigning
✔ Adaptive auto‑patching on failure
✔ Verbose runtime logging + stats
✔ Safe for live debugging (anti‑kill hooks)

What RIPTLS Hooks
Core Android / Java
SSLContext.init() (custom TrustManager injection)
X509TrustManager.checkServerTrusted()
SSLPeerUnverifiedException (auto‑patch caller)
HttpsURLConnection (hostname + socket factory)
Conscrypt (Android ≥ 7)
TrustManagerImpl.verifyChain()
checkTrustedRecursive()
OpenSSLSocketImpl.verifyCertificateChain()
OpenSSLEngineSocketImpl.verifyCertificateChain()
Third‑Party Libraries
OkHTTP v3
CertificatePinner.check()
Builder pinning removal
Trustkit
Hostname verifier bypass
PinningTrustManager bypass
Cronet
Public Key Pinning bypass
Netty
Fingerprint trust checks
WebView
WebViewClient.onReceivedSslError() → proceed()
Native
libssl.so → SSL_verify_cert (forced success)
Anti‑Kill
System.exit()
Process.killProcess()

How It Works

RIPTLS does not rely on a single bypass.
Instead, it:
Overrides trust managers at runtime
Short‑circuits certificate chain verification
Neutralizes pinning logic in popular libraries
Patches native OpenSSL verification
Dynamically adapts when apps throw TLS exceptions
Prevents self‑termination attempts

If an app makes any TLS trust decision, RIPTLS intercepts it.

Usage
Requirements
Rooted device or emulator
Frida server running on target
Frida ≥ 16.x recommended

Run
frida -U -f com.target.app -l riptls.js --no-pause

Or attach to a running process:

frida -U -n com.target.app -l riptls.js

Output

RIPTLS provides:
Hook execution logs
Thread IDs
Certificate subject + issuer dumps
Runtime hook statistics

Example:
[RIPTLS] [OkHTTPv3.check] (#12) [T:23] api.example.com
[RIPTLS] [TrustManagerImpl.verifyChain] api.example.com
[RIPTLS] [native] SSL_verify_cert => OK


At runtime shutdown:
[RIPTLS] ==== HOOK STATS ====
[RIPTLS] OkHTTPv3.check: 34
[RIPTLS] TrustManagerImpl.verifyChain: 18
[RIPTLS] SSLContext.init: 4

Why This Exists
Android TLS pinning is fragmented across:

Platform APIs
Vendor TLS stacks
App‑level libraries
Native fallbacks

Most bypass scripts assume one implementation.
RIPTLS assumes all of them.

Intended Use
RIPTLS is designed for:
Mobile security research
Red teaming / adversarial testing
Reverse engineering
TLS inspection during debugging
Do not use against systems you do not own or have permission to test.

Compatibility
Android Version	Supported
≤ 6 (pre‑N)	✅
7–14+	✅
Emulators	✅
Physical devices	✅

Disclaimer
This tool is provided for educational and research purposes only.
You are responsible for complying with all applicable laws and authorization requirements.

Credits
Inspired by and extending work from:
akabe1
avltree9798
The Frida community
Assembled, weaponized, and maintained by w0rmer.

License

MIT
