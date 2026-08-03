package core

type Module struct {
	ID          string
	Name        string
	Category    string
	Description string
}

var Modules = []Module{
	{"secure-context", "Secure browser context", "Security controls", "Checks whether modern security-gated browser APIs are running in a trustworthy context."},
	{"csp-enforcement", "Content Security Policy enforcement", "Security controls", "Verifies that unsafe dynamic code execution is blocked by the scanner's strict CSP."},
	{"trusted-types", "Trusted Types support", "Security controls", "Checks support for DOM injection hardening through Trusted Types."},
	{"cross-origin-isolation", "Cross-origin isolation", "Security controls", "Checks COOP/COEP isolation and SharedArrayBuffer gating."},
	{"automation-exposure", "Automation exposure", "Security controls", "Detects navigator.webdriver automation disclosure."},
	{"permission-state", "Sensitive permission states", "Permissions", "Reads permission states without asking the user for camera, microphone, location, notifications, or clipboard access."},
	{"media-device-labels", "Media device metadata", "Permissions", "Checks whether camera or microphone labels are exposed before permission is granted."},
	{"webauthn", "WebAuthn and passkeys", "Capabilities", "Checks modern phishing-resistant authentication support without creating credentials."},
	{"privacy-signals", "Privacy preference signals", "Privacy signals", "Checks Global Privacy Control and Do Not Track signals."},
	{"request-headers", "Browser request headers", "Privacy signals", "Records locally observed headers, including User-Agent Client Hints and Sec-GPC."},
	{"first-party-cookies", "First-party cookies", "Storage", "Tests normal first-party cookie operation."},
	{"third-party-cookies", "Third-party cookie policy", "Storage", "Best-effort loopback test of cross-site cookie access."},
	{"web-storage", "Browser storage", "Storage", "Tests localStorage, sessionStorage, IndexedDB, Cache API, and quota disclosure."},
	{"webrtc-addresses", "WebRTC address exposure", "Network privacy", "Checks whether WebRTC exposes raw local IP addresses or privacy-preserving mDNS hostnames."},
	{"network-information", "Network Information API", "Network privacy", "Checks whether connection type, RTT, and downlink estimates are exposed."},
	{"canvas-fingerprint", "Canvas fingerprint surface", "Fingerprinting", "Measures deterministic canvas output available to websites."},
	{"webgl-fingerprint", "WebGL device exposure", "Fingerprinting", "Checks graphics vendor and renderer information exposed through WebGL."},
	{"audio-fingerprint", "Audio fingerprint surface", "Fingerprinting", "Measures deterministic OfflineAudioContext output available to websites."},
	{"font-enumeration", "Installed font inference", "Fingerprinting", "Checks how many common local fonts can be inferred through rendering differences."},
	{"ua-client-hints", "User-Agent Client Hints", "Fingerprinting", "Checks browser and device details exposed through low- and high-entropy hints."},
	{"screen-hardware", "Screen and hardware entropy", "Fingerprinting", "Checks screen, CPU-thread, memory, touch, and locale information exposed to websites."},
	{"plugins-mime", "Plug-in and MIME metadata", "Fingerprinting", "Checks browser plug-in, MIME type, and PDF viewer exposure."},
	{"webgpu", "WebGPU adapter exposure", "Fingerprinting", "Checks whether WebGPU and adapter metadata are exposed."},
	{"legacy-technology", "Legacy browser technologies", "Legacy technology", "Checks for ActiveX, Flash, Java applets, Silverlight, VBScript, and related obsolete surfaces."},
	{"platform-capabilities", "Modern platform capabilities", "Capabilities", "Inventory of WebAssembly, Service Workers, SVG, MathML, WebRTC, media, and related APIs."},
}
