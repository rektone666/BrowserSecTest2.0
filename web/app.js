'use strict';

(() => {
  const params = new URLSearchParams(location.search);
  const token = params.get('token') || '';
  const started = performance.now();
  const startedAt = new Date().toISOString();
  const findings = [];
  const observations = {};

  const ui = {
    phase: document.getElementById('phase'),
    counter: document.getElementById('counter'),
    progress: document.getElementById('progress'),
    track: document.querySelector('.progress-track'),
    current: document.getElementById('current'),
    results: document.getElementById('results'),
    complete: document.getElementById('complete'),
    completeMessage: document.getElementById('complete-message')
  };

  function finding(id, name, category, status, severity, summary, evidence = {}, recommendation = '') {
    return { id, name, category, status, severity, summary, evidence, recommendation };
  }

  function renderFinding(item) {
    const row = document.createElement('div');
    row.className = 'result';

    const badge = document.createElement('span');
    badge.className = `badge ${item.status}`;
    badge.textContent = item.status;

    const body = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = item.name;
    const text = document.createElement('p');
    text.textContent = item.summary;
    body.append(title, text);
    row.append(badge, body);
    ui.results.append(row);
  }

  function asError(error) {
    return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  }

  async function sha256(value) {
    if (!crypto.subtle) return null;
    const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
  }

  async function withTimeout(promise, milliseconds, label = 'operation') {
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds);
    });
    try {
      return await Promise.race([promise, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  function classifyCandidate(candidate) {
    const text = candidate || '';
    const parts = text.split(/\s+/);
    const typeIndex = parts.indexOf('typ');
    const type = typeIndex >= 0 ? parts[typeIndex + 1] : 'unknown';
    const address = parts.length > 4 ? parts[4] : '';
    let addressClass = 'unknown';
    if (/\.local$/i.test(address)) addressClass = 'mdns';
    else if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address)) addressClass = 'private-ipv4';
    else if (/^(127\.|0\.)/.test(address)) addressClass = 'loopback-ipv4';
    else if (/^[0-9.]+$/.test(address)) addressClass = 'public-ipv4';
    else if (address.includes(':')) {
      addressClass = /^(fc|fd|fe80)/i.test(address) ? 'private-ipv6' : 'ipv6';
    }
    return { type, addressClass };
  }

  async function queryPermission(name) {
    if (!navigator.permissions?.query) return { state: 'unsupported' };
    try {
      const result = await withTimeout(navigator.permissions.query({ name }), 2500, `permission ${name}`);
      return { state: result.state };
    } catch (error) {
      return { state: 'unsupported', error: asError(error) };
    }
  }

  async function testSecureContext() {
    const secure = window.isSecureContext === true;
    const cryptoAvailable = Boolean(globalThis.crypto?.subtle);
    observations.secureContext = { secure, cryptoAvailable, origin: location.origin };
    return finding(
      'secure-context', 'Secure browser context', 'Security controls',
      secure && cryptoAvailable ? 'pass' : 'fail', secure ? 'none' : 'high',
      secure ? 'The browser recognizes the local scanner as a trustworthy context.' : 'Security-gated browser APIs are unavailable because this context is not considered secure.',
      observations.secureContext,
      secure ? '' : 'Use an up-to-date browser that treats loopback origins as trustworthy.'
    );
  }

  async function testCSP() {
    let evalBlocked = false;
    let error = '';
    try {
      // This must be blocked by the scanner page's Content Security Policy.
      globalThis.eval('1 + 1');
    } catch (caught) {
      evalBlocked = true;
      error = caught?.name || 'blocked';
    }
    observations.csp = { evalBlocked, error };
    return finding(
      'csp-enforcement', 'Content Security Policy enforcement', 'Security controls',
      evalBlocked ? 'pass' : 'fail', evalBlocked ? 'none' : 'high',
      evalBlocked ? 'Unsafe dynamic JavaScript execution was blocked.' : 'The browser did not enforce the scanner page’s strict script policy.',
      observations.csp,
      evalBlocked ? '' : 'Update the browser and check whether enterprise policy or extensions are weakening CSP enforcement.'
    );
  }

  async function testTrustedTypes() {
    const supported = Boolean(globalThis.trustedTypes);
    let assignmentBlocked = false;
    let error = '';
    try {
      const node = document.createElement('div');
      node.innerHTML = '<b>browsersec</b>';
    } catch (caught) {
      assignmentBlocked = true;
      error = caught?.name || 'blocked';
    }
    observations.trustedTypes = { supported, assignmentBlocked, error };
    return finding(
      'trusted-types', 'Trusted Types DOM protection', 'Security controls',
      supported && assignmentBlocked ? 'pass' : 'info', 'none',
      supported && assignmentBlocked
        ? 'Trusted Types is available and blocked an unsafe HTML assignment.'
        : supported
          ? 'Trusted Types is available, but enforcement was not observed.'
          : 'Trusted Types is not implemented by this browser; this is currently browser-dependent.',
      observations.trustedTypes
    );
  }

  async function testIsolation() {
    const isolated = globalThis.crossOriginIsolated === true;
    const sharedArrayBuffer = typeof SharedArrayBuffer === 'function';
    observations.isolation = { crossOriginIsolated: isolated, sharedArrayBuffer };
    return finding(
      'cross-origin-isolation', 'Cross-origin isolation', 'Security controls',
      isolated && sharedArrayBuffer ? 'pass' : 'warn', isolated ? 'low' : 'medium',
      isolated && sharedArrayBuffer
        ? 'COOP/COEP isolation is active and SharedArrayBuffer is correctly gated behind it.'
        : 'The browser did not establish the expected cross-origin isolated environment.',
      observations.isolation,
      isolated ? '' : 'Update the browser; isolation headers are supplied automatically by BrowserSec.'
    );
  }

  async function testAutomation() {
    const webdriver = navigator.webdriver === true;
    observations.automation = { webdriver };
    return finding(
      'automation-exposure', 'Automation disclosure', 'Security controls',
      webdriver ? 'warn' : 'pass', webdriver ? 'medium' : 'none',
      webdriver ? 'The browser tells websites that it is controlled by automation.' : 'The browser does not expose the standard automation flag.',
      observations.automation,
      webdriver ? 'Run the normal desktop browser rather than a WebDriver-controlled session for everyday browsing.' : ''
    );
  }

  async function testPermissions() {
    const names = ['geolocation', 'camera', 'microphone', 'notifications', 'clipboard-read', 'clipboard-write'];
    const states = {};
    for (const name of names) states[name] = await queryPermission(name);
    if (globalThis.Notification && states.notifications.state === 'unsupported') {
      states.notifications = { state: Notification.permission };
    }
    const sensitiveGranted = ['geolocation', 'camera', 'microphone', 'clipboard-read'].filter(name => states[name]?.state === 'granted');
    observations.permissions = states;
    return finding(
      'permission-state', 'Sensitive permission state', 'Permissions',
      sensitiveGranted.length ? 'warn' : 'pass', sensitiveGranted.length ? 'high' : 'none',
      sensitiveGranted.length
        ? `This fresh local origin unexpectedly has sensitive access: ${sensitiveGranted.join(', ')}.`
        : 'No sensitive permission was granted, and no permission prompt was shown.',
      { states, sensitiveGranted },
      sensitiveGranted.length ? 'Review browser site permissions and revoke access that is not intentional.' : ''
    );
  }

  async function testMediaDevices() {
    if (!navigator.mediaDevices?.enumerateDevices) {
      return finding('media-device-labels', 'Media device metadata', 'Permissions', 'unavailable', 'none', 'The MediaDevices enumeration API is unavailable.');
    }
    try {
      const devices = await withTimeout(navigator.mediaDevices.enumerateDevices(), 3500, 'media device enumeration');
      const counts = devices.reduce((acc, device) => {
        acc[device.kind] = (acc[device.kind] || 0) + 1;
        return acc;
      }, {});
      const labeled = devices.filter(device => Boolean(device.label)).map(device => ({ kind: device.kind, label: device.label }));
      observations.mediaDevices = { counts, labeledCount: labeled.length, labeled };
      return finding(
        'media-device-labels', 'Media device metadata', 'Permissions',
        labeled.length ? 'warn' : 'pass', labeled.length ? 'medium' : 'none',
        labeled.length ? 'Camera or microphone labels are visible without a permission prompt.' : 'Device labels are hidden until the user grants permission.',
        observations.mediaDevices,
        labeled.length ? 'Review existing camera and microphone permissions for this browser profile.' : ''
      );
    } catch (error) {
      return finding('media-device-labels', 'Media device metadata', 'Permissions', 'unavailable', 'none', 'Media device enumeration failed safely.', { error: asError(error) });
    }
  }

  async function testWebAuthn() {
    const available = typeof PublicKeyCredential === 'function';
    let platformAuthenticator = null;
    let conditionalMediation = null;
    if (available && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
      try { platformAuthenticator = await withTimeout(PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), 3000, 'platform authenticator check'); } catch { platformAuthenticator = null; }
    }
    if (available && PublicKeyCredential.isConditionalMediationAvailable) {
      try { conditionalMediation = await withTimeout(PublicKeyCredential.isConditionalMediationAvailable(), 3000, 'conditional mediation check'); } catch { conditionalMediation = null; }
    }
    observations.webauthn = { available, platformAuthenticator, conditionalMediation };
    return finding(
      'webauthn', 'WebAuthn and passkey support', 'Capabilities',
      available ? 'pass' : 'info', 'none',
      available ? 'The browser supports phishing-resistant WebAuthn authentication.' : 'WebAuthn is unavailable in this browser.',
      observations.webauthn
    );
  }

  async function testPrivacySignals() {
    const gpcSupported = 'globalPrivacyControl' in navigator;
    const gpc = navigator.globalPrivacyControl === true;
    const dnt = navigator.doNotTrack ?? null;
    observations.privacySignals = { gpcSupported, globalPrivacyControl: gpc, doNotTrack: dnt };
    return finding(
      'privacy-signals', 'Privacy preference signals', 'Privacy signals',
      gpc ? 'pass' : 'warn', gpc ? 'none' : 'low',
      gpc ? 'Global Privacy Control is enabled.' : gpcSupported ? 'Global Privacy Control is supported but not enabled.' : 'Global Privacy Control is not exposed by this browser.',
      observations.privacySignals,
      gpc ? '' : 'Consider enabling Global Privacy Control in the browser or through a trusted privacy extension.'
    );
  }

  async function testRequestHeaders() {
    try {
      const response = await fetch(`/api/headers?token=${encodeURIComponent(token)}`, { cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const observed = await response.json();
      const headers = observed.headers || {};
      const lower = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
      const clientHintNames = Object.keys(lower).filter(name => name.startsWith('sec-ch-'));
      const secGPC = lower['sec-gpc'] || null;
      observations.requestHeaders = observed;
      return finding(
        'request-headers', 'Locally observed browser headers', 'Privacy signals',
        'info', 'none',
        `The browser sent ${Object.keys(headers).length} non-sensitive headers; ${clientHintNames.length} were User-Agent Client Hints.`,
        { protocol: observed.proto, clientHints: clientHintNames, secGPC, headers }
      );
    } catch (error) {
      return finding('request-headers', 'Locally observed browser headers', 'Privacy signals', 'unavailable', 'none', 'The local header observation request failed.', { error: asError(error) });
    }
  }

  async function testFirstPartyCookies() {
    const key = `browsersec_fp_${Date.now()}`;
    let readable = false;
    try {
      document.cookie = `${key}=1; Path=/; SameSite=Strict`;
      readable = document.cookie.includes(`${key}=1`);
      document.cookie = `${key}=; Path=/; Max-Age=0; SameSite=Strict`;
    } catch { readable = false; }
    observations.firstPartyCookies = { navigatorCookieEnabled: navigator.cookieEnabled, readable };
    return finding(
      'first-party-cookies', 'First-party cookie operation', 'Storage',
      readable ? 'pass' : 'warn', readable ? 'none' : 'medium',
      readable ? 'Normal first-party cookies work in this browser.' : 'First-party cookies are blocked or unavailable; some logins and site preferences may fail.',
      observations.firstPartyCookies,
      readable ? '' : 'Review cookie settings and ensure trusted sites can store first-party cookies.'
    );
  }

  async function testThirdPartyCookies() {
    const result = await new Promise(resolve => {
      const iframe = document.createElement('iframe');
      iframe.hidden = true;
      const finish = value => {
        window.removeEventListener('message', onMessage);
        iframe.remove();
        resolve(value);
      };
      const onMessage = event => {
        if (event.data?.type === 'browsersec-third-party') finish(event.data);
      };
      window.addEventListener('message', onMessage);
      iframe.src = `http://localhost:${location.port}/third-party.html`;
      document.body.append(iframe);
      setTimeout(() => finish(null), 4500);
    });
    observations.thirdPartyCookies = result;
    if (!result) {
      return finding('third-party-cookies', 'Third-party cookie policy', 'Storage', 'unavailable', 'none', 'The best-effort cross-site loopback test could not complete.');
    }
    const readable = result.cookieReadable === true;
    return finding(
      'third-party-cookies', 'Third-party cookie policy', 'Storage',
      readable ? 'warn' : 'pass', readable ? 'medium' : 'none',
      readable ? 'A cross-site frame could read its cookie, which can permit traditional third-party tracking.' : 'The cross-site frame could not read the test cookie. This normally indicates blocking, although localhost handling can differ between browsers.',
      result,
      readable ? 'Enable third-party cookie blocking or tracking protection in the browser.' : ''
    );
  }

  async function testStorage() {
    const result = { localStorage: false, sessionStorage: false, indexedDB: false, cacheAPI: false, serviceWorker: false, estimate: null };
    try {
      localStorage.setItem('browsersec_test', '1');
      result.localStorage = localStorage.getItem('browsersec_test') === '1';
      localStorage.removeItem('browsersec_test');
    } catch {}
    try {
      sessionStorage.setItem('browsersec_test', '1');
      result.sessionStorage = sessionStorage.getItem('browsersec_test') === '1';
      sessionStorage.removeItem('browsersec_test');
    } catch {}
    if (globalThis.indexedDB) {
      result.indexedDB = await new Promise(resolve => {
        const request = indexedDB.open('browsersec_test', 1);
        request.onerror = () => resolve(false);
        request.onupgradeneeded = () => {};
        request.onsuccess = () => {
          request.result.close();
          indexedDB.deleteDatabase('browsersec_test');
          resolve(true);
        };
      });
    }
    if (globalThis.caches) {
      try {
        const cache = await caches.open('browsersec-test');
        await cache.put('/api/health', new Response('ok'));
        result.cacheAPI = Boolean(await cache.match('/api/health'));
        await caches.delete('browsersec-test');
      } catch {}
    }
    if (navigator.storage?.estimate) {
      try {
        const estimate = await navigator.storage.estimate();
        result.estimate = { quota: estimate.quota ?? null, usage: estimate.usage ?? null };
      } catch {}
    }
    if (navigator.serviceWorker?.register) {
      try {
        const registration = await withTimeout(navigator.serviceWorker.register('/sw.js', { scope: '/' }), 4000, 'service worker registration');
        result.serviceWorker = true;
        await registration.unregister();
      } catch {}
    }
    observations.storage = result;
    const coreStorage = result.localStorage && result.sessionStorage && result.indexedDB;
    return finding(
      'web-storage', 'Browser storage availability', 'Storage',
      coreStorage ? 'info' : 'warn', coreStorage ? 'none' : 'low',
      coreStorage ? 'Standard site storage is available; websites can retain data in this browser profile.' : 'One or more standard storage systems are unavailable.',
      result,
      'Clear site data periodically and use private browsing when persistent storage is not desired.'
    );
  }

  async function testWebRTC() {
    if (typeof RTCPeerConnection !== 'function') {
      return finding('webrtc-addresses', 'WebRTC address exposure', 'Network privacy', 'unavailable', 'none', 'WebRTC is unavailable.');
    }
    const candidates = [];
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel('browsersec');
      pc.onicecandidate = event => {
        if (event.candidate?.candidate) candidates.push(classifyCandidate(event.candidate.candidate));
      };
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await new Promise(resolve => setTimeout(resolve, 2200));
      pc.close();
    } catch (error) {
      return finding('webrtc-addresses', 'WebRTC address exposure', 'Network privacy', 'unavailable', 'none', 'The WebRTC test could not complete.', { error: asError(error) });
    }
    const rawPrivate = candidates.filter(c => c.addressClass === 'private-ipv4' || c.addressClass === 'private-ipv6');
    const mdns = candidates.filter(c => c.addressClass === 'mdns');
    observations.webrtc = { candidates, rawPrivateCount: rawPrivate.length, mdnsCount: mdns.length };
    return finding(
      'webrtc-addresses', 'WebRTC local-address protection', 'Network privacy',
      rawPrivate.length ? 'warn' : 'pass', rawPrivate.length ? 'medium' : 'none',
      rawPrivate.length ? 'WebRTC exposed one or more raw private network addresses.' : mdns.length ? 'WebRTC used privacy-preserving mDNS hostnames instead of raw private addresses.' : 'No raw private address was observed through WebRTC.',
      observations.webrtc,
      rawPrivate.length ? 'Enable WebRTC IP protection in the browser or use a privacy-focused browser configuration.' : ''
    );
  }

  async function testNetworkInformation() {
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!connection) {
      return finding('network-information', 'Network Information API', 'Network privacy', 'pass', 'none', 'Connection speed and network type estimates are not exposed.');
    }
    const exposed = {
      effectiveType: connection.effectiveType ?? null,
      downlink: connection.downlink ?? null,
      rtt: connection.rtt ?? null,
      saveData: connection.saveData ?? null,
      type: connection.type ?? null
    };
    observations.networkInformation = exposed;
    return finding(
      'network-information', 'Network Information API', 'Network privacy',
      'info', 'none', 'Websites can read approximate connection characteristics.', exposed
    );
  }

  async function testCanvas() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 320;
      canvas.height = 90;
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '16px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(10, 10, 120, 40);
      ctx.fillStyle = '#069';
      ctx.fillText('BrowserSec Ω 2026', 8, 58);
      ctx.globalCompositeOperation = 'multiply';
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.beginPath();
      ctx.arc(180, 38, 28, 0, Math.PI * 2);
      ctx.fill();
      const data = canvas.toDataURL();
      const hash = await sha256(data);
      observations.canvas = { readable: true, hash };
      return finding('canvas-fingerprint', 'Canvas fingerprint surface', 'Fingerprinting', 'warn', 'low', 'Websites can read deterministic canvas rendering data that may contribute to fingerprinting.', { hash }, 'Use anti-fingerprinting protections if reducing cross-site uniqueness is important.');
    } catch (error) {
      observations.canvas = { readable: false, error: asError(error) };
      return finding('canvas-fingerprint', 'Canvas fingerprint surface', 'Fingerprinting', 'pass', 'none', 'Canvas pixel extraction was blocked or unavailable.', observations.canvas);
    }
  }

  async function testWebGL() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
    if (!gl) return finding('webgl-fingerprint', 'WebGL device exposure', 'Fingerprinting', 'pass', 'none', 'WebGL is unavailable, so graphics hardware metadata is not exposed through it.');
    const debug = gl.getExtension('WEBGL_debug_renderer_info');
    const result = {
      version: gl.getParameter(gl.VERSION),
      shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
      vendor: gl.getParameter(gl.VENDOR),
      renderer: gl.getParameter(gl.RENDERER),
      unmaskedVendor: debug ? gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) : null,
      unmaskedRenderer: debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : null
    };
    observations.webgl = result;
    const unmasked = Boolean(result.unmaskedVendor || result.unmaskedRenderer);
    return finding(
      'webgl-fingerprint', 'WebGL device exposure', 'Fingerprinting',
      unmasked ? 'warn' : 'info', unmasked ? 'low' : 'none',
      unmasked ? 'WebGL exposes unmasked graphics vendor or renderer information.' : 'WebGL is available, but unmasked renderer details were not exposed.',
      result,
      unmasked ? 'Consider browser anti-fingerprinting settings that standardize or restrict WebGL details.' : ''
    );
  }

  async function testAudioFingerprint() {
    const Offline = globalThis.OfflineAudioContext || globalThis.webkitOfflineAudioContext;
    if (!Offline) return finding('audio-fingerprint', 'Audio fingerprint surface', 'Fingerprinting', 'pass', 'none', 'Offline audio rendering is unavailable.');
    try {
      const context = new Offline(1, 44100, 44100);
      const oscillator = context.createOscillator();
      const compressor = context.createDynamicsCompressor();
      oscillator.type = 'triangle';
      oscillator.frequency.value = 10000;
      compressor.threshold.value = -50;
      compressor.knee.value = 40;
      compressor.ratio.value = 12;
      compressor.attack.value = 0;
      compressor.release.value = 0.25;
      oscillator.connect(compressor);
      compressor.connect(context.destination);
      oscillator.start(0);
      const rendered = await withTimeout(context.startRendering(), 5000, 'audio rendering');
      const channel = rendered.getChannelData(0);
      const sample = new Float32Array(512);
      for (let i = 0; i < sample.length; i++) sample[i] = channel[i * 8];
      const hash = await sha256(new Uint8Array(sample.buffer));
      observations.audioFingerprint = { hash };
      return finding('audio-fingerprint', 'Audio fingerprint surface', 'Fingerprinting', 'warn', 'low', 'Websites can obtain deterministic offline audio output that may contribute to fingerprinting.', { hash }, 'Anti-fingerprinting modes may standardize or restrict audio rendering details.');
    } catch (error) {
      return finding('audio-fingerprint', 'Audio fingerprint surface', 'Fingerprinting', 'unavailable', 'none', 'The offline audio test did not complete.', { error: asError(error) });
    }
  }

  async function testFonts() {
    const candidates = ['Arial', 'Calibri', 'Cambria', 'Comic Sans MS', 'Courier New', 'DejaVu Sans', 'Fira Code', 'Georgia', 'Helvetica', 'Liberation Sans', 'Noto Sans', 'Roboto', 'Segoe UI', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Ubuntu', 'Verdana'];
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const text = 'mmmmmmmmmmlli BrowserSec 0123456789';
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const baseline = {};
    for (const base of baseFonts) {
      ctx.font = `72px ${base}`;
      baseline[base] = ctx.measureText(text).width;
    }
    const detected = [];
    for (const font of candidates) {
      const available = baseFonts.some(base => {
        ctx.font = `72px "${font}", ${base}`;
        return Math.abs(ctx.measureText(text).width - baseline[base]) > 0.01;
      });
      if (available) detected.push(font);
    }
    observations.fonts = { tested: candidates.length, detected };
    return finding(
      'font-enumeration', 'Installed font inference', 'Fingerprinting',
      detected.length >= 8 ? 'warn' : 'info', detected.length >= 8 ? 'low' : 'none',
      `${detected.length} of ${candidates.length} common fonts could be inferred through text measurement.`,
      observations.fonts,
      detected.length >= 8 ? 'Use a browser anti-fingerprinting mode that limits local font exposure.' : ''
    );
  }

  async function testUAClientHints() {
    const result = {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      vendor: navigator.vendor,
      appVersion: navigator.appVersion,
      userAgentData: null,
      highEntropy: null
    };
    if (navigator.userAgentData) {
      result.userAgentData = {
        brands: navigator.userAgentData.brands,
        mobile: navigator.userAgentData.mobile,
        platform: navigator.userAgentData.platform
      };
      try {
        result.highEntropy = await navigator.userAgentData.getHighEntropyValues([
          'architecture', 'bitness', 'formFactors', 'fullVersionList', 'model', 'platformVersion', 'wow64'
        ]);
      } catch (error) {
        result.highEntropy = { error: asError(error) };
      }
    }
    observations.userAgent = result;
    const highKeys = result.highEntropy && !result.highEntropy.error ? Object.keys(result.highEntropy).filter(key => result.highEntropy[key] !== '' && result.highEntropy[key] !== false && result.highEntropy[key] != null) : [];
    return finding(
      'ua-client-hints', 'User-Agent and Client Hints exposure', 'Fingerprinting',
      highKeys.length >= 4 ? 'warn' : 'info', highKeys.length >= 4 ? 'low' : 'none',
      highKeys.length ? `The browser supplied ${highKeys.length} high-entropy Client Hint fields.` : 'No high-entropy User-Agent Client Hint values were returned.',
      { ...result, highEntropyFields: highKeys },
      highKeys.length >= 4 ? 'Privacy-focused browsers may reduce or standardize high-entropy device details.' : ''
    );
  }

  async function testScreenHardware() {
    const media = query => matchMedia(query).matches;
    const result = {
      screen: {
        width: screen.width, height: screen.height,
        availWidth: screen.availWidth, availHeight: screen.availHeight,
        colorDepth: screen.colorDepth, pixelDepth: screen.pixelDepth,
        orientation: screen.orientation ? { type: screen.orientation.type, angle: screen.orientation.angle } : null
      },
      viewport: { innerWidth, innerHeight, outerWidth, outerHeight, devicePixelRatio },
      hardwareConcurrency: navigator.hardwareConcurrency ?? null,
      deviceMemory: navigator.deviceMemory ?? null,
      maxTouchPoints: navigator.maxTouchPoints ?? null,
      language: navigator.language,
      languages: navigator.languages,
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      preferences: {
        dark: media('(prefers-color-scheme: dark)'),
        reducedMotion: media('(prefers-reduced-motion: reduce)'),
        highContrast: media('(prefers-contrast: more)'),
        forcedColors: media('(forced-colors: active)'),
        colorGamutP3: media('(color-gamut: p3)')
      }
    };
    observations.screenHardware = result;
    const entropyFields = [result.hardwareConcurrency, result.deviceMemory, result.screen.width, result.screen.height, result.viewport.devicePixelRatio, result.timeZone].filter(value => value != null).length;
    return finding('screen-hardware', 'Screen and hardware entropy', 'Fingerprinting', 'info', 'none', `Websites can read ${entropyFields} major screen, hardware, or locale attributes from this browser.`, result);
  }

  async function testPlugins() {
    const plugins = Array.from(navigator.plugins || [], plugin => ({ name: plugin.name, filename: plugin.filename, description: plugin.description }));
    const mimeTypes = Array.from(navigator.mimeTypes || [], mime => mime.type);
    const pdfViewerEnabled = 'pdfViewerEnabled' in navigator ? navigator.pdfViewerEnabled : null;
    observations.plugins = { plugins, mimeTypes, pdfViewerEnabled };
    return finding(
      'plugins-mime', 'Plug-in, MIME, and PDF metadata', 'Fingerprinting',
      plugins.length > 5 ? 'warn' : 'info', plugins.length > 5 ? 'low' : 'none',
      `The browser exposes ${plugins.length} plug-in entries and ${mimeTypes.length} MIME type entries.`,
      observations.plugins
    );
  }

  async function testWebGPU() {
    if (!navigator.gpu?.requestAdapter) {
      return finding('webgpu', 'WebGPU adapter exposure', 'Fingerprinting', 'pass', 'none', 'WebGPU is unavailable, so it does not expose adapter information.');
    }
    try {
      const adapter = await withTimeout(navigator.gpu.requestAdapter({ powerPreference: 'low-power' }), 4000, 'WebGPU adapter request');
      if (!adapter) return finding('webgpu', 'WebGPU adapter exposure', 'Fingerprinting', 'info', 'none', 'WebGPU exists but no adapter was returned.');
      const info = adapter.info ? {
        vendor: adapter.info.vendor || null,
        architecture: adapter.info.architecture || null,
        device: adapter.info.device || null,
        description: adapter.info.description || null
      } : null;
      const limits = adapter.limits ? {
        maxTextureDimension2D: adapter.limits.maxTextureDimension2D,
        maxBindGroups: adapter.limits.maxBindGroups,
        maxBufferSize: Number(adapter.limits.maxBufferSize)
      } : null;
      observations.webgpu = { info, limits };
      const detailed = info && Object.values(info).some(Boolean);
      return finding('webgpu', 'WebGPU adapter exposure', 'Fingerprinting', detailed ? 'warn' : 'info', detailed ? 'low' : 'none', detailed ? 'WebGPU exposes adapter-identifying information.' : 'WebGPU is available without useful identifying adapter text.', observations.webgpu);
    } catch (error) {
      return finding('webgpu', 'WebGPU adapter exposure', 'Fingerprinting', 'unavailable', 'none', 'The WebGPU test could not complete.', { error: asError(error) });
    }
  }

  async function testLegacy() {
    let javaEnabled = false;
    try { javaEnabled = typeof navigator.javaEnabled === 'function' && navigator.javaEnabled(); } catch {}
    const pluginNames = Array.from(navigator.plugins || [], plugin => plugin.name.toLowerCase());
    const detected = {
      activeX: typeof globalThis.ActiveXObject !== 'undefined',
      vbscript: typeof globalThis.VBArray !== 'undefined',
      java: javaEnabled || pluginNames.some(name => name.includes('java')),
      flash: pluginNames.some(name => name.includes('flash') || name.includes('shockwave')),
      silverlight: pluginNames.some(name => name.includes('silverlight')),
      quicktime: pluginNames.some(name => name.includes('quicktime')),
      realplayer: pluginNames.some(name => name.includes('realplayer'))
    };
    const present = Object.entries(detected).filter(([, value]) => value).map(([name]) => name);
    observations.legacy = detected;
    return finding(
      'legacy-technology', 'Obsolete browser technology', 'Legacy technology',
      present.length ? 'fail' : 'pass', present.length ? 'high' : 'none',
      present.length ? `Obsolete high-risk technologies were detected: ${present.join(', ')}.` : 'ActiveX, Flash, Java applets, Silverlight, VBScript, and similar legacy surfaces were not detected.',
      detected,
      present.length ? 'Remove legacy plug-ins or move to a supported modern browser immediately.' : ''
    );
  }

  async function testCapabilities() {
    const result = {
      webAssembly: typeof WebAssembly === 'object',
      serviceWorker: 'serviceWorker' in navigator,
      webRTC: typeof RTCPeerConnection === 'function',
      webSocket: typeof WebSocket === 'function',
      webCrypto: Boolean(crypto?.subtle),
      webAuthn: typeof PublicKeyCredential === 'function',
      webShare: typeof navigator.share === 'function',
      clipboard: Boolean(navigator.clipboard),
      fileSystemAccess: typeof globalThis.showOpenFilePicker === 'function',
      paymentRequest: typeof globalThis.PaymentRequest === 'function',
      usb: Boolean(navigator.usb),
      serial: Boolean(navigator.serial),
      hid: Boolean(navigator.hid),
      bluetooth: Boolean(navigator.bluetooth),
      sensors: {
        accelerometer: typeof globalThis.Accelerometer === 'function',
        gyroscope: typeof globalThis.Gyroscope === 'function',
        ambientLight: typeof globalThis.AmbientLightSensor === 'function'
      },
      svg: Boolean(document.createElementNS('http://www.w3.org/2000/svg', 'svg').createSVGRect),
      mathML: CSS.supports?.('math-style', 'normal') || false,
      avifCSS: CSS.supports?.('background-image', 'url("data:image/avif;base64,AAAA")') || false,
      webpCanvas: (() => {
        try { return document.createElement('canvas').toDataURL('image/webp').startsWith('data:image/webp'); } catch { return false; }
      })()
    };
    observations.capabilities = result;
    return finding('platform-capabilities', 'Modern browser capability inventory', 'Capabilities', 'info', 'none', 'A local inventory of security-relevant and privacy-relevant Web APIs was completed.', result);
  }

  const tests = [
    ['Secure context', testSecureContext],
    ['Content Security Policy', testCSP],
    ['Trusted Types', testTrustedTypes],
    ['Cross-origin isolation', testIsolation],
    ['Automation disclosure', testAutomation],
    ['Permission states', testPermissions],
    ['Media device metadata', testMediaDevices],
    ['WebAuthn and passkeys', testWebAuthn],
    ['Privacy preference signals', testPrivacySignals],
    ['Request headers', testRequestHeaders],
    ['First-party cookies', testFirstPartyCookies],
    ['Third-party cookies', testThirdPartyCookies],
    ['Browser storage', testStorage],
    ['WebRTC address exposure', testWebRTC],
    ['Network information', testNetworkInformation],
    ['Canvas fingerprinting', testCanvas],
    ['WebGL device exposure', testWebGL],
    ['Audio fingerprinting', testAudioFingerprint],
    ['Font inference', testFonts],
    ['User-Agent Client Hints', testUAClientHints],
    ['Screen and hardware entropy', testScreenHardware],
    ['Plug-in and MIME metadata', testPlugins],
    ['WebGPU adapter exposure', testWebGPU],
    ['Legacy technology', testLegacy],
    ['Platform capabilities', testCapabilities]
  ];

  async function run() {
    ui.counter.textContent = `0 / ${tests.length}`;
    for (let index = 0; index < tests.length; index++) {
      const [label, test] = tests[index];
      ui.current.textContent = label;
      try {
        const output = await test();
        const items = Array.isArray(output) ? output : [output];
        for (const item of items) {
          findings.push(item);
          renderFinding(item);
        }
      } catch (error) {
        const fallback = finding(
          `internal-${index}`, label, 'Capabilities', 'unavailable', 'none',
          'This check failed without affecting the remaining scan.', { error: asError(error) }
        );
        findings.push(fallback);
        renderFinding(fallback);
      }
      const completed = index + 1;
      const percent = Math.round((completed / tests.length) * 100);
      ui.counter.textContent = `${completed} / ${tests.length}`;
      ui.progress.style.width = `${percent}%`;
      ui.track.setAttribute('aria-valuenow', String(percent));
      await new Promise(resolve => requestAnimationFrame(resolve));
    }

    ui.phase.textContent = 'Finalizing report';
    ui.current.textContent = 'Sending results to the local BrowserSec application.';

    const payload = {
      meta: {
        version: '0.1.0',
        startedAt,
        completedAt: new Date().toISOString(),
        origin: location.origin,
        userAgent: navigator.userAgent,
        browserName: navigator.userAgentData?.brands?.map(item => item.brand).join(', ') || navigator.appName,
        platform: navigator.userAgentData?.platform || navigator.platform,
        language: navigator.language,
        scanDurationMs: Math.round(performance.now() - started)
      },
      findings,
      observations
    };

    try {
      const response = await fetch(`/api/results?token=${encodeURIComponent(token)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
        credentials: 'same-origin',
        body: JSON.stringify(payload)
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      ui.phase.textContent = 'Scan complete';
      ui.current.textContent = 'The local report is ready.';
      ui.complete.hidden = false;
      ui.completeMessage.textContent = 'BrowserSec is generating and opening the local report. No scan data was uploaded.';
    } catch (error) {
      ui.phase.textContent = 'Report generation failed';
      ui.current.textContent = 'The browser checks completed, but the local application did not accept the result.';
      ui.complete.hidden = false;
      ui.completeMessage.textContent = asError(error);
    }
  }

  run();
})();
