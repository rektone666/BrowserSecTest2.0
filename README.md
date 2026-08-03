# BrowserSec Framework v0.1

BrowserSec is a local, automatic browser-security and privacy scanner intended to be usable by non-technical users.

## What the user does

1. Run `browsersec`.
2. The default browser opens automatically.
3. BrowserSec performs safe checks without asking for camera, microphone, location, file, password, or account access.
4. A plain-language HTML report opens automatically.

The temporary HTTP service is internal. It binds only to `127.0.0.1`, uses a random scan token, starts automatically, and stops after the report is generated. No scan data is uploaded.

## Current modules

Version 0.1 includes 25 modules covering:

- secure-context, CSP, Trusted Types, and COOP/COEP behavior;
- sensitive permission states without permission prompts;
- first-party and best-effort third-party cookie policy;
- localStorage, sessionStorage, IndexedDB, Cache API, Service Workers, and quota exposure;
- WebRTC local-address leakage and mDNS masking;
- GPC, DNT, request headers, User-Agent Client Hints, and automation disclosure;
- canvas, audio, WebGL, WebGPU, font, screen, hardware, plug-in, and MIME fingerprint surfaces;
- camera/microphone device-label exposure;
- WebAuthn/passkey support;
- ActiveX, Flash, Java, Silverlight, VBScript, QuickTime, and RealPlayer legacy checks;
- a modern security-relevant Web API capability inventory.

## Run from source

Requires Go 1.23 or later for building. The produced binary has no Go runtime dependency.

```bash
go build -o browsersec ./cmd/browsersec
./browsersec
```

## Commands

```text
browsersec
browsersec scan
browsersec scan --browser firefox
browsersec modules
browsersec console
browsersec version
```

## Reports

By default reports are created under `~/BrowserSec Reports/`:

- `report.html` — plain-language report;
- `report.json` — scored structured report;
- `raw-scan.json` — complete local observations.

## Scope and limitations

BrowserSec is not an antivirus, exploit scanner, or proof that a browser is safe. It reports locally observable browser posture and privacy exposure. Version 0.1 intentionally avoids online IP, DNS, proxy, TLS, reputation, breach, and update checks. Those can be added later as clearly optional online modules.

## Project status

This is an initial testable build. The scoring model, wording, browser compatibility, packaging, signing, GUI, website integration, and mobile versions are expected to evolve.
