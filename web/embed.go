package web

import "embed"

// Assets contains the browser scanner application.
//
//go:embed index.html app.js styles.css third-party.html sw.js
var Assets embed.FS
