// =============================================================================
// Datei:    sw.js
// Zweck:    Offline-Zwischenspeicher der Tor-Steuerung (startet auch ohne Netz)
// Autor:    Stefan Weinzetl
// Hinweis:  Die Version kommt als Parameter ?v= aus APP_VERSION in app.js.
// =============================================================================
"use strict";

const VERSION = new URL(self.location).searchParams.get("v") || "0";
const CACHE_NAME = `tor-app-${VERSION}`;
const DATEIEN = ["./", "./index.html", "./app.js", "./manifest.webmanifest", "./icon-192.png", "./icon-512.png"];

self.addEventListener("install", (ereignis) => {
  ereignis.waitUntil(caches.open(CACHE_NAME).then((c) => c.addAll(DATEIEN)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (ereignis) => {
  ereignis.waitUntil(
    caches.keys()
      .then((namen) => Promise.all(namen.filter((n) => n.startsWith("tor-app-") && n !== CACHE_NAME).map((n) => caches.delete(n))))
      .then(() => self.clients.claim())
  );
});

// Zuerst Zwischenspeicher (sofortiger Start auch bei schwachem Netz vor dem Tor),
// im Hintergrund wird aktualisiert.
self.addEventListener("fetch", (ereignis) => {
  if (ereignis.request.method !== "GET") return;
  ereignis.respondWith(
    caches.open(CACHE_NAME).then(async (cache) => {
      const gespeichert = await cache.match(ereignis.request, { ignoreSearch: true });
      const ausNetz = fetch(ereignis.request)
        .then((antwort) => { if (antwort.ok) cache.put(ereignis.request, antwort.clone()); return antwort; })
        .catch(() => gespeichert);
      return gespeichert || ausNetz;
    })
  );
});
