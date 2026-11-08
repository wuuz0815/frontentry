// =============================================================================
// Datei:    sw.js
// Zweck:    Offline-Zwischenspeicher der Tor-Steuerung (startet auch ohne Netz)
// Autor:    Stefan Weinzetl
// Hinweis:  Die Version kommt als Parameter ?v= aus APP_VERSION in app.js.
//           Strategie: zuerst Netz mit kurzem Zeitlimit (Updates kommen sofort an),
//           bei fehlendem oder langsamem Netz sofort aus dem Zwischenspeicher.
// =============================================================================
"use strict";

const VERSION = new URL(self.location).searchParams.get("v") || "0";
const CACHE_NAME = `tor-app-${VERSION}`;
const NETZ_ZEITLIMIT_MS = 1500;
const DATEIEN = ["./", "./index.html", "./app.js", "./manifest.webmanifest", "./icon-192.png", "./icon-512.png"];

self.addEventListener("install", (ereignis) => {
  ereignis.waitUntil(
    caches.open(CACHE_NAME)
      .then((c) => c.addAll(DATEIEN.map((d) => new Request(d, { cache: "no-cache" }))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (ereignis) => {
  ereignis.waitUntil(
    caches.keys()
      .then((namen) => Promise.all(namen.filter((n) => n.startsWith("tor-app-") && n !== CACHE_NAME).map((n) => caches.delete(n))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (ereignis) => {
  if (ereignis.request.method !== "GET") return;
  ereignis.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const ausNetz = fetch(ereignis.request, { cache: "no-cache" }).then((antwort) => {
      if (antwort.ok) cache.put(ereignis.request, antwort.clone());
      return antwort;
    });
    const zeitlimit = new Promise((r) => setTimeout(() => r(null), NETZ_ZEITLIMIT_MS));
    try {
      const antwort = await Promise.race([ausNetz, zeitlimit]);
      if (antwort) return antwort;
    } catch (e) {
      // offline: weiter mit Zwischenspeicher
    }
    const gespeichert = await cache.match(ereignis.request, { ignoreSearch: true });
    return gespeichert || ausNetz;
  })());
});
