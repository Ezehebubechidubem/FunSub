const CACHE_NAME = "funsub-v1";
const ASSETS = [
  "/FunSub/index.html",
  "/FunSub/manifest.webmanifest",
  "/FunSub/icons/icon-192.png",
  "/FunSub/icons/icon-512.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});