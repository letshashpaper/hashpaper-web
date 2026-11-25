// Self-cleaning Service Worker: clears old broken caches and never hijacks page loads
self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
  );
  self.clients.claim();
});

// Pass all requests straight to the network (zero stale/broken cache issues)
self.addEventListener('fetch', () => {});
