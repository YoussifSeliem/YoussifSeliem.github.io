---
title: "Web: Bad_Worker (beginner)"
date: "2024-06-23"
thumbnail: "/assets/img/thumbnail/wani24.png"
---

# Description
---

We created a web application that works offline.

Flag Format: FLAG{...}

# Solution

When we first open the challange we see this
<img src="/assets/img/wani24/capture.png">

After movement within the site, I found nothing interesting.
Then i went to examine the JS files within the site.
I found a file named `service-worker.js` with the content

```js
// Caution! Be sure you understand the caveats before publishing an application with
// offline support. See https://aka.ms/blazor-offline-considerations

self.importScripts('./service-worker-assets.js');
self.addEventListener('install', event => event.waitUntil(onInstall(event)));
self.addEventListener('activate', event => event.waitUntil(onActivate(event)));
self.addEventListener('fetch', event => event.respondWith(onFetch(event)));

const cacheNamePrefix = 'offline-cache-';
const cacheName = `${cacheNamePrefix}${self.assetsManifest.version}`;
const offlineAssetsInclude = [ /\.dll$/, /\.pdb$/, /\.wasm/, /\.html/, /\.js$/, /\.json$/, /\.css$/, /\.woff$/, /\.png$/, /\.jpe?g$/, /\.gif$/, /\.ico$/, /\.blat$/, /\.dat$/ ];
const offlineAssetsExclude = [ /^service-worker\.js$/ ];

async function onInstall(event) {
    //console.info('Service worker: Install');

    // Fetch and cache all matching items from the assets manifest
    const assetsRequests = self.assetsManifest.assets
        .filter(asset => offlineAssetsInclude.some(pattern => pattern.test(asset.url)))
        .filter(asset => !offlineAssetsExclude.some(pattern => pattern.test(asset.url)))
        .map(asset => new Request(asset.url, { integrity: asset.hash, cache: 'no-cache' }));
    await caches.open(cacheName).then(cache => cache.addAll(assetsRequests));
    event.waitUntil(self.skipWaiting());        // すぐにactivateにする
}

async function onActivate(event) {

    // Delete unused caches
    const cacheKeys = await caches.keys();
    await Promise.all(cacheKeys
        .filter(key => key.startsWith(cacheNamePrefix) && key !== cacheName)
        .map(key => caches.delete(key)));
    event.waitUntil(self.clients.claim());    // すぐにserviceWorkerを有効にする
}

async function onFetch(event) {
    let cachedResponse = null;
    if (event.request.method === 'GET') {
      const shouldServeIndexHtml = event.request.mode === 'navigate';
      let request = event.request;
      if (request.url.toString().includes("FLAG.txt")) {
            request = "DUMMY.txt";
      }
      if (shouldServeIndexHtml) {
        request = "index.html"
      }
        return  fetch(request);
    }

    return cachedResponse || fetch(event.request);
}

/* Manifest version: Rq/NTVa4 */
```

So We need to send a GET request to /FLAG.txt endpoint and we will get the flag
<img src="/assets/img/wani24/capture.png">
Congratzzzzzzzzzzzzzzz
