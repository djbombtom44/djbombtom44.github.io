/* Service worker: (1) adds the cross-origin-isolation headers Firefox-WASM needs on hosts that can't set them
   (e.g. GitHub Pages) and (2) keeps app.html in Cache Storage so the 74 MB is downloaded once, not every visit.
   The version comes from the script URL (?v=...), which also names the cache. */
const VER = new URL(self.location.href).searchParams.get('v') || '0';
const CACHE = 'ffwasm-' + VER;
const APP = new URL('app.html', self.registration.scope).href;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k.startsWith('ffwasm-') && k !== CACHE) await caches.delete(k);
  await self.clients.claim();
})()));

function isolate(res) {
  if (res.status === 0) return res;
  const h = new Headers(res.headers);
  h.set('Cross-Origin-Embedder-Policy', 'require-corp');
  h.set('Cross-Origin-Opener-Policy', 'same-origin');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

async function app(e) {
  const cache = await caches.open(CACHE);
  const hit = await cache.match(APP);
  if (hit) return isolate(hit);
  const net = await fetch(APP);
  if (net.ok && net.status === 200) e.waitUntil(cache.put(APP, net.clone()).catch(() => {}));
  return isolate(net);
}

self.addEventListener('fetch', e => {
  const r = e.request;
  if (r.cache === 'only-if-cached' && r.mode !== 'same-origin') return;
  const u = new URL(r.url);
  if (r.method === 'GET' && u.origin === location.origin && u.pathname === new URL(APP).pathname) return e.respondWith(app(e));
  e.respondWith(fetch(r).then(isolate).catch(() => Response.error()));
});
