const CACHE="cdim-pac-v2";
const BASE=["./paciente.html","./cotizacion.html","./paciente_manifest.json","./icon-192.png","./icon-512.png"];
self.addEventListener("install",e=>{
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(BASE).catch(()=>{})));
});
self.addEventListener("activate",e=>{
  e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});
self.addEventListener("fetch",e=>{
  // Las llamadas al servidor siempre van a la red: los resultados deben ser frescos
  if(e.request.url.includes("/api/"))return;
  e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request).catch(()=>caches.match("./paciente.html"))));
});
