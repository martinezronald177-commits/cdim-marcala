/* Service worker del portal del paciente y del formulario público de
   cotización (paciente.html y cotizacion.html). La aplicación del laboratorio
   -index.html- NO lo usa: se sirve siempre de la red.

   ── El problema que tenía la versión anterior ──
   Servía TODO desde la caché primero ("cache-first") y nunca volvía a pedir
   nada a la red. Como el nombre de la caché está escrito a mano y el archivo
   no cambiaba, esas dos páginas quedaban CONGELADAS para siempre en la
   versión que cada visitante hubiera cargado la primera vez. Cualquier
   corrección posterior -un precio, un texto, un fallo- no le llegaba nunca a
   quien ya había entrado antes. Todavía no había mordido porque ninguna de
   las dos se ha modificado desde entonces; era cuestión de tiempo.

   ── Lo que hace ahora ──
   Los documentos van a la RED PRIMERO y solo caen a la caché si no hay
   conexión. Así el paciente siempre ve la versión de hoy cuando tiene línea,
   y sigue pudiendo abrir la página cuando no la tiene. Los iconos y el
   manifiesto sí van de la caché primero: no cambian, y son los que hacen que
   la página arranque rápido.

   Al cambiar el nombre de la caché, la versión anterior se borra sola en
   cuanto este archivo llegue al navegador. */
const CACHE = "cdim-pac-v3";
const BASE = ["./paciente.html","./cotizacion.html","./paciente_manifest.json",
              "./icon-192.png","./icon-512.png"];

self.addEventListener("install", e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(BASE).catch(() => {})));
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys()
      .then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* Sin conexión, cada página cae a la suya. La versión anterior devolvía
   siempre paciente.html ante cualquier fallo, lo que en teoría le daba el
   portal de resultados a quien pedía una cotización. No conseguí reproducirlo
   en el navegador -las dos direcciones están en la precarga y se resuelven
   antes de llegar aquí, y con parámetros detrás la propia caché del navegador
   se adelanta-, así que esto es prudencia, no la corrección de un fallo
   observado. Cuesta tres líneas y quita la duda. */
function paginaDeRespaldo(url) {
  return url.pathname.indexOf("cotizacion") >= 0 ? "./cotizacion.html" : "./paciente.html";
}

async function redPrimero(req, url) {
  try {
    const r = await fetch(req);
    /* Solo se guarda lo que sirve: una respuesta 404 o 500 en la caché
       convertiría un error pasajero en un error permanente. */
    if (r && r.ok && req.method === "GET") {
      const c = await caches.open(CACHE);
      c.put(req, r.clone()).catch(() => {});
    }
    return r;
  } catch (e) {
    const guardada = await caches.match(req);
    if (guardada) return guardada;
    const respaldo = await caches.match(paginaDeRespaldo(url));
    if (respaldo) return respaldo;
    return new Response("Sin conexión", {status: 503, headers: {"Content-Type": "text/plain"}});
  }
}

async function cachePrimero(req) {
  const guardada = await caches.match(req);
  if (guardada) return guardada;
  return fetch(req);
}

self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  // Las llamadas al servidor siempre van a la red: los resultados de un
  // paciente no se guardan nunca en el disco de su navegador.
  if (url.pathname.indexOf("/api/") >= 0) return;
  // Otro origen (fuentes, CDN): que lo resuelva el navegador.
  if (url.origin !== self.location.origin) return;

  const esDocumento = req.mode === "navigate" ||
    (req.headers.get("accept") || "").indexOf("text/html") >= 0;
  e.respondWith(esDocumento ? redPrimero(req, url) : cachePrimero(req));
});
