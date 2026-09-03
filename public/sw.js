/* Service worker de TODO el sitio: la aplicación del laboratorio
   (index.html), el portal del paciente y el formulario público de cotización.

   Su alcance es la raíz, así que controla las tres. La aplicación lo registra
   al arrancar (ver registrarServicioSinConexion en 80_bitacora.js) para que
   haya algo que abrir cuando no hay red: sin esto, con la línea caída el
   navegador no tenía ni el programa que ejecutar, y el laboratorio se
   quedaba parado aunque los datos estuvieran en el disco de la máquina.

   ── La regla que gobierna todo esto ──
   Los DOCUMENTOS van a la RED PRIMERO y solo caen a la caché si no hay
   conexión. Estando en línea siempre se ve la versión desplegada; guardar el
   programa no puede convertirse nunca en servir uno viejo.

   No es una precaución teórica: la versión anterior de este archivo servía
   todo desde la caché primero y no volvía a preguntarle a la red jamás. Las
   dos páginas públicas quedaban congeladas para siempre en la versión que
   cada visitante hubiera cargado la primera vez, y ninguna corrección
   posterior le llegaba. No llegó a morder porque no se modificaron; era
   cuestión de tiempo.

   Los iconos y el manifiesto sí van de la caché primero: no cambian, y son
   los que hacen que la página arranque rápido. */
/* VERSION la escribe el despliegue a partir del contenido real de index.html
   (ver herramientas/desplegar.js), así que el nombre de la caché cambia solo
   en cada despliegue y la anterior se borra sola. Dejarlo escrito a mano fue
   justo el error de la versión anterior. */
const VERSION = "01570806be";
const CACHE = "cdim-" + VERSION;
const BASE = ["./index.html","./paciente.html","./cotizacion.html",
              "./paciente_manifest.json","./icon-192.png","./icon-512.png"];

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
  const p = url.pathname;
  if (p.indexOf("cotizacion") >= 0) return "./cotizacion.html";
  if (p.indexOf("paciente") >= 0) return "./paciente.html";
  return "./index.html";
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
  /* Las llamadas al servidor NUNCA se guardan: ahí viajan expedientes
     clínicos, y la caché del navegador no es sitio para eso. Sin conexión
     fallan, que es lo correcto — la aplicación ya sabe encolar y reintentar. */
  if (url.pathname.indexOf("/api/") >= 0) return;
  // La pantalla de acceso necesita servidor para autenticar: guardarla en
  // caché solo serviría para enseñar un formulario que no puede funcionar.
  if (url.pathname.indexOf("/login.html") >= 0) return;
  // Otro origen (fuentes, CDN): que lo resuelva el navegador.
  if (url.origin !== self.location.origin) return;

  const esDocumento = req.mode === "navigate" ||
    (req.headers.get("accept") || "").indexOf("text/html") >= 0;
  e.respondWith(esDocumento ? redPrimero(req, url) : cachePrimero(req));
});
