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
const VERSION = "146df00a7e";
const CACHE = "cdim-" + VERSION;
const BASE = ["./index.html","./paciente.html","./cotizacion.html",
              "./paciente_manifest.json","./icon-192.png","./icon-512.png"];

/* ── Interruptor de emergencia ──
   Trabajar en línea es lo que importa; guardar el programa es el seguro. Si el
   seguro llegara a estorbar —un navegador que se comporte raro, una máquina que
   se quede pegada en una versión—, se pone esto en true y se despliega: cada
   navegador que pida el sw.js borra lo guardado, se da de baja y vuelve a
   hablar con el servidor directamente, como si nunca hubiera existido.
   Encender:  npm run desplegar -- --sin-sw
   Apagar:    npm run desplegar
   (Con esto en true la aplicación lo vuelve a registrar en cada carga y él se
   vuelve a dar de baja. Es ruido inofensivo: no guarda ni sirve nada.) */
const APAGADO = false;

self.addEventListener("install", e => {
  self.skipWaiting();
  if (APAGADO) return;
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(BASE).catch(() => {})));
});

self.addEventListener("activate", e => {
  e.waitUntil((async () => {
    try {
      const ks = await caches.keys();
      await Promise.all(ks.filter(k => APAGADO || k !== CACHE).map(k => caches.delete(k)));
    } catch (e) { /* si no se pudo limpiar, no se bloquea la activación */ }
    if (APAGADO) { try { await self.registration.unregister(); } catch (e) {} }
    await self.clients.claim();
  })());
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
  let r;
  try {
    r = await fetch(req);
  } catch (e) {
    /* Solo aquí, con la red caída de verdad, se recurre a lo guardado. */
    try {
      const guardada = await caches.match(req);
      if (guardada) return guardada;
      const respaldo = await caches.match(paginaDeRespaldo(url));
      if (respaldo) return respaldo;
    } catch (e2) { /* sin caché tampoco: se responde abajo */ }
    return new Response("Sin conexión", {status: 503, headers: {"Content-Type": "text/plain"}});
  }
  /* Guardar es un EXTRA, y va en su propio try a propósito. Si el
     almacenamiento falla -disco lleno, ventana privada, política del
     navegador-, eso no puede cambiar lo que ve quien está trabajando: la red
     ya respondió y esa respuesta es la que manda. Estando en línea, lo que se
     entrega viene siempre de la red; no hay ningún camino por el que un
     problema de caché acabe sirviendo una versión vieja.
     Solo se guarda lo que sirve: un 404 o un 500 en la caché convertiría un
     error pasajero en uno permanente. */
  if (r && r.ok && req.method === "GET") {
    try {
      const c = await caches.open(CACHE);
      await c.put(req, r.clone());
    } catch (e) { /* da igual: la respuesta de la red se entrega igual */ }
  }
  return r;
}

async function cachePrimero(req) {
  try {
    const guardada = await caches.match(req);
    if (guardada) return guardada;
  } catch (e) { /* sin caché disponible: se pide a la red */ }
  /* Si la red tampoco puede, se devuelve un error en vez de dejar que la
     promesa de respondWith se rompa: una promesa rota aquí le rompe la
     petición al navegador. */
  try { return await fetch(req); }
  catch (e) { return new Response("", {status: 504}); }
}

self.addEventListener("fetch", e => {
  if (APAGADO) return;          // apagado: todo va directo a la red
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
