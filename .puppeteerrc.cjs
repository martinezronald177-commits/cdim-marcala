/* Le dice a Puppeteer dónde guardar/buscar el Chrome que descarga durante
   `npm install`, en vez de usar su ubicación por defecto (~/.cache/puppeteer,
   que depende de la variable $HOME).

   Bug real visto en producción (ago. 2026): en Render, el paso de build y el
   contenedor donde después corre `node server.js` resuelven $HOME de forma
   distinta -- el Chrome que Puppeteer descargó durante `npm install` quedó
   en /opt/render/.cache/puppeteer, y cuando alguien pedía un PDF del
   informe (navegador(), en server.js), el proceso en producción buscaba en
   OTRO /opt/render/.cache/puppeteer que no era el mismo directorio real, y
   fallaba con "Could not find Chrome". El propio mensaje de error de
   Puppeteer apunta a esto (https://pptr.dev/guides/configuration).

   La corrección: fijar la caché DENTRO de esta misma carpeta del proyecto
   (cdim-server/), que Render sí garantiza que persiste igual entre el paso
   de build y el contenedor que sirve las peticiones -- a diferencia del
   directorio home del usuario, que no. Esto hace que la descarga (durante
   el build) y la búsqueda (en producción, dentro de navegador()) miren
   siempre el mismo lugar.

   Ver ARQUITECTURA.md, "PDF directo del informe del paciente", para el
   resto del diseño de esa función. */
const {join} = require('path');
module.exports = {
  cacheDirectory: join(__dirname, '.cache', 'puppeteer'),
};
