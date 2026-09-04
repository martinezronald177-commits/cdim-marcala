# ═══════════════════════════════════════════════════════════════
#  CDI Marcala · imagen del servidor
#
#  Por qué existe este archivo. El servidor arma los PDF del portal con
#  Chrome. Sin esta imagen, quien pone ese Chrome es Puppeteer: lo descarga
#  de los servidores de Google, atado a la versión exacta que fija cada
#  release suya. Esa descarga es la pieza más frágil de todo el sistema —
#  las versiones viejas dejan de servirse con el tiempo, y ahí los PDF del
#  paciente dejan de generarse aunque el código esté intacto.
#
#  Aquí el Chromium viene del catálogo de Debian: se actualiza con los
#  parches de seguridad de la distribución al reconstruir la imagen, y ya no
#  depende de la versión de Puppeteer ni de ninguna descarga en tiempo de
#  arranque. Puppeteer queda como lo que conviene que sea: una librería para
#  manejar un navegador que ya está instalado.
#
#  Ver ARQUITECTURA.md y el mantenimiento periódico.
# ═══════════════════════════════════════════════════════════════

# La versión va fijada a propósito: es la única forma de que la imagen de
# dentro de un año sea la misma que la de hoy. Actualizarla es una decisión
# anual, no algo que ocurra solo.
FROM node:24-bookworm-slim

# chromium: el navegador que arma los PDF.
# fonts-dejavu-core: NO es opcional. El informe marca los valores fuera de
#   rango con ▲ y ▼, y los rangos usan ≥. Esos signos no están en el
#   subconjunto latino de las fuentes propias del laboratorio, así que los
#   pone una fuente del sistema. Sin ella salen recuadros vacíos justo en lo
#   que señala un resultado alterado.
# fonts-liberation: respaldo general para cualquier texto que caiga fuera.
# ca-certificates: para hablar por HTTPS con el almacenamiento del respaldo
#   externo.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      chromium \
      fonts-dejavu-core \
      fonts-liberation \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# PUPPETEER_EXECUTABLE_PATH: server.js ya lo respeta (ver asegurarChrome()).
#   Con esto puesto, ni se comprueba ni se descarga nada al arrancar.
# PUPPETEER_SKIP_DOWNLOAD: y con esto tampoco se descarga al instalar. Va
#   ANTES del npm ci a propósito: si fuera después, la descarga ya habría
#   ocurrido durante la instalación.
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    PUPPETEER_SKIP_DOWNLOAD=1 \
    NODE_ENV=production

WORKDIR /app

# Las dependencias, en su propia capa: mientras package-lock.json no cambie,
# reconstruir la imagen tras un cambio de código no vuelve a instalarlas.
# `npm ci` instala exactamente lo que dice el archivo de bloqueo, ni una
# versión distinta; --omit=dev deja fuera lo que solo sirve para desarrollar.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# Informativo: quien manda es la variable PORT que pone el proveedor
# (ver `const PORT` en server.js).
EXPOSE 10000

CMD ["node", "server.js"]
