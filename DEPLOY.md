# CDI Marcala — Guía de despliegue y actualización

## ⚠ Lo más importante que debes saber

El sistema guarda los datos en archivos dentro del servidor. En los planes gratuitos
(Render Free, Railway trial), **el servidor se reconstruye desde cero cada vez que
actualizas el código, y los datos se borran**.

Tienes dos caminos:

| Camino | Costo | Riesgo |
|---|---|---|
| **A. Disco persistente** (recomendado) | ~$7/mes | Ninguno: los datos sobreviven a las actualizaciones |
| **B. Plan gratuito + respaldo manual** | $0 | Debes descargar el respaldo ANTES de cada actualización |

---

## Camino A — Disco persistente (recomendado para un laboratorio real)

### En Render

1. En tu servicio → pestaña **Disks** → **Add Disk**
2. Configura:
   - **Name**: `cdim-datos`
   - **Mount Path**: `/var/data`
   - **Size**: 1 GB (suficiente para años de operación)
3. Ve a **Environment** → **Add Environment Variable**:
   - `DATA_DIR` = `/var/data`
4. Guarda. El servicio se reinicia solo.

Desde ese momento puedes actualizar el código cuando quieras: los datos
viven en el disco, no en el código, y no se tocan.

Para confirmarlo, entra al LIS → **💾 Respaldos**. Debe decir en verde
"Disco persistente activo".

### En un VPS propio (Contabo, DigitalOcean)

Los datos ya son persistentes por defecto. Opcionalmente puedes apuntarlos
a otra carpeta:

```bash
DATA_DIR=/home/usuario/cdim-datos pm2 start server.js --name cdim
```

---

## Camino B — Plan gratuito con respaldo manual

Si por ahora usas el plan gratuito, **el procedimiento antes de CADA actualización es**:

1. Entra al LIS → **💾 Respaldos**
2. Botón **⬇ Descargar respaldo ahora** → se guarda un `.json` en tu computadora
3. Sube tu cambio a GitHub (Render redespliega solo)
4. Cuando termine, entra al LIS → **💾 Respaldos**
5. Botón **⬆ Restaurar desde archivo** → selecciona el `.json` que descargaste
6. Verifica que los pacientes y órdenes estén completos

**Si olvidas el paso 2, los datos se pierden y no hay forma de recuperarlos.**
Por eso, si el laboratorio ya está operando con datos reales, contrata el disco.

---

## Cómo actualizar el sistema (cuando ya está en línea)

1. Descarga el archivo nuevo que te entregué
2. Ve a tu repositorio en GitHub → carpeta `public`
3. Clic en `index.html` → botón del lápiz (Edit) → borra todo y pega el contenido nuevo
   - O más fácil: **Add file → Upload files** y arrastra el archivo nuevo
4. Abajo escribe qué cambiaste (ej. "Nuevo formato de frotis")
5. **Commit changes**
6. Render lo detecta solo y redespliega en 2–3 minutos

> Si estás en el plan gratuito, **descarga el respaldo antes del paso 5**.

> **Cuando la actualización trae varios archivos a la vez** (por ejemplo, la que agrega
> el PDF directo del informe del paciente): sube **todos** los archivos entregados en
> el mismo commit — `server.js`, `public/informe.html`, `package.json` y
> `package-lock.json`. Si subes `server.js` pero no el `package.json` nuevo, Render
> instala las dependencias viejas y el servidor no arranca (falta el paquete nuevo).

---

## Dependencia nueva: Puppeteer (PDF directo del informe del paciente)

Desde ago. 2026 el servidor genera el PDF del informe del paciente él mismo (ver
`ARQUITECTURA.md`), usando **Puppeteer** (un Chrome sin interfaz que corre dentro
del servidor). Esto cambia el despliegue en tres cosas:

1. **La instalación tarda más y pesa más.** `npm install` ahora descarga también
   un Chromium completo (~200–300 MB). Es normal que el build en Render tarde
   más que antes — no es un error.
2. **El servidor usa más memoria en todo momento**, porque mantiene ese Chrome
   abierto en segundo plano (para no tener que abrirlo de cero en cada PDF). En
   el plan Starter de Render esto no debería ser un problema, pero si el
   servicio empieza a reiniciarse solo por falta de memoria, es lo primero a
   revisar.
3. **Si Render no logra instalar/arrancar Chromium** (poco común, pero puede
   pasar según el entorno del build), hay una válvula de escape: variable de
   entorno `PUPPETEER_EXECUTABLE_PATH` apuntando a un Chrome ya instalado en el
   servidor. Sin esa variable, Puppeteer usa el Chromium que descargó él mismo
   (lo normal).

Después de subir esta actualización, entra a **Render → tu servicio → Logs** y
confirma que el build terminó sin errores y que el servicio quedó "Live". Si
ves errores relacionados a "chrome" o "chromium" durante el build, avísame.

---

## Respaldos automáticos

El servidor guarda una copia cada día y conserva los últimos 30 días.
Los ves en el LIS → **💾 Respaldos**, y puedes restaurar cualquiera con un clic.

Con disco persistente, esos respaldos también sobreviven a las actualizaciones.
Sin disco persistente, se borran junto con todo lo demás.

**Aun con disco persistente, descarga un respaldo a tu computadora una vez por semana.**
Un disco puede fallar; una copia en tu Google Drive no.

---

## Primer despliegue

### 1. GitHub
1. Cuenta en github.com → **New repository** → nombre `cdim-marcala`
2. **uploading an existing file** → arrastra todo el contenido de esta carpeta
3. **Commit changes**

### 2. Render
1. Cuenta en render.com → **Continue with GitHub**
2. **New +** → **Web Service** → conecta `cdim-marcala`
3. Configuración:
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
4. **Environment Variables**:
   - `JWT_SECRET` = una frase larga solo tuya
   - `NODE_ENV` = `production`
   - `DATA_DIR` = `/var/data`  *(solo si contrataste el disco)*
5. **Create Web Service**

### 3. Primer ingreso
- Usuario: `admin`
- Clave: `cdim2024`
- **Cámbiala de inmediato** en Usuarios → Cambiar mi contraseña

---

## URLs del sistema

| URL | Para qué |
|---|---|
| `https://tu-url.com/` | LIS completo (requiere ingresar) |
| `https://tu-url.com/cotizacion.html` | Portal público de cotización |
| `https://tu-url.com/api/salud` | Diagnóstico del servidor |

## Consulta de resultados por el paciente

El paciente consulta sus resultados enviando **número de identidad y fecha de nacimiento**
(los dos datos, no solo el DNI). Se limita a cinco intentos cada quince minutos por
dirección IP, para que nadie pueda probar números uno tras otro.

```
POST /api/resultado
{ "dni": "1208-1998-00596", "fnac": "1998-09-22" }
```

Solo devuelve órdenes ya validadas o entregadas.

---

## App en el celular

**Android**: abre la URL en Chrome → aparece "Instalar" → toca
**iPhone**: abre en Safari → compartir → "Añadir a pantalla de inicio"
