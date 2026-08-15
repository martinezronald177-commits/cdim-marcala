# CDI Marcala — Guía rápida

## Las cuatro direcciones de tu sistema

Cuando termines de montarlo (ejemplo con `cdim-marcala.onrender.com`):

| Dirección | Para quién | Qué hace |
|---|---|---|
| `cdim-marcala.onrender.com` | **Tú y tu personal** | El LIS completo. Pide usuario y clave. |
| `cdim-marcala.onrender.com/paciente` | **Tus pacientes** | Ven resultados, cotizan y siguen sus solicitudes. |
| `cdim-marcala.onrender.com/cotizar` | **Público** | Misma app, entra directo a cotizar. |
| `cdim-marcala.onrender.com/login.html` | — | Pantalla de acceso al LIS. |

La que compartes en redes sociales y WhatsApp es la de **`/paciente`**.

---

## Qué puede hacer el paciente

**Ver sus resultados.** Entra con su número de identidad y su fecha de nacimiento.
Los dos datos, no solo el DNI: así nadie más puede ver sus resultados.
Solo aparecen las órdenes que tú ya validaste.

**Cotizar exámenes.** Elige de tu catálogo con los precios que tú tengas puestos.
La solicitud te llega al LIS.

**Seguir sus solicitudes.** Ve si su cotización está "Recibida", "En revisión" o "Aprobada".

**Instalar la app.** En Android sale un botón "Instalar". En iPhone, desde Safari:
compartir → "Añadir a pantalla de inicio".

---

## Cómo apruebas una cotización

1. En el LIS entra a **Cotizaciones**
2. Las del portal llegan marcadas **🌐 Web** con estado **⏳ Por aprobar**
3. Botón **✓ Aprobar**

Con ese clic el sistema:
- Busca al paciente por su número de identidad
- Si no existe, lo crea con los datos que él llenó
- Crea la orden de trabajo
- Te pregunta si quieres ir a imprimir las etiquetas

---

## Montarlo gratis en Render

### 1. GitHub
1. Cuenta en github.com → **New repository** → nombre `cdim-marcala`
2. **uploading an existing file** → arrastra todo el contenido de esta carpeta
3. **Commit changes**

### 2. Render
1. Cuenta en render.com → **Continue with GitHub**
2. **New +** → **Web Service** → conecta `cdim-marcala`
3. Runtime: **Node** · Build: `npm install` · Start: `node server.js`
4. Instance Type: **Free**
5. **Environment Variables**:
   - `JWT_SECRET` = una frase larga que solo tú sepas
   - `NODE_ENV` = `production`
6. **Create Web Service**

### 3. Primer ingreso
Usuario `admin`, clave `cdim2024`. **Cámbiala de inmediato** en Usuarios.

### 4. Sube tus datos actuales
En tu LIS de la computadora: Configuración → Exportar respaldo.
En el LIS de internet: 💾 Respaldos → ⬆ Restaurar desde archivo.

---

## Lo que debes saber del plan gratuito

**El servidor se duerme.** Si nadie lo usa por 15 minutos, la siguiente visita
tarda unos 30 segundos en despertar. Después va rápido.

**Los datos se borran al actualizar.** Cada vez que subas una versión nueva del
sistema, el disco se reinicia. Por eso:

> Antes de actualizar: 💾 Respaldos → ⬇ Descargar respaldo
> Después de actualizar: 💾 Respaldos → ⬆ Restaurar desde archivo

**Para evitarlo:** en Render, pestaña **Disks** → **Add Disk** → Mount Path
`/var/data` → 1 GB. Luego agrega la variable `DATA_DIR` = `/var/data`.
Cuesta unos $7 al mes y los datos ya nunca se borran.
