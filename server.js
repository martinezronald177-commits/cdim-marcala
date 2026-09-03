/* ============================================================
   CDI MARCALA · SERVIDOR WEB
   Node.js + Express · Almacenamiento en JSON + archivos
   Sin base de datos externa: todo vive en /data/*.json
   Listo para desplegar en Render / Railway / VPS
   ============================================================ */
'use strict';
const express    = require('express');
const helmet     = require('helmet');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const compression= require('compression');
const cookieParser=require('cookie-parser');
const path       = require('path');
const zlib       = require('zlib');
const fs         = require('fs');
const crypto     = require('crypto');
const multer     = require('multer');
const puppeteer  = require('puppeteer');

// ── Configuración ────────────────────────────────────────────
const PORT    = process.env.PORT || 3000;
const SECRET  = process.env.JWT_SECRET || 'cdim-secret-cambiar-en-produccion';
// Sin JWT_SECRET en el entorno, el servidor firmaría todo con un secreto
// público (está en este mismo archivo, en el repositorio). En producción eso
// es inaceptable, así que ni siquiera arranca; en desarrollo solo advierte.
if(!process.env.JWT_SECRET){
  if(process.env.NODE_ENV === 'production'){
    console.error('[CDIM] JWT_SECRET no está definido. El servidor no puede arrancar así en producción.');
    process.exit(1);
  }
  console.warn('[CDIM] ⚠ JWT_SECRET no definido — usando el secreto de desarrollo inseguro. No usar así en producción.');
}
// Vida del token de acceso (JWT en la cookie 'token'). Ver ARQUITECTURA.md:
// Fase 3 del despliegue (ago. 2026) — todo el personal ya cerró sesión y
// volverá a entrar con el frontend que sabe renovar sola vía apiFetch(), así
// que ya no hace falta el margen largo de las fases 1-2.
const ACCESO_TTL      = '15m';
const RENOVACION_DIAS = 7;    // ventana "rolling" del refresh token: cada uso exitoso la extiende otros 7 días
const SESION_MAX_DIAS = 30;   // tope absoluto desde el login original, aunque el uso sea diario
// DATA_DIR se puede apuntar a un disco persistente con la variable de entorno
// DATA_DIR (en Render: /var/data). Si no se define, usa la carpeta local.
const DATA_DIR= process.env.DATA_DIR || path.join(__dirname, 'data');
const UPL_DIR = process.env.UPL_DIR  || path.join(DATA_DIR, 'uploads');
const PUB_DIR = path.join(__dirname, 'public');

[DATA_DIR, UPL_DIR, PUB_DIR].forEach(d => fs.mkdirSync(d, {recursive:true}));

// ── Cifrado en disco (AES-256-GCM) ─────────────────────────────
/* Los datos clínicos (estado.json.gz: pacientes, órdenes, resultados) y sus
   respaldos se cifran antes de tocar el disco. Así, quien copie el disco
   del servidor, una imagen de respaldo, o el archivo suelto, no puede leer
   los datos de los pacientes sin esta clave -- solo este mismo servidor,
   que la trae por variable de entorno (nunca en el código ni en el repo),
   puede volver a leerlos.

   Formato del archivo cifrado: IV (12 bytes) + AUTH TAG (16 bytes) +
   contenido cifrado (el .gz de siempre, cifrado tal cual iría a disco). Se
   detecta solo si un archivo YA está cifrado mirando sus dos primeros
   bytes: un .gz sin cifrar SIEMPRE empieza con la firma 0x1f 0x8b; el
   cifrado, al ser bytes al azar (el IV), prácticamente nunca. Esto permite
   migrar sin downtime los datos que ya existían sin cifrar la primera vez
   que este código se despliega: se leen como antes y, en el siguiente
   guardado -- que ocurre todo el tiempo -- quedan cifrados. */
const DATA_KEY_HEX = process.env.DATA_ENCRYPTION_KEY || '';
if(!DATA_KEY_HEX && process.env.NODE_ENV === 'production'){
  console.error('[CDIM] DATA_ENCRYPTION_KEY no está definida. El servidor no puede arrancar así en producción.');
  process.exit(1);
}
if(DATA_KEY_HEX && !/^[0-9a-fA-F]{64}$/.test(DATA_KEY_HEX)){
  console.error('[CDIM] DATA_ENCRYPTION_KEY debe ser una cadena hexadecimal de 64 caracteres (32 bytes). El servidor no puede arrancar así.');
  process.exit(1);
}
if(!DATA_KEY_HEX)
  console.warn('[CDIM] ⚠ DATA_ENCRYPTION_KEY no definida — los datos se guardan SIN cifrar en disco. No usar así en producción.');
const DATA_KEY = DATA_KEY_HEX ? Buffer.from(DATA_KEY_HEX, 'hex') : null;
function esGzip(buf){ return buf.length>=2 && buf[0]===0x1f && buf[1]===0x8b; }
function cifrar(buf){
  if(!DATA_KEY) return buf;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', DATA_KEY, iv);
  const ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}
function descifrar(buf){
  if(esGzip(buf)) return buf;   // dato viejo aún sin cifrar (o sin clave configurada)
  if(!DATA_KEY) throw new Error('El archivo está cifrado pero no hay DATA_ENCRYPTION_KEY configurada');
  const iv = buf.subarray(0,12), tag = buf.subarray(12,28), ct = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', DATA_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ── Almacenamiento JSON ──────────────────────────────────────
const DB_FILES = {
  usuarios : 'usuarios.json',
  estado   : 'estado.json',    // todo el estado del LIS
  cola_cot : 'cola_cot.json',  // cotizaciones del portal web
  sesiones : 'sesiones.json',
};
/* El estado se guarda comprimido (y cifrado, ver arriba): a 3000 órdenes
   son 11 MB que bajarían a unos 100 KB. Como se escribe en cada guardado,
   la diferencia en desgaste de disco y en tiempo es grande. Los archivos
   pequeños (usuarios, cola) se dejan en texto plano para poder
   inspeccionarlos a mano si hace falta -- no llevan datos clínicos: las
   claves y PIN ya viajan con hash, nunca en claro. */
const COMPRIMIR = ['estado'];

function leerDB(nombre){
  const f  = path.join(DATA_DIR, DB_FILES[nombre]);
  const fz = f + '.gz';
  // Se prefiere el comprimido; si no está, se lee el de texto (versiones anteriores)
  try{
    if(fs.existsSync(fz))
      return JSON.parse(zlib.gunzipSync(descifrar(fs.readFileSync(fz))).toString('utf8'));
    if(fs.existsSync(f))
      return JSON.parse(fs.readFileSync(f,'utf8'));
  }catch(e){
    console.error(`[CDIM] No se pudo leer ${nombre}: ${e.message}`);
  }
  return null;
}
function escribirDB(nombre, datos){
  const f = path.join(DATA_DIR, DB_FILES[nombre]);
  const texto = JSON.stringify(datos);
  // Escritura segura: primero a un temporal y luego se renombra.
  // Si se corta la luz a mitad de la escritura, el archivo anterior queda intacto.
  if(COMPRIMIR.includes(nombre)){
    const fz = f + '.gz', tmp = fz + '.tmp';
    fs.writeFileSync(tmp, cifrar(zlib.gzipSync(texto, {level:6})));
    fs.renameSync(tmp, fz);
    // Se retira la versión en texto para que no queden dos fuentes de verdad
    try{ if(fs.existsSync(f)) fs.unlinkSync(f); }catch{}
  }else{
    const tmp = f + '.tmp';
    fs.writeFileSync(tmp, texto, 'utf8');
    fs.renameSync(tmp, f);
  }
}

/* ── Respaldos automáticos ──────────────────────────────────
   Cada vez que se guarda el estado se conserva una copia diaria.
   Se mantienen los últimos 30 días. */
const BAK_DIR = path.join(DATA_DIR, 'respaldos');
fs.mkdirSync(BAK_DIR, {recursive:true});

/* ── Copia fuera del servidor ────────────────────────────────
   Los 30 respaldos diarios viven en la misma carpeta de datos que la base
   viva. Si ese disco se pierde, se corrompe o la cuenta se cierra, se pierden
   los 30 con ella — y son expedientes clínicos con obligación legal de
   conservarse por años.

   Aquí se manda además una copia a un almacenamiento externo compatible con
   S3 (sirve Backblaze B2, Cloudflare R2, Amazon S3 o Wasabi: todos hablan el
   mismo protocolo). Se sube el archivo TAL CUAL, ya comprimido y cifrado con
   DATA_ENCRYPTION_KEY, así que el proveedor nunca ve un dato clínico: sin esa
   llave, para él es ruido.

   La firma SigV4 se arma a mano con `crypto` en vez de traer el SDK de AWS:
   son cuarenta líneas contra quince megabytes de dependencia, y esto es lo
   único que se necesita de todo el protocolo.

   Si no está configurado, no pasa nada: el servidor avisa una vez al arrancar
   y sigue funcionando igual que antes. */
/* El panel de Backblaze (y el de casi todos) muestra el endpoint SIN esquema
   -- "s3.us-east-005.backblazeb2.com" --, así que es lo que uno copia y pega.
   Sin el https:// por delante, new URL() lanza un "Invalid URL" opaco y la
   copia falla cada hora sin decir por qué. Se completa aquí en vez de exigir
   que se escriba a mano. */
function normalizarEndpoint(v){
  const s = String(v||'').trim().replace(/\/+$/,'');
  if(!s) return '';
  return /^https?:\/\//i.test(s) ? s : 'https://'+s;
}
/* Todo valor se recorta: al pegar una llave en el panel del proveedor es
   facilísimo arrastrar un espacio o un salto de línea, y un salto dentro de la
   cabecera Authorization hace que fetch la rechace de plano con un
   "invalid header value" que no dice nada de dónde está el problema. */
const env = k => String(process.env[k]||'').trim();
/* La región va DENTRO del hostname en Backblaze y en Amazon
   ("s3.us-east-005.backblazeb2.com"), y tiene que coincidir con la que se
   firma o el proveedor rechaza la firma. Si el hostname la lleva, esa manda:
   es la única que puede ser correcta, y escribirla aparte solo da ocasión de
   equivocarse. */
function regionDelEndpoint(ep){
  const m = /^https?:\/\/(?:[a-z0-9-]+\.)?s3[.-]([a-z]{2}-[a-z]+-\d+)\./i.exec(ep||'');
  return m ? m[1] : '';
}
const _endpoint = normalizarEndpoint(env('RESPALDO_S3_ENDPOINT'));
const _regionDicha = env('RESPALDO_S3_REGION');
const _regionReal  = regionDelEndpoint(_endpoint);
const S3 = {
  endpoint : _endpoint,
  bucket   : env('RESPALDO_S3_BUCKET'),
  region   : _regionReal || _regionDicha || 'auto',
  keyId    : env('RESPALDO_S3_KEY_ID'),
  secret   : env('RESPALDO_S3_SECRET'),
  prefijo  : (env('RESPALDO_S3_PREFIJO')||'respaldos').replace(/^\/+|\/+$/g,''),
  // Cada cuánto se manda la copia. Por defecto una vez por hora: el archivo
  // pesa menos de un megabyte, así que sale barato y deja como mucho una hora
  // de trabajo fuera de la copia externa, en vez de un día entero.
  minutos  : Math.max(5, Number(process.env.RESPALDO_S3_MINUTOS)||60),
};
/* Se comprueba al arrancar y no en cada subida: un endpoint mal escrito debe
   verse en el primer log, no descubrirse una hora después en un mensaje que
   solo dice "Invalid URL". */
let S3_MOTIVO = '';
const S3_LISTO = (()=>{
  const faltan = ['ENDPOINT','BUCKET','KEY_ID','SECRET']
    .filter(k=>!S3[{ENDPOINT:'endpoint',BUCKET:'bucket',KEY_ID:'keyId',SECRET:'secret'}[k]]);
  if(faltan.length===4) return false;                       // sin configurar, es lo normal
  if(faltan.length){ S3_MOTIVO='Faltan variables: '+faltan.map(k=>'RESPALDO_S3_'+k).join(', '); return false; }
  try{ new URL(S3.endpoint); }
  catch{ S3_MOTIVO=`RESPALDO_S3_ENDPOINT no es una dirección válida: "${S3.endpoint}"`; return false; }
  /* Una llave con un carácter de control (el salto de línea que se arrastra al
     pegar) no puede ir en una cabecera HTTP. Sin esta comprobación el fallo
     aparecía cada hora como un "invalid header value" del propio fetch, que no
     dice qué variable revisar. */
  for(const [k,v] of [['RESPALDO_S3_KEY_ID',S3.keyId],['RESPALDO_S3_SECRET',S3.secret],
                      ['RESPALDO_S3_BUCKET',S3.bucket]])
    if(/[\x00-\x1f\x7f]/.test(v)){
      S3_MOTIVO=`${k} lleva un salto de línea o un carácter invisible. Vuelve a pegarla sin espacios ni saltos.`;
      return false;
    }
  if(_regionReal && _regionDicha && _regionReal!==_regionDicha)
    console.warn(`[CDIM] RESPALDO_S3_REGION dice "${_regionDicha}" pero el endpoint es de `
      +`"${_regionReal}". Se usa la del endpoint, que es la que el proveedor exige al firmar.`);
  return true;
})();
const respaldoExterno = {activo:S3_LISTO, ultimoOk:null, ultimoError:null, subidas:0};
let _ultimaSubidaS3 = 0;

function _hmac(clave, dato){ return crypto.createHmac('sha256', clave).update(dato).digest(); }
function _sha256(dato){ return crypto.createHash('sha256').update(dato).digest('hex'); }

async function subirRespaldoExterno(nombre, contenido){
  const ruta = '/' + [S3.bucket, S3.prefijo, nombre].filter(Boolean)
    .join('/').split('/').map(encodeURIComponent).join('/');
  const url  = new URL(S3.endpoint + ruta);
  const amz  = new Date().toISOString().replace(/[:-]|\.\d{3}/g,'');  // 20260901T120000Z
  const dia  = amz.slice(0,8);
  const hash = _sha256(contenido);
  const cab  = {host:url.host, 'x-amz-content-sha256':hash, 'x-amz-date':amz};
  const nombres = Object.keys(cab).sort();
  const canonica = [
    'PUT', url.pathname, '',
    nombres.map(h=>`${h}:${cab[h]}\n`).join(''),
    nombres.join(';'),
    hash,
  ].join('\n');
  const ambito = `${dia}/${S3.region}/s3/aws4_request`;
  const aFirmar = ['AWS4-HMAC-SHA256', amz, ambito, _sha256(canonica)].join('\n');
  let k = _hmac('AWS4'+S3.secret, dia);
  k = _hmac(k, S3.region); k = _hmac(k, 's3'); k = _hmac(k, 'aws4_request');
  const firma = crypto.createHmac('sha256', k).update(aFirmar).digest('hex');
  cab.Authorization = `AWS4-HMAC-SHA256 Credential=${S3.keyId}/${ambito},`
    + ` SignedHeaders=${nombres.join(';')}, Signature=${firma}`;
  const r = await fetch(url, {method:'PUT', headers:cab, body:contenido});
  if(!r.ok) throw new Error(explicarErrorS3(r.status, await r.text()));
  return true;
}
/* Los proveedores contestan en XML con códigos como "InvalidAccessKeyId", que
   no le dicen a nadie QUÉ variable revisar. Se traducen a la acción concreta:
   este mensaje termina en la tarjeta de Respaldos, y ahí lo que hace falta es
   saber qué corregir, no el código del error. */
function explicarErrorS3(estado, xml){
  const cod = (/<Code>([^<]+)<\/Code>/.exec(xml)||[])[1] || '';
  const guia = {
    InvalidAccessKeyId:
      'RESPALDO_S3_KEY_ID no es válida. En Backblaze es el «keyID» de una Application Key '
      +'(unos 25 caracteres, empieza por 005…), no el Account ID ni el nombre de la llave.',
    SignatureDoesNotMatch:
      'RESPALDO_S3_SECRET no corresponde a esa llave. Backblaze solo muestra el '
      +'applicationKey al crearla: si no lo guardaste, crea una llave nueva.',
    NoSuchBucket:
      `El bucket "${S3.bucket}" no existe en esa cuenta. Revisa RESPALDO_S3_BUCKET.`,
    AccessDenied:
      'La llave no tiene permiso de escritura sobre ese bucket. Vuelve a crearla con '
      +'«Read and Write» y, si la limitaste a un bucket, que sea a este.',
    RequestTimeTooSkewed:
      'La hora del servidor está desfasada respecto al proveedor. Es del proveedor de '
      +'hosting, no de esta aplicación.',
  }[cod];
  if(guia) return `${cod}: ${guia}`;
  return `HTTP ${estado} ${String(xml).replace(/\s+/g,' ').slice(0,200)}`;
}
/* Se llama después de escribir el respaldo del día. Nunca lanza ni espera:
   que el almacenamiento externo esté caído no puede impedir que se guarde el
   trabajo del laboratorio. */
function mandarCopiaExterna(nombre, contenido, forzar){
  if(!S3_LISTO) return;
  const ahora = Date.now();
  if(!forzar && ahora - _ultimaSubidaS3 < S3.minutos*60000) return;
  _ultimaSubidaS3 = ahora;
  subirRespaldoExterno(nombre, contenido)
    .then(()=>{
      respaldoExterno.ultimoOk = new Date().toISOString();
      respaldoExterno.ultimoError = null;
      respaldoExterno.subidas++;
      console.log(`[CDIM] Respaldo externo subido: ${nombre} (${(contenido.length/1024).toFixed(0)} KB)`);
    })
    .catch(e=>{
      respaldoExterno.ultimoError = e.message;
      // Se reintenta en la próxima vuelta, no en un bucle que sature la red.
      _ultimaSubidaS3 = ahora - (S3.minutos*60000) + 5*60000;   // reintento en 5 min
      console.warn('[CDIM] Falló el respaldo externo:', e.message);
    });
}

function respaldoDiario(estado){
  try{
    const hoy = new Date().toISOString().slice(0,10);
    // Respaldo comprimido y cifrado: un estado de 20 MB baja a menos de 1 MB.
    // Sin la compresión, 30 respaldos diarios llenarían el disco en unos dos
    // años; sin el cifrado, cada respaldo sería una copia legible de los
    // datos clínicos completos regada en 30 archivos distintos.
    const f = path.join(BAK_DIR, `estado-${hoy}.json.gz`);
    const contenido = cifrar(zlib.gzipSync(JSON.stringify(estado), {level:6}));
    fs.writeFileSync(f, contenido);
    // La misma copia, ya cifrada, sale también fuera del servidor.
    mandarCopiaExterna(`estado-${hoy}.json.gz`, contenido);
    // Se limpian también los respaldos antiguos sin comprimir
    const archivos = fs.readdirSync(BAK_DIR)
      .filter(x => x.startsWith('estado-'))
      .sort().reverse();
    archivos.slice(30).forEach(x => {
      try{ fs.unlinkSync(path.join(BAK_DIR, x)); }catch{}
    });
  }catch(e){ console.warn('[CDIM] No se pudo crear el respaldo diario:', e.message); }
}

// ── Inicializar usuarios si no existen ───────────────────────
/* Migración de roles: el sistema pasó de dos roles a cuatro.
   El usuario 'admin' y quien quedara con el rol antiguo 'Administrador'
   como único dueño del sistema deben conservar el control total. */
function migrarRoles(){
  const usuarios = leerDB('usuarios');
  if(!usuarios || !usuarios.length) return;
  let cambio = false;
  // 1. La cuenta 'admin' siempre tiene control total
  const admin = usuarios.find(u => u.usuario === 'admin');
  if(admin && admin.rol !== 'Admin'){ admin.rol = 'Admin'; cambio = true;
    console.log('[CDIM] Cuenta admin promovida a rol Admin'); }
  // 2. Si nadie tiene rol Admin, se promueve el primer usuario:
  //    sin esto el laboratorio quedaría sin acceso a configuración.
  if(!usuarios.some(u => u.rol === 'Admin')){
    usuarios[0].rol = 'Admin'; cambio = true;
    console.log(`[CDIM] ${usuarios[0].usuario} promovido a Admin (no había ninguno)`);
  }
  // 3. Si la cuenta 'admin' TODAVÍA usa la contraseña de fábrica (la misma
  //    que trae este código, público en el repositorio), se le exige
  //    cambiarla en su próximo ingreso -- sin esto, cualquiera que lea el
  //    código fuente conoce una contraseña válida del sistema en producción.
  if(admin && admin.clave && !admin.debeCambiarClave && bcrypt.compareSync('cdim2024', admin.clave)){
    admin.debeCambiarClave = true; cambio = true;
    console.log('[CDIM] La cuenta admin sigue con la contraseña de fábrica: se exigirá cambiarla al entrar');
  }
  if(cambio) escribirDB('usuarios', usuarios);
}

function inicializarUsuarios(){
  if(leerDB('usuarios')){ migrarRoles(); return; }
  const admin = {
    id    : 'usr-admin',
    nombre: 'Dr. Ronald Enrique Martínez Márquez',
    usuario: 'admin',
    clave  : bcrypt.hashSync('cdim2024', 10),
    rol    : 'Admin',
    activo : true,
    creado : new Date().toISOString(),
    debeCambiarClave: true,
  };
  escribirDB('usuarios', [admin]);
  console.log('[CDIM] Usuario admin creado. Cambia la clave en primer ingreso.');
}

// ── Sesiones y tokens de renovación ────────────────────────────
/* El token de renovación nunca se guarda en claro, solo su huella SHA-256.
   A diferencia de una contraseña o PIN (que una persona elige — por eso
   bcrypt es lento a propósito), el token de renovación es 256 bits al azar
   generados por el servidor: no hay diccionario que probar, así que un hash
   rápido y determinista es correcto, y permite encontrar el registro por
   igualdad de huella en vez de comparar contra cada una con bcrypt. */
function tokenCrudo(){ return crypto.randomBytes(32).toString('hex'); }
function huella(t){ return crypto.createHash('sha256').update(t).digest('hex'); }

function crearSesion(usuario, req){
  const ahora = Date.now();
  const cruda = tokenCrudo();
  const sesiones = leerDB('sesiones') || [];
  const s = {
    id: 'ses-'+ahora.toString(36)+'-'+crypto.randomBytes(4).toString('hex'),
    usuarioId: usuario.id,
    refreshHash: huella(cruda),
    refreshHashAnterior: null,   // ver buscarPorToken(): detección de robo por reuso
    creado: new Date(ahora).toISOString(),
    ultimoUso: new Date(ahora).toISOString(),
    expira: new Date(ahora + RENOVACION_DIAS*86400000).toISOString(),     // rolling
    expiraAbs: new Date(ahora + SESION_MAX_DIAS*86400000).toISOString(),  // tope absoluto, nunca se extiende
    ip: ipDe(req),
    userAgent: req.headers['user-agent'] || '',
    revocada: false, revocadaEn: null, revocadaPor: null,
  };
  sesiones.push(s);
  escribirDB('sesiones', limpiarSesionesViejas(sesiones));
  return {sesion: s, cruda};
}
// Igual criterio que respaldoDiario(): no crece para siempre. Sesiones ya
// revocadas o vencidas se conservan 30 días más (auditoría de quién entró
// desde dónde) y después se descartan.
function limpiarSesionesViejas(sesiones){
  const limite = Date.now() - 30*86400000;
  return sesiones.filter(s => !((s.revocada || new Date(s.expiraAbs).getTime() < Date.now())
    && new Date(s.ultimoUso).getTime() < limite));
}
// Distingue tres casos al presentar un token de renovación:
// (a) coincide con el vigente → sesión válida, se procede.
// (b) coincide con el INMEDIATO ANTERIOR (ya reemplazado por una rotación)
//     → posible robo: alguien más tiene una copia de un token ya superado.
// (c) no coincide con nada → simplemente inválido/desconocido.
function buscarPorToken(cruda){
  if(!cruda) return null;
  const h = huella(cruda);
  const sesiones = leerDB('sesiones') || [];
  const actual = sesiones.find(s => s.refreshHash === h);
  if(actual) return {sesion: actual, reutilizado: false};
  const previa = sesiones.find(s => s.refreshHashAnterior === h && !s.revocada);
  if(previa) return {sesion: previa, reutilizado: true};
  return null;
}
function sesionValida(s){
  if(!s || s.revocada) return false;
  const ahora = Date.now();
  return new Date(s.expira).getTime() > ahora && new Date(s.expiraAbs).getTime() > ahora;
}
// Rota EN EL LUGAR (mismo id): una fila por dispositivo en "sesiones
// activas", no una nueva cada vez que se renueva el token de acceso. Guarda
// la huella saliente en refreshHashAnterior para poder detectar un reuso en
// la SIGUIENTE llamada.
function rotarSesion(s, req){
  const cruda = tokenCrudo();
  const sesiones = leerDB('sesiones') || [];
  const actual = sesiones.find(x => x.id === s.id);
  if(!actual) return null;
  actual.refreshHashAnterior = actual.refreshHash;
  actual.refreshHash = huella(cruda);
  actual.ultimoUso = new Date().toISOString();
  actual.expira = new Date(Date.now() + RENOVACION_DIAS*86400000).toISOString();
  // expiraAbs NUNCA se toca aquí: es el tope de 30 días desde el login original.
  actual.ip = ipDe(req);
  escribirDB('sesiones', sesiones);
  return cruda;
}
function revocarSesionPorId(id, motivo){
  const sesiones = leerDB('sesiones') || [];
  const s = sesiones.find(x => x.id === id);
  if(s && !s.revocada){ s.revocada=true; s.revocadaEn=new Date().toISOString(); s.revocadaPor=motivo; escribirDB('sesiones', sesiones); }
}
function revocarSesionPorToken(cruda, motivo){
  const hallazgo = buscarPorToken(cruda);
  if(hallazgo) revocarSesionPorId(hallazgo.sesion.id, motivo || 'usuario');
}
// Detección de robo: se presentó un refresh token ya superado por una
// rotación. Se cierra TODA la actividad de esa persona, no solo esta sesión.
function revocarTodasSesionesDeUsuario(usuarioId, motivo){
  const sesiones = leerDB('sesiones') || [];
  let cambio = false;
  sesiones.forEach(s => { if(s.usuarioId === usuarioId && !s.revocada){
    s.revocada = true; s.revocadaEn = new Date().toISOString(); s.revocadaPor = motivo; cambio = true; } });
  if(cambio) escribirDB('sesiones', sesiones);
}
// Mismo criterio que ya usaba soloAdmin(); se extrae para reusarlo también
// en las rutas de sesiones activas.
function puedeGestionarUsuarios(user){
  const p = user && user.permisos;
  if(p && 'usuarios' in p) return !!p.usuarios;
  return user && user.rol === 'Admin';
}
// Con `trust proxy` activo (ver app.set más abajo), req.ip ya resuelve
// correctamente la cadena de proxies -- evita repetir a mano el parseo de
// X-Forwarded-For en cada ruta que necesita la IP del cliente.
function ipDe(req){ return req.ip || req.socket.remoteAddress || 'sin-ip'; }
// COOKIE_SECURE: en Render, detrás de su proxy TLS, NODE_ENV=production ya es
// requisito de despliegue (ver DEPLOY.md) — se usa como señal de "esto es
// HTTPS de verdad". En desarrollo local (http) queda en false a propósito:
// Chrome nunca manda una cookie Secure por http, y con true el login local
// dejaría de funcionar para probar.
const COOKIE_SECURE = process.env.NODE_ENV === 'production';
/* Cookies de SESIÓN: van SIN maxAge ni expires a propósito, así el navegador
   las borra al cerrarse y cerrar el navegador cierra la sesión. Antes eran
   persistentes (15 min el acceso, 7 días la renovación), de modo que quien
   volviera a abrir el navegador en esa computadora entraba directo al
   historial clínico sin que nadie le pidiera nada -- en un laboratorio con un
   equipo compartido en recepción, eso es un problema.

   Los plazos del SERVIDOR no cambian: el JWT sigue venciendo a los
   ACCESO_TTL y el registro de la sesión en sesiones.json a los
   RENOVACION_DIAS. Lo que se acorta es cuánto vive la credencial en el
   navegador, que es lo que importa para el equipo compartido.

   Mientras el navegador siga abierto no molesta a nadie: al vencer el token
   de 15 minutos, el frontend renueva solo con la cookie de refresh (que sigue
   ahí hasta que se cierre el navegador). */
function emitirCookiesSesion(res, usuario, sesionId, cruda){
  const token = jwt.sign({id:usuario.id, sid:sesionId, nombre:usuario.nombre, usuario:usuario.usuario,
    rol:usuario.rol, permisos:usuario.permisos||null}, SECRET, {expiresIn:ACCESO_TTL});
  res.cookie('token', token, {httpOnly:true, secure:COOKIE_SECURE, sameSite:'lax'});
  res.cookie('refresh', cruda, {httpOnly:true, secure:COOKIE_SECURE, sameSite:'lax', path:'/api/auth'});
}

// ── Middleware de autenticación ───────────────────────────────
function auth(req, res, next){
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ','');
  if(!token) return res.status(401).json({error:'No autenticado'});
  try{
    req.user = jwt.verify(token, SECRET);
    next();
  }catch{
    res.clearCookie('token');
    res.status(401).json({error:'Sesión expirada'});
  }
}
function soloAdmin(req, res, next){
  if(puedeGestionarUsuarios(req.user)) return next();
  res.status(403).json({error:'Esta acción requiere el permiso de usuarios'});
}

// ── Subida de archivos ────────────────────────────────────────
const storage = multer.diskStorage({
  destination: UPL_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5*1024*1024 },
  fileFilter: (req, file, cb) => {
    const ok = /image\/(jpeg|png|webp)|application\/pdf/.test(file.mimetype);
    cb(null, ok);
  }
});
/* El fileFilter de arriba solo mira el mimetype que MANDA el cliente, y ese
   es un header cualquiera -- se falsifica sin esfuerzo. Antes de aceptar el
   archivo ya guardado se revisan también sus primeros bytes (la "firma" real
   del formato); si no coincide con lo declarado, se borra y se rechaza. No
   decodifica el archivo entero, pero cierra el caso simple de subir un .exe
   o script disfrazado de imagen o PDF con el header falsificado. */
function firmaValida(buf, mimetype){
  if(mimetype === 'image/jpeg') return buf[0]===0xFF && buf[1]===0xD8 && buf[2]===0xFF;
  if(mimetype === 'image/png')  return buf[0]===0x89 && buf[1]===0x50 && buf[2]===0x4E && buf[3]===0x47;
  if(mimetype === 'image/webp') return buf.toString('ascii',0,4)==='RIFF' && buf.toString('ascii',8,12)==='WEBP';
  if(mimetype === 'application/pdf') return buf.toString('ascii',0,4)==='%PDF';
  return false;
}

// ── Aplicación ────────────────────────────────────────────────
const app = express();
// Render (y casi cualquier hosting con proxy delante) termina el HTTPS y le
// reenvía al servidor una conexión HTTP normal -- sin esto, req.protocol
// siempre diría "http" aunque el paciente haya entrado por https, y el QR
// que se genera dentro del PDF (ver /r/:numero/:token/pdf) quedaría con la
// URL equivocada.
// "1" (y no true): se confía solo en el salto directo de Render, el único
// proxy real delante de este servidor. Con "true" se confía en TODA la
// cadena de X-Forwarded-For, y esa cadena la puede iniciar el propio
// cliente -- cualquiera podía mandar su propio X-Forwarded-For y aparecer
// con la IP que quisiera, saltándose así TODOS los límites de intentos
// (login, PIN, refresh, PDF, cotización pública) que dependen de ipDe(req).
// Con "1", Express toma el valor que Render mismo añadió al final de la
// cadena -- el salto más cercano al servidor -- e ignora cualquier cosa que
// el cliente haya intentado anteponer.
app.set('trust proxy', 1);
// El CSP por defecto de helmet bloquearía la app: todo el JS de index.html
// (e informe.html) vive en un único <script> inline, y ese mismo archivo
// carga JsBarcode desde cdn.jsdelivr.net -- ninguno de los dos pasa un
// script-src 'self' sin más. Se desactiva el CSP y se dejan las demás
// cabeceras de helmet (X-Content-Type-Options, X-Frame-Options, Referrer
// -Policy, HSTS, etc.), que sí son compatibles sin tocar el frontend.
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());

/* El estado completo crece con cada orden. A 3000 órdenes ronda los 20 MB,
   así que el límite de 10 MB detendría los guardados en menos de un año.
   Se acepta hasta 64 MB y, si el cliente lo envía comprimido, se descomprime
   antes de interpretarlo: así por la red viaja menos de un megabyte. */
app.use('/api/estado', (req, res, next) => {
  if(req.method !== 'POST' || req.headers['content-encoding'] !== 'gzip') return next();
  const trozos = [];
  let total = 0;
  req.on('data', c => {
    total += c.length;
    if(total > 64*1024*1024){ res.status(413).json({error:'Estado demasiado grande'}); req.destroy(); return; }
    trozos.push(c);
  });
  req.on('end', () => {
    try{
      req.body = JSON.parse(zlib.gunzipSync(Buffer.concat(trozos)).toString('utf8'));
      req._yaLeido = true;
      next();
    }catch(e){ res.status(400).json({error:'No se pudo leer el estado comprimido'}); }
  });
  req.on('error', () => res.status(400).json({error:'Error de transmisión'}));
});
app.use((req, res, next) => req._yaLeido ? next() : express.json({limit:'64mb'})(req, res, next));
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.use(express.static(PUB_DIR));
app.use('/uploads', auth, express.static(UPL_DIR));

inicializarUsuarios();

// ════════════════════════════════════════════════════════════
// RUTAS DE AUTENTICACIÓN
// ════════════════════════════════════════════════════════════
app.post('/api/auth/login', (req, res) => {
  const {usuario, clave} = req.body;
  if(!usuario || !clave) return res.status(400).json({error:'Datos incompletos'});
  if(!limitarLogin(usuario))
    return res.status(429).json({error:'Demasiados intentos con este usuario. Espera unos minutos.'});
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.usuario === usuario && x.activo !== false);
  if(!u || !bcrypt.compareSync(clave, u.clave))
    return res.status(401).json({error:'Usuario o clave incorrectos'});
  _intentosLogin.delete(usuario);
  const {sesion, cruda} = crearSesion(u, req);
  emitirCookiesSesion(res, u, sesion.id, cruda);
  res.json({ok:true, id:u.id, nombre:u.nombre, rol:u.rol, usuario:u.usuario, permisos:u.permisos||null,
    debeCambiarClave: !!u.debeCambiarClave});
});

/* Lista para el desplegable de la pantalla de acceso.
   Devuelve solo nombre y usuario: ni el rol ni el PIN salen de aquí.
   Quien ve esta lista todavía necesita el PIN correcto para entrar. */
app.get('/api/auth/lista', (req, res) => {
  const usuarios = (leerDB('usuarios') || [])
    .filter(u => u.activo !== false)
    .map(u => ({ usuario: u.usuario, nombre: u.nombre }));
  res.json(usuarios);
});

/* Límite de intentos por USUARIO (no por IP): compartido entre el login por
   clave y el login por PIN, para que probar una cuenta por un método no sirva
   para esquivar el límite del otro. Por usuario y no por IP para que un
   intento fallido en recepción no bloquee al resto del personal. */
const _intentosLogin = new Map();
function limitarLogin(usuario){
  const ahora = Date.now(), ventana = 10*60*1000;   // 10 minutos
  const reg = _intentosLogin.get(usuario) || {n:0, desde:ahora};
  if(ahora - reg.desde > ventana){ reg.n = 0; reg.desde = ahora; }
  reg.n++;
  _intentosLogin.set(usuario, reg);
  if(_intentosLogin.size > 500){
    for(const [k,v] of _intentosLogin) if(ahora - v.desde > ventana) _intentosLogin.delete(k);
  }
  return reg.n <= 6;
}
/* Igual patrón que limitarLogin(), por IP: /api/auth/refresh no manda usuario
   en el cuerpo. El límite es generoso a propósito — apiFetch() del frontend
   lo llama automáticamente cada vez que vence el token de acceso, y varias
   personas del laboratorio pueden compartir la misma IP saliente. */
const _intentosRefresco = new Map();
function limitarRefresco(ip){
  const ahora = Date.now(), ventana = 10*60*1000;
  const reg = _intentosRefresco.get(ip) || {n:0, desde:ahora};
  if(ahora - reg.desde > ventana){ reg.n = 0; reg.desde = ahora; }
  reg.n++;
  _intentosRefresco.set(ip, reg);
  if(_intentosRefresco.size > 2000){
    for(const [k,v] of _intentosRefresco) if(ahora - v.desde > ventana) _intentosRefresco.delete(k);
  }
  return reg.n <= 60;
}
app.post('/api/auth/pin', (req, res) => {
  const {usuario, pin} = req.body || {};
  if(!usuario || !pin) return res.status(400).json({error:'Falta el usuario o el PIN'});
  if(!limitarLogin(usuario))
    return res.status(429).json({error:'Demasiados intentos con este usuario. Espera unos minutos.'});
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.usuario === usuario && x.activo !== false);
  // Mismo mensaje si el usuario no existe o el PIN no coincide
  if(!u || !u.pin || !bcrypt.compareSync(String(pin), u.pin))
    return res.status(401).json({error:'PIN incorrecto'});
  _intentosLogin.delete(usuario);
  const {sesion, cruda} = crearSesion(u, req);
  emitirCookiesSesion(res, u, sesion.id, cruda);
  res.json({ok:true, id:u.id, nombre:u.nombre, rol:u.rol, usuario:u.usuario, permisos:u.permisos||null,
    debeCambiarClave: !!u.debeCambiarClave});
});

/* Renovar la sesión sin volver a pedir clave/PIN. Recibe el token de
   renovación por cookie (nunca por cuerpo/JS visible) y, si es válido, emite
   un access token nuevo y ROTA el de renovación (mismo id de sesión, huella
   nueva). Deliberadamente SIN el middleware auth: el access token puede ya
   estar vencido, es justo el caso que esta ruta existe para resolver. */
app.post('/api/auth/refresh', (req, res) => {
  const ip = ipDe(req);
  if(!limitarRefresco(ip))
    return res.status(429).json({error:'Demasiados intentos de renovar la sesión. Espera unos minutos.'});
  const cruda = req.cookies?.refresh;
  const hallazgo = buscarPorToken(cruda);
  const limpiarYRechazar = () => {
    res.clearCookie('token'); res.clearCookie('refresh', {path:'/api/auth'});
    return res.status(401).json({error:'Sesión expirada, inicia sesión de nuevo'});
  };
  if(!hallazgo) return limpiarYRechazar();
  if(hallazgo.reutilizado){
    // Token de renovación ya reemplazado por uno más nuevo: señal de que
    // alguien más tiene una copia. Se cierran TODAS las sesiones de esta
    // persona, no solo esta, y se avisa con el mismo mensaje genérico.
    revocarTodasSesionesDeUsuario(hallazgo.sesion.usuarioId, 'reuso_detectado');
    res.clearCookie('token'); res.clearCookie('refresh', {path:'/api/auth'});
    return res.status(401).json({error:'Se detectó un uso inusual de tu sesión. Por seguridad, se cerraron todas tus sesiones activas. Inicia sesión de nuevo.'});
  }
  if(!sesionValida(hallazgo.sesion)) return limpiarYRechazar();
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.id === hallazgo.sesion.usuarioId && x.activo !== false);
  if(!u) return limpiarYRechazar();
  const nuevaCruda = rotarSesion(hallazgo.sesion, req);
  emitirCookiesSesion(res, u, hallazgo.sesion.id, nuevaCruda);
  res.json({ok:true, id:u.id, nombre:u.nombre, rol:u.rol, usuario:u.usuario, permisos:u.permisos||null,
    debeCambiarClave: !!u.debeCambiarClave});
});

/* Permisos propios de una persona. Un objeto vacío o null significa
   "usa los que trae su rol". */
const PERMISOS_VALIDOS = ['capturar','validar','pacientes','ordenes','cobrar',
  'contabilidad','examenes','calidad','almacen','config','usuarios'];

app.post('/api/usuarios/:id/permisos', auth, soloAdmin, (req, res) => {
  const {permisos} = req.body || {};
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.id === req.params.id);
  if(!u) return res.status(404).json({error:'Usuario no encontrado'});

  if(permisos === null || permisos === undefined){
    delete u.permisos;                       // vuelve a los del rol
  }else{
    const limpio = {};
    PERMISOS_VALIDOS.forEach(p => { if(p in permisos) limpio[p] = !!permisos[p]; });
    // El laboratorio no puede quedarse sin nadie que administre el sistema
    if(limpio.usuarios === false){
      const otros = usuarios.filter(x => x.id !== u.id && x.activo !== false)
        .filter(x => x.permisos ? x.permisos.usuarios !== false : x.rol === 'Admin');
      if(!otros.length)
        return res.status(400).json({error:'Debe quedar alguien que pueda gestionar usuarios.'});
    }
    u.permisos = limpio;
  }
  escribirDB('usuarios', usuarios);
  res.json({ok:true, permisos: u.permisos || null});
});

/* Definir o cambiar el PIN de un usuario */
app.post('/api/usuarios/:id/pin', auth, (req, res) => {
  const {pin} = req.body || {};
  // Cada quien puede cambiar el suyo; el Admin puede cambiar el de cualquiera
  const esPropio = req.params.id === req.user.id;
  const esAdmin  = req.user.rol === 'Admin';
  if(!esPropio && !esAdmin)
    return res.status(403).json({error:'Solo puedes cambiar tu propio PIN'});
  if(pin && !/^\d{4,8}$/.test(String(pin)))
    return res.status(400).json({error:'El PIN debe tener entre 4 y 8 dígitos'});
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.id === req.params.id);
  if(!u) return res.status(404).json({error:'Usuario no encontrado'});
  u.pin = pin ? bcrypt.hashSync(String(pin), 10) : null;   // sin pin = solo contraseña
  escribirDB('usuarios', usuarios);
  res.json({ok:true, tienePin: !!u.pin});
});

app.post('/api/auth/logout', (req, res) => {
  revocarSesionPorToken(req.cookies?.refresh, 'usuario');
  res.clearCookie('token');
  res.clearCookie('refresh', {path:'/api/auth'});
  res.json({ok:true});
});

app.get('/api/auth/me', auth, (req, res) => {
  // debeCambiarClave se busca fresco en la base (no viaja en el JWT): así,
  // si un Admin resetea la clave de alguien, esa persona queda obligada a
  // cambiarla en su siguiente consulta, sin esperar a que su token de
  // acceso actual (hasta 15 min de vida) venza y se renueve.
  const u = (leerDB('usuarios')||[]).find(x => x.id === req.user.id);
  res.json({id:req.user.id, nombre:req.user.nombre, rol:req.user.rol, usuario:req.user.usuario,
    permisos:req.user.permisos||null, debeCambiarClave: !!(u && u.debeCambiarClave)});
});

app.post('/api/auth/cambiar-clave', auth, (req, res) => {
  const {claveActual, claveNueva} = req.body;
  if(!claveNueva || claveNueva.length < 6)
    return res.status(400).json({error:'La clave nueva debe tener al menos 6 caracteres'});
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.id === req.user.id);
  if(!u || !bcrypt.compareSync(claveActual, u.clave))
    return res.status(401).json({error:'La clave actual es incorrecta'});
  u.clave = bcrypt.hashSync(claveNueva, 10);
  u.debeCambiarClave = false;
  escribirDB('usuarios', usuarios);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════════════
// GESTIÓN DE USUARIOS (solo Admin)
// ════════════════════════════════════════════════════════════
app.get('/api/usuarios', auth, soloAdmin, (req, res) => {
  const usuarios = (leerDB('usuarios') || [])
    .map(({clave, pin, ...u}) => ({...u, tienePin: !!pin, debeCambiarClave: !!u.debeCambiarClave}));   // permisos sí viajan: el Admin los edita
  res.json(usuarios);
});

app.post('/api/usuarios', auth, soloAdmin, (req, res) => {
  const {nombre, usuario, clave, rol} = req.body;
  if(!nombre || !usuario || !clave) return res.status(400).json({error:'Datos incompletos'});
  if(clave.length < 6) return res.status(400).json({error:'La clave debe tener al menos 6 caracteres'});
  const usuarios = leerDB('usuarios') || [];
  if(usuarios.some(u => u.usuario === usuario))
    return res.status(409).json({error:'El nombre de usuario ya existe'});
  const nuevo = {
    id     : 'usr-'+Date.now().toString(36),
    nombre, usuario,
    clave  : bcrypt.hashSync(clave, 10),
    pin    : (req.body.pin && /^\d{4,8}$/.test(String(req.body.pin)))
             ? bcrypt.hashSync(String(req.body.pin), 10) : null,
    rol    : ['Admin','Dr','Administrador','Técnico'].includes(rol) ? rol : 'Técnico',
    activo : true,
    creado : new Date().toISOString(),
    // La contraseña la elige quien da de alta a la persona, no ella misma:
    // se le exige cambiarla en su primer ingreso.
    debeCambiarClave: true,
  };
  usuarios.push(nuevo);
  escribirDB('usuarios', usuarios);
  // Ni la clave ni el PIN salen del servidor, ni siquiera cifrados
  const {clave:_, pin:__, ...publico} = nuevo;
  res.json({...publico, tienePin: !!nuevo.pin});
});

app.put('/api/usuarios/:id', auth, soloAdmin, (req, res) => {
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.id === req.params.id);
  if(!u) return res.status(404).json({error:'Usuario no encontrado'});
  const {nombre, rol, activo, clave} = req.body;
  // El laboratorio no puede quedarse sin nadie que administre el sistema
  const quitaAdmin = u.rol === 'Admin' && ((rol && rol !== 'Admin') || activo === false);
  if(quitaAdmin && usuarios.filter(x => x.rol === 'Admin' && x.activo !== false).length <= 1)
    return res.status(400).json({error:'Debe quedar al menos un usuario con rol Admin. Crea otro antes de cambiar este.'});
  if(clave && clave.length < 6)
    return res.status(400).json({error:'La clave debe tener al menos 6 caracteres'});
  if(nombre) u.nombre = nombre;
  if(rol)    u.rol    = rol;
  if(activo !== undefined) u.activo = activo;
  if(clave){ u.clave = bcrypt.hashSync(clave, 10); u.debeCambiarClave = true; }
  escribirDB('usuarios', usuarios);
  const {clave:_, pin:__, ...publico} = u;
  res.json({...publico, tienePin: !!u.pin});
});

app.delete('/api/usuarios/:id', auth, soloAdmin, (req, res) => {
  if(req.params.id === req.user.id) return res.status(400).json({error:'No puedes eliminarte a ti mismo'});
  const todos = leerDB('usuarios') || [];
  const victima = todos.find(x => x.id === req.params.id);
  if(victima && victima.rol === 'Admin' &&
     todos.filter(x => x.rol === 'Admin' && x.activo !== false).length <= 1)
    return res.status(400).json({error:'Es el único usuario con rol Admin. Crea otro antes de eliminarlo.'});
  const usuarios = (leerDB('usuarios') || []).filter(x => x.id !== req.params.id);
  escribirDB('usuarios', usuarios);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════════════
// SESIONES ACTIVAS
// ════════════════════════════════════════════════════════════
/* Nota de diseño: revocar una sesión aquí solo bloquea su PRÓXIMO refresh —
   el access token que ese dispositivo ya tiene sigue sirviendo hasta que
   venza por sí solo (≤ACCESO_TTL). Un kill instantáneo exigiría consultar
   esta lista en cada request autenticado, justo lo que un access token
   corto y sin estado evita. */
app.get('/api/auth/sesiones', auth, soloAdmin, (req, res) => {
  const usuarios = leerDB('usuarios') || [];
  const sesiones = (leerDB('sesiones') || []).filter(sesionValida);
  res.json(sesiones
    .sort((a,b) => b.ultimoUso.localeCompare(a.ultimoUso))
    .map(s => {
      const u = usuarios.find(x => x.id === s.usuarioId);
      return {
        id: s.id, usuarioId: s.usuarioId,
        usuarioNombre: u ? u.nombre : '(usuario eliminado)',
        usuario: u ? u.usuario : '', rol: u ? u.rol : '',
        creado: s.creado, ultimoUso: s.ultimoUso, expira: s.expira,
        ip: s.ip, userAgent: s.userAgent,
        actual: s.id === req.user.sid,
      };
    }));
});
app.delete('/api/auth/sesiones/:id', auth, (req, res) => {
  const sesiones = leerDB('sesiones') || [];
  const s = sesiones.find(x => x.id === req.params.id && !x.revocada);
  if(!s) return res.status(404).json({error:'Sesión no encontrada'});
  const esPropia = s.usuarioId === req.user.id;
  if(!esPropia && !puedeGestionarUsuarios(req.user))
    return res.status(403).json({error:'No puedes cerrar la sesión de otra persona'});
  revocarSesionPorId(s.id, esPropia ? 'usuario' : ('admin:'+req.user.id));
  res.json({ok:true});
});

// ════════════════════════════════════════════════════════════
// ESTADO DEL LIS (sincronización completa)
// ════════════════════════════════════════════════════════════

// Leer el estado del LIS
app.get('/api/estado', auth, (req, res) => {
  const estado = leerDB('estado');
  if(!estado) return res.json(null);
  res.json(estado);
});

// Guardar el estado del LIS (envía el JSON completo)
app.post('/api/estado', auth, (req, res) => {
  const {estado, ts} = req.body;
  if(!estado) return res.status(400).json({error:'Estado vacío'});
  // Control de conflictos: solo se acepta si el timestamp es igual o mayor
  const actual = leerDB('estado');
  if(actual && actual._ts && ts && ts < actual._ts)
    return res.status(409).json({error:'Conflicto: hay una versión más nueva en el servidor', estado:actual});
  estado._ts  = Date.now();
  estado._por = req.user.nombre;
  escribirDB('estado', estado);
  respaldoDiario(estado);
  res.json({ok:true, ts:estado._ts});
});

// Sincronizar: el cliente envía su timestamp, el servidor responde con el estado
// si el servidor tiene uno más nuevo
app.get('/api/estado/ts', auth, (req, res) => {
  const estado = leerDB('estado');
  res.json({ts: estado?._ts || 0});
});

/* ════════════════════════════════════════════════════════════
   SINCRONIZACIÓN POR REGISTRO (delta)
   ════════════════════════════════════════════════════════════
   POST /api/estado guarda el documento ENTERO y resuelve los choques por
   marca de tiempo: si dos personas guardaban casi a la vez, la segunda se
   topaba con un 409 y tenía que elegir entre descargar lo del servidor
   —perdiendo su trabajo— o insistir. Con una recepcionista abriendo órdenes
   mientras el microbiólogo valida, eso pasa todos los días, y quien elige no
   tiene forma de saber qué está perdiendo.

   Aquí el cliente manda SOLO los registros que tocó. El servidor los mezcla
   uno por uno sobre su propia copia, identificándolos por su clave. Dos
   personas trabajando sobre registros distintos ya no chocan: cada una
   aporta lo suyo y ambas cosas quedan. Solo dos ediciones de la MISMA orden
   compiten, y ahí gana la última, que es lo razonable.

   El handler es deliberadamente SÍNCRONO de principio a fin: Node atiende
   una petición a la vez en el hilo principal, así que leer, mezclar y
   escribir sin ningún await es atómico. Meter un await en medio abriría la
   puerta a que dos mezclas se pisen. */
const COLECCIONES = {
  pacientes:          {ruta:['pacientes'],           clave:'codigo'},
  examenes:           {ruta:['examenes'],            clave:'id'},
  perfiles:           {ruta:['perfiles'],            clave:'id'},
  medicos:            {ruta:['medicos'],             clave:'id'},
  cotizaciones:       {ruta:['cotizaciones'],        clave:'numero'},
  citas:              {ruta:['citas'],               clave:'id'},
  cortes:             {ruta:['cortes'],              clave:'numero'},
  ordenes:            {ruta:['ordenes'],             clave:'numero'},
  recibos:            {ruta:['recibos'],             clave:'numero'},
  facturas:           {ruta:['facturas'],            clave:'numero'},
  movimientos:        {ruta:['movimientos'],         clave:'id'},
  'almacen.insumos':  {ruta:['almacen','insumos'],   clave:'id'},
  'almacen.movs':     {ruta:['almacen','movs'],      clave:'id'},
  'cc.controles':     {ruta:['cc','controles'],      clave:'id'},
  'cc.datos':         {ruta:['cc','datos'],          clave:'id'},
  'sgc.documentos':   {ruta:['sgc','documentos'],    clave:'id'},
  'sgc.nc':           {ruta:['sgc','nc'],            clave:'id'},
  'sgc.personal':     {ruta:['sgc','personal'],      clave:'id'},
  'sgc.equipos':      {ruta:['sgc','equipos'],       clave:'id'},
  'sgc.riesgos':      {ruta:['sgc','riesgos'],       clave:'id'},
  'sgc.revisiones':   {ruta:['sgc','revisiones'],    clave:'id'},
  // La bitácora es un registro de solo-añadir: no tiene identificador propio,
  // así que se reconoce por su contenido para no duplicar una misma entrada
  // si el envío se reintenta.
  bitacora:           {ruta:['bitacora'],            clave:null},
};
// usuarios: cuentas de acceso LOCAL ya retiradas, con el PIN en texto plano.
// Viaja para que el vaciado que hace la migracion llegue de verdad al estado
// guardado. Los usuarios reales del sistema no viven aqui, sino en su propia
// coleccion (/api/usuarios).
const SINGLETONES = ['config','caja','meta','usuarios'];
function claveBitacora(b){
  return [b.fecha,b.hora,b.responsable,b.tipo,b.descripcion].join('');
}
function claveDe(col, reg){
  return COLECCIONES[col].clave ? reg[COLECCIONES[col].clave] : claveBitacora(reg);
}
// Devuelve el arreglo de una colección dentro del estado, creándolo si falta.
function arregloDe(estado, col){
  const ruta = COLECCIONES[col].ruta;
  let nodo = estado;
  for(let i=0;i<ruta.length-1;i++){
    if(!nodo[ruta[i]] || typeof nodo[ruta[i]]!=='object') nodo[ruta[i]] = {};
    nodo = nodo[ruta[i]];
  }
  const ultima = ruta[ruta.length-1];
  if(!Array.isArray(nodo[ultima])) nodo[ultima] = [];
  return nodo[ultima];
}
app.post('/api/estado/delta', auth, (req, res) => {
  const {cambios={}, borrados={}, singletones={}, seq={}, base} = req.body || {};
  const estado = leerDB('estado');
  if(!estado) return res.status(409).json({error:'SIN_BASE',
    detalle:'El servidor todavía no tiene un estado; envía el estado completo por /api/estado primero.'});
  // Si el cliente venía de una copia anterior a la del servidor, igual se
  // aceptan sus registros: mezclarlos no pisa nada de nadie más. `base` solo
  // se devuelve para que el cliente sepa si conviene bajar el resto.
  const servidorMasNuevo = !!(estado._ts && base && base < estado._ts);

  let aplicados = 0, quitados = 0;
  for(const col of Object.keys(cambios)){
    if(!COLECCIONES[col] || !Array.isArray(cambios[col])) continue;
    const lista = arregloDe(estado, col);
    const indice = new Map();
    lista.forEach((r,i) => indice.set(String(claveDe(col,r)), i));
    for(const reg of cambios[col]){
      const k = String(claveDe(col, reg));
      if(k==='undefined' || k==='null') continue;   // registro sin clave: no se puede mezclar
      const i = indice.get(k);
      if(i===undefined){ indice.set(k, lista.length); lista.push(reg); }
      else lista[i] = reg;
      aplicados++;
    }
  }
  for(const col of Object.keys(borrados)){
    if(!COLECCIONES[col] || !Array.isArray(borrados[col])) continue;
    const fuera = new Set(borrados[col].map(String));
    if(!fuera.size) continue;
    const lista = arregloDe(estado, col);
    const quedan = lista.filter(r => !fuera.has(String(claveDe(col,r))));
    quitados += lista.length - quedan.length;
    lista.length = 0; quedan.forEach(r => lista.push(r));
  }
  for(const s of SINGLETONES)
    if(singletones[s] && typeof singletones[s]==='object') estado[s] = singletones[s];
  /* Los contadores se mezclan por el MÁXIMO, nunca por el último que llegó:
     si dos equipos avanzaron el suyo por su cuenta, quedarse con el menor
     repetiría un número de paciente o de orden ya usado. */
  if(seq && typeof seq==='object'){
    if(!estado.seq || typeof estado.seq!=='object') estado.seq = {};
    for(const k of Object.keys(seq)){
      const n = Number(seq[k]);
      if(Number.isFinite(n)) estado.seq[k] = Math.max(Number(estado.seq[k])||0, n);
    }
  }

  estado._ts  = Date.now();
  estado._por = req.user.nombre;
  escribirDB('estado', estado);
  respaldoDiario(estado);
  res.json({ok:true, ts:estado._ts, aplicados, quitados, servidorMasNuevo});
});

// ════════════════════════════════════════════════════════════
// DOCUMENTOS FISCALES: FACTURAS Y RECIBOS (correlativo atómico)
// ════════════════════════════════════════════════════════════
/* El resto del estado del LIS (pacientes, órdenes, resultados…) se
   sincroniza como un solo bloque en /api/estado, con un control de
   conflictos por timestamp que es correcto para eso: si dos personas
   editan casi a la vez, se acepta el último y punto.

   El NÚMERO de una factura (o de un recibo con C.A.I. propio) no puede
   tratarse así. La SAR exige que el correlativo autorizado por un C.A.I.
   nunca se salte ni se repita — y con la sincronización de "todo el
   estado", dos personas emitiendo casi al mismo tiempo desde equipos
   distintos pueden terminar con el MISMO número calculado en su propio
   navegador (ambos partieron del mismo S.seq.fac todavía no sincronizado),
   o peor: una de las dos, al perder el conflicto de sincronización, ve
   desaparecer en silencio una factura que ya imprimió y entregó, con un
   número que quedó reservado en el papel pero sin ningún registro.

   Por eso emitir/anular un documento fiscal y ajustar su correlativo
   pasan por estos tres endpoints, que hacen TODO su trabajo —leer el
   estado, decidir el número, escribirlo— dentro de un solo bloque
   síncrono, sin ningún await de por medio. Node.js ejecuta un handler de
   ruta hasta el primer punto de espera asíncrona antes de atender la
   siguiente petición; sin await no hay dónde intercalarse, así que dos
   peticiones que lleguen "al mismo tiempo" de todas formas se procesan
   una completa y luego la otra — nunca a medias entre sí. Es la misma
   garantía que ya usa escribirDB() para no dejar el archivo a medio
   escribir, aplicada ahora también a la LÓGICA de negocio, no solo al
   archivo. */

// Fecha/hora en el huso horario de Honduras — igual que ahoraHN() del
// cliente (lis/src/10_nucleo.js): así "venció el C.A.I." se decide con la
// fecha de Honduras sin importar en qué huso horario esté físicamente el
// servidor (Render corre en UTC).
const _fmtHN = new Intl.DateTimeFormat('en-CA', {timeZone:'America/Tegucigalpa',
  year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', hourCycle:'h23'});
function ahoraHN(){
  const p = _fmtHN.formatToParts(new Date());
  const g = t => (p.find(x => x.type===t)||{}).value || '';
  return {fecha: g('year')+'-'+g('month')+'-'+g('day'), hora: g('hour')+':'+g('minute')};
}

function emitirFactura(datos, usuario){
  const estado = leerDB('estado');
  if(!estado) return {status:409, body:{error:'No se pudo leer el estado del servidor'}};
  const c = estado.config || {};
  if(!c.facCAI || !c.facSerie || !c.facDesde || !c.facHasta)
    return {status:409, body:{error:'Configura el C.A.I. de la Factura en Configuración antes de emitir'}};
  const {fecha, hora} = ahoraHN();
  if(c.facLimite && fecha > c.facLimite)
    return {status:409, body:{error:'El rango autorizado venció el '+c.facLimite+'. Solicita uno nuevo a la SAR.'}};
  const seqActual = estado.seq.fac || c.facDesde;
  if(seqActual > c.facHasta)
    return {status:409, body:{error:'Se agotó el rango autorizado de facturas. Solicita un nuevo rango a la SAR (SAR-927).'}};
  const numero = c.facSerie + String(seqActual).padStart(8,'0');
  const factura = {...datos, numero, fecha, hora, cai:c.facCAI,
    emitidoPor:usuario.nombre, anulado:false, motivoAnulacion:''};
  estado.facturas = estado.facturas || [];
  estado.facturas.push(factura);
  estado.seq.fac = seqActual + 1;
  estado._ts = Date.now();
  estado._por = usuario.nombre;
  escribirDB('estado', estado);
  respaldoDiario(estado);
  return {status:200, body:{ok:true, factura, seqFac:estado.seq.fac}};
}
app.post('/api/facturas', auth, (req, res) => {
  const r = emitirFactura(req.body||{}, req.user);
  res.status(r.status).json(r.body);
});

function anularFactura(numero, motivo, usuario){
  const estado = leerDB('estado');
  if(!estado) return {status:409, body:{error:'No se pudo leer el estado del servidor'}};
  if(usuario.rol !== 'Admin') return {status:403, body:{error:'Solo un Admin puede anular una factura'}};
  const f = (estado.facturas||[]).find(x => x.numero===numero);
  if(!f) return {status:404, body:{error:'Factura no encontrada'}};
  if(f.anulado) return {status:409, body:{error:'Esa factura ya estaba anulada'}};
  if(!motivo || !motivo.trim()) return {status:400, body:{error:'Se requiere un motivo para anular'}};
  const {fecha, hora} = ahoraHN();
  f.anulado = true; f.motivoAnulacion = motivo.trim();
  f.fechaAnulacion = fecha; f.horaAnulacion = hora;
  estado._ts = Date.now();
  estado._por = usuario.nombre;
  escribirDB('estado', estado);
  respaldoDiario(estado);
  return {status:200, body:{ok:true, factura:f}};
}
app.post('/api/facturas/:numero/anular', auth, (req, res) => {
  const r = anularFactura(req.params.numero, (req.body||{}).motivo, req.user);
  res.status(r.status).json(r.body);
});

/* Ajustar el correlativo a mano — para migrar facturas ya emitidas en
   otro sistema autoimpresor (el próximo número debe continuar donde se
   quedó el otro sistema, no repetir), o para corregir el contador si
   alguna vez queda desalineado. Nunca se permite un valor que ya esté en
   uso: el mínimo aceptado es uno más que el número más alto que ya exista
   en S.facturas, para que ajustar el correlativo no pueda, él mismo,
   crear un duplicado futuro. */
function ajustarCorrelativoFactura(nuevoValor, motivo, usuario){
  const estado = leerDB('estado');
  if(!estado) return {status:409, body:{error:'No se pudo leer el estado del servidor'}};
  if(usuario.rol !== 'Admin') return {status:403, body:{error:'Solo un Admin puede ajustar el correlativo'}};
  if(!motivo || !motivo.trim()) return {status:400, body:{error:'Se requiere un motivo para ajustar el correlativo'}};
  const c = estado.config || {};
  const n = Number(nuevoValor);
  if(!Number.isInteger(n) || n < 1) return {status:400, body:{error:'El número debe ser un entero positivo'}};
  if(c.facDesde && n < c.facDesde)
    return {status:400, body:{error:'No puede ser menor que el inicio del rango autorizado ('+c.facDesde+')'}};
  if(c.facHasta && n > c.facHasta + 1)
    return {status:400, body:{error:'No puede superar el final del rango autorizado + 1 ('+(c.facHasta+1)+')'}};
  const maxUsado = (estado.facturas||[]).reduce((m,f) => {
    const suf = String(f.numero||'').slice(-8);
    const v = /^\d{8}$/.test(suf) ? Number(suf) : 0;
    return Math.max(m, v);
  }, 0);
  if(n <= maxUsado)
    return {status:400, body:{error:'Ese número ya está en uso (la última factura registrada usa el '+maxUsado+'). Debe ser mayor.'}};
  const anterior = estado.seq.fac || c.facDesde || 1;
  estado.seq.fac = n;
  estado.bitacora = estado.bitacora || [];
  const {fecha, hora} = ahoraHN();
  estado.bitacora.push({fecha, hora, responsable:usuario.nombre, tipo:'No conformidad',
    descripcion:'Ajuste manual del correlativo de Facturas: de '+anterior+' a '+n+'. Motivo: '+motivo.trim()});
  estado._ts = Date.now();
  estado._por = usuario.nombre;
  escribirDB('estado', estado);
  respaldoDiario(estado);
  return {status:200, body:{ok:true, seqFac:n}};
}
app.post('/api/facturas/ajustar-correlativo', auth, (req, res) => {
  const {nuevoValor, motivo} = req.body||{};
  const r = ajustarCorrelativoFactura(nuevoValor, motivo, req.user);
  res.status(r.status).json(r.body);
});

/* ---- Mismo mecanismo para Recibos de Venta -----------------------------
   El Recibo puede o no tener su propio C.A.I. (opcional, 60_config.js:
   "C.A.I. del Recibo"). Si lo tiene, numera con esa serie igual que la
   Factura (pero sin el chequeo de rango agotado: ese C.A.I. legado guarda
   el rango como texto libre, no como desde/hasta numéricos). Si no lo
   tiene, numera con el prefijo interno RV-AAAA-NNNN de siempre — sin
   relación con la SAR, pero igual de expuesto a la misma carrera entre
   dos personas emitiendo a la vez, así que igual pasa por aquí. */
function emitirRecibo(datos, usuario){
  const estado = leerDB('estado');
  if(!estado) return {status:409, body:{error:'No se pudo leer el estado del servidor'}};
  const c = estado.config || {};
  const {fecha, hora} = ahoraHN();
  if(c.facturaSerie && c.facturaLimite && fecha > c.facturaLimite)
    return {status:409, body:{error:'El C.A.I. del Recibo venció el '+c.facturaLimite+'. Solicita uno nuevo a la SAR.'}};
  const seqActual = estado.seq.rec || 1;
  const numero = c.facturaSerie
    ? c.facturaSerie + String(seqActual).padStart(8,'0')
    : (c.reciboPrefijo||'RV')+'-'+fecha.slice(0,4)+'-'+String(seqActual).padStart(4,'0');
  const recibo = {...datos, numero, fecha, hora, emitidoPor:usuario.nombre, anulado:false, motivoAnulacion:''};
  estado.recibos = estado.recibos || [];
  estado.recibos.push(recibo);
  estado.seq.rec = seqActual + 1;
  estado._ts = Date.now();
  estado._por = usuario.nombre;
  escribirDB('estado', estado);
  respaldoDiario(estado);
  return {status:200, body:{ok:true, recibo, seqRec:estado.seq.rec}};
}
app.post('/api/recibos', auth, (req, res) => {
  const r = emitirRecibo(req.body||{}, req.user);
  res.status(r.status).json(r.body);
});

function anularRecibo(numero, motivo, usuario){
  const estado = leerDB('estado');
  if(!estado) return {status:409, body:{error:'No se pudo leer el estado del servidor'}};
  if(usuario.rol !== 'Admin') return {status:403, body:{error:'Solo un Admin puede anular un recibo'}};
  const r = (estado.recibos||[]).find(x => x.numero===numero);
  if(!r) return {status:404, body:{error:'Recibo no encontrado'}};
  if(r.anulado) return {status:409, body:{error:'Ese recibo ya estaba anulado'}};
  if(!motivo || !motivo.trim()) return {status:400, body:{error:'Se requiere un motivo para anular'}};
  const {fecha, hora} = ahoraHN();
  r.anulado = true; r.motivoAnulacion = motivo.trim();
  r.fechaAnulacion = fecha; r.horaAnulacion = hora;
  estado._ts = Date.now();
  estado._por = usuario.nombre;
  escribirDB('estado', estado);
  respaldoDiario(estado);
  return {status:200, body:{ok:true, recibo:r}};
}
app.post('/api/recibos/:numero/anular', auth, (req, res) => {
  const r = anularRecibo(req.params.numero, (req.body||{}).motivo, req.user);
  res.status(r.status).json(r.body);
});

function ajustarCorrelativoRecibo(nuevoValor, motivo, usuario){
  const estado = leerDB('estado');
  if(!estado) return {status:409, body:{error:'No se pudo leer el estado del servidor'}};
  if(usuario.rol !== 'Admin') return {status:403, body:{error:'Solo un Admin puede ajustar el correlativo'}};
  if(!motivo || !motivo.trim()) return {status:400, body:{error:'Se requiere un motivo para ajustar el correlativo'}};
  const n = Number(nuevoValor);
  if(!Number.isInteger(n) || n < 1) return {status:400, body:{error:'El número debe ser un entero positivo'}};
  const maxUsado = (estado.recibos||[]).reduce((m,r) => {
    const suf = String(r.numero||'').replace(/\D/g,'');
    const v = Number(suf.slice(-8))||0;
    return Math.max(m, v);
  }, 0);
  if(n <= maxUsado)
    return {status:400, body:{error:'Ese número ya está en uso (el último recibo registrado usa el '+maxUsado+'). Debe ser mayor.'}};
  const anterior = estado.seq.rec || 1;
  estado.seq.rec = n;
  estado.bitacora = estado.bitacora || [];
  const {fecha, hora} = ahoraHN();
  estado.bitacora.push({fecha, hora, responsable:usuario.nombre, tipo:'No conformidad',
    descripcion:'Ajuste manual del correlativo de Recibos: de '+anterior+' a '+n+'. Motivo: '+motivo.trim()});
  estado._ts = Date.now();
  estado._por = usuario.nombre;
  escribirDB('estado', estado);
  respaldoDiario(estado);
  return {status:200, body:{ok:true, seqRec:n}};
}
app.post('/api/recibos/ajustar-correlativo', auth, (req, res) => {
  const {nuevoValor, motivo} = req.body||{};
  const r = ajustarCorrelativoRecibo(nuevoValor, motivo, req.user);
  res.status(r.status).json(r.body);
});

// ════════════════════════════════════════════════════════════
// COTIZACIONES DEL PORTAL WEB (sin autenticación)
// ════════════════════════════════════════════════════════════
/* Sin límite, cualquiera podía mandar cotizaciones sin freno y llenar
   cola_cot.json con datos arbitrarios (spam / crecimiento de disco). */
const _intentosCotizacion = new Map();
function limitarCotizacion(ip){
  const ahora = Date.now(), ventana = 15*60*1000;
  const reg = _intentosCotizacion.get(ip) || {n:0, desde:ahora};
  if(ahora - reg.desde > ventana){ reg.n = 0; reg.desde = ahora; }
  reg.n++;
  _intentosCotizacion.set(ip, reg);
  if(_intentosCotizacion.size > 5000){
    for(const [k,v] of _intentosCotizacion) if(ahora - v.desde > ventana) _intentosCotizacion.delete(k);
  }
  return reg.n <= 10;
}
app.post('/api/cotizacion-publica', (req, res) => {
  if(!limitarCotizacion(ipDe(req)))
    return res.status(429).json({error:'Demasiadas solicitudes. Espera unos minutos e inténtalo de nuevo.'});
  const cot = req.body;
  if(!cot || !cot.numero || !cot.nombre)
    return res.status(400).json({error:'Datos incompletos'});
  // numCot() en cotizacion.html solo genera "COT-WEB-AAAAMMDD-HHMMSS": letras,
  // dígitos y guiones. Cualquier otra cosa aquí no es un número legítimo del
  // portal -- se rechaza para que nunca llegue a guardarse. Sin este filtro,
  // este campo se guardaba tal cual y el frontend lo mostraba sin escapar en
  // varios sitios (ver tablaCotizaciones() en index.html): quien mandara un
  // numero con HTML/JS incrustado lograba que corriera en la sesión de
  // cualquier persona del laboratorio que abriera Cotizaciones.
  if(!/^[A-Za-z0-9_-]{1,40}$/.test(cot.numero))
    return res.status(400).json({error:'Número de cotización inválido'});
  const cola = leerDB('cola_cot') || [];
  if(cola.some(c => c.numero === cot.numero))
    return res.json({ok:true, mensaje:'Ya recibida'});
  cola.push({...cot, recibida: new Date().toISOString()});
  escribirDB('cola_cot', cola);
  console.log(`[CDIM] Cotización web recibida: ${cot.numero} - ${cot.nombre}`);
  res.json({ok:true, numero:cot.numero});
});

app.get('/api/cotizaciones-web', auth, (req, res) => {
  const cola = leerDB('cola_cot') || [];
  res.json(cola);
});

app.delete('/api/cotizaciones-web/:numero', auth, (req, res) => {
  const cola = (leerDB('cola_cot') || []).filter(c => c.numero !== req.params.numero);
  escribirDB('cola_cot', cola);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════════════
// SUBIDA DE ARCHIVOS (comprobantes, resultados PDF)
// ════════════════════════════════════════════════════════════
app.post('/api/archivo', auth, upload.single('archivo'), (req, res) => {
  if(!req.file) return res.status(400).json({error:'Sin archivo'});
  const buf = Buffer.alloc(12);
  const fd = fs.openSync(req.file.path, 'r');
  fs.readSync(fd, buf, 0, 12, 0);
  fs.closeSync(fd);
  if(!firmaValida(buf, req.file.mimetype)){
    fs.unlink(req.file.path, ()=>{});
    return res.status(400).json({error:'El archivo no parece ser del tipo declarado'});
  }
  res.json({
    ok      : true,
    nombre  : req.file.originalname,
    ruta    : `/uploads/${req.file.filename}`,
    tipo    : req.file.mimetype,
    tamaño  : req.file.size,
  });
});

app.delete('/api/archivo/:nombre', auth, soloAdmin, (req, res) => {
  const f = path.join(UPL_DIR, path.basename(req.params.nombre));
  if(fs.existsSync(f)) fs.unlinkSync(f);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════════════
// RESULTADOS PARA PACIENTES (acceso con DNI, sin login)
// ════════════════════════════════════════════════════════════
/* Limitador de intentos: protege contra quien pruebe números de identidad
   uno tras otro. Cinco intentos fallidos por IP cada quince minutos.

   Ojo: /r/:numero/:token/pdf (más abajo) genera el PDF navegando por dentro
   del propio servidor a /r/:numero/:token, y esa página llama a
   /api/informe/:numero/:token -- que también pasa por este mismo limitador.
   Esas llamadas SIEMPRE llegan por loopback (127.0.0.1/::1): a través del
   proxy de Render, un pedido externo real nunca aparece con esa IP. Sin este
   descarte, cinco PDF generados (de CUALQUIER paciente, no solo uno) agotaban
   esta cuota compartida y todo el resto de la clínica se quedaba sin poder
   generar más PDFs ni consultar resultados durante 15 minutos -- un límite
   pensado para frenar a un atacante externo terminaba frenando el propio uso
   normal del sistema. */
const _intentos = new Map();
function limitarIntentos(ip){
  if(ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
  const ahora = Date.now(), ventana = 15*60*1000;
  const reg = _intentos.get(ip) || {n:0, desde:ahora};
  if(ahora - reg.desde > ventana){ reg.n = 0; reg.desde = ahora; }
  reg.n++;
  _intentos.set(ip, reg);
  // Limpieza periódica para que el mapa no crezca sin control
  if(_intentos.size > 5000){
    for(const [k,v] of _intentos) if(ahora - v.desde > ventana) _intentos.delete(k);
  }
  return reg.n <= 5;
}

/* Límite aparte para la descarga de PDF del informe: el de arriba (5 cada 15
   min) es para frenar a quien adivina números de identidad, y sería muy
   agresivo aplicárselo también aquí -- un paciente legítimo puede reabrir su
   propio PDF varias veces (reenviarlo a un familiar, a su médico, etc.) en
   pocos minutos. Este es más permisivo, pero sigue existiendo porque cada
   PDF cuesta abrir una página de Chromium -- sin tope, sería un vector fácil
   para agotar CPU/memoria del servidor. */
const _pdfIntentos = new Map();
function limitarPDF(ip){
  const ahora = Date.now(), ventana = 5*60*1000;
  const reg = _pdfIntentos.get(ip) || {n:0, desde:ahora};
  if(ahora - reg.desde > ventana){ reg.n = 0; reg.desde = ahora; }
  reg.n++;
  _pdfIntentos.set(ip, reg);
  if(_pdfIntentos.size > 5000){
    for(const [k,v] of _pdfIntentos) if(ahora - v.desde > ventana) _pdfIntentos.delete(k);
  }
  return reg.n <= 20;
}

/* ── Generación de PDF del informe del paciente (Chromium sin cabeza) ──
   Antes, "Guardar PDF" llamaba a window.print() y era el propio paciente
   quien, en el diálogo nativo del navegador, elegía "Guardar como PDF" --
   en el celular eso son varios toques por un menú que muchos no reconocen.
   Ahora el servidor genera el PDF él mismo con un Chromium invisible
   (Puppeteer) y lo manda ya armado: un toque, el navegador lo abre o lo
   descarga directo, sin ningún diálogo de por medio.

   Un solo navegador (Chromium) se mantiene abierto y se reutiliza entre
   pedidos -- abrir uno nuevo por cada PDF tarda segundos y gasta memoria de
   más; abrir solo una PÁGINA nueva por pedido (y cerrarla al terminar) es
   barato. Si el navegador se cae (o nunca llegó a abrir), _navegadorProm se
   limpia para que el siguiente pedido lo vuelva a intentar en vez de quedar
   fallando para siempre. */
let _navegadorProm = null;
function navegador(){
  if(!_navegadorProm){
    _navegadorProm = puppeteer.launch({
      headless: 'new',
      // Permite apuntar a un Chrome del sistema si hiciera falta (por
      // ejemplo, si el que trae Puppeteer no pudiera descargarse en el
      // entorno de despliegue) -- en el caso normal queda sin definir y usa
      // el Chromium que Puppeteer instala solo con `npm install`.
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
      args: ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage'],
    }).then(b => {
      b.on('disconnected', () => { _navegadorProm = null; });
      return b;
    }).catch(e => { _navegadorProm = null; throw e; });
  }
  return _navegadorProm;
}

/* Consulta de resultados por el paciente.
   Exige número de identidad Y fecha de nacimiento: el DNI por sí solo es
   predecible y no basta para proteger un dato clínico. */
app.post('/api/resultado', (req, res) => {
  const ip = ipDe(req);
  if(!limitarIntentos(ip))
    return res.status(429).json({error:'Demasiados intentos. Espera unos minutos e inténtalo de nuevo.'});

  const { dni: dniRaw, fnac } = req.body || {};
  if(!dniRaw || !fnac)
    return res.status(400).json({error:'Se necesitan el número de identidad y la fecha de nacimiento'});

  const estado = leerDB('estado');
  if(!estado) return res.status(404).json({error:'No hay resultados disponibles'});
  const dni = String(dniRaw).replace(/\D/g,'');
  const pac = (estado.pacientes||[]).find(p =>
    p.idNumero && p.idNumero.replace(/\D/g,'') === dni && p.fnac === fnac
  );
  // Mismo mensaje si el DNI no existe o la fecha no coincide:
  // así no se revela qué números de identidad están registrados.
  if(!pac) return res.status(404).json({error:'No encontramos resultados con esos datos'});
  // Solo órdenes validadas y entregadas del paciente
  const ordenes = (estado.ordenes||[]).filter(o =>
    o.pacCodigo === pac.codigo &&
    (o.estado === 'Validada' || o.estado === 'Entregada')
  ).map(o => ({
    numero     : o.numero,
    fecha      : o.fecha,
    estado     : o.estado,
    token      : o.token || null,        // permite abrir el informe completo
    examenes   : o.examenes.map(e => ({
      nombre   : e.nombre,
      area     : e.area,
      validado : e.validado,
      params   : e.params.map(p => ({
        nombre : p.nombre,
        valor  : p.valor,
        unidad : p.unidad,
        refMin : p.refMin,
        refMax : p.refMax,
      }))
    }))
  }));
  res.json({
    nombre  : pac.nombre,
    sexo    : pac.sexo || '',
    fnac    : pac.fnac || '',
    ordenes,
  });
});

/* Estado de las cotizaciones que envió el paciente desde el portal */
app.post('/api/mis-cotizaciones', (req, res) => {
  const ip = ipDe(req);
  if(!limitarIntentos(ip))
    return res.status(429).json({error:'Demasiados intentos. Espera unos minutos.'});
  const { dni: dniRaw } = req.body || {};
  if(!dniRaw) return res.status(400).json({error:'Falta el número de identidad'});
  const dni = String(dniRaw).replace(/\D/g,'');
  const estado = leerDB('estado') || {};
  const cola   = leerDB('cola_cot') || [];
  // Las que ya entraron al sistema del laboratorio
  const enSistema = (estado.cotizaciones||[])
    .filter(c => c.idNumero && c.idNumero.replace(/\D/g,'') === dni)
    .map(c => ({
      numero : c.numero,
      fecha  : c.fecha,
      total  : (c.items||[]).reduce((a,i)=>a+(i.precio||0)*(i.cantidad||1),0),
      items  : (c.items||[]).map(i=>i.nombre),
      estado : c.ot ? 'Aprobada · orden '+c.ot
             : c.estadoCot === 'Pendiente' ? 'En revisión'
             : 'Aprobada',
    }));
  // Las que aún están en la cola, sin revisar
  const enCola = cola
    .filter(c => c.idNumero && String(c.idNumero).replace(/\D/g,'') === dni)
    .filter(c => !enSistema.some(x => x.numero === c.numero))
    .map(c => ({
      numero : c.numero,
      fecha  : c.fecha,
      total  : c.total || 0,
      items  : (c.items||[]).map(i=>i.nombre),
      estado : 'Recibida',
    }));
  res.json([...enCola, ...enSistema].sort((a,b)=>b.fecha.localeCompare(a.fecha)));
});

/* Catálogo público de exámenes con precio, para el portal de cotización */
app.get('/api/catalogo', (req, res) => {
  const estado = leerDB('estado');
  if(!estado || !estado.examenes) return res.json([]);
  res.json(estado.examenes
    .filter(e => (e.precio||0) > 0)
    .map(e => ({ id:e.id, nombre:e.nombre, precio:e.precio, area:e.area, entrega:e.entrega||'' })));
});

// ════════════════════════════════════════════════════════════
// RESPALDOS (solo Administrador)
// ════════════════════════════════════════════════════════════

// Descargar el estado actual como archivo .json
app.get('/api/respaldo', auth, soloAdmin, (req, res) => {
  const estado = leerDB('estado');
  if(!estado) return res.status(404).json({error:'Sin datos que respaldar'});
  const fecha = new Date().toISOString().slice(0,10);
  res.setHeader('Content-Disposition', `attachment; filename="CDIM-respaldo-${fecha}.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(estado));
});

// Listar los respaldos diarios que hay en el servidor
app.get('/api/respaldos', auth, soloAdmin, (req, res) => {
  try{
    const archivos = fs.readdirSync(BAK_DIR)
      .filter(x => x.startsWith('estado-') && (x.endsWith('.json') || x.endsWith('.json.gz')))
      .sort().reverse()
      .map(x => {
        const st = fs.statSync(path.join(BAK_DIR, x));
        return { archivo:x, fecha:x.slice(7,17), tamaño:st.size,
                 comprimido:x.endsWith('.gz'), modificado:st.mtime };
      });
    res.json(archivos);
  }catch(e){ res.json([]); }
});

// Resguardo de última hora antes de sobrescribir con una restauración --
// cifrado y comprimido igual que respaldoDiario(), para no dejar tirada en
// disco una copia legible de los datos clínicos completos.
function respaldarAntesDeRestaurar(actual){
  if(!actual) return;
  fs.writeFileSync(path.join(BAK_DIR,'antes-de-restaurar.json.gz'),
    cifrar(zlib.gzipSync(JSON.stringify(actual))));
}

// Restaurar desde un respaldo del servidor
app.post('/api/respaldo/restaurar', auth, soloAdmin, (req, res) => {
  const { archivo } = req.body;
  if(!archivo || !/^estado-\d{4}-\d{2}-\d{2}\.json(\.gz)?$/.test(archivo))
    return res.status(400).json({error:'Nombre de archivo no válido'});
  const f = path.join(BAK_DIR, archivo);
  if(!fs.existsSync(f)) return res.status(404).json({error:'Ese respaldo no existe'});
  try{
    // Antes de restaurar se guarda el estado actual, por si acaso
    respaldarAntesDeRestaurar(leerDB('estado'));
    // Los respaldos nuevos vienen comprimidos (y cifrados si hay clave
    // configurada); descifrar() detecta sola cuál es el caso. Los muy
    // antiguos, de antes de esta función, se leen igual que siempre.
    const crudo = fs.readFileSync(f);
    const estado = JSON.parse(archivo.endsWith('.gz')
      ? zlib.gunzipSync(descifrar(crudo)).toString('utf8')
      : crudo.toString('utf8'));
    estado._ts = Date.now();
    estado._por = req.user.nombre + ' (restauración)';
    escribirDB('estado', estado);
    console.log(`[CDIM] Estado restaurado desde ${archivo} por ${req.user.nombre}`);
    res.json({ok:true, ts:estado._ts});
  }catch(e){ res.status(500).json({error:'No se pudo leer el respaldo: '+e.message}); }
});

/* Restaurar el archivo que uno se baja del almacenamiento externo.
   Sin esto, la copia de Backblaze era un archivo que la aplicación no sabía
   leer: va comprimida y cifrada, así que "Restaurar desde archivo" —que
   esperaba un .json plano— la rechazaba, y "Restaurar este" solo mira el disco
   del servidor, que es justo lo que se habría perdido. Es decir, en el único
   escenario para el que existe el respaldo externo, no servía.
   Acepta los tres formatos por su contenido, no por su nombre: el .json plano
   que descarga el botón de arriba, un .gz sin cifrar y el .json.gz cifrado. */
app.post('/api/respaldo/restaurar-archivo', auth, soloAdmin,
  express.raw({type:'*/*', limit:'64mb'}), (req, res) => {
  const crudo = req.body;
  if(!crudo || !crudo.length) return res.status(400).json({error:'Archivo vacío'});
  let estado;
  try{
    const esJson = crudo[0]===0x7b || crudo[0]===0x20 || crudo[0]===0x0a;   // '{'
    estado = JSON.parse(esJson ? crudo.toString('utf8')
                               : zlib.gunzipSync(descifrar(crudo)).toString('utf8'));
  }catch(e){
    return res.status(400).json({error:
      'No se pudo leer el archivo. Si viene del almacenamiento externo, se descifra con la '
      +'misma DATA_ENCRYPTION_KEY con la que se guardó: comprueba que sea la de este servidor. '
      +'('+e.message+')'});
  }
  if(!estado || !estado.pacientes)
    return res.status(400).json({error:'El archivo no parece un respaldo del LIS'});
  try{
    respaldarAntesDeRestaurar(leerDB('estado'));
    estado._ts = Date.now();
    estado._por = req.user.nombre + ' (restauración desde archivo externo)';
    escribirDB('estado', estado);
    console.log(`[CDIM] Estado restaurado desde archivo externo por ${req.user.nombre}`);
    res.json({ok:true, ts:estado._ts,
      pacientes:(estado.pacientes||[]).length, ordenes:(estado.ordenes||[]).length});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// Subir un respaldo desde la computadora y restaurarlo
app.post('/api/respaldo/subir', auth, soloAdmin, (req, res) => {
  const { estado } = req.body;
  if(!estado || !estado.pacientes) return res.status(400).json({error:'El archivo no parece un respaldo válido'});
  try{
    respaldarAntesDeRestaurar(leerDB('estado'));
    estado._ts = Date.now();
    estado._por = req.user.nombre + ' (restauración desde archivo)';
    escribirDB('estado', estado);
    console.log(`[CDIM] Estado restaurado desde archivo por ${req.user.nombre}`);
    res.json({ok:true, ts:estado._ts});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// Diagnóstico: dónde viven los datos y si el disco es persistente
app.get('/api/salud', auth, (req, res) => {
  const estado = leerDB('estado');
  let nRespaldos = 0;
  try{ nRespaldos = fs.readdirSync(BAK_DIR).filter(x=>x.startsWith('estado-')).length; }catch{}
  res.json({
    carpetaDatos : DATA_DIR,
    discoPersistente : !!process.env.DATA_DIR,
    pacientes : estado?.pacientes?.length || 0,
    ordenes   : estado?.ordenes?.length   || 0,
    ultimoGuardado : estado?._ts ? new Date(estado._ts).toISOString() : null,
    guardadoPor    : estado?._por || null,
    respaldosDiarios : nRespaldos,
    /* Copia fuera del servidor: lo que de verdad protege de que se pierda el
       disco. Si "activo" es false, los 30 respaldos viven solo aquí. */
    respaldoExterno : {
      activo    : respaldoExterno.activo,
      // Cuando está mal configurado, el motivo concreto: sin esto había que ir
      // a los logs del proveedor para saber qué variable estaba mal escrita.
      malConfigurado : S3_MOTIVO || null,
      destino   : respaldoExterno.activo ? `${S3.endpoint}/${S3.bucket}/${S3.prefijo}` : null,
      cadaMin   : respaldoExterno.activo ? S3.minutos : null,
      ultimoOk  : respaldoExterno.ultimoOk,
      ultimoError : respaldoExterno.ultimoError,
      subidas   : respaldoExterno.subidas,
    },
  });
});

/* Forzar una copia externa ahora mismo, sin esperar el intervalo. Sirve para
   comprobar la configuración recién puesta sin tener que esperar una hora, y
   para llevarse una copia antes de un cambio delicado. */
app.post('/api/respaldo-externo', auth, soloAdmin, async (req, res) => {
  if(!S3_LISTO) return res.status(400).json({ok:false,
    error:'El respaldo externo no está configurado. Faltan las variables RESPALDO_S3_*.'});
  const estado = leerDB('estado');
  if(!estado) return res.status(400).json({ok:false, error:'Todavía no hay estado que respaldar.'});
  const hoy = new Date().toISOString().slice(0,10);
  const contenido = cifrar(zlib.gzipSync(JSON.stringify(estado), {level:6}));
  try{
    await subirRespaldoExterno(`estado-${hoy}.json.gz`, contenido);
    respaldoExterno.ultimoOk = new Date().toISOString();
    respaldoExterno.ultimoError = null;
    respaldoExterno.subidas++;
    _ultimaSubidaS3 = Date.now();
    res.json({ok:true, archivo:`estado-${hoy}.json.gz`, kb:Math.round(contenido.length/1024),
      destino:`${S3.endpoint}/${S3.bucket}/${S3.prefijo}`});
  }catch(e){
    respaldoExterno.ultimoError = e.message;
    res.status(502).json({ok:false, error:e.message});
  }
});

/* Informe de una orden por su token. La dirección la lleva el QR impreso:
   quien tiene el papel puede abrirlo, igual que puede leerlo. */
app.get('/api/informe/:numero/:token', (req, res) => {
  const ip = ipDe(req);
  if(!limitarIntentos(ip))
    return res.status(429).json({error:'Demasiadas consultas. Espera unos minutos.'});
  const estado = leerDB('estado');
  if(!estado) return res.status(404).json({error:'No encontrado'});
  const o = (estado.ordenes||[]).find(x =>
    x.numero === req.params.numero && x.token && x.token === req.params.token);
  // Mismo mensaje si la orden no existe o el token no coincide
  if(!o) return res.status(404).json({error:'No encontramos ese informe'});
  if(o.estado !== 'Validada' && o.estado !== 'Entregada')
    return res.status(404).json({error:'Este informe aún no está listo'});
  const pac = (estado.pacientes||[]).find(p => p.codigo === o.pacCodigo) || {};
  // El médico que se muestra al paciente es el asignado a ESTA orden
  // (o.medicoId, catálogo agregado ago. 2026 — ver 21e_medicos.js del LIS),
  // no el campo histórico del paciente: el mismo paciente puede tener un
  // médico distinto en cada orden. Si la orden no tiene médico asignado
  // (órdenes de antes de esta fase que no calzaron en la migración, o que
  // nunca tuvieron médico), se usa el campo viejo del paciente como último
  // recurso, igual que hace el LIS internamente.
  const medicoOrden = (estado.medicos||[]).find(m => m.id === o.medicoId);
  const medicoMostrado = (medicoOrden && medicoOrden.nombre) || pac.medico || '';
  res.json({
    config: {
      nombre: estado.config?.nombre, direccion: estado.config?.direccion,
      whatsapp: estado.config?.whatsapp, telefono2: estado.config?.telefono2,
      correo: estado.config?.correo, horario: estado.config?.horario,
      regente: estado.config?.regente, colegiacion: estado.config?.colegiacion,
      profesional: estado.config?.profesional, profesionalTitulo: estado.config?.profesionalTitulo,
      servicios: estado.config?.servicios, anclaSGC: estado.config?.anclaSGC,
      logo: estado.config?.logo, firma: estado.config?.firma, sello: estado.config?.sello,
      prefijoId: estado.config?.prefijoId,
    },
    paciente: {
      nombre: pac.nombre, idNumero: pac.idNumero, idTipo: pac.idTipo, fnac: pac.fnac,
      sexo: pac.sexo, medico: medicoMostrado, codigo: pac.codigo, tel: pac.tel,
      respNombre: pac.respNombre, respParentesco: pac.respParentesco, respId: pac.respId,
    },
    orden: o,
  });
});

// Atajos cómodos para compartir con los pacientes
app.get(['/paciente','/resultados','/mis-resultados'], (req,res)=>
  res.sendFile(path.join(PUB_DIR,'paciente.html')));
// Informe abierto desde el código QR impreso
app.get('/r/:numero/:token', (req,res)=>
  res.sendFile(path.join(PUB_DIR,'informe.html')));
/* PDF directo del informe -- mismo informe, ya armado en PDF, sin pasar por
   el diálogo de impresión del navegador (ver navegador() más arriba). */
app.get('/r/:numero/:token/pdf', async (req, res) => {
  const ip = ipDe(req);
  if(!limitarPDF(ip))
    return res.status(429).send('Demasiadas solicitudes de PDF. Espera unos minutos e intenta de nuevo.');
  const estado = leerDB('estado');
  if(!estado) return res.status(404).send('No encontrado.');
  const o = (estado.ordenes||[]).find(x =>
    x.numero === req.params.numero && x.token && x.token === req.params.token);
  // Mismo mensaje si la orden no existe o el token no coincide, igual que /api/informe
  if(!o) return res.status(404).send('No encontramos ese informe.');
  if(o.estado !== 'Validada' && o.estado !== 'Entregada')
    return res.status(404).send('Este informe aún no está listo.');
  let page = null;
  try{
    const browser = await navegador();
    page = await browser.newPage();
    // El ancho del viewport importa: repaginarHojas() (llamada por
    // pintarPDF() en informe.html, Fase 8) mide alturas reales del DOM para
    // decidir dónde partir cada hoja -- el mismo ancho que usa el LIS para
    // esa misma medición (el iframe oculto de ventanaImpresion(), ver
    // 50_impresion.js) para que el resultado pagine EXACTAMENTE igual.
    await page.setViewport({width:780, height:1100});
    // Se abre la MISMA página que ve el paciente, por loopback interno (no
    // depende de host/protocolo público): así el PDF nunca se desalinea del
    // informe en pantalla -- es la fuente de verdad, no una segunda plantilla.
    // El origen público (https://dominio-real.com) SÍ hay que pasárselo
    // aparte: la página se carga por 127.0.0.1, así que su propio
    // location.origin ahí adentro sería ese loopback -- y el QR que dibuja
    // (que debe apuntar al dominio real, no a localhost) saldría inválido si
    // no se le avisa por dónde entró de verdad el paciente.
    // "modo=pdf" (Fase 8, ago. 2026): le dice a informe.html que llame a
    // pintarPDF() en vez de pintar() -- el mismo código que usa el LIS por
    // dentro (cabeceraInforme()/construirHojasInforme()/repaginarHojas()),
    // para que este PDF sea idéntico al que imprime el laboratorio. Ver
    // ARQUITECTURA.md, "Fase 8".
    const origenPublico = `${req.protocol}://${req.get('host')}`;
    const propia = `http://127.0.0.1:${PORT}/r/${req.params.numero}/${req.params.token}`
      + `?origen=${encodeURIComponent(origenPublico)}&modo=pdf`;
    await page.goto(propia, {waitUntil:'networkidle0', timeout:15000});
    await page.waitForSelector('.hoja', {timeout:10000});
    // Puppeteer moderno devuelve un Uint8Array, no un Buffer de Node -- sin
    // este Buffer.from(), Express no lo reconoce como binario (Buffer.isBuffer
    // da false) y termina mandándolo mal, serializado como JSON en vez de
    // como PDF binario.
    const pdf = Buffer.from(await page.pdf({format:'Letter', printBackground:true, preferCSSPageSize:true}));
    // Reutiliza el título que la propia página ya calculó (pintarPDF(), en
    // informe.html) -- lleva paciente y fecha, no solo el número de orden.
    // Así el nombre del archivo no depende de duplicar esa misma lógica acá.
    const titulo = await page.title().catch(() => '');
    res.set({
      'Content-Type': 'application/pdf',
      // "inline" (no "attachment"): en el celular esto abre el PDF directo
      // en el visor del navegador, con su propio botón de descarga/compartir
      // -- exactamente "ver y descargar" en un solo toque.
      'Content-Disposition': `inline; filename="${(titulo||'Resultados_'+o.numero).replace(/"/g,'')}.pdf"`,
      'Content-Length': pdf.length,
    });
    res.send(pdf);
  }catch(e){
    console.error('Error generando PDF de informe:', e.message);
    res.status(500).send('No se pudo generar el PDF en este momento. Intenta de nuevo en un momento.');
  }finally{
    if(page) await page.close().catch(()=>{});
  }
});
app.get(['/cotizar','/cotizacion'], (req,res)=>
  res.sendFile(path.join(PUB_DIR,'paciente.html')));

// ════════════════════════════════════════════════════════════
// SPA: todas las rutas no conocidas devuelven el index
// ════════════════════════════════════════════════════════════
app.get('*', (req, res) => {
  if(req.path.startsWith('/api/')) return res.status(404).json({error:'Ruta no encontrada'});
  res.sendFile(path.join(PUB_DIR, 'index.html'));
});

// ── Arrancar ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════╗`);
  console.log(`║   CDI Marcala · Servidor activo      ║`);
  console.log(`║   http://localhost:${PORT}              ║`);
  console.log(`╚══════════════════════════════════════╝`);
  console.log(`\n  Usuario: admin`);
  console.log(`  Clave:   cdim2024  ← cámbiala al entrar\n`);
  if(S3_LISTO)
    console.log(`  Respaldo externo: ${S3.endpoint}/${S3.bucket}/${S3.prefijo} · cada ${S3.minutos} min\n`);
  else if(S3_MOTIVO)
    console.error(`  ⚠ Respaldo externo MAL CONFIGURADO: ${S3_MOTIVO}\n`
      +'    Los respaldos viven SOLO en este disco hasta que se corrija.\n');
  else
    console.warn('  ⚠ Sin respaldo externo: los respaldos viven SOLO en este disco.\n'
      +'    Configura RESPALDO_S3_ENDPOINT, _BUCKET, _KEY_ID y _SECRET para tener copia fuera.\n');
});
