/* ============================================================
   CDI MARCALA · SERVIDOR WEB
   Node.js + Express · Almacenamiento en JSON + archivos
   Sin base de datos externa: todo vive en /data/*.json
   Listo para desplegar en Render / Railway / VPS
   ============================================================ */
'use strict';
const express    = require('express');
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

// ── Almacenamiento JSON ──────────────────────────────────────
const DB_FILES = {
  usuarios : 'usuarios.json',
  estado   : 'estado.json',    // todo el estado del LIS
  cola_cot : 'cola_cot.json',  // cotizaciones del portal web
  sesiones : 'sesiones.json',
};
/* El estado se guarda comprimido: a 3000 órdenes son 11 MB que bajarían a
   unos 100 KB. Como se escribe en cada guardado, la diferencia en desgaste
   de disco y en tiempo es grande. Los archivos pequeños (usuarios, cola)
   se dejan en texto plano para poder inspeccionarlos a mano si hace falta. */
const COMPRIMIR = ['estado'];

function leerDB(nombre){
  const f  = path.join(DATA_DIR, DB_FILES[nombre]);
  const fz = f + '.gz';
  // Se prefiere el comprimido; si no está, se lee el de texto (versiones anteriores)
  try{
    if(fs.existsSync(fz))
      return JSON.parse(zlib.gunzipSync(fs.readFileSync(fz)).toString('utf8'));
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
    fs.writeFileSync(tmp, zlib.gzipSync(texto, {level:6}));
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

function respaldoDiario(estado){
  try{
    const hoy = new Date().toISOString().slice(0,10);
    // Respaldo comprimido: un estado de 20 MB baja a menos de 1 MB.
    // Sin esto, 30 respaldos diarios llenarían el disco en unos dos años.
    const f = path.join(BAK_DIR, `estado-${hoy}.json.gz`);
    fs.writeFileSync(f, zlib.gzipSync(JSON.stringify(estado), {level:6}));
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
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '',
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
  actual.ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || actual.ip;
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
function msDeTTL(ttl){
  const m = /^(\d+)([hm])$/.exec(ttl);
  return m ? Number(m[1]) * (m[2]==='h' ? 3600000 : 60000) : 12*3600*1000;
}
// COOKIE_SECURE: en Render, detrás de su proxy TLS, NODE_ENV=production ya es
// requisito de despliegue (ver DEPLOY.md) — se usa como señal de "esto es
// HTTPS de verdad". En desarrollo local (http) queda en false a propósito:
// Chrome nunca manda una cookie Secure por http, y con true el login local
// dejaría de funcionar para probar.
const COOKIE_SECURE = process.env.NODE_ENV === 'production';
function emitirCookiesSesion(res, usuario, sesionId, cruda){
  const token = jwt.sign({id:usuario.id, sid:sesionId, nombre:usuario.nombre, usuario:usuario.usuario,
    rol:usuario.rol, permisos:usuario.permisos||null}, SECRET, {expiresIn:ACCESO_TTL});
  res.cookie('token', token, {httpOnly:true, secure:COOKIE_SECURE, sameSite:'lax', maxAge: msDeTTL(ACCESO_TTL)});
  res.cookie('refresh', cruda, {httpOnly:true, secure:COOKIE_SECURE, sameSite:'lax', path:'/api/auth', maxAge: RENOVACION_DIAS*86400000});
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

// ── Aplicación ────────────────────────────────────────────────
const app = express();
// Render (y casi cualquier hosting con proxy delante) termina el HTTPS y le
// reenvía al servidor una conexión HTTP normal -- sin esto, req.protocol
// siempre diría "http" aunque el paciente haya entrado por https, y el QR
// que se genera dentro del PDF (ver /r/:numero/:token/pdf) quedaría con la
// URL equivocada.
app.set('trust proxy', true);
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
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.usuario === usuario && x.activo !== false);
  if(!u || !bcrypt.compareSync(clave, u.clave))
    return res.status(401).json({error:'Usuario o clave incorrectos'});
  const {sesion, cruda} = crearSesion(u, req);
  emitirCookiesSesion(res, u, sesion.id, cruda);
  res.json({ok:true, id:u.id, nombre:u.nombre, rol:u.rol, usuario:u.usuario, permisos:u.permisos||null});
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

/* Ingreso por PIN. El limitador es por usuario, no por IP: así un intento
   fallido en recepción no bloquea al resto del personal. */
const _intentosPin = new Map();
function limitarPin(usuario){
  const ahora = Date.now(), ventana = 10*60*1000;   // 10 minutos
  const reg = _intentosPin.get(usuario) || {n:0, desde:ahora};
  if(ahora - reg.desde > ventana){ reg.n = 0; reg.desde = ahora; }
  reg.n++;
  _intentosPin.set(usuario, reg);
  if(_intentosPin.size > 500){
    for(const [k,v] of _intentosPin) if(ahora - v.desde > ventana) _intentosPin.delete(k);
  }
  return reg.n <= 6;
}
/* Igual patrón que limitarPin(), por IP: /api/auth/refresh no manda usuario
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
  if(!limitarPin(usuario))
    return res.status(429).json({error:'Demasiados intentos con este usuario. Espera unos minutos.'});
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.usuario === usuario && x.activo !== false);
  // Mismo mensaje si el usuario no existe o el PIN no coincide
  if(!u || !u.pin || !bcrypt.compareSync(String(pin), u.pin))
    return res.status(401).json({error:'PIN incorrecto'});
  _intentosPin.delete(usuario);
  const {sesion, cruda} = crearSesion(u, req);
  emitirCookiesSesion(res, u, sesion.id, cruda);
  res.json({ok:true, id:u.id, nombre:u.nombre, rol:u.rol, usuario:u.usuario, permisos:u.permisos||null});
});

/* Renovar la sesión sin volver a pedir clave/PIN. Recibe el token de
   renovación por cookie (nunca por cuerpo/JS visible) y, si es válido, emite
   un access token nuevo y ROTA el de renovación (mismo id de sesión, huella
   nueva). Deliberadamente SIN el middleware auth: el access token puede ya
   estar vencido, es justo el caso que esta ruta existe para resolver. */
app.post('/api/auth/refresh', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'sin-ip';
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
  res.json({ok:true, id:u.id, nombre:u.nombre, rol:u.rol, usuario:u.usuario, permisos:u.permisos||null});
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
  res.json({id:req.user.id, nombre:req.user.nombre, rol:req.user.rol, usuario:req.user.usuario, permisos:req.user.permisos||null});
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
  escribirDB('usuarios', usuarios);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════════════
// GESTIÓN DE USUARIOS (solo Admin)
// ════════════════════════════════════════════════════════════
app.get('/api/usuarios', auth, soloAdmin, (req, res) => {
  const usuarios = (leerDB('usuarios') || [])
    .map(({clave, pin, ...u}) => ({...u, tienePin: !!pin}));   // permisos sí viajan: el Admin los edita
  res.json(usuarios);
});

app.post('/api/usuarios', auth, soloAdmin, (req, res) => {
  const {nombre, usuario, clave, rol} = req.body;
  if(!nombre || !usuario || !clave) return res.status(400).json({error:'Datos incompletos'});
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
  if(nombre) u.nombre = nombre;
  if(rol)    u.rol    = rol;
  if(activo !== undefined) u.activo = activo;
  if(clave && clave.length >= 6) u.clave = bcrypt.hashSync(clave, 10);
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

// ════════════════════════════════════════════════════════════
// COTIZACIONES DEL PORTAL WEB (sin autenticación)
// ════════════════════════════════════════════════════════════
app.post('/api/cotizacion-publica', (req, res) => {
  const cot = req.body;
  if(!cot || !cot.numero || !cot.nombre)
    return res.status(400).json({error:'Datos incompletos'});
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
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'sin-ip';
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
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'sin-ip';
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

// Restaurar desde un respaldo del servidor
app.post('/api/respaldo/restaurar', auth, soloAdmin, (req, res) => {
  const { archivo } = req.body;
  if(!archivo || !/^estado-\d{4}-\d{2}-\d{2}\.json(\.gz)?$/.test(archivo))
    return res.status(400).json({error:'Nombre de archivo no válido'});
  const f = path.join(BAK_DIR, archivo);
  if(!fs.existsSync(f)) return res.status(404).json({error:'Ese respaldo no existe'});
  try{
    // Antes de restaurar se guarda el estado actual, por si acaso
    const actual = leerDB('estado');
    if(actual) fs.writeFileSync(path.join(BAK_DIR,'antes-de-restaurar.json.gz'),
      zlib.gzipSync(JSON.stringify(actual)));
    // Los respaldos nuevos vienen comprimidos; los antiguos se leen igual
    const crudo = fs.readFileSync(f);
    const estado = JSON.parse(archivo.endsWith('.gz')
      ? zlib.gunzipSync(crudo).toString('utf8')
      : crudo.toString('utf8'));
    estado._ts = Date.now();
    estado._por = req.user.nombre + ' (restauración)';
    escribirDB('estado', estado);
    console.log(`[CDIM] Estado restaurado desde ${archivo} por ${req.user.nombre}`);
    res.json({ok:true, ts:estado._ts});
  }catch(e){ res.status(500).json({error:'No se pudo leer el respaldo: '+e.message}); }
});

// Subir un respaldo desde la computadora y restaurarlo
app.post('/api/respaldo/subir', auth, soloAdmin, (req, res) => {
  const { estado } = req.body;
  if(!estado || !estado.pacientes) return res.status(400).json({error:'El archivo no parece un respaldo válido'});
  try{
    const actual = leerDB('estado');
    if(actual) fs.writeFileSync(path.join(BAK_DIR,'antes-de-restaurar.json'), JSON.stringify(actual));
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
  });
});

/* Informe de una orden por su token. La dirección la lleva el QR impreso:
   quien tiene el papel puede abrirlo, igual que puede leerlo. */
app.get('/api/informe/:numero/:token', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'sin-ip';
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
      sexo: pac.sexo, medico: pac.medico, codigo: pac.codigo, tel: pac.tel,
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
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'sin-ip';
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
});
