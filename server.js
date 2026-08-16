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
const fs         = require('fs');
const multer     = require('multer');

// ── Configuración ────────────────────────────────────────────
const PORT    = process.env.PORT || 3000;
const SECRET  = process.env.JWT_SECRET || 'cdim-secret-cambiar-en-produccion';
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
function leerDB(nombre){
  const f = path.join(DATA_DIR, DB_FILES[nombre]);
  if(!fs.existsSync(f)) return null;
  try{ return JSON.parse(fs.readFileSync(f,'utf8')); }catch{ return null; }
}
function escribirDB(nombre, datos){
  const f = path.join(DATA_DIR, DB_FILES[nombre]);
  // Escritura segura: primero a un temporal y luego se renombra.
  // Si se corta la luz a mitad de la escritura, el archivo anterior queda intacto.
  const tmp = f + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(datos), 'utf8');
  fs.renameSync(tmp, f);
}

/* ── Respaldos automáticos ──────────────────────────────────
   Cada vez que se guarda el estado se conserva una copia diaria.
   Se mantienen los últimos 30 días. */
const BAK_DIR = path.join(DATA_DIR, 'respaldos');
fs.mkdirSync(BAK_DIR, {recursive:true});

function respaldoDiario(estado){
  try{
    const hoy = new Date().toISOString().slice(0,10);
    const f = path.join(BAK_DIR, `estado-${hoy}.json`);
    // Solo un respaldo por día: se sobrescribe con la versión más reciente
    fs.writeFileSync(f, JSON.stringify(estado), 'utf8');
    // Limpieza: se conservan los 30 más recientes
    const archivos = fs.readdirSync(BAK_DIR)
      .filter(x => x.startsWith('estado-') && x.endsWith('.json'))
      .sort().reverse();
    archivos.slice(30).forEach(x => {
      try{ fs.unlinkSync(path.join(BAK_DIR, x)); }catch{}
    });
  }catch(e){ console.warn('[CDIM] No se pudo crear el respaldo diario:', e.message); }
}

// ── Inicializar usuarios si no existen ───────────────────────
function inicializarUsuarios(){
  if(leerDB('usuarios')) return;
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
  // El control del sistema (usuarios, respaldos) corresponde al rol Admin
  if(req.user?.rol !== 'Admin' && req.user?.rol !== 'Administrador')
    return res.status(403).json({error:'Esta acción requiere el rol Admin'});
  next();
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
app.use(compression());
app.use(express.json({limit:'10mb'}));
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
  const token = jwt.sign({id:u.id, nombre:u.nombre, usuario:u.usuario, rol:u.rol}, SECRET, {expiresIn:'12h'});
  res.cookie('token', token, {httpOnly:true, sameSite:'lax', maxAge:12*3600*1000});
  res.json({ok:true, nombre:u.nombre, rol:u.rol, usuario:u.usuario});
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ok:true});
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({nombre:req.user.nombre, rol:req.user.rol, usuario:req.user.usuario});
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
  const usuarios = (leerDB('usuarios') || []).map(({clave,...u}) => u);
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
    rol    : ['Admin','Dr','Administrador','Técnico'].includes(rol) ? rol : 'Técnico',
    activo : true,
    creado : new Date().toISOString(),
  };
  usuarios.push(nuevo);
  escribirDB('usuarios', usuarios);
  const {clave:_, ...sin_clave} = nuevo;
  res.json(sin_clave);
});

app.put('/api/usuarios/:id', auth, soloAdmin, (req, res) => {
  const usuarios = leerDB('usuarios') || [];
  const u = usuarios.find(x => x.id === req.params.id);
  if(!u) return res.status(404).json({error:'Usuario no encontrado'});
  const {nombre, rol, activo, clave} = req.body;
  if(nombre) u.nombre = nombre;
  if(rol)    u.rol    = rol;
  if(activo !== undefined) u.activo = activo;
  if(clave && clave.length >= 6) u.clave = bcrypt.hashSync(clave, 10);
  escribirDB('usuarios', usuarios);
  const {clave:_, ...sin_clave} = u;
  res.json(sin_clave);
});

app.delete('/api/usuarios/:id', auth, soloAdmin, (req, res) => {
  if(req.params.id === req.user.id) return res.status(400).json({error:'No puedes eliminarte a ti mismo'});
  const usuarios = (leerDB('usuarios') || []).filter(x => x.id !== req.params.id);
  escribirDB('usuarios', usuarios);
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
   uno tras otro. Cinco intentos fallidos por IP cada quince minutos. */
const _intentos = new Map();
function limitarIntentos(ip){
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
      .filter(x => x.startsWith('estado-') && x.endsWith('.json'))
      .sort().reverse()
      .map(x => {
        const st = fs.statSync(path.join(BAK_DIR, x));
        return { archivo:x, fecha:x.slice(7,17), tamaño:st.size, modificado:st.mtime };
      });
    res.json(archivos);
  }catch(e){ res.json([]); }
});

// Restaurar desde un respaldo del servidor
app.post('/api/respaldo/restaurar', auth, soloAdmin, (req, res) => {
  const { archivo } = req.body;
  if(!archivo || !/^estado-\d{4}-\d{2}-\d{2}\.json$/.test(archivo))
    return res.status(400).json({error:'Nombre de archivo no válido'});
  const f = path.join(BAK_DIR, archivo);
  if(!fs.existsSync(f)) return res.status(404).json({error:'Ese respaldo no existe'});
  try{
    // Antes de restaurar se guarda el estado actual, por si acaso
    const actual = leerDB('estado');
    if(actual) fs.writeFileSync(path.join(BAK_DIR,'antes-de-restaurar.json'), JSON.stringify(actual));
    const estado = JSON.parse(fs.readFileSync(f,'utf8'));
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

// Atajos cómodos para compartir con los pacientes
app.get(['/paciente','/resultados','/mis-resultados'], (req,res)=>
  res.sendFile(path.join(PUB_DIR,'paciente.html')));
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
