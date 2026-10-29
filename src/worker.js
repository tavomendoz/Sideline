// Sideline — Worker: sirve el sitio (carpeta public) y la API /api/* con D1.
// Requiere: base D1 enlazada como "DB" (wrangler.jsonc) y secreto "COACH_KEY"
// (clave de administrador: panel /admin y solicitudes del cuestionario).
//
// Cuentas: cada equipo tiene coaches (editan) y jugadores (solo ven).
// Contraseñas con PBKDF2-SHA256; sesión en cookie HttpOnly.

let ready = false;
async function init(db) {
  if (ready) return;
  await db.batch([
    // datos anteriores (una sola sala), se conservan para migrarlos a un equipo
    db.prepare(`CREATE TABLE IF NOT EXISTS plays (video TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (video, id))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS videos (id TEXT PRIMARY KEY, title TEXT, updated_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS leads (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, data TEXT NOT NULL)`),
    // equipos y cuentas
    db.prepare(`CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, modules TEXT NOT NULL DEFAULT 'video,playbook')`),
    db.prepare(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, username TEXT NOT NULL UNIQUE, name TEXT NOT NULL, role TEXT NOT NULL, pass TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS login_fail (username TEXT PRIMARY KEY, count INTEGER NOT NULL, until INTEGER NOT NULL)`),
    // datos por equipo
    db.prepare(`CREATE TABLE IF NOT EXISTS tplays (team_id TEXT NOT NULL, video TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (team_id, video, id))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS tvideos (team_id TEXT NOT NULL, id TEXT NOT NULL, title TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (team_id, id))`),
    // playbooks: format = modalidad (11 y 8 tacleo; 80 flag 8 vs 8; 7 y 5 flag); side = O (ofensiva) o D (defensiva)
    db.prepare(`CREATE TABLE IF NOT EXISTS pbooks (team_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, format INTEGER NOT NULL, side TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (team_id, id))`),
    // videos subidos a Cloudflare Stream por cada equipo; seconds = duración real cuando ya se procesó
    db.prepare(`CREATE TABLE IF NOT EXISTS uploads (team_id TEXT NOT NULL, uid TEXT NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL, seconds REAL NOT NULL DEFAULT 0, max_seconds INTEGER NOT NULL DEFAULT 0, size INTEGER NOT NULL DEFAULT 0, host TEXT, created_at INTEGER NOT NULL, PRIMARY KEY (team_id, uid))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS pbplays (team_id TEXT NOT NULL, book_id TEXT NOT NULL, id TEXT NOT NULL, pos INTEGER NOT NULL, data TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (team_id, book_id, id))`),
  ]);
  // equipos creados antes de los módulos: se agrega la columna con ambos módulos activos (falla si ya existe)
  try { await db.prepare(`ALTER TABLE teams ADD COLUMN modules TEXT NOT NULL DEFAULT 'video,playbook'`).run(); } catch (e) {}
  // horas de video propio que incluye el plan del equipo (0 = no puede subir)
  try { await db.prepare(`ALTER TABLE teams ADD COLUMN video_hours INTEGER NOT NULL DEFAULT 0`).run(); } catch (e) {}
  ready = true;
}

const json = (obj, status = 200, headers = {}) => new Response(JSON.stringify(obj), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
});
const YTID = /^[\w-]{11}$/;
const SVID = /^s[0-9a-f]{32}$/;           // video subido: «s» + uid de Cloudflare Stream
const VID = { test: v => YTID.test(v) || SVID.test(v) };
const PID = /^[\w-]{1,40}$/;
const USERNAME = /^[a-z0-9._-]{3,32}$/;
const SESSION_DAYS = 30;
// módulos que se contratan por equipo
const MODULES = ['video', 'playbook'];
const parseModules = v => MODULES.filter(m => String(v ?? MODULES.join(',')).split(',').includes(m));
const moduleList = v => MODULES.filter(m => (Array.isArray(v) ? v : []).includes(m));
const enc = new TextEncoder();

// ---------- helpers ----------
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = s => new Uint8Array(s.match(/../g).map(h => parseInt(h, 16)));
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
function tempPassword() {
  const a = 'abcdefghjkmnpqrstuvwxyz23456789';
  const r = crypto.getRandomValues(new Uint8Array(8));
  const c = [...r].map(x => a[x % a.length]).join('');
  return c.slice(0, 4) + '-' + c.slice(4);
}
async function hashPass(pw, saltHex) {
  const salt = saltHex ? unhex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256);
  return `pbkdf2$100000$${hex(salt)}$${hex(bits)}`;
}
async function checkPass(pw, stored) {
  const [, , salt, want] = String(stored).split('$');
  if (!salt || !want) return false;
  const got = (await hashPass(pw, salt)).split('$')[3];
  let d = 0; for (let i = 0; i < want.length; i++) d |= want.charCodeAt(i) ^ (got.charCodeAt(i) || 0);
  return d === 0 && got.length === want.length;
}
function isAdmin(request, env) {
  const given = request.headers.get('x-coach-key') || '';
  const secret = env.COACH_KEY || '';
  if (!secret || given.length !== secret.length) return false;
  let diff = 0;
  for (let i = 0; i < secret.length; i++) diff |= secret.charCodeAt(i) ^ given.charCodeAt(i);
  return diff === 0;
}
// límite de intentos: cuenta cada intento dentro de una ventana (atómico en D1).
// Reutiliza la tabla login_fail: username = clave, count = intentos, until = fin de la ventana.
const LOCK_MS = 15 * 60000;
const clientIp = request => request.headers.get('cf-connecting-ip') || '';
async function hit(db, key, now, windowMs = LOCK_MS) {
  const r = await db.prepare(`INSERT INTO login_fail (username, count, until) VALUES (?1, 1, ?2)
      ON CONFLICT(username) DO UPDATE SET
        count = CASE WHEN login_fail.until <= ?3 THEN 1 ELSE login_fail.count + 1 END,
        until = CASE WHEN login_fail.until <= ?3 THEN ?2 ELSE login_fail.until END
      RETURNING count`).bind(key, now + windowMs, now).first();
  return r ? r.count : 1;
}
async function overLimit(db, key, max, now) {
  const r = await db.prepare('SELECT count, until FROM login_fail WHERE username = ?1').bind(key).first();
  return !!(r && r.until > now && r.count >= max);
}
// clave de administrador con límite de intentos fallidos por IP
async function adminDenied(request, env, db) {
  const now = Date.now(), key = 'admin:' + clientIp(request);
  if (await overLimit(db, key, 10, now)) return json({ error: 'locked', message: 'Demasiados intentos. Espera 15 minutos.' }, 429);
  if (isAdmin(request, env)) return null;
  await hit(db, key, now);
  return json({ error: 'bad_key' }, 401);
}
function cookieToken(request) {
  const m = (request.headers.get('cookie') || '').match(/(?:^|;\s*)sl_session=([a-f0-9]{64})/);
  return m ? m[1] : '';
}
const setCookie = (token, maxAge) => `sl_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const str = (v, n) => String(v ?? '').trim().slice(0, n);
const publicUser = u => ({ id: u.id, username: u.username, name: u.name, role: u.role, must_change: !!u.must_change, active: !!u.active });

async function currentUser(request, db) {
  const t = cookieToken(request);
  if (!t) return null;
  const row = await db.prepare(`SELECT u.*, t.name AS team_name, t.active AS team_active, t.modules AS team_modules FROM sessions s
      JOIN users u ON u.id = s.user_id JOIN teams t ON t.id = u.team_id
      WHERE s.token_hash = ?1 AND s.expires_at > ?2`).bind(await sha256(t), Date.now()).first();
  if (!row || !row.active || !row.team_active) return null;
  return row;
}
const me = u => ({ user: publicUser(u), team: { id: u.team_id, name: u.team_name, modules: parseModules(u.team_modules) } });

async function createUser(db, teamId, { name, username, role }) {
  name = str(name, 80); username = str(username, 32).toLowerCase(); role = role === 'coach' ? 'coach' : 'player';
  if (!name) return { error: 'Escribe el nombre.' };
  if (!USERNAME.test(username)) return { error: 'El usuario debe tener de 3 a 32 letras minúsculas, números, punto, guion o guion bajo, sin espacios.' };
  const exists = await db.prepare('SELECT 1 FROM users WHERE username = ?1').bind(username).first();
  if (exists) return { error: `El usuario "${username}" ya existe. Elige otro.` };
  const temp = tempPassword();
  const id = randHex(8);
  try {
    await db.prepare('INSERT INTO users (id, team_id, username, name, role, pass, must_change, active, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1, ?7)')
      .bind(id, teamId, username, name, role, await hashPass(temp), Date.now()).run();
  } catch (e) {
    if (/UNIQUE/i.test(String(e && e.message))) return { error: `El usuario "${username}" ya existe. Elige otro.` };
    throw e;
  }
  return { user: { id, username, name, role, must_change: true, active: true }, temp_password: temp };
}
async function resetUser(db, id, teamId) {
  const temp = tempPassword();
  const q = teamId
    ? db.prepare('UPDATE users SET pass = ?1, must_change = 1 WHERE id = ?2 AND team_id = ?3').bind(await hashPass(temp), id, teamId)
    : db.prepare('UPDATE users SET pass = ?1, must_change = 1 WHERE id = ?2').bind(await hashPass(temp), id);
  const r = await q.run();
  if (!r.meta || !r.meta.changes) return null;
  await db.prepare('DELETE FROM sessions WHERE user_id = ?1').bind(id).run();
  return temp;
}

async function handleApi(request, env, path) {
  const url = new URL(request.url);
  const method = request.method;

  if (path === 'health') return json({ ok: true, db: !!env.DB, key: !!env.COACH_KEY, accounts: true });
  // reportes de la política de contenido: se ven en Observability → Logs del worker
  if (path === 'csp-report' && method === 'POST') {
    const t = await request.text().catch(() => '');
    console.log('csp-report', t.slice(0, 2000));
    return new Response(null, { status: 204 });
  }
  if (!env.DB) return json({ error: 'no_db' }, 503);

  try {
    await init(env.DB);
    const db = env.DB;
    const body = async () => { try { return await request.json(); } catch (e) { return {}; } };

    // ---------- sesión ----------
    if (path === 'login' && method === 'POST') {
      const b = await body();
      const username = str(b.username, 32).toLowerCase(), password = String(b.password || '');
      // un usuario inválido no puede existir; tampoco se cuenta (evita claves de límite fabricadas, p. ej. "ana|1.2.3.4")
      if (!USERNAME.test(username)) return json({ error: 'bad_login', message: 'Usuario o contraseña incorrectos.' }, 401);
      const now = Date.now(), ip = clientIp(request);
      const locked = json({ error: 'locked', message: 'Demasiados intentos. Espera 15 minutos o pide a tu coach que restablezca tu contraseña.' }, 429);
      // se cuenta el intento antes de comprobar la contraseña, así los intentos en paralelo no saltan el límite:
      // 5 por usuario desde una IP, 50 por usuario en total, 30 fallos por IP
      if (await overLimit(db, 'ip:' + ip, 30, now)) return locked;
      const [perIp, perUser] = await Promise.all([hit(db, `u:${username}|${ip}`, now), hit(db, 'u:' + username, now)]);
      if (perIp > 5 || perUser > 50) return locked;
      const u = await db.prepare(`SELECT u.*, t.name AS team_name, t.active AS team_active, t.modules AS team_modules FROM users u JOIN teams t ON t.id = u.team_id WHERE u.username = ?1`).bind(username).first();
      const ok = u && u.active && u.team_active && await checkPass(password, u.pass);
      if (!ok) {
        await hit(db, 'ip:' + ip, now);
        return json({ error: 'bad_login', message: 'Usuario o contraseña incorrectos.' }, 401);
      }
      const token = randHex(32);
      await db.batch([
        db.prepare('DELETE FROM login_fail WHERE username IN (?1, ?2) OR until < ?3').bind(`u:${username}|${ip}`, 'u:' + username, now),
        db.prepare('DELETE FROM sessions WHERE expires_at < ?1').bind(now),
        db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)').bind(await sha256(token), u.id, now + SESSION_DAYS * 864e5),
      ]);
      return json(me(u), 200, { 'set-cookie': setCookie(token, SESSION_DAYS * 86400) });
    }
    if (path === 'logout' && method === 'POST') {
      const t = cookieToken(request);
      if (t) await db.prepare('DELETE FROM sessions WHERE token_hash = ?1').bind(await sha256(t)).run();
      return json({ ok: true }, 200, { 'set-cookie': setCookie('', 0) });
    }

    // ---------- administrador (clave COACH_KEY) ----------
    if (path === 'check') return (await adminDenied(request, env, db)) || json({ ok: true });
    if (path.startsWith('admin/')) {
      const denied = await adminDenied(request, env, db);
      if (denied) return denied;
      const sub = path.slice(6);
      if (sub === 'teams' && method === 'GET') {
        const r = await db.prepare(`SELECT t.id, t.name, t.active, t.created_at, t.modules,
            (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'coach') AS coaches,
            (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'player') AS players,
            (SELECT COUNT(*) FROM tvideos v WHERE v.team_id = t.id) AS games,
            t.video_hours, (SELECT COALESCE(SUM(seconds), 0) FROM uploads x WHERE x.team_id = t.id AND x.status = 'ready') AS video_used
          FROM teams t ORDER BY t.created_at DESC`).all();
        const legacy = await db.prepare('SELECT COUNT(*) AS n FROM plays').first();
        return json({ teams: (r.results || []).map(t => ({ ...t, modules: parseModules(t.modules) })), legacy_plays: legacy ? legacy.n : 0 });
      }
      if (sub === 'teams' && method === 'POST') {
        const b = await body();
        const name = str(b.name, 80);
        if (!name) return json({ error: 'bad_request', message: 'Escribe el nombre del equipo.' }, 400);
        const modules = b.modules === undefined ? MODULES : moduleList(b.modules);
        if (!modules.length) return json({ error: 'bad_request', message: 'Elige al menos un módulo.' }, 400);
        const id = randHex(6);
        await db.prepare('INSERT INTO teams (id, name, active, created_at, modules) VALUES (?1, ?2, 1, ?3, ?4)').bind(id, name, Date.now(), modules.join(',')).run();
        const c = await createUser(db, id, { name: b.coach_name, username: b.coach_username, role: 'coach' });
        if (c.error) { await db.prepare('DELETE FROM teams WHERE id = ?1').bind(id).run(); return json({ error: 'bad_request', message: c.error }, 400); }
        return json({ team: { id, name }, ...c });
      }
      if (sub === 'teams/active' && method === 'POST') {
        const b = await body();
        await db.prepare('UPDATE teams SET active = ?1 WHERE id = ?2').bind(b.active ? 1 : 0, str(b.id, 20)).run();
        return json({ ok: true });
      }
      if (sub === 'teams/videohours' && method === 'POST') {
        const b = await body();
        const hours = Math.floor(+b.hours);
        if (!(hours >= 0 && hours <= 1000)) return json({ error: 'bad_request', message: 'Escribe un número de horas entre 0 y 1000.' }, 400);
        const r = await db.prepare('UPDATE teams SET video_hours = ?1 WHERE id = ?2').bind(hours, str(b.id, 20)).run();
        return r.meta && r.meta.changes ? json({ ok: true, hours }) : json({ error: 'not_found' }, 404);
      }
      if (sub === 'teams/modules' && method === 'POST') {
        const b = await body();
        const modules = moduleList(b.modules);
        if (!modules.length) return json({ error: 'bad_request', message: 'Elige al menos un módulo.' }, 400);
        const r = await db.prepare('UPDATE teams SET modules = ?1 WHERE id = ?2').bind(modules.join(','), str(b.id, 20)).run();
        return r.meta && r.meta.changes ? json({ ok: true, modules }) : json({ error: 'not_found' }, 404);
      }
      if (sub === 'users' && method === 'GET') {
        const r = await db.prepare('SELECT * FROM users WHERE team_id = ?1 ORDER BY role, name').bind(str(url.searchParams.get('team'), 20)).all();
        return json({ users: (r.results || []).map(publicUser) });
      }
      if (sub === 'users' && method === 'POST') {
        const b = await body();
        const team = await db.prepare('SELECT id FROM teams WHERE id = ?1').bind(str(b.team, 20)).first();
        if (!team) return json({ error: 'bad_request', message: 'Ese equipo no existe.' }, 400);
        const c = await createUser(db, team.id, b);
        return c.error ? json({ error: 'bad_request', message: c.error }, 400) : json(c);
      }
      if (sub === 'users/reset' && method === 'POST') {
        const b = await body();
        const temp = await resetUser(db, str(b.id, 20));
        return temp ? json({ temp_password: temp }) : json({ error: 'not_found' }, 404);
      }
      if (sub === 'migrate' && method === 'POST') {
        const b = await body();
        const team = await db.prepare('SELECT id FROM teams WHERE id = ?1').bind(str(b.team, 20)).first();
        if (!team) return json({ error: 'bad_request', message: 'Ese equipo no existe.' }, 400);
        await db.batch([
          db.prepare('INSERT OR IGNORE INTO tplays (team_id, video, id, data, updated_at) SELECT ?1, video, id, data, updated_at FROM plays').bind(team.id),
          db.prepare('INSERT OR IGNORE INTO tvideos (team_id, id, title, updated_at) SELECT ?1, id, title, updated_at FROM videos').bind(team.id),
        ]);
        const n = await db.prepare('SELECT COUNT(*) AS n FROM tplays WHERE team_id = ?1').bind(team.id).first();
        return json({ ok: true, plays: n ? n.n : 0 });
      }
      return json({ error: 'not_found' }, 404);
    }

    // ---------- cuestionario de contacto ----------
    if (path === 'leads') {
      if (method === 'POST') {
        const raw = await request.text();
        if (raw.length > 12000) return json({ error: 'too_large' }, 413);
        let b; try { b = JSON.parse(raw); } catch (e) { return json({ error: 'bad_request' }, 400); }
        if (b.sitio) return json({ ok: true }); // campo trampa para bots
        if (await hit(db, 'lead:' + clientIp(request), Date.now(), 3600000) > 5) return json({ error: 'too_many', message: 'Ya recibimos varias solicitudes desde tu conexión. Intenta más tarde.' }, 429);
        const list = (v, n) => (Array.isArray(v) ? v : []).slice(0, 10).map(x => str(x, n));
        const lead = {
          rol: str(b.rol, 60), categoria: list(b.categoria, 40), equipos: str(b.equipos, 10),
          grabacion: str(b.grabacion, 60), herramienta: str(b.herramienta, 60), prioridad: list(b.prioridad, 60),
          presupuesto: str(b.presupuesto, 40), nombre: str(b.nombre, 120), equipo: str(b.equipo, 120),
          ciudad: str(b.ciudad, 80), whatsapp: str(b.whatsapp, 30), correo: str(b.correo, 160),
          mensaje: str(b.mensaje, 1500), plan: str(b.plan, 40),
        };
        if (!lead.nombre || (!lead.whatsapp && !lead.correo)) return json({ error: 'missing_contact' }, 400);
        await db.prepare('INSERT INTO leads (created_at, data) VALUES (?1, ?2)').bind(Date.now(), JSON.stringify(lead)).run();
        return json({ ok: true });
      }
      if (method === 'GET') {
        const denied = await adminDenied(request, env, db);
        if (denied) return denied;
        const r = await db.prepare('SELECT id, created_at, data FROM leads ORDER BY created_at DESC LIMIT 500').all();
        const leads = (r.results || []).map(row => { try { return { id: row.id, created_at: row.created_at, ...JSON.parse(row.data) }; } catch (e) { return null; } }).filter(Boolean);
        return json({ leads });
      }
    }

    // ---------- todo lo demás requiere sesión ----------
    const u = await currentUser(request, db);
    if (!u) return json({ error: 'no_session' }, 401);
    const coach = u.role === 'coach';
    const team = u.team_id;

    if (path === 'me' && method === 'GET') return json(me(u));
    // con contraseña temporal solo se permite cambiarla
    if (u.must_change && path !== 'password') return json({ error: 'must_change', message: 'Primero crea tu propia contraseña.' }, 403);

    if (path === 'password' && method === 'POST') {
      const b = await body();
      const next = String(b.new || '');
      if (!(await checkPass(String(b.current || ''), u.pass))) return json({ error: 'bad_password', message: 'La contraseña actual no es correcta.' }, 400);
      if (next.length < 8) return json({ error: 'weak', message: 'La nueva contraseña debe tener al menos 8 caracteres.' }, 400);
      await db.batch([
        db.prepare('UPDATE users SET pass = ?1, must_change = 0 WHERE id = ?2').bind(await hashPass(next), u.id),
        // cierra las demás sesiones abiertas con la contraseña anterior
        db.prepare('DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2').bind(u.id, await sha256(cookieToken(request))),
      ]);
      return json({ ok: true });
    }

    // usuarios del equipo (coaches)
    if (path.startsWith('team/users')) {
      if (!coach) return json({ error: 'forbidden', message: 'Solo los coaches administran el equipo.' }, 403);
      if (path === 'team/users' && method === 'GET') {
        const r = await db.prepare('SELECT * FROM users WHERE team_id = ?1 ORDER BY role, name').bind(team).all();
        return json({ users: (r.results || []).map(publicUser) });
      }
      if (path === 'team/users' && method === 'POST') {
        const c = await createUser(db, team, await body());
        return c.error ? json({ error: 'bad_request', message: c.error }, 400) : json(c);
      }
      if (path === 'team/users/reset' && method === 'POST') {
        const b = await body();
        if (str(b.id, 20) === u.id) return json({ error: 'bad_request', message: 'Para tu propia contraseña usa «Cambiar contraseña».' }, 400);
        const temp = await resetUser(db, str(b.id, 20), team);
        return temp ? json({ temp_password: temp }) : json({ error: 'not_found' }, 404);
      }
      if (path === 'team/users' && method === 'DELETE') {
        const id = str(url.searchParams.get('id'), 20);
        if (id === u.id) return json({ error: 'bad_request', message: 'No puedes darte de baja a ti mismo.' }, 400);
        await db.batch([
          db.prepare('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE id = ?1 AND team_id = ?2)').bind(id, team),
          db.prepare('DELETE FROM users WHERE id = ?1 AND team_id = ?2').bind(id, team),
        ]);
        return json({ ok: true });
      }
    }

    // cada módulo solo responde si el plan del equipo lo incluye
    const modules = parseModules(u.team_modules);
    const off = m => json({ error: 'module_off', module: m, message: m === 'video' ? 'Tu plan no incluye el módulo de video.' : 'Tu plan no incluye el módulo de playbook.' }, 403);
    if ((path === 'videos' || path === 'plays' || path.startsWith('stream')) && !modules.includes('video')) return off('video');
    if (path.startsWith('playbooks') && !modules.includes('playbook')) return off('playbook');

    // ---------- video propio (Cloudflare Stream) ----------
    if (path.startsWith('stream')) {
      const S = await streamRoutes(request, env, db, path, method, url, team, coach, body);
      if (S) return S;
    }

    if (path === 'videos') {
      if (method === 'GET') {
        const r = await db.prepare('SELECT id, title, updated_at FROM tvideos WHERE team_id = ?1 ORDER BY updated_at DESC LIMIT 200').bind(team).all();
        return json({ videos: r.results || [] });
      }
      if (method === 'POST') {
        if (!coach) return json({ error: 'forbidden' }, 403);
        const b = await body();
        if (!VID.test(b.id || '')) return json({ error: 'bad_video' }, 400);
        await db.prepare(`INSERT INTO tvideos (team_id, id, title, updated_at) VALUES (?1, ?2, ?3, ?4)
          ON CONFLICT(team_id, id) DO UPDATE SET title = excluded.title, updated_at = excluded.updated_at`)
          .bind(team, b.id, str(b.title || b.id, 200), Date.now()).run();
        return json({ ok: true });
      }
    }

    if (path === 'plays') {
      if (method === 'GET') {
        const v = url.searchParams.get('v') || '';
        if (!VID.test(v)) return json({ error: 'bad_video' }, 400);
        const r = await db.prepare('SELECT id, data FROM tplays WHERE team_id = ?1 AND video = ?2').bind(team, v).all();
        const plays = (r.results || []).map(row => { try { return { ...JSON.parse(row.data), id: row.id }; } catch (e) { return null; } }).filter(Boolean);
        return json({ plays });
      }
      if (!coach) return json({ error: 'forbidden' }, 403);
      if (method === 'POST') {
        const b = await body();
        if (!VID.test(b.video || '') || !PID.test(b.id || '')) return json({ error: 'bad_request' }, 400);
        const data = JSON.stringify(b.data || {});
        if (data.length > 500000) return json({ error: 'too_large' }, 413);
        const now = Date.now();
        await db.batch([
          db.prepare(`INSERT INTO tplays (team_id, video, id, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(team_id, video, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`).bind(team, b.video, b.id, data, now),
          db.prepare(`INSERT INTO tvideos (team_id, id, title, updated_at) VALUES (?1, ?2, ?2, ?3)
            ON CONFLICT(team_id, id) DO UPDATE SET updated_at = excluded.updated_at`).bind(team, b.video, now),
        ]);
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        const v = url.searchParams.get('v') || '', id = url.searchParams.get('id') || '';
        if (!VID.test(v) || !PID.test(id)) return json({ error: 'bad_request' }, 400);
        await db.prepare('DELETE FROM tplays WHERE team_id = ?1 AND video = ?2 AND id = ?3').bind(team, v, id).run();
        return json({ ok: true });
      }
    }

    // ---------- playbooks (coaches editan, jugadores solo ven) ----------
    if (path === 'playbooks') {
      if (method === 'GET') {
        const r = await db.prepare(`SELECT b.id, b.name, b.format, b.side, b.updated_at,
            (SELECT COUNT(*) FROM pbplays p WHERE p.team_id = b.team_id AND p.book_id = b.id) AS plays
          FROM pbooks b WHERE b.team_id = ?1 ORDER BY b.name COLLATE NOCASE`).bind(team).all();
        return json({ playbooks: r.results || [] });
      }
      if (!coach) return json({ error: 'forbidden', message: 'Solo los coaches editan los playbooks.' }, 403);
      if (method === 'POST') {
        const b = await body();
        const id = str(b.id, 40), name = str(b.name, 80);
        const format = [5, 7, 8, 11, 80].includes(+b.format) ? +b.format : 11, side = b.side === 'D' ? 'D' : 'O';
        if (!PID.test(id)) return json({ error: 'bad_request' }, 400);
        if (!name) return json({ error: 'bad_request', message: 'Escribe el nombre del playbook.' }, 400);
        const n = await db.prepare('SELECT COUNT(*) AS n FROM pbooks WHERE team_id = ?1 AND id != ?2').bind(team, id).first();
        if (n && n.n >= 100) return json({ error: 'too_many', message: 'Tu equipo llegó al máximo de 100 playbooks.' }, 400);
        // el formato y el lado no cambian después de crear el playbook (las jugadas dependen de ellos)
        await db.prepare(`INSERT INTO pbooks (team_id, id, name, format, side, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
          ON CONFLICT(team_id, id) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at`)
          .bind(team, id, name, format, side, Date.now()).run();
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        const id = str(url.searchParams.get('id'), 40);
        await db.batch([
          db.prepare('DELETE FROM pbplays WHERE team_id = ?1 AND book_id = ?2').bind(team, id),
          db.prepare('DELETE FROM pbooks WHERE team_id = ?1 AND id = ?2').bind(team, id),
        ]);
        return json({ ok: true });
      }
    }
    if (path === 'playbooks/plays' || path === 'playbooks/order') {
      const b = method === 'POST' ? await body() : {};
      const book = str(method === 'POST' ? b.book : url.searchParams.get('book'), 40);
      if (!PID.test(book)) return json({ error: 'bad_request' }, 400);
      const exists = await db.prepare('SELECT 1 FROM pbooks WHERE team_id = ?1 AND id = ?2').bind(team, book).first();
      if (!exists) return json({ error: 'not_found', message: 'Ese playbook ya no existe.' }, 404);
      if (path === 'playbooks/plays' && method === 'GET') {
        const r = await db.prepare('SELECT id, pos, data FROM pbplays WHERE team_id = ?1 AND book_id = ?2 ORDER BY pos, updated_at').bind(team, book).all();
        const plays = (r.results || []).map(row => { try { return { ...JSON.parse(row.data), id: row.id, pos: row.pos }; } catch (e) { return null; } }).filter(Boolean);
        return json({ plays });
      }
      if (!coach) return json({ error: 'forbidden', message: 'Solo los coaches editan los playbooks.' }, 403);
      const now = Date.now();
      if (path === 'playbooks/plays' && method === 'POST') {
        if (!PID.test(b.id || '')) return json({ error: 'bad_request' }, 400);
        const data = JSON.stringify(b.data && typeof b.data === 'object' ? b.data : {});
        if (data.length > 200000) return json({ error: 'too_large', message: 'La jugada es demasiado grande.' }, 413);
        const old = await db.prepare('SELECT 1 FROM pbplays WHERE team_id = ?1 AND book_id = ?2 AND id = ?3').bind(team, book, b.id).first();
        if (!old) {
          const n = await db.prepare('SELECT COUNT(*) AS n FROM pbplays WHERE team_id = ?1 AND book_id = ?2').bind(team, book).first();
          if (n && n.n >= 300) return json({ error: 'too_many', message: 'Este playbook llegó al máximo de 300 jugadas.' }, 400);
        }
        await db.batch([
          db.prepare(`INSERT INTO pbplays (team_id, book_id, id, pos, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(team_id, book_id, id) DO UPDATE SET pos = excluded.pos, data = excluded.data, updated_at = excluded.updated_at`)
            .bind(team, book, b.id, Math.max(0, Math.min(9999, Math.floor(+b.pos) || 0)), data, now),
          db.prepare('UPDATE pbooks SET updated_at = ?1 WHERE team_id = ?2 AND id = ?3').bind(now, team, book),
        ]);
        return json({ ok: true });
      }
      if (path === 'playbooks/plays' && method === 'DELETE') {
        const id = str(url.searchParams.get('id'), 40);
        await db.prepare('DELETE FROM pbplays WHERE team_id = ?1 AND book_id = ?2 AND id = ?3').bind(team, book, id).run();
        return json({ ok: true });
      }
      if (path === 'playbooks/order' && method === 'POST') {
        const ids = (Array.isArray(b.ids) ? b.ids : []).slice(0, 300).filter(x => PID.test(String(x)));
        if (ids.length) await db.batch(ids.map((id, i) => db.prepare('UPDATE pbplays SET pos = ?1 WHERE team_id = ?2 AND book_id = ?3 AND id = ?4').bind(i, team, book, id)));
        return json({ ok: true });
      }
    }

    return json({ error: 'not_found' }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: 'server_error', message: 'Error del servidor. Intenta de nuevo.' }, 500);
  }
}

// ---------- Cloudflare Stream ----------
// Secretos del worker: STREAM_TOKEN (permiso Stream: Edit) y STREAM_ACCOUNT_ID.
const streamOn = env => !!(env.STREAM_TOKEN && env.STREAM_ACCOUNT_ID);
const streamApi = (env, path = '', opts = {}) => fetch(`https://api.cloudflare.com/client/v4/accounts/${env.STREAM_ACCOUNT_ID}/stream${path}`,
  { ...opts, headers: { authorization: 'Bearer ' + env.STREAM_TOKEN, ...(opts.headers || {}) } });
const b64 = s => btoa(String.fromCharCode(...enc.encode(s)));
const PENDING = ['uploading', 'processing'];
const publicUpload = v => ({ uid: v.uid, id: 's' + v.uid, name: v.name, status: v.status, seconds: Math.round(v.seconds || 0), size: v.size, created_at: v.created_at });
// segundos ocupados: los listos cuentan su duración real
const usedSeconds = rows => rows.reduce((a, v) => a + (v.status === 'ready' ? (+v.seconds || 0) : 0), 0);
// consulta en Stream el estado de un video que no está listo y lo guarda
async function refreshUpload(env, db, team, v) {
  const r = await streamApi(env, '/' + v.uid);
  if (r.status === 404) {
    // nunca se terminó de subir: después de 1 día se da por perdido
    if (Date.now() - v.created_at > 864e5) { v.status = 'error'; await db.prepare('UPDATE uploads SET status = ?1 WHERE team_id = ?2 AND uid = ?3').bind('error', team, v.uid).run(); }
    return v;
  }
  if (!r.ok) return v;
  const d = (await r.json().catch(() => ({}))).result || {};
  const state = d.status && d.status.state;
  const host = (() => { try { const h = new URL(d.preview || '').hostname; return /^customer-[a-z0-9]+\.cloudflarestream\.com$/.test(h) ? h : null; } catch (e) { return null; } })();
  const status = d.readyToStream && state === 'ready' ? 'ready' : state === 'error' ? 'error' : state === 'pendingupload' ? 'uploading' : 'processing';
  v.status = status; v.seconds = +d.duration > 0 ? +d.duration : 0; v.host = host || v.host;
  await db.prepare('UPDATE uploads SET status = ?1, seconds = ?2, host = ?3 WHERE team_id = ?4 AND uid = ?5').bind(status, v.seconds, v.host, team, v.uid).run();
  // ya listo: aparece en «Partidos guardados»
  if (status === 'ready') await db.prepare(`INSERT INTO tvideos (team_id, id, title, updated_at) VALUES (?1, ?2, ?3, ?4)
    ON CONFLICT(team_id, id) DO NOTHING`).bind(team, 's' + v.uid, v.name, Date.now()).run();
  return v;
}
async function streamRoutes(request, env, db, path, method, url, team, coach, body) {
  const listRows = async () => (await db.prepare('SELECT * FROM uploads WHERE team_id = ?1 ORDER BY created_at DESC').bind(team).all()).results || [];
  const quotaOf = async () => { const t = await db.prepare('SELECT video_hours FROM teams WHERE id = ?1').bind(team).first(); return (t ? +t.video_hours || 0 : 0) * 3600; };
  if (path === 'stream' && method === 'GET') {
    const rows = await listRows();
    if (streamOn(env)) for (const v of rows.filter(v => PENDING.includes(v.status)).slice(0, 5)) await refreshUpload(env, db, team, v);
    return json({ enabled: streamOn(env), quota: await quotaOf(), used: Math.round(usedSeconds(rows)), videos: rows.map(publicUpload) });
  }
  if (path === 'stream/upload' && method === 'POST') {
    if (!coach) return json({ error: 'forbidden', message: 'Solo los coaches suben videos.' }, 403);
    if (!streamOn(env)) return json({ error: 'stream_off', message: 'La subida de video todavía no está activada.' }, 503);
    const b = await body();
    const name = str(b.name, 120), size = Math.floor(+b.size);
    if (!name) return json({ error: 'bad_request', message: 'Escribe el nombre del partido.' }, 400);
    if (!(size > 0 && size <= 30e9)) return json({ error: 'bad_request', message: 'El archivo debe pesar menos de 30 GB.' }, 400);
    const quota = await quotaOf();
    if (!quota) return json({ error: 'no_quota', message: 'Tu plan no incluye horas para subir video. Pide que te las agreguen.' }, 403);
    const rows = await listRows();
    for (const v of rows.filter(v => PENDING.includes(v.status))) await refreshUpload(env, db, team, v);
    // un video a la vez: así la duración máxima de cada uno nunca pasa de lo que le queda al equipo
    if (rows.some(v => PENDING.includes(v.status) && Date.now() - v.created_at < 6 * 3600e3))
      return json({ error: 'busy', message: 'Espera a que termine de subirse y procesarse el video anterior.' }, 409);
    const left = Math.floor(quota - usedSeconds(rows));
    if (left < 60) return json({ error: 'quota', message: `Ya usaste las ${Math.round(quota / 3600)} horas de video de tu plan. Borra partidos viejos o pide horas extra.` }, 403);
    // subida directa (tus): el navegador manda el archivo a Cloudflare por pedazos, sin pasar por este worker
    const r = await streamApi(env, '?direct_user=true', { method: 'POST', headers: {
      'Tus-Resumable': '1.0.0', 'Upload-Length': String(size),
      'Upload-Metadata': `name ${b64(name)},requiresignedurls,maxdurationseconds ${b64(String(left))}`,
    } });
    const uploadUrl = r.headers.get('location') || '', uid = r.headers.get('stream-media-id') || '';
    if (r.status !== 201 || !/^[0-9a-f]{32}$/.test(uid) || !/^https:\/\//.test(uploadUrl)) {
      console.error('stream upload', r.status, await r.text().catch(() => ''));
      return json({ error: 'stream_error', message: 'Cloudflare no aceptó la subida. Intenta de nuevo en unos minutos.' }, 502);
    }
    await db.prepare('INSERT INTO uploads (team_id, uid, name, status, seconds, max_seconds, size, created_at) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7)')
      .bind(team, uid, name, 'uploading', left, size, Date.now()).run();
    return json({ uid, id: 's' + uid, url: uploadUrl, max_seconds: left });
  }
  if (path === 'stream/token' && method === 'POST') {
    if (!streamOn(env)) return json({ error: 'stream_off', message: 'La reproducción de videos subidos no está activada.' }, 503);
    const b = await body(), uid = String(b.id || '').replace(/^s/, '');
    let v = /^[0-9a-f]{32}$/.test(uid) ? await db.prepare('SELECT * FROM uploads WHERE team_id = ?1 AND uid = ?2').bind(team, uid).first() : null;
    if (!v) return json({ error: 'not_found', message: 'Ese video no es de tu equipo.' }, 404);
    if (v.status !== 'ready' || !v.host) v = await refreshUpload(env, db, team, v);
    if (v.status !== 'ready') return json({ error: 'not_ready', message: 'El video todavía se está procesando. Intenta en unos minutos.' }, 409);
    // enlace firmado que vence en 4 horas: solo quien tiene sesión en el equipo lo obtiene
    const r = await streamApi(env, `/${uid}/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 4 * 3600 }) });
    const token = r.ok ? ((await r.json().catch(() => ({}))).result || {}).token : null;
    if (!token || !v.host) { console.error('stream token', r.status); return json({ error: 'stream_error', message: 'No se pudo abrir el video. Intenta de nuevo.' }, 502); }
    return json({ token, iframe: `https://${v.host}/${token}/iframe`, name: v.name, seconds: Math.round(v.seconds) });
  }
  if (path === 'stream' && method === 'DELETE') {
    if (!coach) return json({ error: 'forbidden', message: 'Solo los coaches borran videos.' }, 403);
    const uid = String(url.searchParams.get('uid') || '');
    const v = /^[0-9a-f]{32}$/.test(uid) ? await db.prepare('SELECT uid FROM uploads WHERE team_id = ?1 AND uid = ?2').bind(team, uid).first() : null;
    if (!v) return json({ error: 'not_found' }, 404);
    if (streamOn(env)) {
      const r = await streamApi(env, '/' + uid, { method: 'DELETE' });
      if (!r.ok && r.status !== 404) return json({ error: 'stream_error', message: 'Cloudflare no pudo borrar el video. Intenta de nuevo.' }, 502);
    }
    await db.batch([
      db.prepare('DELETE FROM uploads WHERE team_id = ?1 AND uid = ?2').bind(team, uid),
      db.prepare('DELETE FROM tvideos WHERE team_id = ?1 AND id = ?2').bind(team, 's' + uid),
      db.prepare('DELETE FROM tplays WHERE team_id = ?1 AND video = ?2').bind(team, 's' + uid),
    ]);
    return json({ ok: true });
  }
  return null;
}

// ---------- dominio y cabeceras de seguridad ----------
const CANONICAL = 'sidelinemx.com';
// Política de contenido: solo scripts de este sitio (con nonce por respuesta), de YouTube y del contador de
// Cloudflare Web Analytics (no usa cookies); fuentes de Google.
// Va en modo «solo reportar» hasta confirmar en producción que nada legítimo se bloquea.
const csp = nonce => [
  "default-src 'self'",
  `script-src 'self' 'nonce-${nonce}' https://www.youtube.com https://s.ytimg.com https://static.cloudflareinsights.com https://embed.cloudflarestream.com`,
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: blob: https://i.ytimg.com https://*.cloudflarestream.com",
  'frame-src https://www.youtube.com https://www.youtube-nocookie.com https://*.cloudflarestream.com',
  // subida por pedazos (tus) directo a Cloudflare Stream
  "connect-src 'self' https://cloudflareinsights.com https://*.cloudflarestream.com https://upload.videodelivery.net https://edge-production.gateway.api.cloudflare.com",
  "media-src 'self' blob:",
  "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'none'",
  'report-uri /api/csp-report',
].join('; ');
function secure(res, url) {
  res.headers.set('x-content-type-options', 'nosniff');
  res.headers.set('referrer-policy', 'strict-origin-when-cross-origin');
  // HSTS solo en el dominio real (https obligatorio en el navegador por 180 días)
  if (url.hostname === CANONICAL) res.headers.set('strict-transport-security', 'max-age=15552000');
  return res;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // www.sidelinemx.com → sidelinemx.com (una sola dirección)
    if (url.hostname === 'www.' + CANONICAL) { url.hostname = CANONICAL; return Response.redirect(url.toString(), 301); }
    if (url.pathname.startsWith('/api/')) {
      const r = await handleApi(request, env, url.pathname.slice(5).replace(/\/+$/, ''));
      return secure(new Response(r.body, r), url);
    }
    const asset = await env.ASSETS.fetch(request);
    const res = secure(new Response(asset.body, asset), url);
    // las páginas no se pueden incrustar en otros sitios
    res.headers.set('x-frame-options', 'DENY');
    if (!(res.headers.get('content-type') || '').includes('text/html')) return res;
    const nonce = randHex(16);
    res.headers.set('content-security-policy-report-only', csp(nonce));
    if (typeof HTMLRewriter === 'undefined') return res;
    return new HTMLRewriter().on('script', { element(e) { e.setAttribute('nonce', nonce); } }).transform(res);
  },
};
