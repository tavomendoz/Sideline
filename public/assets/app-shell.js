// Sideline — barra superior compartida por los módulos (Video y Playbook): menú de usuario y pestañas.
(() => {
  const $ = id => document.getElementById(id);
  // menús desplegables: <div class="umenu"><button aria-haspopup>…</button><div class="pop" hidden>…</div></div>
  const menus = [...document.querySelectorAll('.umenu')].map(m => ({ btn: m.querySelector('[aria-haspopup]'), pop: m.querySelector('.pop') })).filter(m => m.btn && m.pop);
  const close = except => menus.forEach(m => { if (m !== except && !m.pop.hidden) { m.pop.hidden = true; m.btn.setAttribute('aria-expanded', 'false'); } });
  menus.forEach(m => {
    m.btn.addEventListener('click', e => { e.stopPropagation(); close(m); m.pop.hidden = !m.pop.hidden; m.btn.setAttribute('aria-expanded', String(!m.pop.hidden)); });
    m.pop.addEventListener('click', e => { if (e.target.closest('.pi')) close(); });
  });
  document.addEventListener('click', e => { if (!e.target.closest('.umenu')) close(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
  // tema: automático (según el sistema), claro u oscuro; se recuerda en este navegador
  const THEME_KEY = 'sideline:theme';
  const ICONS = {
    auto: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M12 4a8 8 0 0 1 0 16z" fill="currentColor"/></svg>',
    light: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    dark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" aria-hidden="true"><path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/></svg>',
  };
  const NAMES = { auto: 'automático (como tu dispositivo)', light: 'claro', dark: 'oscuro' };
  const pref = () => { try { const t = localStorage.getItem(THEME_KEY); return t === 'light' || t === 'dark' ? t : 'auto'; } catch (e) { return 'auto'; } };
  const media = window.matchMedia ? matchMedia('(prefers-color-scheme: dark)') : null;
  const isDark = () => { const t = document.documentElement.dataset.theme; return t ? t === 'dark' : !!(media && media.matches); };
  function applyTheme(p) {
    if (p === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = p;
    const b = $('themeBtn');
    if (b) { b.innerHTML = ICONS[p]; b.title = `Tema ${NAMES[p]}. Clic para cambiar.`; b.setAttribute('aria-label', b.title); }
    document.dispatchEvent(new CustomEvent('sideline:theme', { detail: { dark: isDark() } }));
  }
  if ($('themeBtn')) $('themeBtn').addEventListener('click', () => {
    const next = { auto: 'light', light: 'dark', dark: 'auto' }[pref()];
    try { if (next === 'auto') localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, next); } catch (e) {}
    applyTheme(next);
  });
  if (media && media.addEventListener) media.addEventListener('change', () => { if (pref() === 'auto') applyTheme('auto'); });
  applyTheme(pref());

  const LOCK ='<svg class="lock" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/></svg>';
  window.SidelineShell = {
    isDark,
    // muestra quién está conectado (null = sin sesión)
    setUser(user, team) {
      const m = $('userMenu'); if (!m) return;
      m.hidden = !user;
      if (!user) return;
      const ini = String(user.name || user.username || '?').trim().split(/\s+/).slice(0, 2).map(w => w[0] || '').join('').toUpperCase();
      $('userIni').textContent = ini || '?';
      $('userName').textContent = user.name || user.username;
      $('userSub').textContent = `${user.role === 'coach' ? 'Coach' : 'Jugador'} · ${team ? team.name : ''}`;
      if ($('userHead')) $('userHead').textContent = team ? team.name : '';
      document.querySelectorAll('[data-coach-only]').forEach(e => e.hidden = user.role !== 'coach');
    },
    // marca con candado los módulos que el plan del equipo no incluye
    setModules(mods) {
      document.querySelectorAll('.modnav .mod[data-mod]').forEach(a => {
        const off = Array.isArray(mods) && !mods.includes(a.dataset.mod);
        a.classList.toggle('off', off);
        a.title = off ? 'No incluido en el plan de tu equipo' : '';
        const l = a.querySelector('.lock');
        if (off && !l) a.insertAdjacentHTML('beforeend', LOCK);
        if (!off && l) l.remove();
      });
    },
  };
})();
