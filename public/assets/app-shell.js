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
  const LOCK = '<svg class="lock" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/></svg>';
  window.SidelineShell = {
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
