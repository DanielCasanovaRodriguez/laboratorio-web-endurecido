"use strict";
(function () {
  /* ---------- Tema ---------- */
  var root = document.documentElement,
      tBtn = document.getElementById('themeBtn'),
      tIco = document.getElementById('themeIco'),
      tTxt = document.getElementById('themeTxt');
  function sysDark(){ return window.matchMedia && window.matchMedia('(prefers-color-scheme:dark)').matches; }
  function curDark(){ var a = root.getAttribute('data-theme'); return a ? a === 'dark' : sysDark(); }
  function paintBtn(){ var d = curDark(); tIco.textContent = d ? '☀' : '☾'; tTxt.textContent = d ? 'Claro' : 'Oscuro'; }
  try { var sv = localStorage.getItem('lab_theme'); if (sv === 'dark' || sv === 'light') root.setAttribute('data-theme', sv); } catch (e) {}
  paintBtn();
  tBtn.addEventListener('click', function () {
    var next = curDark() ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('lab_theme', next); } catch (e) {}
    paintBtn();
  });

  /* ---------- 1. Cabeceras en vivo ---------- */
  var HEADERS = [
    { k:'content-security-policy', meta:'csp', d:'Define de dónde pueden cargarse scripts, estilos e imágenes. Es la barrera principal contra el XSS.' },
    { k:'strict-transport-security', d:'Obliga al navegador a usar siempre HTTPS, bloqueando ataques de downgrade y de intermediario (MITM).' },
    { k:'x-content-type-options', d:'Con nosniff impide que el navegador adivine el tipo de un recurso y lo ejecute como algo que no es.' },
    { k:'x-frame-options', d:'Impide que la página se incruste dentro de un iframe ajeno. Defensa contra el clickjacking.' },
    { k:'referrer-policy', meta:'ref', d:'Controla cuánta información de la URL de origen se envía al seguir enlaces, reduciendo fugas de datos.' },
    { k:'permissions-policy', d:'Desactiva APIs sensibles del navegador (cámara, micrófono, geolocalización) que la página no necesita.' },
    { k:'cross-origin-opener-policy', d:'Aísla esta ventana de otros orígenes para frenar ataques entre ventanas (XS-Leaks).' }
  ];
  var hdlist = document.getElementById('hdlist');
  function row(h, status){
    var r = document.createElement('div'); r.className = 'hdrow';
    var b = document.createElement('span');
    b.className = 'badge ' + (status === 'ok' ? 'ok' : status === 'meta' ? 'ok' : status === 'miss' ? 'miss' : 'wait');
    b.textContent = status === 'ok' ? '✓ activa' : status === 'meta' ? '✓ activa (meta)' : status === 'miss' ? '— no detectada' : '…';
    var n = document.createElement('div'); n.className = 'hdname'; n.textContent = h.k;
    var d = document.createElement('div'); d.className = 'hddesc'; d.textContent = h.d;
    r.appendChild(b); r.appendChild(n); r.appendChild(d); return r;
  }
  HEADERS.forEach(function (h) { hdlist.appendChild(row(h, 'wait')); });
  var scanState = document.getElementById('scanState'), pulse = document.getElementById('pulse');
  function metaPresent(kind){
    if (kind === 'csp') return !!document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
    if (kind === 'ref') return !!document.querySelector('meta[name="referrer" i]');
    return false;
  }
  (function scan(){
    fetch(location.href, { method:'GET', cache:'no-store' }).then(function (res) {
      var active = 0; hdlist.innerHTML = '';
      HEADERS.forEach(function (h) {
        var inHeader = false; try { inHeader = res.headers.get(h.k) !== null; } catch (e) {}
        var status = inHeader ? 'ok' : (h.meta && metaPresent(h.meta)) ? 'meta' : 'miss';
        if (status !== 'miss') active++;
        hdlist.appendChild(row(h, status));
      });
      scanState.textContent = active + ' de ' + HEADERS.length + ' protecciones activas (cabecera del servidor o <meta> equivalente).';
      pulse.style.background = active === HEADERS.length ? 'var(--ok)' : 'var(--warn)';
    }).catch(function () {
      var active = 0; hdlist.innerHTML = '';
      HEADERS.forEach(function (h) {
        var status = (h.meta && metaPresent(h.meta)) ? 'meta' : 'wait';
        if (status === 'meta') active++;
        hdlist.appendChild(row(h, status));
      });
      scanState.textContent = 'No se pudo leer la respuesta en vivo; se muestran las protecciones declaradas por <meta> y la función de cada cabecera.';
      pulse.style.background = 'var(--warn)';
    });
  })();

  /* ---------- 2. Defensas ---------- */
  var DEFS = [
    { t:'XSS', th:'Inyección de scripts', html:'CSP que solo permite <span class="chip">script-src \'self\'</span>: ningún script inline o inyectado se ejecuta. Salida con <span class="chip">textContent</span>.' },
    { t:'Clickjacking', th:'Engaño con iframes', html:'<span class="chip">frame-ancestors \'none\'</span> más <span class="chip">X-Frame-Options: DENY</span>.' },
    { t:'MIME sniffing', th:'Tipo adivinado', html:'<span class="chip">X-Content-Type-Options: nosniff</span> para que nada se interprete fuera de su tipo.' },
    { t:'Downgrade / MITM', th:'Intermediario', html:'HTTPS forzado con <span class="chip">HSTS</span>; sin canal en claro que interceptar.' },
    { t:'SQLi / RCE', th:'Ataque al servidor', html:'No hay servidor de aplicación ni base de datos: no existe superficie que atacar.' },
    { t:'Fuga de datos', th:'Exfiltración', html:'<span class="chip">Referrer-Policy: no-referrer</span> y APIs del navegador desactivadas.' },
    { t:'DDoS', th:'Saturación', html:'Contenido estático servido y mitigado por la CDN del hosting.' }
  ];
  var defgrid = document.getElementById('defgrid');
  DEFS.forEach(function (x) {
    var c = document.createElement('div'); c.className = 'def';
    var th = document.createElement('div'); th.className = 'thr'; th.textContent = x.th;
    var h = document.createElement('h3'); h.textContent = x.t;
    var p = document.createElement('p'); p.innerHTML = x.html; // contenido fijo y propio, no entrada de usuario
    c.appendChild(th); c.appendChild(h); c.appendChild(p); defgrid.appendChild(c);
  });

  /* ---------- 3. Libro de visitas (XSS seguro) ---------- */
  var KEY = 'lab_guestbook',
      form = document.getElementById('gbForm'),
      inName = document.getElementById('gbName'),
      inMsg = document.getElementById('gbMsg'),
      entries = document.getElementById('entries'),
      hint = document.getElementById('gbHint');

  var SEED = { name:"visitante_anonimo", msg:"<script>alert('XSS')<\/script>  <img src=x onerror=alert(1)>", ts:0, example:true };

  function load(){ try { var r = localStorage.getItem(KEY); return r ? JSON.parse(r) : []; } catch (e) { return []; } }
  function save(a){ try { localStorage.setItem(KEY, JSON.stringify(a)); } catch (e) {} }

  function makeEntry(item){
    var e = document.createElement('div'); e.className = 'entry';
    var meta = document.createElement('div'); meta.className = 'meta';
    var who = document.createElement('span'); who.className = 'who';
    who.textContent = item.name;                 // texto plano: el payload no se ejecuta
    meta.appendChild(who);
    var tag = document.createElement('span'); tag.className = 'tag';
    tag.textContent = item.example ? 'ejemplo' : 'tú'; meta.appendChild(tag);
    var msg = document.createElement('p'); msg.className = 'msg';
    msg.textContent = item.msg;                   // textContent, nunca innerHTML
    var note = document.createElement('p'); note.className = 'note';
    note.textContent = '▲ Si escribiste código, mira: aparece literal. El navegador lo trató como texto, no lo interpretó.';
    e.appendChild(meta); e.appendChild(msg); e.appendChild(note);
    return e;
  }

  function render(){
    entries.innerHTML = '';
    entries.appendChild(makeEntry(SEED));
    load().slice().reverse().forEach(function (it) { entries.appendChild(makeEntry(it)); });
  }

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var n = inName.value.trim(), m = inMsg.value.trim();
    if (!n || !m) return;
    var a = load(); a.push({ name:n, msg:m, ts:Date.now() }); save(a);
    inName.value = ''; inMsg.value = ''; render();
    hint.textContent = 'Publicado. Se guardó como texto en tu navegador (sin ejecutar nada).';
    if (entries.children[1]) entries.children[1].scrollIntoView({ behavior:'smooth', block:'nearest' });
  });
  document.getElementById('gbClear').addEventListener('click', function () {
    try { localStorage.removeItem(KEY); } catch (e) {}
    render();
    hint.textContent = 'Tus mensajes se borraron de este navegador.';
  });

  render();
})();
