(() => {
const POLL_MS = 2000;
const state = { events: [], lastId: 0, gen: 0, filter: 'ALL', history: [], busy: false };
const $ = (id) => document.getElementById(id);

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ── 이벤트 폴링 ──
async function poll() {
  try {
    const res = await fetch(`/api/events?since_id=${state.lastId}&gen=${state.gen}`);
    const data = await res.json();
    let fresh = [];
    if (data.reset) {
      state.events = data.events;
    } else {
      fresh = data.events;
      state.events.push(...fresh);
    }
    state.gen = data.gen;
    state.lastId = data.last_id;
    renderStats(data.stats);
    if (data.reset || fresh.length) renderTable(new Set(fresh.map((e) => e.id)));
    $('live').classList.remove('offline');
    $('live').textContent = '실시간 모니터링';
    $('last-update').textContent =
      new Date().toLocaleTimeString('ko-KR', { hour: 'numeric', minute: '2-digit', second: '2-digit' }) + ' 갱신';
  } catch (e) {
    $('live').classList.add('offline');
    $('live').textContent = '서버 연결 끊김';
  }
}

function renderStats(s) {
  $('stat-total').textContent = s.total;
  $('stat-high').textContent = s.high;
  $('stat-medium').textContent = s.medium;
  $('stat-blocked').textContent = s.blocked;
}

function matchFilter(e) {
  if (state.filter === 'ALL') return true;
  if (state.filter === 'HONEYPOT') return /honeypot/i.test(e.reason || '');
  if (state.filter === 'ESCALATE') return ['ESCALATE', 'SIGSTOP', 'RETURN'].includes(e.action) || e.result === 'ESCALATED_TO_HIGH';
  return e.level === state.filter;
}

function renderTable(newIds = new Set()) {
  const rows = state.events.filter(matchFilter).slice().reverse();
  $('event-count').textContent = `${rows.length}개 이벤트`;
  if (!rows.length) {
    $('event-body').innerHTML = `<tr><td colspan="8" class="empty">${state.events.length
      ? '필터에 해당하는 이벤트가 없습니다.'
      : '수신된 이벤트가 없습니다.<br><br>에이전트 실행: <code>python dashboard/agent.py</code> &nbsp;·&nbsp; 샘플: <code>python dashboard/agent.py --demo</code>'}</td></tr>`;
    return;
  }
  $('event-body').innerHTML = rows.slice(0, 500).map((e) => `
    <tr class="lv-${esc(e.level)}${newIds.has(e.id) ? ' new' : ''}">
      <td class="time">${esc(e.time)}</td>
      <td><span class="badge badge-${esc(e.level)}">${esc(e.level)}</span></td>
      <td><span class="pid-link" data-pid="${esc(e.pid)}" title="AI 분석관에게 이 PID 분석 요청">${esc(e.pid)}</span></td>
      <td class="proc">${esc(e.process || '-')}</td>
      <td class="target">${esc(e.target).replace(/\//g, '/<wbr>')}</td>
      <td><span class="action">${esc(e.action)}</span></td>
      <td class="result res-${esc(e.result)}">${esc(e.result)}</td>
      <td class="reason">${esc(e.reason)}</td>
    </tr>`).join('');
}

document.querySelectorAll('.filter-btn').forEach((b) => b.addEventListener('click', () => {
  document.querySelectorAll('.filter-btn').forEach((x) => x.classList.remove('active'));
  b.classList.add('active');
  state.filter = b.dataset.filter;
  renderTable();
}));

// ── AI 분석관 패널 열기/닫기 (기본: 닫힘 → 이벤트 로그 전체 화면) ──
function setAiOpen(open) {
  $('layout').classList.toggle('ai-open', open);
  $('tab-ai').classList.toggle('active', open);
  $('tab-ai').setAttribute('aria-expanded', String(open));
  if (open) {
    $('ai-dot').classList.remove('show');
    $('chat').scrollTop = $('chat').scrollHeight;
    if (window.matchMedia('(max-width: 960px)').matches) $('ai-pane').scrollIntoView({ behavior: 'smooth' });
    else $('input').focus();
  }
}
const aiOpen = () => $('layout').classList.contains('ai-open');
$('tab-ai').addEventListener('click', () => setAiOpen(!aiOpen()));
$('ai-close').addEventListener('click', () => setAiOpen(false));
// ── 메인 뷰 전환 (이벤트 로그 / 파일 상태) ──
function showView(name) {
  $('view-events').hidden = name !== 'events';
  $('view-files').hidden = name !== 'files';
  $('tab-events').classList.toggle('active', name === 'events');
  $('tab-files').classList.toggle('active', name === 'files');
  if (name === 'files') pollFiles();
}
$('tab-events').addEventListener('click', () => showView('events'));
$('tab-files').addEventListener('click', () => showView('files'));
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && aiOpen()) setAiOpen(false); });

$('event-body').addEventListener('click', (ev) => {
  const el = ev.target.closest('.pid-link');
  if (!el) return;
  setAiOpen(true);
  ask(`pid ${el.dataset.pid}가 뭘 한건지 알려줘. 왜 격상됐는지도 설명해줘.`);
});

// ── 마크다운 렌더러 (LLM 응답용, 외부 라이브러리 없이) ──
function inline(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>');
}
function markdown(src) {
  const lines = String(src).replace(/\r/g, '').split('\n');
  const out = [];
  let list = null, inCode = false, code = [];
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  for (const line of lines) {
    if (line.trim().startsWith('```')) {
      if (inCode) { out.push(`<pre><code>${esc(code.join('\n'))}</code></pre>`); code = []; inCode = false; }
      else { closeList(); inCode = true; }
      continue;
    }
    if (inCode) { code.push(line); continue; }
    let m;
    if ((m = line.match(/^\s*#{1,6}\s+(.*)/))) { closeList(); out.push(`<h3>${inline(m[1])}</h3>`); }
    else if ((m = line.match(/^\s*\d+[.)]\s+(.*)/))) {
      if (list !== 'ol') { closeList(); out.push('<ol>'); list = 'ol'; }
      out.push(`<li>${inline(m[1])}</li>`);
    } else if ((m = line.match(/^\s*[-*•]\s+(.*)/))) {
      if (list !== 'ul') { closeList(); out.push('<ul>'); list = 'ul'; }
      out.push(`<li>${inline(m[1])}</li>`);
    } else if ((m = line.match(/^\s*>\s?(.*)/))) { closeList(); out.push(`<blockquote>${inline(m[1])}</blockquote>`); }
    else if (!line.trim()) { closeList(); }
    else { closeList(); out.push(`<p>${inline(line)}</p>`); }
  }
  if (inCode) out.push(`<pre><code>${esc(code.join('\n'))}</code></pre>`);
  closeList();
  return out.join('');
}

// ── 채팅 ──
function addMsg(role, html) {
  const div = document.createElement('div');
  div.className = `msg ${role}`;
  div.innerHTML = `<div class="avatar">${role === 'ai' ? 'AI' : '나'}</div><div class="bubble">${html}</div>`;
  $('chat').appendChild(div);
  $('chat').scrollTop = $('chat').scrollHeight;
  return div;
}

function setBusy(b) {
  state.busy = b;
  $('send').disabled = b;
  document.querySelectorAll('.quick button').forEach((x) => { x.disabled = b; });
  const st = $('ai-status');
  if (b) { st.className = 'busy'; st.textContent = '● 분석 중'; }
  else refreshHealth();
}

async function ask(text) {
  text = (text || '').trim();
  if (!text || state.busy) return;
  addMsg('user', esc(text));
  const pending = addMsg('ai', '<div class="typing"><span></span><span></span><span></span></div>');
  setBusy(true);
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, history: state.history }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    const src = data.sources || {};
    const meta = [
      data.mode === 'llm' ? 'LLM 분석' : '로컬 규칙 기반 분석',
      src.pids && src.pids.length ? `참조 PID: ${src.pids.join(', ')}` : '',
      src.events ? `이벤트 ${src.events}건` : '',
      src.docs && src.docs.length ? `지식: ${src.docs.join(' · ')}` : '',
    ].filter(Boolean).join(' | ');
    pending.querySelector('.bubble').innerHTML = markdown(data.reply) + `<div class="sources">${esc(meta)}</div>`;
    if (!aiOpen()) $('ai-dot').classList.add('show');
    state.history.push({ role: 'user', content: text }, { role: 'assistant', content: data.reply });
    state.history = state.history.slice(-16);
  } catch (e) {
    pending.querySelector('.bubble').innerHTML = `<blockquote>분석 요청 실패: ${esc(e.message)}</blockquote>`;
  } finally {
    setBusy(false);
    $('chat').scrollTop = $('chat').scrollHeight;
  }
}

async function refreshHealth() {
  try {
    const h = await (await fetch('/api/health')).json();
    const st = $('ai-status');
    if (h.llm) { st.className = ''; st.textContent = '● 준비됨'; st.title = h.model; }
    else { st.className = 'local'; st.textContent = '● 로컬 모드'; st.title = 'OPENAI_API_KEY 미설정 — 규칙 기반 분석'; }
  } catch (e) { /* 폴링에서 연결 상태 표시 */ }
}

document.querySelectorAll('.quick button').forEach((b) => b.addEventListener('click', () => ask(b.dataset.q)));
$('send').addEventListener('click', () => { ask($('input').value); $('input').value = ''; autosize(); });
$('input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
    e.preventDefault();
    ask($('input').value); $('input').value = ''; autosize();
  }
});
const autosize = () => { const t = $('input'); t.style.height = 'auto'; t.style.height = Math.min(t.scrollHeight, 120) + 'px'; };
$('input').addEventListener('input', autosize);

// ── 파일 상태 (/api/files, 읽기 전용) ──
const FILE_POLL_MS = 2000;
const files = { data: null, selected: {}, preview: {}, previewKey: {} };
// 비어 있을 때 안내할 시뮬레이터 실행 경로 (보호 폴더는 마운트를 거쳐야 HoldFS가 개입한다)
const SIM_TARGET = {
  protected: '~/guardfs_runtime/mount/sim_target',
  unprotected: '~/guardfs_demo/unprotected/sim_target',
};
const fmtSize = (b) => b >= 1048576 ? (b / 1048576).toFixed(1) + ' MB' : b >= 1024 ? (b / 1024).toFixed(1) + ' KB' : b + ' B';
const hhmmss = (d) => [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, '0')).join(':');
const fmtTime = (t) => hhmmss(new Date(t * 1000));
const filesVisible = () => !$('view-files').hidden;

const STATE_LABEL = {
  ok: ['ok', '✅ 정상'],
  encrypted: ['enc', '🔴 암호화 의심'],
  unknown: ['unknown', '판정 불가'],
  honeypot: ['honey', '🍯 미끼 파일'],
  unreadable: ['unknown', '읽기 실패'],
};

function emptyHtml(folder) {
  const cmd = `python3 experiments/simulators/sim_highentropy.py ${SIM_TARGET[folder.key]} --keep`;
  if (!folder.exists) {
    return `<div class="folder-empty">폴더가 없습니다.<br><code>mkdir -p ${esc(folder.path)}</code></div>`;
  }
  return `<div class="folder-empty">파일이 없습니다. 시뮬레이터를 실행해 보세요.<br><code>${esc(cmd)}</code></div>`;
}

function renderFolder(folder) {
  const key = folder.key;
  const list = $('list-' + key);
  const scroll = list.scrollTop;
  $('path-' + key).textContent = folder.path;

  const enc = folder.files.filter((f) => f.state === 'encrypted').length;
  const ok = folder.files.filter((f) => f.state === 'ok').length;
  const honey = folder.files.filter((f) => f.state === 'honeypot').length;
  $('sum-' + key).innerHTML = folder.files.length
    ? `<span class="sum ok">정상 ${ok}</span>` + (enc ? `<span class="sum bad">암호화 ${enc}</span>` : '')
      + (honey ? `<span class="sum honey" title="정상/암호화 개수에서 제외">미끼 ${honey}</span>` : '')
    : '';

  if (!folder.files.length) {
    list.innerHTML = emptyHtml(folder);
    $('preview-' + key).innerHTML = '';
    files.selected[key] = null;
    return;
  }

  // 선택 유지. 없으면 암호화 의심 파일 → 첫 파일 순으로 고른다.
  let sel = folder.files.find((f) => f.path === files.selected[key]);
  if (!sel) sel = folder.files.find((f) => f.state === 'encrypted') || folder.files[0];
  files.selected[key] = sel.path;

  list.innerHTML = folder.files.map((f) => {
    const [cls, label] = STATE_LABEL[f.state] || STATE_LABEL.unknown;
    const hi = f.state === 'encrypted';
    const hp = f.state === 'honeypot';
    const ent = f.entropy;
    return `<li class="file-row${hi ? ' enc' : ''}${hp ? ' honey' : ''}${f.path === sel.path ? ' selected' : ''}" data-key="${key}" data-path="${esc(f.path)}">
      <div class="fname">${f.dir ? `<span class="fdir">${esc(f.dir)}/</span>` : ''}${esc(f.name)}${f.ransom_ext ? '<span class="tag-ext">의심 확장자</span>' : ''}</div>
      <span class="fstate ${cls}">${label}</span>
      <div><div class="entbar${hi ? ' hi' : ''}${hp ? ' honey' : ''}"><span style="width:${ent == null ? 0 : (ent / 8 * 100).toFixed(1)}%"></span></div>
           <div class="entval">${ent == null ? '샘플 부족' : '엔트로피 ' + ent.toFixed(2)}</div></div>
      <div class="fmeta">${fmtSize(f.size)}<br>${fmtTime(f.mtime)}</div>
    </li>`;
  }).join('') + (folder.truncated ? '<li class="folder-empty">파일이 많아 일부만 표시합니다.</li>' : '');
  list.scrollTop = scroll;
  loadPreview(key, sel);
}

async function loadPreview(key, f) {
  const pkey = `${f.path}|${f.mtime}|${f.size}`;
  if (files.previewKey[key] !== pkey) {
    files.previewKey[key] = pkey;
    try {
      const res = await fetch(`/api/files/preview?folder=${key}&path=${encodeURIComponent(f.path)}`);
      files.preview[key] = res.ok ? await res.json() : { kind: 'error' };
    } catch (e) {
      files.preview[key] = { kind: 'error' };
    }
  }
  const p = files.preview[key];
  if (!p || files.selected[key] !== f.path) return;
  const desc = p.kind === 'text' ? '앞부분 텍스트' : p.kind === 'hex' ? `앞부분 ${p.bytes} 바이트 (hex)` : '';
  $('preview-' + key).innerHTML = `
    <div class="preview-head"><span>미리보기 · <b>${esc(f.path)}</b></span><span>${desc}</span></div>
    <pre class="${p.kind === 'hex' ? 'hex' : ''}">${p.kind === 'error' ? '미리보기를 불러오지 못했습니다.' : esc(p.content)}</pre>`;
}

function renderFiles() {
  if (!files.data) return;
  $('files-threshold').textContent = files.data.threshold.toFixed(1);
  files.data.folders.forEach(renderFolder);
}

async function pollFiles() {
  if (!filesVisible()) return;
  try {
    const res = await fetch('/api/files');
    files.data = await res.json();
    renderFiles();
    $('files-updated').textContent = hhmmss(new Date()) + ' 갱신';
  } catch (e) {
    $('files-updated').textContent = '서버 연결 끊김';
  }
}

$('view-files').addEventListener('click', (ev) => {
  const row = ev.target.closest('.file-row');
  if (!row) return;
  files.selected[row.dataset.key] = row.dataset.path;
  renderFiles();
});

setInterval(pollFiles, FILE_POLL_MS);

refreshHealth();
poll();
setInterval(poll, POLL_MS);
})();
