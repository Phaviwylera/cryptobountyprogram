"""The dashboard HTML (served at /). Self-contained: no external assets, dark tech theme."""

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>bountyscan control</title>
<style>
  :root{
    --bg:#0a0e14; --panel:#111722; --panel2:#0d131c; --line:#1e2733; --ink:#e6edf3;
    --mut:#7d8aa0; --acc:#38e0b0; --acc2:#2bb3ff; --crit:#ff4d6d; --high:#ff9f43; --ok:#3ad07a; --warn:#f5c542;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#13202e 0%,var(--bg) 55%);
    color:var(--ink);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;min-height:100vh}
  header{display:flex;align-items:center;gap:14px;padding:14px 24px;border-bottom:1px solid var(--line);
    position:sticky;top:0;background:rgba(10,14,20,.88);backdrop-filter:blur(8px);z-index:5}
  .logo{font-weight:700;letter-spacing:.5px;font-size:18px} .logo b{color:var(--acc)}
  .pill{display:inline-flex;align-items:center;gap:7px;padding:4px 11px;border-radius:999px;font:600 12px var(--mono);
    border:1px solid var(--line);color:var(--mut);background:var(--panel2)}
  .pill .d{width:8px;height:8px;border-radius:50%;background:var(--mut)}
  .pill.live{color:var(--ok);border-color:rgba(58,208,122,.4)} .pill.live .d{background:var(--ok);animation:pulse 1.6s infinite}
  .pill.drain{color:var(--acc2);border-color:rgba(43,179,255,.4)} .pill.drain .d{background:var(--acc2);animation:pulse 1.6s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(58,208,122,.55)}70%{box-shadow:0 0 0 9px rgba(58,208,122,0)}100%{box-shadow:0 0 0 0 rgba(58,208,122,0)}}
  .wrap{max-width:1180px;margin:0 auto;padding:22px 24px 60px}
  .muted{color:var(--mut)} .mono{font-family:var(--mono)}

  /* NOW panel */
  .now{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-bottom:16px;
    position:relative;overflow:hidden}
  .now .lbl{font:600 11px var(--mono);letter-spacing:.8px;color:var(--mut);text-transform:uppercase}
  .now .stage{font-size:16px;font-weight:600;margin:4px 0 10px;min-height:24px}
  .now .meta{display:flex;gap:18px;flex-wrap:wrap;font:12px var(--mono);color:var(--mut)}
  .bar{height:6px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);overflow:hidden;position:relative}
  .bar .fill{height:100%;width:0;background:linear-gradient(90deg,var(--acc),var(--acc2));transition:width .6s ease}
  .bar.indet .fill{width:35%;position:absolute;animation:slide 1.4s ease-in-out infinite}
  @keyframes slide{0%{left:-35%}100%{left:100%}}
  .bar.off .fill{width:0;animation:none}

  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:18px}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
  .stat .n{font-size:24px;font-weight:700;font-family:var(--mono);transition:color .3s}
  .stat .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
  .stat.crit .n{color:var(--crit)} .stat.ok .n{color:var(--ok)} .stat.acc .n{color:var(--acc)} .stat.warn .n{color:var(--warn)}
  .stat.bump{animation:bump .5s ease}
  @keyframes bump{0%{transform:scale(1)}40%{transform:scale(1.05)}100%{transform:scale(1)}}

  .cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:860px){.cols{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}
  .card h2{margin:0 0 4px;font-size:16px} .card p{color:var(--mut);margin:0 0 12px;font-size:13px}
  label{display:block;color:var(--mut);font-size:12px;margin:10px 0 4px}
  input,textarea,select{width:100%;background:var(--panel2);border:1px solid var(--line);color:var(--ink);
    border-radius:8px;padding:9px 11px;font-family:var(--mono);font-size:13px}
  textarea{resize:vertical;min-height:70px}
  .row{display:flex;gap:8px;margin-top:12px}
  .btn{appearance:none;border:0;border-radius:10px;padding:12px 16px;font-weight:650;font-size:14px;cursor:pointer;
    color:#06130f;flex:1;transition:filter .15s,opacity .2s,transform .05s;display:inline-flex;align-items:center;justify-content:center;gap:8px}
  .btn:hover{filter:brightness(1.08)} .btn:active{transform:translateY(1px)}
  .btn:disabled{opacity:.55;cursor:default;filter:none}
  .btn.live{background:linear-gradient(135deg,var(--acc),#13b98a)}
  .btn.live.running{background:#0f2a22;color:var(--ok);border:1px solid rgba(58,208,122,.45)}
  .btn.imm{background:linear-gradient(135deg,var(--acc2),#1f74ff);color:#fff}
  .btn.stop{background:#26303d;color:var(--ink);border:1px solid var(--line);flex:0 0 auto}
  .btn.ghost{background:transparent;color:var(--mut);border:1px solid var(--line);flex:0 0 auto}
  .spin{width:14px;height:14px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:rot .7s linear infinite}
  @keyframes rot{to{transform:rotate(360deg)}}

  .batch{margin-top:14px;padding-top:12px;border-top:1px dashed var(--line)}
  .batch .top{display:flex;justify-content:space-between;font-size:12px;margin-bottom:6px}
  .batch .top b{font-family:var(--mono)}

  .sec{display:flex;align-items:center;justify-content:space-between;margin:24px 0 10px}
  .sec h3{margin:0;font-size:14px;text-transform:uppercase;letter-spacing:.7px;color:var(--mut)}
  .feed{background:var(--panel);border:1px solid var(--line);border-radius:14px;max-height:340px;overflow:auto}
  .ev{display:flex;gap:12px;padding:9px 14px;border-bottom:1px solid var(--line);font-size:13px;align-items:baseline}
  .ev:last-child{border-bottom:0}
  .ev.new{animation:fadein .7s ease}
  @keyframes fadein{from{opacity:0;transform:translateY(-6px);background:rgba(56,224,176,.10)}to{opacity:1;transform:none;background:transparent}}
  .ev .t{font:11px var(--mono);color:var(--mut);flex:0 0 64px}
  .ev .k{font:700 10px var(--mono);padding:2px 7px;border-radius:999px;flex:0 0 auto;text-transform:uppercase}
  .k.vulnerable{background:rgba(255,77,109,.16);color:var(--crit)} .k.safe{background:rgba(58,208,122,.14);color:var(--ok)}
  .k.found{background:rgba(43,179,255,.14);color:var(--acc2)} .k.unverified{background:rgba(245,197,66,.13);color:var(--warn)}
  .k.info{background:#1a2230;color:var(--mut)} .k.error{background:rgba(255,77,109,.1);color:var(--crit)}
  .k.no_code,.k.low_value,.k.unverified_final{background:#1a2230;color:var(--mut)}
  .ev .m{word-break:break-all} .ev.vulnerable .m{color:#ffd0d8;font-weight:600}

  .tabs{display:flex;gap:6px;flex-wrap:wrap}
  .tab{padding:6px 13px;border:1px solid var(--line);border-radius:999px;color:var(--mut);cursor:pointer;font-size:12px}
  .tab.active{color:var(--ink);border-color:var(--acc);background:#0f1b1a}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
  th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
  td.addr{font-family:var(--mono)}
  tr.click{cursor:pointer} tr.click:hover{background:#0f1721}
  .sev{display:inline-block;padding:2px 9px;border-radius:999px;font:700 11px var(--mono)}
  .sev.critical{background:rgba(255,77,109,.15);color:var(--crit)} .sev.high{background:rgba(255,159,67,.15);color:var(--high)}
  .empty{color:var(--mut);padding:26px;text-align:center}
  dialog{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:14px;max-width:920px;width:94%;padding:0}
  dialog::backdrop{background:rgba(2,6,12,.75)}
  .modhead{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;border-bottom:1px solid var(--line)}
  .modbody{padding:18px;max-height:72vh;overflow:auto}
  pre{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto;
    font-family:var(--mono);font-size:12.5px;white-space:pre-wrap;word-break:break-word;margin:0}
  .x{cursor:pointer;color:var(--mut);font-size:22px;border:0;background:0}
  .toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:8px;z-index:50}
  .toast{background:#132030;border:1px solid var(--line);border-left:3px solid var(--acc);border-radius:10px;padding:10px 14px;
    font-size:13px;max-width:360px;box-shadow:0 8px 30px rgba(0,0,0,.4);animation:tin .3s ease}
  .toast.err{border-left-color:var(--crit)}
  .toast.out{animation:tout .4s ease forwards}
  @keyframes tin{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
  @keyframes tout{to{opacity:0;transform:translateY(10px)}}
</style>
</head>
<body>
<header>
  <span class="logo"><b>bounty</b>scan</span>
  <span class="pill" id="modePill"><span class="d"></span><span id="modeText">IDLE</span></span>
  <span style="flex:1"></span>
  <span class="muted mono" id="rpcLabel" style="font-size:12px"></span>
</header>

<div class="wrap">
  <!-- What is happening right now -->
  <div class="now">
    <div class="lbl">Now</div>
    <div class="stage" id="stage">Idle</div>
    <div class="bar off" id="stageBar"><div class="fill"></div></div>
    <div class="meta" style="margin-top:10px">
      <span id="mChain"></span><span id="mBlock"></span><span id="mElapsed"></span><span id="mUptime"></span>
    </div>
    <div id="batches"></div>
  </div>

  <div class="grid" id="stats"></div>

  <div class="cols">
    <div class="card">
      <h2>Live Scan</h2>
      <p>Follows the chain 24/7. Every newly deployed verified contract is fetched, scanned, independently re-verified, then the next one starts automatically. Progress shows in the Now panel and the activity feed.</p>
      <label>Chain</label>
      <select id="liveChain">
        <option>ethereum</option><option>base</option><option>arbitrum</option><option>optimism</option>
        <option>polygon</option><option>bsc</option><option>avalanche</option>
      </select>
      <label>Min native balance to bother scanning (0 = all)</label>
      <input id="liveMinBal" value="0" inputmode="decimal">
      <label>Start from block (blank = chain head)</label>
      <input id="liveFromBlock" placeholder="latest">
      <div class="row">
        <button class="btn live" id="btnLive">Start live scan</button>
        <button class="btn stop" id="btnStop">Stop</button>
      </div>
    </div>

    <div class="card">
      <h2>Immunefi Scan</h2>
      <p>Scan a bounty program's in-scope contracts. A progress bar appears above showing how many are done.</p>
      <label>Program name</label>
      <input id="immName" placeholder="acme-protocol">
      <label>In-scope addresses (one per line: <span class="mono">chain:0x..</span> or <span class="mono">0x..</span>)</label>
      <textarea id="immAddrs" placeholder="ethereum:0x....&#10;0x...."></textarea>
      <label>…or a scope file path on the server (optional)</label>
      <input id="immScope" placeholder="programs/acme.json">
      <div class="row">
        <button class="btn imm" id="btnImm">Scan program</button>
      </div>
    </div>
  </div>

  <div class="sec"><h3>Activity</h3><span class="muted mono" id="evCount" style="font-size:12px"></span></div>
  <div class="feed" id="feed"><div class="empty">No activity yet. Start a scan.</div></div>

  <div class="sec">
    <h3>Results</h3>
    <div class="tabs" id="tabs">
      <div class="tab active" data-t="results">Vulnerable</div>
      <div class="tab" data-t="safe">Safe</div>
      <div class="tab" data-t="errors">Errors</div>
    </div>
  </div>
  <div class="card" style="padding:0;overflow:hidden"><div id="tableWrap"><div class="empty">Loading…</div></div></div>
</div>

<dialog id="modal">
  <div class="modhead"><strong id="modTitle" class="mono">report</strong>
    <button class="x" onclick="document.getElementById('modal').close()">×</button></div>
  <div class="modbody"><pre id="modBody"></pre></div>
</dialog>
<div class="toasts" id="toasts"></div>

<script>
const $ = s => document.querySelector(s);
const api = (p,m,b) => fetch(p,{method:m||'GET',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):null})
  .then(async r => { const j = await r.json().catch(()=>({})); if(!r.ok && !j.error) j.error = 'HTTP '+r.status; return j; });
let tab = 'results', seenEvents = new Set(), firstLoad = true, lastCounts = {}, busyBtn = null;

function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function short(a){return a?a.slice(0,10)+'…'+a.slice(-6):'';}
function ago(sec){sec=Math.max(0,Math.round(sec)); if(sec<60)return sec+'s'; if(sec<3600)return Math.floor(sec/60)+'m '+(sec%60)+'s'; return Math.floor(sec/3600)+'h '+Math.floor(sec%3600/60)+'m';}
function clock(t){return new Date(t*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function toast(msg, err){
  const el = document.createElement('div'); el.className = 'toast'+(err?' err':''); el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(()=>{el.classList.add('out'); setTimeout(()=>el.remove(),400);}, 4200);
}
function setBusy(btn, text){ btn.dataset.label = btn.dataset.label || btn.textContent; btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span>${esc(text)}`; busyBtn = btn; }
function clearBusy(btn){ if(!btn)return; btn.disabled = false; btn.textContent = btn.dataset.label; if(busyBtn===btn) busyBtn=null; }

async function refresh(){
  let s; try{ s = await api('/api/status'); }catch{ return; }
  const busy = s.mode !== 'idle';
  // header pill
  const pill = $('#modePill');
  pill.className = 'pill' + (s.mode==='live' ? ' live' : s.mode==='draining' ? ' drain' : '');
  $('#modeText').textContent = s.mode==='live' ? 'LIVE' : s.mode==='draining' ? 'SCANNING QUEUE' : 'IDLE';
  $('#rpcLabel').textContent = (s.rpc ? 'rpc connected' : 'no rpc') + (s.verify ? ' · independent verification on' : '');
  // NOW panel
  $('#stage').textContent = s.stage || (busy ? 'Working…' : 'Idle');
  const bar = $('#stageBar');
  bar.className = 'bar ' + (busy ? 'indet' : 'off');
  $('#mChain').textContent = busy ? 'chain: '+s.chain : '';
  $('#mBlock').textContent = s.cursor ? 'last block read: '+Number(s.cursor).toLocaleString() : '';
  $('#mElapsed').textContent = busy ? 'this step: '+ago(s.stage_age) : '';
  $('#mUptime').textContent = s.started_at && busy ? 'running for: '+ago(Date.now()/1000 - s.started_at) : '';
  // batches (Immunefi / lists)
  const bs = (s.batches||[]).filter(b => b.total>0).slice(-3).reverse();
  $('#batches').innerHTML = bs.map(b => {
    const pct = Math.round(100*b.done/b.total);
    const finished = b.done >= b.total;
    return `<div class="batch"><div class="top"><span>${esc(b.program)} — ${finished?'<span style="color:var(--ok)">complete</span>':'scanning'}</span>
      <b>${b.done}/${b.total} (${pct}%)</b></div>
      <div class="bar"><div class="fill" style="width:${pct}%"></div></div>
      <div class="muted mono" style="font-size:11px;margin-top:5px">${b.vulnerable} vulnerable · ${b.safe} safe · ${b.waiting_verification} waiting for explorer verification</div></div>`;
  }).join('');
  // stats with a little bump when a number changes
  const c = s.counts||{};
  const stats = [['vulnerable',c.vulnerable||0,'crit'],['safe',c.safe||0,'ok'],['in queue',s.pending||0,'acc'],
    ['awaiting verify',c.unverified||0,'warn'],['skipped',(c.no_code||0)+(c.low_value||0)+(c.unverified_final||0),''],
    ['errors',c.error||0,''],['scanned (session)',s.scanned_this_session||0,'']];
  $('#stats').innerHTML = stats.map(([l,n,k])=>`<div class="stat ${k}${(lastCounts[l]!==undefined && lastCounts[l]!==n)?' bump':''}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');
  stats.forEach(([l,n])=>lastCounts[l]=n);
  // live button state
  const lb = $('#btnLive');
  if(busyBtn !== lb){
    if(s.mode==='live'){ lb.classList.add('running'); lb.innerHTML = '<span class="spin"></span>Live scan running'; lb.disabled = true; }
    else { lb.classList.remove('running'); lb.textContent = 'Start live scan'; lb.disabled = false; }
  }
  $('#btnStop').disabled = !busy;
  // activity feed (newest first, new rows fade in)
  const evs = (s.events||[]).slice().reverse();
  $('#evCount').textContent = evs.length ? evs.length+' recent events' : '';
  if(evs.length){
    $('#feed').innerHTML = evs.map(e => {
      const isNew = !firstLoad && !seenEvents.has(e.id);
      return `<div class="ev ${esc(e.kind)}${isNew?' new':''}"><span class="t">${clock(e.t)}</span>
        <span class="k ${esc(e.kind)}">${esc(e.kind.replace('_',' '))}</span><span class="m">${esc(e.msg)}</span></div>`;
    }).join('');
    evs.forEach(e => {
      if(!firstLoad && !seenEvents.has(e.id) && e.kind==='vulnerable') toast('⚠ '+e.msg, true);
      seenEvents.add(e.id);
    });
  }
  firstLoad = false;
  loadTable();
}

async function loadTable(){
  const ep = tab==='results'?'/api/results':tab==='safe'?'/api/safe':'/api/errors';
  let d; try{ d = await api(ep); }catch{ return; }
  const rows = d[tab==='results'?'results':tab]||[];
  const w = $('#tableWrap');
  if(!rows.length){ w.innerHTML = `<div class="empty">${tab==='results'?'No confirmed vulnerabilities yet. Findings appear here the moment the second pass confirms them.':'Nothing here yet.'}</div>`; return; }
  if(tab==='results'){
    w.innerHTML = `<table><thead><tr><th>Severity</th><th>Findings</th><th>Chain</th><th>Address</th><th>Contract</th><th>Balance</th></tr></thead><tbody>`
      + rows.map(r=>`<tr class="click" onclick="openReport('${esc(r.chain)}','${esc(r.address)}')">
        <td><span class="sev ${esc(r.max_severity)}">${esc(r.max_severity)}</span></td><td class="mono">${r.findings||0}</td><td>${esc(r.chain)}</td>
        <td class="addr">${short(r.address)}</td><td>${esc(r.name||'')}</td>
        <td class="mono">${r.balance==null?'?':r.balance.toFixed(4)}</td></tr>`).join('') + `</tbody></table>`;
  } else {
    w.innerHTML = `<table><thead><tr><th>Chain</th><th>Address</th><th>Contract</th><th>Note</th></tr></thead><tbody>`
      + rows.map(r=>`<tr><td>${esc(r.chain)}</td><td class="addr">${short(r.address)}</td><td>${esc(r.name||'')}</td><td class="muted">${esc(r.error||'clear')}</td></tr>`).join('')+`</tbody></table>`;
  }
}

async function openReport(chain,addr){
  const d = await api(`/api/result?chain=${chain}&addr=${addr}`);
  $('#modTitle').textContent = `${chain} ${addr}`;
  $('#modBody').textContent = d.markdown || JSON.stringify(d,null,2);
  $('#modal').showModal();
}

$('#tabs').addEventListener('click',e=>{
  if(!e.target.classList.contains('tab'))return;
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  e.target.classList.add('active'); tab = e.target.dataset.t; loadTable();
});

$('#btnLive').onclick = async()=>{
  const btn = $('#btnLive'); setBusy(btn, 'Starting…');
  const fb = $('#liveFromBlock').value.trim();
  const r = await api('/api/live/start','POST',{chain:$('#liveChain').value,
    min_balance:parseFloat($('#liveMinBal').value||'0')||0, from_block: fb?parseInt(fb):null});
  clearBusy(btn);
  if(r.error) toast('Could not start: '+r.error, true); else toast('Live scan started on '+$('#liveChain').value+'. Watch the Now panel and Activity feed.');
  refresh();
};
$('#btnStop').onclick = async()=>{
  const btn = $('#btnStop'); setBusy(btn,'Stopping…');
  await api('/api/live/stop','POST',{}); clearBusy(btn);
  toast('Stopping - the current contract finishes first.'); refresh();
};

function addrLines(){return $('#immAddrs').value.split('\n').map(x=>x.trim()).filter(Boolean);}
function parseAssets(lines){return lines.map(l=>{const m=l.match(/^(?:([\w-]+)[:,\s]+)?(0x[0-9a-fA-F]{40})$/);
  return m?{chain:(m[1]||'ethereum').toLowerCase(),address:m[2]}:null;}).filter(Boolean);}

$('#btnImm').onclick = async()=>{
  const scope = $('#immScope').value.trim();
  const assets = parseAssets(addrLines());
  if(!scope && !assets.length) return toast('Paste at least one valid 0x address (40 hex chars).', true);
  const btn = $('#btnImm'); setBusy(btn,'Queuing…');
  const body = scope ? {scope_path:scope} : {program:$('#immName').value||'manual', assets};
  const r = await api('/api/immunefi/scan','POST',body);
  clearBusy(btn);
  if(r.error) return toast('Error: '+r.error, true);
  toast(`Scanning ${r.total} contract(s) for "${r.program}" - progress bar is in the Now panel.`);
  refresh();
};

refresh(); setInterval(refresh, 1500);
</script>
</body>
</html>"""
