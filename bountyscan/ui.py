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
    --mut:#7d8aa0; --acc:#38e0b0; --acc2:#2bb3ff; --crit:#ff4d6d; --high:#ff9f43; --ok:#3ad07a;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#13202e 0%,var(--bg) 55%);
    color:var(--ink);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;min-height:100vh}
  header{display:flex;align-items:center;gap:14px;padding:16px 24px;border-bottom:1px solid var(--line);
    position:sticky;top:0;background:rgba(10,14,20,.85);backdrop-filter:blur(8px);z-index:5}
  .logo{font-weight:700;letter-spacing:.5px;font-size:18px}
  .logo b{color:var(--acc)}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--mut);box-shadow:0 0 0 0 rgba(58,208,122,.5)}
  .dot.on{background:var(--ok);animation:pulse 2s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(58,208,122,.5)}70%{box-shadow:0 0 0 8px rgba(58,208,122,0)}100%{box-shadow:0 0 0 0 rgba(58,208,122,0)}}
  .wrap{max-width:1180px;margin:0 auto;padding:24px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
  .stat .n{font-size:26px;font-weight:700;font-family:var(--mono)}
  .stat .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
  .stat.crit .n{color:var(--crit)} .stat.ok .n{color:var(--ok)} .stat.acc .n{color:var(--acc)}
  .cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:820px){.cols{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
  .card h2{margin:0 0 4px;font-size:16px}
  .card p{color:var(--mut);margin:0 0 16px;font-size:13px}
  .btn{appearance:none;border:0;border-radius:10px;padding:13px 18px;font-weight:650;font-size:14px;
    cursor:pointer;color:#06130f;width:100%;transition:transform .05s,filter .15s}
  .btn:hover{filter:brightness(1.08)} .btn:active{transform:translateY(1px)}
  .btn.live{background:linear-gradient(135deg,var(--acc),#13b98a)}
  .btn.imm{background:linear-gradient(135deg,var(--acc2),#1f74ff);color:#fff}
  .btn.stop{background:#26303d;color:var(--ink);border:1px solid var(--line)}
  .btn.ghost{background:transparent;color:var(--mut);border:1px solid var(--line)}
  .row{display:flex;gap:8px;margin-top:10px} .row .btn{width:auto;flex:1}
  label{display:block;color:var(--mut);font-size:12px;margin:10px 0 4px}
  input,textarea,select{width:100%;background:var(--panel2);border:1px solid var(--line);color:var(--ink);
    border-radius:8px;padding:9px 11px;font-family:var(--mono);font-size:13px}
  textarea{resize:vertical;min-height:70px}
  .tabs{display:flex;gap:6px;margin:26px 0 14px;flex-wrap:wrap}
  .tab{padding:8px 14px;border:1px solid var(--line);border-radius:999px;color:var(--mut);cursor:pointer;font-size:13px}
  .tab.active{color:var(--ink);border-color:var(--acc);background:#0f1b1a}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
  th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
  td.mono,.addr{font-family:var(--mono)}
  tr.click{cursor:pointer} tr.click:hover{background:#0f1721}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;font-family:var(--mono)}
  .pill.critical{background:rgba(255,77,109,.15);color:var(--crit)} .pill.high{background:rgba(255,159,67,.15);color:var(--high)}
  .empty{color:var(--mut);padding:30px;text-align:center}
  .banner{display:flex;align-items:center;gap:10px;background:var(--panel);border:1px solid var(--line);
    border-left:3px solid var(--acc);border-radius:10px;padding:12px 16px;margin-bottom:18px;font-family:var(--mono);font-size:13px}
  .banner .mut{color:var(--mut)}
  dialog{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:14px;
    max-width:900px;width:92%;padding:0}
  dialog::backdrop{background:rgba(2,6,12,.72)}
  .modhead{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--line)}
  .modbody{padding:20px;max-height:70vh;overflow:auto}
  pre{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto;
    font-family:var(--mono);font-size:12.5px;white-space:pre-wrap;word-break:break-word}
  .x{cursor:pointer;color:var(--mut);font-size:20px;border:0;background:0}
  .muted{color:var(--mut)} .warn{color:var(--high)}
  a{color:var(--acc2)}
</style>
</head>
<body>
<header>
  <span class="dot" id="dot"></span>
  <span class="logo"><b>bounty</b>scan</span>
  <span class="muted" id="modeLabel" style="font-family:var(--mono)">idle</span>
  <span style="flex:1"></span>
  <span class="muted" id="rpcLabel" style="font-size:12px"></span>
</header>

<div class="wrap">
  <div class="banner" id="banner">
    <span class="dot" id="dot2"></span>
    <span id="bannerText">Not scanning.</span>
    <span style="flex:1"></span>
    <span class="mut" id="currentTarget"></span>
  </div>

  <div class="grid" id="stats"></div>

  <div class="cols">
    <div class="card">
      <h2>Live Scan</h2>
      <p>Follow the chain 24/7. Every newly deployed verified contract is fetched, scanned, independently re-confirmed, and the next one starts automatically.</p>
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
      <p>Scan a bounty program's in-scope contracts. Paste addresses or point at a saved scope file. Each is fetched, scanned and confirmed.</p>
      <label>Program name</label>
      <input id="immName" placeholder="acme-protocol">
      <label>In-scope addresses (one per line, <span class="mono">chain:0x..</span> or <span class="mono">0x..</span>)</label>
      <textarea id="immAddrs" placeholder="ethereum:0x....&#10;0x...."></textarea>
      <label>…or a scope file path on the server (optional)</label>
      <input id="immScope" placeholder="programs/acme.json">
      <div class="row">
        <button class="btn imm" id="btnImm">Scan program</button>
        <button class="btn ghost" id="btnQueue">Queue only</button>
      </div>
    </div>
  </div>

  <div class="tabs" id="tabs">
    <div class="tab active" data-t="results">Results (vulnerable)</div>
    <div class="tab" data-t="safe">Safe</div>
    <div class="tab" data-t="errors">Errors</div>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <div id="tableWrap"><div class="empty">Loading…</div></div>
  </div>
</div>

<dialog id="modal">
  <div class="modhead">
    <strong id="modTitle" class="mono">report</strong>
    <button class="x" onclick="document.getElementById('modal').close()">×</button>
  </div>
  <div class="modbody"><pre id="modBody"></pre></div>
</dialog>

<script>
const $ = s => document.querySelector(s);
const api = (p,m,b) => fetch(p,{method:m||'GET',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):null}).then(r=>r.json());
let tab = 'results';

function sev(s){return s?`<span class="pill ${s}">${s}</span>`:'';}
function short(a){return a?a.slice(0,10)+'…'+a.slice(-6):'';}

async function refresh(){
  let s; try{ s = await api('/api/status'); }catch{ return; }
  const live = s.mode==='live', busy = s.mode!=='idle';
  $('#dot').className = 'dot'+(busy?' on':''); $('#dot2').className='dot'+(busy?' on':'');
  $('#modeLabel').textContent = s.mode + (s.verify?' · verify on':' · verify off');
  $('#rpcLabel').textContent = s.rpc ? 'rpc connected' : 'no rpc (lists/programs only)';
  const c = s.counts||{};
  const cur = s.current ? `${short(s.current.address)} ${s.current.status||'scanning…'}` : '';
  $('#currentTarget').textContent = cur;
  $('#bannerText').innerHTML = busy
    ? `<b>${s.mode==='live'?'LIVE':'Draining queue'}</b> — ${s.pending} pending · ${s.scanned_this_session} scanned this session`
    + (s.cursor?` · block ${s.cursor}`:'') + (s.last_error?` · <span class="warn">${s.last_error}</span>`:'')
    : 'Not scanning.' + (s.last_error?` <span class="warn">(${s.last_error})</span>`:'');
  const stats = [
    ['vulnerable',c.vulnerable||0,'crit'],['safe',c.safe||0,'ok'],
    ['pending',s.pending||0,'acc'],['unverified',(c.unverified_final||0),''],
    ['errors',c.error||0,''],['scanned (session)',s.scanned_this_session||0,'']
  ];
  $('#stats').innerHTML = stats.map(([l,n,k])=>`<div class="stat ${k}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');
  loadTable();
}

async function loadTable(){
  const ep = tab==='results'?'/api/results':tab==='safe'?'/api/safe':'/api/errors';
  const key = tab==='results'?'results':tab==='safe'?'safe':'errors';
  let d; try{ d = await api(ep); }catch{ return; }
  const rows = d[key]||[];
  const w = $('#tableWrap');
  if(!rows.length){ w.innerHTML = `<div class="empty">${tab==='results'?'No confirmed vulnerabilities yet. Start a scan.':'Nothing here yet.'}</div>`; return; }
  if(tab==='results'){
    w.innerHTML = `<table><thead><tr><th>Severity</th><th>Findings</th><th>Chain</th><th>Address</th><th>Contract</th><th>Balance</th></tr></thead><tbody>`
      + rows.map(r=>`<tr class="click" onclick="openReport('${r.chain}','${r.address}')">
        <td>${sev(r.max_severity)}</td><td class="mono">${r.findings||0}</td><td>${r.chain}</td>
        <td class="addr">${short(r.address)}</td><td>${r.name||''}</td>
        <td class="mono">${r.balance==null?'?':r.balance.toFixed(4)}</td></tr>`).join('') + `</tbody></table>`;
  } else if(tab==='safe'){
    w.innerHTML = `<table><thead><tr><th>Chain</th><th>Address</th><th>Contract</th><th>Note</th></tr></thead><tbody>`
      + rows.map(r=>`<tr><td>${r.chain}</td><td class="addr">${short(r.address)}</td><td>${r.name||''}</td><td class="muted">${r.error||'clear'}</td></tr>`).join('')+`</tbody></table>`;
  } else {
    w.innerHTML = `<table><thead><tr><th>Chain</th><th>Address</th><th>Error</th></tr></thead><tbody>`
      + rows.map(r=>`<tr><td>${r.chain}</td><td class="addr">${short(r.address)}</td><td class="muted">${r.error||''}</td></tr>`).join('')+`</tbody></table>`;
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
  const fb = $('#liveFromBlock').value.trim();
  const r = await api('/api/live/start','POST',{chain:$('#liveChain').value,
    min_balance:parseFloat($('#liveMinBal').value||'0')||0, from_block: fb?parseInt(fb):null});
  if(r.error) alert(r.error); refresh();
};
$('#btnStop').onclick = async()=>{ await api('/api/live/stop','POST',{}); refresh(); };

function addrLines(){return $('#immAddrs').value.split('\n').map(x=>x.trim()).filter(Boolean);}
function parseAssets(lines){return lines.map(l=>{const m=l.match(/^(?:([\w-]+)[:,\s]+)?(0x[0-9a-fA-F]{40})$/);
  return m?{chain:(m[1]||'ethereum').toLowerCase(),address:m[2]}:null;}).filter(Boolean);}

$('#btnImm').onclick = async()=>{
  const scope = $('#immScope').value.trim();
  const body = scope ? {scope_path:scope} : {program:$('#immName').value||'manual', assets:parseAssets(addrLines())};
  const r = await api('/api/immunefi/scan','POST',body);
  if(r.error) return alert(r.error);
  alert(`Queued ${r.added} contract(s) from ${r.program}. Scanning…`); refresh();
};
$('#btnQueue').onclick = async()=>{
  const r = await api('/api/enqueue','POST',{chain:'ethereum',addresses:addrLines().map(l=>l.replace(/^[\w-]+[:,\s]+/,''))});
  if(r.error) return alert(r.error); alert(`Queued ${r.added}.`); refresh();
};

refresh(); setInterval(refresh, 2500);
</script>
</body>
</html>"""
