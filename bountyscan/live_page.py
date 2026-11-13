"""The standalone Live Scan / threat-watch page, served at /live. Isolated from the main dashboard."""

LIVE_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>BountyScan · Live Threat Watch</title>
<style>
  :root{--bg:#070a0f;--panel:#0d131b;--line:#1b2431;--dim:#62707f;--txt:#c7d2de;--teal:#4fd1b5;--pink:#ff5c8a;--yellow:#f2c14e;--violet:#9a7cff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
  a{color:var(--teal);text-decoration:none}
  header{display:flex;align-items:center;gap:14px;padding:14px 18px;border-bottom:1px solid var(--line);position:sticky;top:0;background:linear-gradient(180deg,#0a0e13,#070a0f);z-index:5;flex-wrap:wrap}
  h1{font-size:15px;margin:0;letter-spacing:.5px}
  h1 b{color:var(--pink)}
  .tag{font-size:11px;color:var(--dim)}
  .pill{font-size:11px;padding:2px 9px;border:1px solid var(--line);border-radius:20px;color:var(--dim)}
  .pill.on{color:var(--teal);border-color:var(--teal)}
  .stats{display:flex;gap:18px;margin-left:auto;flex-wrap:wrap}
  .stat b{color:var(--teal);font-size:15px}.stat.pink b{color:var(--pink)}.stat.y b{color:var(--yellow)}
  main{padding:14px 18px}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;color:var(--dim);font-weight:600;font-size:11px;padding:7px 8px;border-bottom:1px solid var(--line);position:sticky;top:54px;background:var(--bg)}
  td{padding:8px;border-bottom:1px solid #121a24;vertical-align:middle}
  tr.row:hover{background:#0f1620;cursor:pointer}
  .sev{font-size:10px;padding:1px 7px;border-radius:4px;text-transform:uppercase}
  .sev.critical{background:#3a1020;color:#ff6f9c;border:1px solid #5a1730}
  .sev.high{background:#3a2410;color:#ffb860;border:1px solid #5a3a16}
  .recv{color:var(--teal);font-weight:700}
  .flat{color:var(--dim)}
  .up{color:var(--teal)} .addr{color:var(--dim)}
  .badge{font-size:10px;padding:1px 7px;border-radius:20px;background:#07261f;color:var(--teal);border:1px solid var(--teal);animation:pulse 1.6s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
  tr.flash{animation:flash 2s ease-out}
  @keyframes flash{0%{background:#102a22}100%{background:transparent}}
  .empty{color:var(--dim);padding:40px;text-align:center}
  .foot{color:var(--dim);font-size:11px;margin-top:12px}
  dialog{background:var(--panel);color:var(--txt);border:1px solid var(--line);max-width:860px;width:92%;border-radius:8px}
  dialog pre{white-space:pre-wrap;max-height:68vh;overflow:auto;font-size:12px}
  .mh{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
  .mh button{background:none;border:1px solid var(--line);color:var(--txt);border-radius:5px;cursor:pointer;padding:2px 9px}
</style></head>
<body>
<header>
  <h1>⚡ <b>LIVE</b> THREAT WATCH</h1>
  <span class="pill" id="mode">live scan: …</span>
  <span class="tag">fresh deployments · watching balances for inflow</span>
  <div class="stats">
    <div class="stat"><b id="sWatch">0</b> <span class="tag">watched</span></div>
    <div class="stat pink"><b id="sRecv">0</b> <span class="tag">receiving $</span></div>
    <div class="stat y"><b id="sVal">$0</b> <span class="tag">value at watch</span></div>
    <a class="pill" href="/">← dashboard</a>
  </div>
</header>
<main>
  <table>
    <thead><tr><th>age</th><th>sev</th><th>finds</th><th>contract</th><th>address</th><th>value held</th><th>native bal</th><th>inflow</th></tr></thead>
    <tbody id="rows"><tr><td colspan="8" class="empty">loading live watch…</td></tr></tbody>
  </table>
  <div class="foot" id="foot">polling every 5s · a 💰 RECEIVING badge means the native balance has grown since first seen</div>
</main>
<dialog id="modal"><div class="mh"><b id="mTitle">report</b><button onclick="document.getElementById('modal').close()">×</button></div><pre id="mBody"></pre></dialog>
<script>
"use strict";
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const short=a=>a?a.slice(0,8)+'…'+a.slice(-6):'';
const usd=v=>v==null?'?':v>=1e9?'$'+(v/1e9).toFixed(2)+'B':v>=1e6?'$'+(v/1e6).toFixed(2)+'M':v>=1e3?'$'+(v/1e3).toFixed(1)+'K':'$'+Number(v).toFixed(v<10?2:0);
const eth=w=>{try{const n=Number(BigInt(w))/1e18;return n>=1?n.toFixed(3)+' Ξ':n>0?n.toExponential(2)+' Ξ':'0';}catch{return '0';}};
const ago=s=>{s=Math.max(0,s|0);return s<60?s+'s':s<3600?(s/60|0)+'m':s<86400?(s/3600|0)+'h':(s/86400|0)+'d';};
let prev={};   // address -> last native wei (string) for live diffing
async function poll(){
  let d; try{ d=await fetch('/api/live/feed').then(r=>r.json()); }catch{ return; }
  const rows=d.contracts||[];
  $('#mode').textContent='live scan: '+(d.mode||'idle');
  $('#mode').className='pill'+(d.mode==='live'?' on':'');
  let recv=0, val=0;
  const html=rows.map(r=>{
    const grew = r.receiving;
    if(grew) recv++;
    val += (r.value_usd||0);
    const key=r.address;
    const flash = (prev[key]!==undefined && r.wei!==undefined && BigInt(r.wei||'0')>BigInt(prev[key]||'0'));
    prev[key]=r.wei||'0';
    const recvCell = grew? '<span class="badge">💰 RECEIVING</span>' : '<span class="flat">—</span>';
    return `<tr class="row ${flash?'flash':''}" data-c="${esc(r.chain)}" data-a="${esc(r.address)}">
      <td>${ago(r.age_sec)}</td>
      <td><span class="sev ${esc(r.severity)}">${esc(r.severity||'')}</span></td>
      <td>${r.findings||0}</td>
      <td>${esc(r.name||'—')}</td>
      <td class="addr">${short(r.address)}</td>
      <td style="color:${(r.value_usd||0)>=1000?'var(--yellow)':'var(--dim)'}">${usd(r.value_usd)}</td>
      <td class="${grew?'up':''}">${eth(r.wei||'0')}</td>
      <td>${recvCell} ${r.inflows?('<span class="tag">×'+r.inflows+'</span>'):''}</td></tr>`;
  }).join('');
  $('#rows').innerHTML = rows.length? html : '<tr><td colspan="8" class="empty">no fresh flagged contracts yet · the live crawler keeps going</td></tr>';
  $('#sWatch').textContent=rows.length; $('#sRecv').textContent=recv; $('#sVal').textContent=usd(val);
  document.querySelectorAll('tr.row').forEach(tr=>tr.onclick=()=>openReport(tr.dataset.c,tr.dataset.a));
}
async function openReport(chain,addr){
  try{ const d=await fetch(`/api/result?chain=${chain}&addr=${addr}`).then(r=>r.json());
    $('#mTitle').textContent=`⚑ ${chain} ${addr}`; $('#mBody').textContent=d.markdown||JSON.stringify(d,null,2); $('#modal').showModal();
  }catch{}
}
poll(); setInterval(poll, 5000);
</script>
</body></html>
"""
