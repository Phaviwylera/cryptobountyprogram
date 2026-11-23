"""The PoC Findings page, served at /poc. Shows ONLY fork-CONFIRMED (PoC-backed) findings - a drain
that actually moved the target's funds to the attacker on a mainnet fork. No candidates, no 'manual
review': if it's here, a Foundry PoC proved it. Isolated from the main dashboard, mirrors /live."""

POC_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>BountyScan · PoC Findings</title>
<style>
  :root{--bg:#070a0f;--panel:#0d131b;--line:#1b2431;--dim:#62707f;--txt:#c7d2de;--teal:#4fd1b5;--pink:#ff5c8a;--yellow:#f2c14e;--violet:#9a7cff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
  a{color:var(--teal);text-decoration:none}
  header{display:flex;align-items:center;gap:14px;padding:14px 18px;border-bottom:1px solid var(--line);position:sticky;top:0;background:linear-gradient(180deg,#0a0e13,#070a0f);z-index:5;flex-wrap:wrap}
  h1{font-size:15px;margin:0;letter-spacing:.5px}
  h1 b{color:var(--teal)}
  .tag{font-size:11px;color:var(--dim)}
  .pill{font-size:11px;padding:2px 9px;border:1px solid var(--line);border-radius:20px;color:var(--dim)}
  .pill.on{color:var(--teal);border-color:var(--teal)}
  .stats{display:flex;gap:18px;margin-left:auto;flex-wrap:wrap;align-items:center}
  .stat b{color:var(--teal);font-size:15px}.stat.pink b{color:var(--pink)}.stat.y b{color:var(--yellow)}
  main{padding:14px 18px}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;color:var(--dim);font-weight:600;font-size:11px;padding:7px 8px;border-bottom:1px solid var(--line);position:sticky;top:54px;background:var(--bg)}
  td{padding:8px;border-bottom:1px solid #121a24;vertical-align:middle}
  tr.row:hover{background:#0f1620;cursor:pointer}
  .sev{font-size:10px;padding:1px 7px;border-radius:4px;text-transform:uppercase}
  .sev.critical{background:#3a1020;color:#ff6f9c;border:1px solid #5a1730}
  .sev.high{background:#3a2410;color:#ffb860;border:1px solid #5a3a16}
  .sev.medium{background:#10263a;color:#6fb8ff;border:1px solid #16405a}
  .addr{color:var(--dim)}
  .poc{font-size:10px;padding:1px 7px;border-radius:20px;background:#07261f;color:var(--teal);border:1px solid var(--teal)}
  tr.flash{animation:flash 2s ease-out}
  @keyframes flash{0%{background:#102a22}100%{background:transparent}}
  .empty{color:var(--dim);padding:48px;text-align:center;line-height:1.8}
  .foot{color:var(--dim);font-size:11px;margin-top:12px}
  dialog{background:var(--panel);color:var(--txt);border:1px solid var(--line);max-width:900px;width:92%;border-radius:8px}
  dialog pre{white-space:pre-wrap;max-height:70vh;overflow:auto;font-size:12px}
  .mh{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
  .mh button{background:none;border:1px solid var(--line);color:var(--txt);border-radius:5px;cursor:pointer;padding:2px 9px}
</style></head>
<body>
<header>
  <h1>🎯 <b>POC</b> FINDINGS</h1>
  <span class="tag">fork-proven exploits only · a drain that actually moved funds to the attacker</span>
  <div class="stats">
    <div class="stat"><b id="sCount">0</b> <span class="tag">confirmed</span></div>
    <div class="stat pink"><b id="sCrit">0</b> <span class="tag">critical</span></div>
    <div class="stat y"><b id="sVal">$0</b> <span class="tag">funds at risk</span></div>
    <a class="pill" href="/live">⚡ live</a>
    <a class="pill" href="/">← dashboard</a>
  </div>
</header>
<main>
  <table>
    <thead><tr><th>sev</th><th>contract</th><th>address</th><th>funds at risk</th><th>findings</th><th>PoC</th></tr></thead>
    <tbody id="rows"><tr><td colspan="6" class="empty">loading PoC findings…</td></tr></tbody>
  </table>
  <div class="foot" id="foot">polling every 8s · severity by funds at stake (Critical ≥ $100k · High ≥ $10k) · click a row for the full forensic report + Foundry PoC</div>
</main>
<dialog id="modal"><div class="mh"><b id="mTitle">report</b><button onclick="document.getElementById('modal').close()">×</button></div><pre id="mBody"></pre></dialog>
<script>
"use strict";
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const short=a=>a?a.slice(0,10)+'…'+a.slice(-6):'';
const usd=v=>v==null?'?':v>=1e9?'$'+(v/1e9).toFixed(2)+'B':v>=1e6?'$'+(v/1e6).toFixed(2)+'M':v>=1e3?'$'+(v/1e3).toFixed(1)+'K':'$'+Number(v).toFixed(v<10?2:0);
const sevOf=v=>(v||0)>=1e5?'critical':(v||0)>=1e4?'high':'medium';
let seen=new Set();
async function poll(){
  let d; try{ d=await fetch('/api/poc/feed').then(r=>r.json()); }catch{ return; }
  const rows=d.findings||[];
  let crit=0, val=0;
  const html=rows.map(r=>{
    const sev=sevOf(r.value_usd); if(sev==='critical') crit++;
    val += (r.value_usd||0);
    const isNew=!seen.has(r.address); seen.add(r.address);
    return `<tr class="row ${isNew?'flash':''}" data-c="${esc(r.chain)}" data-a="${esc(r.address)}">
      <td><span class="sev ${sev}">${sev}</span></td>
      <td>${esc(r.name||'—')}</td>
      <td class="addr">${short(r.address)}</td>
      <td style="color:${(r.value_usd||0)>=1000?'var(--yellow)':'var(--dim)'}">${usd(r.value_usd)}</td>
      <td>${r.findings||0}</td>
      <td><span class="poc">✓ PoC proven</span></td></tr>`;
  }).join('');
  $('#rows').innerHTML = rows.length? html :
    '<tr><td colspan="6" class="empty">no fork-proven exploits yet.<br>Only PoC-backed drains appear here — a candidate is promoted the instant a Foundry fork moves the target\'s funds to the attacker.<br>The scanner keeps probing.</td></tr>';
  $('#sCount').textContent=rows.length; $('#sCrit').textContent=crit; $('#sVal').textContent=usd(val);
  document.querySelectorAll('tr.row').forEach(tr=>tr.onclick=()=>openReport(tr.dataset.c,tr.dataset.a));
}
async function openReport(chain,addr){
  try{ const d=await fetch(`/api/result?chain=${chain}&addr=${addr}`).then(r=>r.json());
    $('#mTitle').textContent=`🎯 ${chain} ${addr}`; $('#mBody').textContent=d.markdown||JSON.stringify(d,null,2); $('#modal').showModal();
  }catch{}
}
poll(); setInterval(poll, 8000);
</script>
</body></html>
"""
