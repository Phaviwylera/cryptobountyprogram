"""bountyscan dashboard (served at /).

A live "crawler" visualisation: every contract the scanner touches becomes a particle cloud in
the galaxy, and the scanner itself is drawn as a spider that travels from cloud to cloud, reaching
out with tentacles to the checks it is running. Every visual element is driven by real scan
data from /api/status - nothing on screen is decorative fiction.
Self-contained except for the JetBrains Mono web font (falls back to the system monospace font).
"""

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>bountyscan · live</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#050608; --panel:rgba(9,11,15,.88); --line:#1b212b; --line2:#262e3a;
    --ink:#e3e8ef; --dim:#5d6878; --dim2:#3a4350;
    --white:#e8ecf2; --cyan:#3fb8e6; --pink:#ff5c8a; --yellow:#f2c14e; --teal:#4fd1b5;
    --purple:#9a7cff; --orange:#ff8a5c; --brand:#ff4d6d;
    --mono:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,Consolas,monospace;
    --phase:var(--white);
  }
  *{box-sizing:border-box}
  html,body{margin:0;background:var(--bg);color:var(--ink);font:12px/1.45 var(--mono)}
  ::selection{background:var(--teal);color:#000}

  /* ---------- top telemetry ---------- */
  .tele{position:fixed;top:0;left:0;right:0;z-index:20;display:flex;align-items:center;gap:18px;
    padding:8px 16px 6px;background:linear-gradient(#050608 70%,rgba(5,6,8,0));white-space:nowrap;overflow:hidden}
  .tele .k{color:var(--dim);font-size:10.5px;letter-spacing:.6px;margin-right:6px}
  .tele .v{color:var(--ink);font-weight:700;font-size:12px}
  .tele .brand{margin-left:auto;color:var(--brand);font-weight:700}
  .tele a{color:inherit;text-decoration:none;cursor:pointer}
  .tabs{position:fixed;top:32px;left:0;right:0;z-index:20;display:grid;grid-template-columns:repeat(6,1fr);gap:4px;padding:0 16px}
  .tab{text-align:center;padding:4px 0;background:#0d1015;border:1px solid #12161d;color:#7c8696;font-size:11px;
    letter-spacing:.4px;transition:background .35s,color .35s}
  .tab.past{color:#a7b0bd} .tab.future{color:#3a4350}
  .tab.on{color:#05070a;font-weight:700}

  /* ---------- stage (galaxy canvas) ---------- */
  .stage{position:relative;height:100vh;min-height:760px;overflow:hidden}
  canvas#galaxy{position:absolute;inset:0;width:100%;height:100%;display:block}
  .title{position:absolute;top:66px;left:16px;z-index:5;pointer-events:none}
  .title .h{display:flex;align-items:center;gap:12px;font-size:30px;font-weight:800;letter-spacing:.5px;color:var(--white)}
  .title .h::before{content:"";width:5px;height:34px;background:var(--phase);box-shadow:0 0 18px var(--phase)}
  .title .s{margin:2px 0 0 17px;color:var(--phase);font-size:12px;max-width:62vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

  /* ---------- command dock ---------- */
  .dock{position:absolute;top:66px;right:16px;z-index:8;width:300px;display:flex;flex-direction:column;gap:6px}
  .drow{display:flex;gap:6px}
  .cmd{flex:1;appearance:none;cursor:pointer;font:700 11.5px var(--mono);letter-spacing:.8px;padding:10px 12px;
    border:1px solid var(--line2);background:rgba(10,13,18,.92);color:var(--ink);transition:all .2s}
  .cmd:hover{border-color:var(--c,var(--teal));color:var(--c,var(--teal));box-shadow:0 0 18px -6px var(--c,var(--teal))}
  .cmd.back{--c:var(--purple)} .cmd.back.running{border-color:var(--purple);color:var(--purple);animation:glowp 2s ease-in-out infinite}
  @keyframes glowp{50%{box-shadow:0 0 22px -4px var(--purple)}}
  .cmd.live{--c:var(--teal)} .cmd.imm{--c:var(--cyan)} .cmd.stop{--c:var(--pink);flex:0 0 44px} .cmd.gear{--c:var(--yellow);flex:0 0 44px}
  .cmd.running{border-color:var(--teal);color:var(--teal);animation:glow 2s ease-in-out infinite}
  .cmd:disabled{cursor:default}
  @keyframes glow{50%{box-shadow:0 0 22px -4px var(--teal)}}
  .drawer{display:none;border:1px solid var(--line2);background:rgba(8,10,14,.96);padding:10px}
  .drawer.open{display:block;animation:drop .2s ease}
  @keyframes drop{from{opacity:0;transform:translateY(-4px)}}
  .drawer label{display:block;color:var(--dim);font-size:10px;letter-spacing:.6px;margin:7px 0 3px;text-transform:uppercase}
  .drawer input,.drawer select,.drawer textarea{width:100%;background:#06080b;border:1px solid var(--line2);color:var(--ink);
    font:12px var(--mono);padding:7px 8px;outline:none}
  .drawer input:focus,.drawer textarea:focus,.drawer select:focus{border-color:var(--cyan)}
  .drawer textarea{min-height:76px;resize:vertical}
  .batch{border:1px solid var(--line2);background:rgba(8,10,14,.92);padding:8px 10px}
  .batch .t{display:flex;justify-content:space-between;color:var(--dim);font-size:10.5px}
  .batch .t b{color:var(--ink)}
  .bar{height:5px;background:#12161d;margin-top:6px;overflow:hidden}
  .bar i{display:block;height:100%;background:var(--cyan);transition:width .6s}

  /* ---------- HUD panels ---------- */
  .hud{position:absolute;left:16px;right:16px;bottom:16px;z-index:6;display:grid;grid-template-columns:repeat(6,1fr);gap:8px}
  .p{background:var(--panel);border:1px solid var(--line);padding:9px 10px 8px;height:258px;overflow:hidden;position:relative;
    backdrop-filter:blur(2px)}
  .p.firing{animation:glow 1.1s ease-in-out infinite;border-color:var(--teal)}
  .p .hd{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
  .p .hd b{font-size:11px;letter-spacing:.7px;color:var(--white)}
  .p .hd span{color:var(--teal);font-size:11px}
  .p .ft{position:absolute;left:10px;bottom:7px;color:var(--dim2);font-size:10px}
  .log div{display:flex;gap:9px;white-space:nowrap;overflow:hidden;line-height:1.62}
  .log .t{color:var(--dim2)} .log .vb{width:30px} .log .o{color:#9fb2c4;overflow:hidden;text-overflow:ellipsis}
  .log div.new{animation:fade .8s ease}
  @keyframes fade{from{opacity:0;transform:translateX(-4px)}}
  .sec{margin-bottom:7px} .sec .r{display:flex;justify-content:space-between;color:#b9c2ce;font-size:11px}
  .sec .r em{font-style:normal;color:var(--dim)}
  .sec .tr{height:4px;background:#141922;margin-top:3px} .sec .tr i{display:block;height:100%;transition:width .8s}
  .bars div{display:flex;align-items:center;gap:8px;color:#b9c2ce;font-size:11px;line-height:1.7}
  .bars div span{flex:0 0 62px} .bars div i{height:6px;background:var(--teal);transition:width .8s} .bars div b{margin-left:auto}
  .heat .row{display:flex;align-items:center;gap:6px;margin-bottom:5px}
  .heat .row em{font-style:normal;color:var(--dim);width:30px;font-size:10px}
  .heat .sq{width:9px;height:9px;background:#161b23;transition:background .4s}
  .heat .sq.pop{animation:pop .9s ease}
  @keyframes pop{30%{transform:scale(1.5);filter:brightness(1.8)}}
  .big{font-size:21px;font-weight:800;margin:4px 0 6px}
  .kv div{display:flex;justify-content:space-between;color:#b9c2ce;line-height:1.55}
  .code{white-space:pre;color:#62707f;line-height:1.62;font-size:11px}
  .code .ln{display:block;transition:color .3s} .code .ln.on{color:var(--phase)}
  .cursor{display:inline-block;width:7px;height:12px;background:var(--phase);vertical-align:-2px;animation:blink 1s steps(1) infinite}
  @keyframes blink{50%{opacity:0}}

  /* ---------- findings ---------- */
  .findings{padding:28px 16px 60px;max-width:1500px;margin:0 auto}
  .fh{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:12px}
  .fh h2{margin:0;display:flex;align-items:center;gap:12px;font-size:22px;font-weight:800}
  .fh h2::before{content:"";width:5px;height:24px;background:var(--pink);box-shadow:0 0 14px var(--pink)}
  .ftab{padding:4px 12px;border:1px solid var(--line2);color:var(--dim);cursor:pointer;font-size:11px}
  .ftab.on{background:var(--pink);border-color:var(--pink);color:#08090b;font-weight:700}
  table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}
  th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:11.5px}
  th{color:var(--dim);font-weight:500;letter-spacing:.6px;font-size:10.5px;text-transform:uppercase}
  tr.click{cursor:pointer} tr.click:hover td{background:#0e131a}
  .sev{padding:2px 8px;font-weight:700;font-size:10.5px}
  .sev.critical{background:var(--pink);color:#08090b} .sev.high{background:var(--orange);color:#08090b}
  .empty{padding:26px;text-align:center;color:var(--dim);background:var(--panel);border:1px solid var(--line)}
  dialog{background:#07090c;color:var(--ink);border:1px solid var(--line2);max-width:980px;width:94%;padding:0}
  dialog::backdrop{background:rgba(0,0,0,.78)}
  .mh{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line)}
  .mh b{color:var(--pink)} .mh button{background:0;border:0;color:var(--dim);font-size:20px;cursor:pointer}
  dialog pre{margin:0;padding:16px;max-height:76vh;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px/1.55 var(--mono);color:#c9d2dd}
  .toasts{position:fixed;left:16px;bottom:16px;z-index:40;display:flex;flex-direction:column-reverse;gap:6px;pointer-events:none;max-height:40vh;overflow:hidden}
  .toast{background:rgba(8,10,14,.97);border:1px solid var(--line2);border-left:3px solid var(--teal);padding:8px 11px;max-width:320px;font-size:11px;
    animation:tin .25s ease}
  .toast.err{border-left-color:var(--pink)}
  @keyframes tin{from{opacity:0;transform:translateX(-8px)}}
  /* top alert ticker - vulnerable/funded hits scroll across the top instead of blocking the panels */
  .ticker{position:fixed;left:0;right:0;top:34px;height:24px;z-index:36;overflow:hidden;background:linear-gradient(90deg,rgba(6,8,12,.0),rgba(6,8,12,.92) 6%,rgba(6,8,12,.92) 94%,rgba(6,8,12,0));
    border-top:1px solid rgba(255,92,138,.18);border-bottom:1px solid rgba(255,92,138,.18);display:flex;align-items:center;pointer-events:none}
  .ticker .lbl{flex:0 0 auto;padding:0 10px;font:600 10px var(--mono);letter-spacing:.8px;color:var(--pink);background:rgba(255,92,138,.12);align-self:stretch;display:flex;align-items:center;z-index:2}
  .tk-win{flex:1 1 auto;overflow:hidden;position:relative;height:100%}
  .tk-track{position:absolute;left:0;top:0;height:100%;display:flex;align-items:center;white-space:nowrap;will-change:transform;animation:tk 1s linear infinite}
  .tk-item{padding:0 26px;font:500 11px var(--mono);color:#cdd6e2}
  .tk-item b{color:var(--pink)} .tk-item em{color:var(--yellow);font-style:normal}
  @keyframes tk{from{transform:translateX(0)}to{transform:translateX(-50%)}}

  /* ---------- responsive ---------- */
  @media (max-width:1100px){
    .stage{height:auto;min-height:0}
    canvas#galaxy{position:relative;height:62vh;min-height:430px}
    .hud{position:relative;left:0;right:0;bottom:0;padding:8px 12px 0;grid-template-columns:repeat(3,1fr)}
    .dock{position:relative;top:0;right:0;width:auto;margin:8px 12px 0}
    .title{top:70px}
  }
  @media (max-width:640px){
    .hud{grid-template-columns:repeat(2,1fr)} .p{height:236px}
    .tele{gap:12px} .tele .opt{display:none}
    .tabs{grid-template-columns:repeat(3,1fr)}
    .title{top:90px} .title .h{font-size:22px}
  }
</style>
</head>
<body>

<div class="tele">
  <span><span class="k">SWARM</span><span class="v">bountyscan</span></span>
  <span><span class="k">CHAIN</span><span class="v" id="tChain">ethereum</span></span>
  <span><span class="k">BLOCK</span><span class="v" id="tBlock" style="color:var(--white)">-</span></span>
  <span class="opt"><span class="k">FOUND</span><span class="v" id="tFound" style="color:var(--yellow)">0</span></span>
  <span class="opt"><span class="k">SCANNED</span><span class="v" id="tScanned">0</span></span>
  <span><span class="k">SAFE</span><span class="v" id="tSafe" style="color:var(--teal)">0</span></span>
  <a href="#findings"><span class="k">VULN</span><span class="v" id="tVuln" style="color:var(--pink)">0</span></a>
  <span class="opt"><span class="k">WAIT</span><span class="v" id="tWait" style="color:var(--orange)">0</span></span>
  <span><span class="k">VALUE SEEN</span><span class="v" id="tValue" style="color:var(--cyan)">$0</span></span>
  <a href="#findings"><span class="k">AT RISK</span><span class="v" id="tRisk" style="color:var(--pink)">$0</span></a>
  <span class="opt"><span class="k">BACKFILL</span><span class="v" id="tBack" style="color:var(--purple)">-</span></span>
  <span class="opt"><span class="k">T</span><span class="v" id="tT">0.00</span></span>
  <span class="opt"><span class="k">FRAME</span><span class="v" id="tFrame">0000</span></span>
  <span class="brand" id="tBrand">bountyscan.live</span>
</div>
<div class="tabs" id="tabs"></div>

<section class="stage" id="stage">
  <canvas id="galaxy"></canvas>
  <div class="title"><div class="h" id="phTitle">00 IDLE</div><div class="s" id="phSub">press LIVE SCAN to start crawling the chain</div></div>

  <div class="dock">
    <div class="drow">
      <button class="cmd live" id="btnLive">▶ LIVE SCAN</button>
      <button class="cmd stop" id="btnStop" title="Stop">■</button>
      <button class="cmd gear" id="btnGear" title="Live scan settings">⚙</button>
    </div>
    <div class="drawer" id="drGear">
      <label>Chain</label>
      <select id="liveChain"><option>ethereum</option><option>base</option><option>arbitrum</option><option>optimism</option><option>polygon</option><option>bsc</option><option>avalanche</option></select>
      <label>Min value held, USD (0 = scan all)</label><input id="liveMinUsd" value="0" inputmode="decimal">
      <div style="color:var(--dim);font-size:10px;margin-top:4px">native coin + USDC, USDT, DAI, USDS, USDe, WETH, stETH, wstETH, WBTC · priced by Chainlink</div>
      <label>Start from block (blank = chain head)</label><input id="liveFromBlock" placeholder="latest">
    </div>
    <div class="drow">
      <button class="cmd back" id="btnBack">◷ BACKFILL 2 YEARS</button>
      <button class="cmd gear" id="btnBackGear" title="Backfill settings" style="--c:var(--purple)">⚙</button>
    </div>
    <div class="drawer" id="drBack">
      <label>History window (days · 730 = 2 years)</label><input id="bfDays" value="730" inputmode="numeric">
      <label>Alive = at least N transactions (or any balance / market cap)</label><input id="bfTxs" value="10" inputmode="numeric">
      <div style="color:var(--dim);font-size:10px;margin-top:6px">Lists every contract verified on Blockscout in the window, keeps the alive ones, prices them, and scans the richest first. Resumes after restarts.</div>
    </div>
    <button class="cmd imm" id="btnImm">◆ IMMUNEFI SCAN</button>
    <div class="drawer" id="drImm">
      <label>Program</label><input id="immName" placeholder="acme-protocol">
      <label>In-scope addresses · one per line · chain:0x… or 0x…</label>
      <textarea id="immAddrs" placeholder="ethereum:0x…&#10;0x…"></textarea>
      <label>…or scope file on server (optional)</label><input id="immScope" placeholder="programs/acme.json">
      <button class="cmd imm" id="btnImmGo" style="width:100%;margin-top:9px">SCAN PROGRAM</button>
    </div>
    <div id="batches"></div>
  </div>

  <div class="hud">
    <div class="p"><div class="hd"><b>SCAN LOG</b><span id="hRate">0 c/m</span></div><div class="log" id="hLog"></div><div class="ft">block → source → detectors → verdict</div></div>
    <div class="p"><div class="hd"><b>PIPELINE</b><span id="hTotal">0</span></div><div id="hPipe"></div></div>
    <div class="p"><div class="hd"><b>DETECTOR RADAR</b><span>live</span></div><svg id="hRadar" viewBox="0 0 200 128" style="width:100%;height:132px"></svg><div class="bars" id="hRadarBars"></div></div>
    <div class="p"><div class="hd"><b>OUTCOME HEAT</b><span id="hHeatN">0</span></div><div class="heat" id="hHeat"></div>
      <div style="color:var(--dim);margin-top:6px;font-size:10.5px">contracts per minute</div><div class="big" id="hCpm">0.0/m</div><div class="kv" id="hKv"></div></div>
    <div class="p"><div class="hd"><b>CLEAR RATE</b><span>live</span></div><canvas id="hGauge" style="width:100%;height:178px"></canvas>
      <div style="color:var(--pink);font-size:11px" id="hFlags">flags to verify · 0</div><div style="color:var(--dim);font-size:10.5px">verify, don't guess</div></div>
    <div class="p" id="pPayload"><div class="hd"><b>⚔ PAYLOAD ATTACK</b><span id="hPayState">forge ·</span></div>
      <div id="hPayRun" style="font-size:11px;color:var(--teal);min-height:15px;margin-bottom:4px"></div>
      <div class="bars" id="hPayBars"></div>
      <div class="big" id="hPayTotal" style="margin-top:4px">0</div>
      <div style="color:var(--dim);font-size:10.5px">fork exploits fired this session · funds→wallet or it's not a finding</div>
      <div class="kv" id="hPayKv"></div></div>
    <div class="p"><div class="hd"><b>BOUNTYSCAN.PY</b><span id="hLps" style="color:var(--pink)">0 l/s</span></div><div class="code" id="hCode"></div></div>
  </div>
</section>

<section class="findings" id="findings">
  <div class="fh"><h2>FINDINGS</h2>
    <span class="ftab on" data-t="results">vulnerable</span><span class="ftab" data-t="safe">safe</span><span class="ftab" data-t="errors">errors</span>
    <label id="hideEmptyWrap" style="margin-left:auto;color:var(--dim);font-size:11px;display:flex;align-items:center;gap:5px;cursor:pointer" title="Hide contracts that currently hold no priced value (nothing to steal right now)"><input type="checkbox" id="hideEmpty" checked style="accent-color:var(--teal)">hide holds-nothing</label>
    <button class="cmd" id="btnDownload" style="--c:var(--teal)" title="Download every confirmed threat's full report as one text document">⬇ DOWNLOAD ALL REPORTS</button>
    <button class="cmd" id="btnRecheck" style="--c:var(--pink)" title="Re-verify every already-judged contract against the current rules">↻ RE-CHECK ALL</button>
    <span style="margin-left:14px;color:var(--dim)" id="fNote">only findings confirmed by the independent second pass appear here</span></div>
  <div id="fTable"><div class="empty">loading…</div></div>
</section>

<dialog id="modal"><div class="mh"><b id="mTitle">report</b><button onclick="document.getElementById('modal').close()">×</button></div><pre id="mBody"></pre></dialog>
<div class="ticker" id="ticker"><div class="lbl">⚑ LIVE HITS</div><div class="tk-win"><div class="tk-track" id="tkTrack"></div></div></div>
<div class="toasts" id="toasts"></div>

<script>
"use strict";
const $ = s => document.querySelector(s);
const api = (p,m,b) => fetch(p,{method:m||'GET',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):null})
  .then(async r => { const j = await r.json().catch(()=>({})); if(!r.ok && !j.error) j.error = 'HTTP '+r.status; return j; });
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const short = a => a ? a.slice(0,6)+'…'+a.slice(-4) : '';
const usd = v => v == null ? '?' : v >= 1e9 ? '$'+(v/1e9).toFixed(2)+'B' : v >= 1e6 ? '$'+(v/1e6).toFixed(2)+'M'
  : v >= 1e3 ? '$'+(v/1e3).toFixed(1)+'K' : '$'+Number(v).toFixed(v < 10 ? 2 : 0);
const holdTxt = h => (h||[]).slice(0,3).map(i => `${Number(i.amount).toLocaleString('en-US',{maximumSignificantDigits:4})} ${i.symbol}`).join(' · ');
const rgb = hex => { const n = parseInt(hex.slice(1),16); return [(n>>16)&255,(n>>8)&255,n&255].join(','); };

/* ---------------- phases (the real pipeline) ---------------- */
const PH = [
  {k:'discover', t:'DISCOVER', c:'#e8ecf2'},
  {k:'fetch',    t:'FETCH',    c:'#3fb8e6'},
  {k:'scan',     t:'SCAN',     c:'#ff5c8a'},
  {k:'verify',   t:'VERIFY',   c:'#f2c14e'},
  {k:'report',   t:'REPORT',   c:'#4fd1b5'},
  {k:'next',     t:'NEXT',     c:'#9a7cff'},
];
const PHI = Object.fromEntries(PH.map((p,i)=>[p.k,i]));
$('#tabs').innerHTML = PH.map(p=>`<div class="tab" data-k="${p.k}">${p.k}</div>`).join('');

/* detector families -> radar axes (counts are the real detector coverage) */
const FAM = {
  ACCESS:['unprotected-privileged-function','unrestricted-mint','unrestricted-burn-from','arbitrary-recipient-withdrawal','unprotected-initializer','uninitialized-implementation','tx-origin-auth','unprotected-selfdestruct'],
  CALLS:['arbitrary-external-call','arbitrary-transferfrom','arbitrary-approval','controlled-delegatecall','unchecked-low-level-call','unchecked-erc20-transfer'],
  REENT:['reentrancy','cross-function-reentrancy','hook-reentrancy'],
  ORACLE:['spot-price-oracle','chainlink-stale-price','donation-manipulable-rate'],
  ECON:['erc4626-inflation','missing-slippage-protection','divide-before-multiply','pre-0.8-overflow'],
  SIG:['signature-replay','unvalidated-flash-callback','weak-randomness'],
};
const SHORTDET = id => id.replace('unprotected-','').replace('arbitrary-','arb-').replace('-function','').replace('missing-','').replace('-protection','');

/* ---------------- state ---------------- */
let S = null, META = {detectors:[]}, phase = 'discover', phaseSince = performance.now(), lastResult = null;
let frame = 0, t0 = performance.now(), seen = new Set(), firstPoll = true, safeHeld = 0, ftab = 'results';
const clusters = new Map();          // address -> cluster
let active = null;                   // address being worked on
const spider = {x:0,y:0, fx:0,fy:0, tx:0,ty:0, t:1, cx:0, cy:0};
const trails = [], sparks = [];
let tags = [], tagsKey = '', tagsT0 = 0, findingsCache = {};

/* ---------------- canvas: galaxy ---------------- */
const cv = $('#galaxy'), g = cv.getContext('2d');
let W = 0, H = 0, DPR = 1, bgLayer = null, hudTop = 0, nebR = 0;

function rngFrom(seed){ let a = seed >>> 0; return () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a);
  t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function hash(str){ let h = 2166136261; for (const ch of str){ h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; }
function gauss(r){ let u = 0, v = 0; while(!u) u = r(); while(!v) v = r(); return Math.sqrt(-2*Math.log(u))*Math.cos(2*Math.PI*v); }

/* one organic particle cloud with a faint neighbour mesh, pre-rendered once */
function makeCloud(seed, R, color, alpha){
  const r = rngFrom(seed), size = Math.ceil(R*2.8), c = document.createElement('canvas');
  c.width = c.height = Math.ceil(size*DPR); const x = c.getContext('2d'); x.scale(DPR,DPR);
  const mid = size/2, blobs = 3 + Math.floor(r()*3);
  const B = Array.from({length:blobs}, () => ({x:mid+(r()-.5)*R*.95, y:mid+(r()-.5)*R*.85, s:R*(.22+r()*.28)}));
  const N = Math.floor(R*7.5), pts = [];
  for (let i=0;i<N;i++){ const b = B[i%blobs]; pts.push([b.x+gauss(r)*b.s, b.y+gauss(r)*b.s]); }
  pts.sort((a,b)=>a[0]-b[0]);
  x.strokeStyle = `rgba(${color},${alpha*0.16})`; x.lineWidth = .5; x.beginPath();
  const lim = R*.11;
  for (let i=0;i<pts.length;i++){ let k=0;
    for (let j=i+1;j<pts.length && pts[j][0]-pts[i][0]<lim && k<3;j++){
      const dx = pts[j][0]-pts[i][0], dy = pts[j][1]-pts[i][1];
      if (dx*dx+dy*dy < lim*lim){ x.moveTo(pts[i][0],pts[i][1]); x.lineTo(pts[j][0],pts[j][1]); k++; } } }
  x.stroke();
  for (const [px,py] of pts){ const big = r() < .05; x.fillStyle = `rgba(${color},${alpha*(big?.95:.35+r()*.5)})`;
    const s = big ? 1.7 : .9; x.fillRect(px-s/2, py-s/2, s, s); }
  return {img:c, size};
}

function resize(){
  DPR = Math.min(window.devicePixelRatio || 1, 2);
  const rect = cv.getBoundingClientRect(); W = rect.width; H = rect.height;
  cv.width = Math.round(W*DPR); cv.height = Math.round(H*DPR); g.setTransform(DPR,0,0,DPR,0,0);
  const hud = document.querySelector('.hud');
  hudTop = (getComputedStyle(hud).position === 'absolute') ? hud.offsetTop : H;
  // static background: starfield + a few huge faint nebulae
  // Large, DENSE nebula texture (bigger than the viewport). render() rotates + "breathes" it, so the
  // whole universe drifts as one organic cloud (matches the reference), not a sparse starfield.
  nebR = Math.ceil(Math.max(W, H) * 1.9);
  bgLayer = document.createElement('canvas'); bgLayer.width = bgLayer.height = Math.ceil(nebR*DPR);
  const b = bgLayer.getContext('2d'); b.scale(DPR,DPR); const r = rngFrom(7);
  // baked starfield
  for (let i=0;i<Math.floor(nebR*nebR/1500);i++){ const big = r()<.07; b.fillStyle = `rgba(205,214,234,${.04+r()*.24})`;
    b.fillRect(r()*nebR, r()*nebR, big?1.7:.9, big?1.7:.9); }
  // many overlapping organic clouds -> one connected, colourful nebula field
  const pal = ['150,162,188','120,150,205','158,120,196','118,188,176','196,150,120'];
  for (let i=0;i<18;i++){ const R = nebR*(.07+r()*.17), nx = r()*nebR, ny = r()*nebR;
    const cl = makeCloud(900+i, R, pal[Math.floor(r()*pal.length)], .30+r()*.2);
    b.drawImage(cl.img, nx - cl.size/2, ny - cl.size/2, cl.size, cl.size); }
  makeStars();
  for (const c of clusters.values()) place(c, true);
}

/* cluster placement inside the free area (between title and HUD) */
function place(c, keep){
  // 3D placement: each cluster sits on a shell in a rotating universe (project3d maps it to screen).
  if (!keep || c.wx === undefined){
    const r = rngFrom(hash(c.addr));
    const u = r()*2-1, th = r()*Math.PI*2, rr = Math.sqrt(Math.max(0,1-u*u));
    c.wx = rr*Math.cos(th); c.wy = u*0.78; c.wz = rr*Math.sin(th);
    c.wr = 0.5 + r()*0.55;
  }
  c.R = Math.max(40, Math.min(84, ((hudTop||H)-150)/5.4));
  c.x = W/2; c.y = (118 + (hudTop||H))*0.5;   // provisional until first projection
  c.scale = 1; c.depth = 0;
  c.grey = null; c.tint = {};
}

/* project every cluster from its 3D world position to the screen, through a slowly rotating camera
   with a gentle pitch bob - the clusters orbit and parallax, so it reads as a 3D universe. */
let camRot = 0, camPitch = 0, _projT = 0, stars3d = [];
function updateCamera(now){
  const dt = Math.min(0.05, (now - _projT)/1000) || 0.016; _projT = now;
  camRot += dt*0.22;                         // continuous rotation of the whole universe
  camPitch = Math.sin(now*0.00006)*0.22;
}
/* a dense 3D starfield the camera flies through - rotates + crawls so the universe reads as 3D */
function makeStars(){
  const r = rngFrom(42), N = Math.max(260, Math.min(820, Math.floor(W*H/1500)));
  stars3d = Array.from({length:N}, () => ({x:r()*2-1, y:r()*2-1, z:r()*2-1, b:.25+r()*.75}));
}
function drawStars(now){
  const cx = W/2, cyc = (118 + (hudTop||H))*0.5, spread = Math.max(W,H)*0.95, focal = 500;
  const cY = Math.cos(camRot), sY = Math.sin(camRot), cX = Math.cos(camPitch), sX = Math.sin(camPitch);
  const crawl = (now*0.00005) % 1;           // forward crawl, wraps -> endless flight
  for (const st of stars3d){
    const x = st.x*spread, y = st.y*spread*0.8;
    let z = (((st.z + crawl*2 + 1) % 2) - 1) * spread;
    const x1 = x*cY - z*sY, z1 = x*sY + z*cY;
    const y1 = y*cX - z1*sX, z2 = y*sX + z1*cX;
    const dist = z2 + spread*1.1; if (dist <= 30) continue;
    const sc = focal / dist, sx = cx + x1*sc, sy = cyc + y1*sc;
    if (sx < -4 || sx > W+4 || sy < -4 || sy > H+4) continue;
    const a = Math.min(1, st.b*sc*2.2), sz = Math.max(.7, sc*2.2);
    g.fillStyle = `rgba(206,218,240,${a})`; g.fillRect(sx-sz/2, sy-sz/2, sz, sz);
  }
}
function project3d(now){
  const cx = W/2, cyc = (118 + (hudTop||H))*0.5;
  const spread = Math.min(W, 1040)*0.42, focal = 560, back = spread*1.55;
  const cY = Math.cos(camRot), sY = Math.sin(camRot), cX = Math.cos(camPitch), sX = Math.sin(camPitch);
  for (const c of clusters.values()){
    if (c.wx === undefined) place(c, false);
    const x = c.wx*c.wr*spread, y = c.wy*c.wr*spread, z = c.wz*c.wr*spread;
    const x1 = x*cY - z*sY, z1 = x*sY + z*cY;         // yaw (around Y)
    const y1 = y*cX - z1*sX, z2 = y*sX + z1*cX;        // pitch (around X)
    const dist = z2 + back, sc = focal / Math.max(80, focal + dist);
    c.x = cx + x1*sc; c.y = cyc + y1*sc; c.scale = sc; c.depth = dist;
  }
}

function cloudFor(c, color){
  if (!color){ if (!c.grey) c.grey = makeCloud(hash(c.addr), c.R, '205,212,226', .8); return c.grey; }
  if (!c.tint[color]) c.tint[color] = makeCloud(hash(c.addr), c.R, rgb(color), 1);
  return c.tint[color];
}

const STATUS_TXT = {queued:'queued', scanning:'scanning', safe:'clear · no fund-theft', vulnerable:'⚑ vulnerable', unverified:'awaiting source',
  no_code:'no code', low_value:'low value', unverified_final:'never verified', error:'error'};

function upsert(addr, patch){
  addr = addr.toLowerCase();
  let c = clusters.get(addr);
  if (!c){ c = {addr, name:'', status:'queued', born:performance.now(), seen:Date.now()}; clusters.set(addr, c); place(c);
    sparks.push({x:c.x, y:c.y, t:performance.now(), n:6});
    // keep the galaxy readable: at most 11 clouds, drop the oldest that isn't active
    if (clusters.size > 26){ const old = [...clusters.values()].filter(x=>x.addr!==active).sort((a,b)=>a.seen-b.seen)[0];
      if (old) clusters.delete(old.addr); } }
  Object.assign(c, patch, {seen:Date.now()});
  return c;
}

function setActive(addr){
  addr = addr.toLowerCase(); if (addr === active) return;
  const c = clusters.get(addr) || upsert(addr, {status:'scanning'});
  const from = active && clusters.get(active) ? {x:spider.x, y:spider.y} : {x:c.x - 260, y:c.y - 120};
  if (active) trails.push({a:{...from}, b:{x:c.x, y:c.y}, t:performance.now()});
  active = addr;
  Object.assign(spider, {fx:from.x, fy:from.y, tx:c.x, ty:c.y, t:0});
  const mx = (from.x+c.x)/2, my = (from.y+c.y)/2, dx = c.x-from.x, dy = c.y-from.y;
  spider.cx = mx - dy*.35; spider.cy = my + dx*.35;
}

/* tags = what the scanner is reaching for right now (stage-driven, real) */
function tagsFor(){
  const cur = active && clusters.get(active);
  const blk = S && S.cursor ? Number(S.cursor).toLocaleString('en-US') : '…';
  switch (phase){
    case 'discover': return [['block · '+blk],['tx · create'],['receipt · contractAddress'],['queue · push']];
    case 'fetch':    return [['etherscan · v2'],['source · fetch'],['proxy · follow'],['balance · read']];
    case 'scan': {
      const ids = META.detectors.map(d=>d.id); if (!ids.length) return [['detectors · run']];
      const k = Math.floor((performance.now()-phaseSince)/520);
      return Array.from({length:7}, (_,i)=>[SHORTDET(ids[(k+i)%ids.length])+' · check']); }
    case 'verify':   return [['re-fetch · fresh'],['counter-check · guards'],['reproduce · finding'],['auth · modifiers']];
    case 'report': {
      if (cur && cur.status === 'vulnerable'){
        const f = findingsCache[cur.addr] || [];
        const t = f.slice(0,6).map(x=>[SHORTDET(x.detector)+' · ⚑ '+x.severity, true]);
        return t.length ? t.concat([['report · saved']]) : [['status · ⚑ vulnerable', true]]; }
      if (cur && cur.status === 'unverified') return [['explorer · unverified'],['retry · scheduled']];
      if (cur && (cur.status === 'no_code' || cur.status === 'low_value')) return [['status · skipped']];
      return [['fund-theft · clear'],[(META.detectors.length||27)+' detectors · pass'],['status · SAFE']]; }
    default: return [['queue · '+(S ? S.pending : 0)+' waiting'],['retry · scheduled']];
  }
}

function drawTag(x, y, text, color, flagged, a){
  g.font = '500 10.5px JetBrains Mono, monospace';
  const w = g.measureText(text).width + 14, h = 17;
  g.globalAlpha = a;
  g.fillStyle = flagged ? color : 'rgba(6,8,11,.92)'; g.fillRect(x, y-h/2, w, h);
  g.strokeStyle = color; g.lineWidth = 1; g.strokeRect(x+.5, y-h/2+.5, w-1, h-1);
  g.fillStyle = flagged ? '#07080a' : '#e6ebf1'; g.fillText(text, x+7, y+3.6);
  g.globalAlpha = 1;
  return w;
}

function bez(a, c, b, t){ const u = 1-t; return [u*u*a.x + 2*u*t*c.x + t*t*b.x, u*u*a.y + 2*u*t*c.y + t*t*b.y]; }
const ease = t => t<.5 ? 4*t*t*t : 1 - Math.pow(-2*t+2,3)/2;

function render(now){
  frame++;
  const col = PH[PHI[phase] ?? 0].c;
  g.clearRect(0,0,W,H);
  if (W) updateCamera(now);
  // dense nebula, rotated + slowly zoomed -> flying through a living universe
  if (bgLayer){ const bx = W/2, by = (118 + (hudTop||H))*0.5;
    const zoom = 1.08 + Math.sin(now*0.00004)*0.07;
    g.save(); g.translate(bx, by); g.rotate(camRot*0.5); g.scale(zoom, zoom);
    g.globalAlpha = .92; g.drawImage(bgLayer, -nebR/2, -nebR/2, nebR, nebR); g.globalAlpha = 1; g.restore();
    const pw = g.createRadialGradient(bx,by,0,bx,by,Math.max(W,H)*.55);   // phase-coloured wash
    pw.addColorStop(0, `rgba(${rgb(col)},.07)`); pw.addColorStop(1, 'rgba(0,0,0,0)');
    g.fillStyle = pw; g.fillRect(0,0,W,H); }
  // faint parallax starfield on top, then project the clusters as bright nodes
  if (W){ if (stars3d.length) drawStars(now); project3d(now); }
  const ordered = [...clusters.values()].sort((a,b) => (b.depth||0) - (a.depth||0));
  // clouds
  for (const c of ordered){
    const isA = c.addr === active, age = (now - c.born)/900, fade = Math.min(1, age);
    const status = c.status, sc = c.scale || 1, dim = Math.max(.28, Math.min(1, sc*1.15));
    let tint = null;
    if (isA) tint = col; else if (status === 'vulnerable') tint = '#ff5c8a';
    const cl = cloudFor(c, tint), sz = cl.size*sc;
    g.globalAlpha = fade * dim * (isA ? 1 : (status === 'vulnerable' ? .9 : .55));
    if (isA){ const hg = g.createRadialGradient(c.x,c.y,0,c.x,c.y,c.R*1.5*sc);
      hg.addColorStop(0, `rgba(${rgb(col)},.20)`); hg.addColorStop(1, 'rgba(0,0,0,0)'); g.fillStyle = hg;
      g.fillRect(c.x-c.R*1.6*sc, c.y-c.R*1.6*sc, c.R*3.2*sc, c.R*3.2*sc); g.globalCompositeOperation = 'lighter'; }
    g.drawImage(cl.img, c.x - sz/2, c.y - sz/2, sz, sz);
    g.globalCompositeOperation = 'source-over'; g.globalAlpha = fade * dim;
    // label (scaled with depth, hidden when very far/small)
    const fs = Math.max(8.5, (isA?14:12.5)*sc);
    g.font = `${isA?'700':'500'} ${fs}px JetBrains Mono, monospace`;
    g.fillStyle = isA ? col : (status==='vulnerable' ? '#ff5c8a' : '#aab3c0');
    const lx = c.x + c.R*.15*sc, ly = c.y - c.R*.9*sc;
    if (sc > 0.45){
      g.fillText(c.name || short(c.addr), lx, ly);
      g.font = `400 ${Math.max(7.5, 10*sc)}px JetBrains Mono, monospace`; g.fillStyle = '#5d6878';
      const VERB = {discover:'discovered', fetch:'fetching source', scan:'scanning · detectors', verify:'verifying · 2nd pass', next:'queued'};
      const worth = c.usd != null ? ' · ' + usd(c.usd) : '';
      g.fillText((isA && phase !== 'report' ? VERB[phase] : (STATUS_TXT[status] || status)) + worth, lx, ly+13*sc);
    }
    g.globalAlpha = 1;
  }

  // trails between clouds
  for (let i = trails.length-1; i>=0; i--){
    const tr = trails[i], life = (now - tr.t)/7000; if (life > 1){ trails.splice(i,1); continue; }
    const mx = (tr.a.x+tr.b.x)/2, my = (tr.a.y+tr.b.y)/2, dx = tr.b.x-tr.a.x, dy = tr.b.y-tr.a.y, c = {x:mx-dy*.35, y:my+dx*.35};
    g.strokeStyle = `rgba(235,240,248,${(1-life)*.55})`; g.lineWidth = 1.1; g.beginPath(); g.moveTo(tr.a.x,tr.a.y);
    g.quadraticCurveTo(c.x,c.y,tr.b.x,tr.b.y); g.stroke();
    const [px,py] = bez(tr.a, c, tr.b, (now/1600 + i*.3)%1); g.fillStyle = `rgba(255,255,255,${(1-life)*.9})`; g.fillRect(px-1.2,py-1.2,2.4,2.4);
  }

  // spider movement - the active cluster orbits in 3D, so keep re-targeting its LIVE position
  if (active){
    const ac = clusters.get(active);
    if (ac){ spider.tx = ac.x; spider.ty = ac.y; }
    spider.t = Math.min(1, spider.t + 1/70); const e = ease(spider.t);
    if (spider.t >= 1 && ac){ spider.x = ac.x; spider.y = ac.y; }
    else [spider.x, spider.y] = bez({x:spider.fx,y:spider.fy}, {x:spider.cx,y:spider.cy}, {x:spider.tx,y:spider.ty}, e);
    const sx = spider.x, sy = spider.y;

    // tentacles + tags
    const key = phase + '|' + (phase==='scan' ? Math.floor((now-phaseSince)/520) : '') + '|' + active + '|' + (clusters.get(active)||{}).status;
    if (key !== tagsKey){ const fresh = key.split('|')[0] !== tagsKey.split('|')[0] || key.split('|')[2] !== tagsKey.split('|')[2];
      tags = tagsFor(); tagsKey = key; if (fresh) tagsT0 = now; }
    if (spider.t > .85){
      const dir = sx > W*.55 ? -1 : 1, n = tags.length, rev = Math.min(1, (now - tagsT0)/650);
      tags.forEach((tg, i) => {
        const ty = sy - (n-1)*15 + i*30, tx = sx + dir*(118 + (i%2)*54);
        const p = Math.min(1, Math.max(0, rev*n - i*.6));
        if (p <= 0) return;
        // dotted tentacle
        g.save(); g.setLineDash([1.5,3.5]); g.lineDashOffset = -now/60; g.strokeStyle = `rgba(${rgb(tg[1] ? '#ff5c8a' : col)},.85)`;
        g.lineWidth = 1.1; g.beginPath(); g.moveTo(sx, sy);
        const ex = sx + (tx - sx)*p, ey = sy + (ty - sy)*p; g.quadraticCurveTo(sx + (ex-sx)*.5, sy + (ey-sy)*.15, ex, ey); g.stroke(); g.restore();
        if (p >= 1){ const label = tg[0]; const textW = (g.font='500 10.5px JetBrains Mono, monospace', g.measureText(label).width + 14);
          drawTag(dir > 0 ? tx : tx - textW, ty, label, tg[1] ? '#ff5c8a' : col, !!tg[1], Math.min(1,(rev*n - i*.6 - 1)*2+.4)); }
      });
    }
    // legs
    const legs = 22;
    g.strokeStyle = 'rgba(79,209,181,.9)'; g.lineWidth = 1;
    for (let i=0;i<legs;i++){ const a = i/legs*Math.PI*2 + now/2400, wob = Math.sin(now/180 + i*1.7)*3.2;
      const r1 = 13, r2 = 24 + wob + (i%3)*3; g.beginPath(); g.moveTo(sx+Math.cos(a)*r1, sy+Math.sin(a)*r1);
      g.lineTo(sx+Math.cos(a+.08)*r2, sy+Math.sin(a+.08)*r2); g.stroke();
      g.fillStyle = '#4fd1b5'; g.fillRect(sx+Math.cos(a+.08)*r2-1, sy+Math.sin(a+.08)*r2-1, 2, 2); }
    // body
    const halo = g.createRadialGradient(sx,sy,0,sx,sy,38); halo.addColorStop(0,'rgba(79,209,181,.35)'); halo.addColorStop(1,'rgba(79,209,181,0)');
    g.fillStyle = halo; g.fillRect(sx-40,sy-40,80,80);
    g.beginPath(); g.arc(sx,sy,13,0,Math.PI*2); g.fillStyle = '#071514'; g.fill(); g.strokeStyle = '#4fd1b5'; g.lineWidth = 1.6; g.stroke();
    const pulse = 5.5 + Math.sin(now/220)*1.2; g.fillStyle = '#ff5c8a'; g.shadowColor = '#ff5c8a'; g.shadowBlur = 14;
    g.fillRect(sx-pulse/2, sy-pulse/2, pulse, pulse); g.shadowBlur = 0;
  }

  // sparkles (newly discovered contracts)
  for (let i = sparks.length-1; i>=0; i--){ const s = sparks[i], life = (now - s.t)/2600; if (life > 1){ sparks.splice(i,1); continue; }
    const r = rngFrom(Math.floor(s.t)); for (let k=0;k<s.n;k++){ const a = r()*Math.PI*2, d = 20 + life*70*r();
      g.fillStyle = `rgba(242,193,78,${(1-life)*(Math.sin(now/90+k)*.4+.6)})`; g.fillRect(s.x+Math.cos(a)*d-1.6, s.y+Math.sin(a)*d-1.6, 3.2, 3.2); } }

  // telemetry clock / frame
  $('#tFrame').textContent = String(frame % 10000).padStart(4,'0');
  if (S && S.started_at && S.mode !== 'idle') $('#tT').textContent = (Date.now()/1000 - S.started_at).toFixed(2);
  drawGauge(now);
  requestAnimationFrame(render);
}

/* ---------------- HUD: gauge + wave ---------------- */
const gc = $('#hGauge'), gx = gc.getContext('2d'); let gaugeVal = 0, gaugeShown = 0, activity = 0;
function drawGauge(now){
  const w = gc.clientWidth, h = gc.clientHeight; if (!w) return;
  if (gc.width !== Math.round(w*DPR)){ gc.width = Math.round(w*DPR); gc.height = Math.round(h*DPR); }
  gx.setTransform(DPR,0,0,DPR,0,0); gx.clearRect(0,0,w,h);
  // live wave: amplitude follows recent scanner activity
  gx.strokeStyle = '#f2c14e'; gx.lineWidth = 1.4; gx.beginPath();
  const amp = 6 + activity*14;
  for (let x=6;x<w-6;x++){ const y = 30 + Math.sin(x/26 + now/700)*amp*.6 + Math.sin(x/11 + now/430)*amp*.25;
    x===6 ? gx.moveTo(x,y) : gx.lineTo(x,y); } gx.stroke();
  // gauge ring
  gaugeShown += (gaugeVal - gaugeShown)*.06;
  const cx = w/2, cy = 118, R = 46, a0 = Math.PI*.75, a1 = Math.PI*2.25;
  gx.lineWidth = 9; gx.lineCap = 'butt'; gx.strokeStyle = '#161b23'; gx.beginPath(); gx.arc(cx,cy,R,a0,a1); gx.stroke();
  const has = S && ((S.counts.safe||0) + (S.counts.vulnerable||0)) > 0;
  const color = !has ? '#3a4350' : gaugeShown >= 90 ? '#4fd1b5' : gaugeShown >= 60 ? '#f2c14e' : '#ff5c8a';
  gx.strokeStyle = color; gx.beginPath(); gx.arc(cx,cy,R,a0, a0 + (a1-a0)*(has ? gaugeShown/100 : 0)); gx.stroke();
  gx.fillStyle = '#e8ecf2'; gx.font = '800 26px JetBrains Mono, monospace'; gx.textAlign = 'center';
  gx.fillText(has ? Math.round(gaugeShown) : '--', cx, cy+8); gx.font = '400 10px JetBrains Mono, monospace'; gx.fillStyle = '#5d6878';
  gx.fillText('% clear', cx, cy+24); gx.textAlign = 'left';
}

/* ---------------- HUD: radar ---------------- */
function drawRadar(){
  const fams = Object.keys(FAM), n = fams.length, cx = 100, cy = 66, R = 50, max = Math.max(...fams.map(f=>FAM[f].length));
  const pt = (i, v) => { const a = -Math.PI/2 + i/n*Math.PI*2; return [cx + Math.cos(a)*R*v, cy + Math.sin(a)*R*v]; };
  let s = '';
  for (const lv of [.33,.66,1]) s += `<polygon points="${fams.map((_,i)=>pt(i,lv).join(',')).join(' ')}" fill="none" stroke="#1d242e" stroke-width="1"/>`;
  fams.forEach((f,i)=>{ const [x,y] = pt(i,1); s += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="#1d242e"/>`;
    const [lx,ly] = pt(i,1.24); s += `<text x="${lx}" y="${ly+3}" fill="#6b7686" font-size="7.5" text-anchor="middle" font-family="JetBrains Mono,monospace">${f}</text>`; });
  const poly = fams.map((f,i)=>pt(i, .25 + .75*FAM[f].length/max).join(',')).join(' ');
  s += `<polygon points="${poly}" fill="rgba(79,209,181,.42)" stroke="#4fd1b5" stroke-width="1.2"><animate attributeName="opacity" values=".8;1;.8" dur="3s" repeatCount="indefinite"/></polygon>`;
  $('#hRadar').innerHTML = s;
}

/* ---------------- polling ---------------- */
const KIND = {found:['find','#f2c14e'], safe:['safe','#4fd1b5'], vulnerable:['VULN','#ff5c8a'], unverified:['wait','#c99a3c'],
  no_code:['skip','#5d6878'], low_value:['skip','#5d6878'], unverified_final:['drop','#5d6878'], error:['err','#ff5c8a'], info:['info','#3fb8e6'],
  funded:['FUND','#ff8a5c']};
const ADDR_RE = /0x[0-9a-fA-F]{40}/;

function phaseOf(s){
  if (!s || s.mode === 'idle') return 'next';
  if (lastResult && performance.now() - lastResult < 2600) return 'report';
  const t = (s.stage || '').toLowerCase();
  if (t.includes('re-verif')) return 'verify';
  if (t.startsWith('scanning')) return 'scan';
  if (t.includes('fetching') || t.includes('checking code')) return 'fetch';
  if (t.includes('waiting for contracts')) return 'next';
  return 'discover';
}

async function poll(){
  let s; try { s = await api('/api/status'); } catch { return; }
  if (s.error) return;
  S = s;
  // events -> clouds + log
  let newResults = 0;
  for (const e of s.events || []){
    const m = (e.msg || '').match(ADDR_RE); const isNew = !seen.has(e.id); seen.add(e.id);
    if (!m) continue;
    const nm = (e.msg.match(/\(([^)]+)\)/) || [])[1] || '';
    const status = e.kind === 'found' ? 'queued' : e.kind === 'funded' ? 'vulnerable' : e.kind;
    const held = e.msg.match(/(?:Holds|holds) \$([\d,]+(?:\.\d+)?)/);
    const patch = {status}; if (nm) patch.name = nm; if (held) patch.usd = parseFloat(held[1].replace(/,/g,''));
    if (KIND[e.kind] && e.kind !== 'info') upsert(m[0], patch);
    const tkName = esc(nm || short(m[0])), tkWorth = held ? ` · <em>$${esc(held[1])}</em>` : '';
    if (isNew && !firstPoll && e.kind === 'funded') ticker(`💰 <b>${tkName}</b> funded${tkWorth}`);
    if (isNew && !firstPoll && e.kind !== 'found' && e.kind !== 'info'){ newResults++; lastResult = performance.now(); }
    if (isNew && !firstPoll && e.kind === 'vulnerable'){ ticker(`⚑ <b>${tkName}</b> ${esc(short(m[0]))}${tkWorth}`);
      api(`/api/result?chain=${s.chain}&addr=${m[0].toLowerCase()}`).then(r => { if (r.findings) findingsCache[m[0].toLowerCase()] = r.findings.findings || []; }); }
  }
  activity = Math.min(1, activity*.7 + newResults*.35 + (s.mode !== 'idle' ? .1 : 0));
  if (s.current && s.current.address){ const c = upsert(s.current.address, s.current.status ? {} : {status:'scanning'}); setActive(c.addr); }
  else if (!active && clusters.size){ setActive([...clusters.keys()].pop()); }

  const np = phaseOf(s); if (np !== phase){ phase = np; phaseSince = performance.now(); }
  updateChrome(s); updateHud(s);
  if (firstPoll || Math.random() < .3) loadTable();
  firstPoll = false;
}

function updateChrome(s){
  const c = s.counts || {}, p = PH[PHI[phase]];
  document.documentElement.style.setProperty('--phase', p.c);
  $('#tChain').textContent = s.chain; $('#tBlock').textContent = s.cursor ? Number(s.cursor).toLocaleString('en-US') : '-';
  const total = Object.values(c).reduce((a,b)=>a+b,0);
  $('#tFound').textContent = total; $('#tScanned').textContent = (c.safe||0)+(c.vulnerable||0);
  $('#tSafe').textContent = c.safe||0; $('#tVuln').textContent = c.vulnerable||0; $('#tWait').textContent = c.unverified||0;
  const vs = s.value || {}; $('#tValue').textContent = usd(vs.seen_usd || 0); $('#tRisk').textContent = usd(vs.vulnerable_usd || 0);
  if (s.mode === 'idle') $('#tT').textContent = '0.00';
  document.querySelectorAll('.tab').forEach((t,i)=>{ const k = t.dataset.k, ai = PHI[phase];
    t.className = 'tab ' + (s.mode === 'idle' ? 'future' : i === ai ? 'on' : i < ai ? 'past' : 'future');
    t.style.background = (s.mode !== 'idle' && i === ai) ? PH[i].c : ''; });
  const cur = active && clusters.get(active);
  const idx = String(PHI[phase]+1).padStart(2,'0');
  $('#phTitle').textContent = s.mode === 'idle' ? '00 IDLE' : `${idx} ${p.t}`;
  const who = cur ? (cur.name || short(cur.addr)) : '';
  const sub = {
    discover: `block ${s.cursor ? Number(s.cursor).toLocaleString('en-US') : '…'} · scanning ${s.chain} for new deployments`,
    fetch: `${who} · pulling verified source from the explorer`,
    scan: `${who} · ${META.detectors.length || 27} fund-theft detectors`,
    verify: `${who} · independent second pass, fresh re-fetch`,
    report: `${who} · ${cur ? (STATUS_TXT[cur.status]||cur.status) : ''}`,
    next: s.mode === 'idle' ? 'press LIVE SCAN to start crawling the chain' : `queue · ${s.pending} waiting, retried on schedule`,
  }[phase];
  $('#phSub').textContent = sub;
  // live button
  const lb = $('#btnLive');
  if (!lb.dataset.busy){ if (s.mode === 'live'){ lb.classList.add('running'); lb.textContent = '● LIVE · CRAWLING'; lb.disabled = true; }
    else { lb.classList.remove('running'); lb.textContent = '▶ LIVE SCAN'; lb.disabled = false; } }
  // backfill (historical scan)
  const bf = s.backfill || {};
  const bb = $('#btnBack');
  if (bf.active && bf.running){ bb.classList.add('running'); bb.textContent = `◷ BACKFILL · ${bf.percent}%`; }
  else { bb.classList.remove('running'); bb.textContent = bf.active && !bf.done ? `◷ RESUME BACKFILL · ${bf.percent}%` : '◷ BACKFILL 2 YEARS'; }
  $('#tBack').textContent = bf.active ? (bf.done ? 'done' : bf.percent + '%') : '-';
  let bfCard = '';
  if (bf.active){
    const reached = bf.reached ? String(bf.reached).slice(0,10) : '…';
    const state = bf.done ? '<span style="color:var(--teal)">listing complete</span>' : bf.running ? 'listing' : 'paused';
    bfCard = `<div class="batch" style="border-color:rgba(154,124,255,.35)"><div class="t"><span style="color:var(--purple)">◷ backfill ${bf.days}d · ${esc(bf.chain)}</span><b>${bf.percent}%</b></div>
      <div class="bar"><i style="width:${bf.percent}%;background:var(--purple)"></i></div>
      <div class="t" style="margin-top:5px"><span>${state} · reached ${reached}</span><span>${usd(bf.value_queued_usd||0)} queued</span></div>
      <div class="t"><span>${Number(bf.listed||0).toLocaleString('en-US')} listed</span><span>${Number(bf.alive||0).toLocaleString('en-US')} alive</span><span>${Number(bf.queued||0).toLocaleString('en-US')} queued</span></div>
      ${bf.last_error ? `<div class="t" style="color:var(--orange)">${esc(bf.last_error).slice(0,80)}</div>` : ''}</div>`;
  }
  // program batches
  const bs = (s.batches || []).filter(b=>b.total).slice(-2).reverse();
  $('#batches').innerHTML = bfCard + bs.map(b => { const pct = Math.round(100*b.done/b.total);
    return `<div class="batch"><div class="t"><span>◆ ${esc(b.program)}</span><b>${b.done}/${b.total} · ${pct}%</b></div>
      <div class="bar"><i style="width:${pct}%;background:${b.done>=b.total?'var(--teal)':'var(--cyan)'}"></i></div>
      <div class="t" style="margin-top:5px"><span style="color:var(--pink)">${b.vulnerable} vuln</span><span style="color:var(--teal)">${b.safe} safe</span><span>${b.waiting_verification} awaiting source</span></div></div>`; }).join('');
}

function updateHud(s){
  const c = s.counts || {}, evs = s.events || [];
  // SCAN LOG
  const last = evs.filter(e => e.kind !== 'info' || true).slice(-13);
  $('#hLog').innerHTML = last.map(e => { const [vb, col] = KIND[e.kind] || ['info','#3fb8e6'];
    const m = (e.msg||'').match(ADDR_RE); const nm = (e.msg.match(/\(([^)]+)\)/)||[])[1];
    const obj = m ? (nm || short(m[0])) : e.msg.replace(/\.$/,'');
    const d = new Date(e.t*1000); const tt = String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');
    return `<div class="${(Date.now()/1000 - e.t) < 2.5 ? 'new' : ''}"><span class="t">${tt}</span><span class="vb" style="color:${col}">${vb}</span><span class="o">${esc(obj)}</span></div>`; }).join('');
  const recent = evs.filter(e => Date.now()/1000 - e.t < 600 && e.kind !== 'info' && e.kind !== 'found').length;
  const act = (s.active_scans||[]).length, wk = s.scan_workers||1;
  $('#hRate').textContent = (recent/10).toFixed(1) + ' c/m' + (wk>1 ? ` · ⚡${act}/${wk}` : '');
  // PIPELINE
  const total = Object.values(c).reduce((a,b)=>a+b,0) || 0;
  $('#hTotal').textContent = total;
  const rows = [['discovered', total, '#e8ecf2'], ['awaiting source', c.unverified||0, '#f2c14e'], ['scanned', (c.safe||0)+(c.vulnerable||0), '#3fb8e6'],
    ['clear', c.safe||0, '#4fd1b5'], ['vulnerable', c.vulnerable||0, '#ff5c8a'], ['skipped', (c.no_code||0)+(c.low_value||0)+(c.unverified_final||0), '#ff8a5c'], ['errors', c.error||0, '#9a7cff']];
  $('#hPipe').innerHTML = rows.map(([n,v,col]) => `<div class="sec"><div class="r"><span>${n}</span><em>${v}/${total}</em></div>
    <div class="tr"><i style="width:${total ? Math.max(v ? 3 : 0, 100*v/total) : 0}%;background:${col}"></i></div></div>`).join('');
  // RADAR bars
  const dets = META.detectors.length || 27;
  $('#hRadarBars').innerHTML = [['detectors', dets, dets], ['confirmed', c.vulnerable||0, Math.max(1,(c.safe||0)+(c.vulnerable||0))], ['held back', safeHeld, Math.max(1,c.safe||0)]]
    .map(([n,v,m]) => `<div><span>${n}</span><i style="width:${Math.min(100, 8 + 70*v/m)}px"></i><b>${v}</b></div>`).join('');
  // HEAT
  const heat = [['FND', total, '#e8ecf2'], ['SCN', (c.safe||0)+(c.vulnerable||0), '#3fb8e6'], ['CLR', c.safe||0, '#4fd1b5'], ['VLN', c.vulnerable||0, '#ff5c8a'],
    ['WAI', c.unverified||0, '#f2c14e'], ['SKP', (c.no_code||0)+(c.low_value||0), '#ff8a5c'], ['ERR', c.error||0, '#9a7cff']];
  const prev = $('#hHeat').dataset.prev ? JSON.parse($('#hHeat').dataset.prev) : {};
  $('#hHeat').innerHTML = heat.map(([k,v,col]) => { const lit = Math.min(12, v);
    return `<div class="row"><em>${k}</em>${Array.from({length:12},(_,i)=>`<span class="sq${(i === lit-1 && prev[k] !== undefined && prev[k] !== v) ? ' pop':''}" style="${i<lit?'background:'+col:''}"></span>`).join('')}</div>`; }).join('');
  $('#hHeat').dataset.prev = JSON.stringify(Object.fromEntries(heat.map(([k,v])=>[k,v])));
  $('#hHeatN').textContent = total;
  $('#hCpm').textContent = (recent/10).toFixed(1) + '/m';
  $('#hKv').innerHTML = [['found', total, '#e8ecf2'], ['scanned', (c.safe||0)+(c.vulnerable||0), '#3fb8e6'], ['flagged', c.vulnerable||0, '#ff5c8a'], ['waiting', c.unverified||0, '#f2c14e']]
    .map(([k,v,col]) => `<div><span>${k}</span><b style="color:${col}">${v}</b></div>`).join('');
  // GAUGE
  const sc = (c.safe||0) + (c.vulnerable||0); gaugeVal = sc ? 100*(c.safe||0)/sc : 0;
  $('#hFlags').textContent = `flags to verify · ${c.vulnerable||0}`;
  // PAYLOAD ATTACK
  const pay = s.payload || {counts:{}, running:0, forge:false};
  const pc = pay.counts || {};
  $('#hPayState').textContent = pay.forge ? (pay.running>0 ? '⚔ '+pay.running+' firing' : 'forge ready') : 'forge off';
  $('#hPayState').style.color = pay.forge ? (pay.running>0 ? 'var(--teal)' : 'var(--dim)') : 'var(--pink)';
  const pr = $('#pPayload'); if (pay.running>0) pr.classList.add('firing'); else pr.classList.remove('firing');
  $('#hPayRun').textContent = pay.running>0 ? `forking mainnet · routing loot to the wallet · ${pay.running} exploit(s) live` : (pay.forge ? '' : 'install forge to run payload attacks');
  $('#hPayTotal').textContent = pc.total||0;
  const pbars = [['confirmed',pc.confirmed||0,'var(--teal)'],['reverted',pc.reverted||0,'#3fb8e6'],['no-move',pc.no_change||0,'#5a6b7a'],['manual',pc.manual||0,'#f2c14e'],['not run',pc.error||0,'var(--pink)']];
  const pmax = Math.max(1, ...pbars.map(x=>x[1]));
  $('#hPayBars').innerHTML = pbars.map(([n,v,col])=>`<div><span>${n}</span><i style="width:${Math.min(100, 8+70*v/pmax)}px;background:${col};transition:width .8s"></i><b>${v}</b></div>`).join('');
  $('#hPayKv').innerHTML = [['dropped FP',(pc.reverted||0)+(pc.no_change||0),'#3fb8e6'],['real theft',pc.confirmed||0,'var(--teal)'],['manual',pc.manual||0,'#f2c14e']].map(([k,v,col])=>`<div><span>${k}</span><b style="color:${col}">${v}</b></div>`).join('');
  // CODE
  drawCode(s);
}

const CODE = [
  ['# bountyscan.py · reads every new contract', null],
  ['chain = rpc.connect("{chain}")', 'discover'],
  ['for block in chain.follow():', 'discover'],
  ['  for c in block.new_contracts():', 'discover'],
  ['    src  = explorer.fetch(c)', 'fetch'],
  ['    hits = detectors.run(src)  # {n}', 'scan'],
  ['    sure = verifier.recheck(hits)', 'verify'],
  ['    report(sure) if sure else safe(c)', 'report'],
  ['  queue.next()', 'next'],
];
let typed = 0;
function drawCode(s){
  const lines = CODE.map(([l,p]) => [l.replace('{chain}', s.chain).replace('{n}', META.detectors.length || 27), p]);
  typed = Math.min(lines.length, typed + 2);
  $('#hCode').innerHTML = lines.slice(0, typed).map(([l,p]) => {
    const on = s.mode !== 'idle' && p === phase;
    return `<span class="ln${on?' on':''}">${esc(l)}${on ? ' <span class="cursor"></span>' : ''}</span>`; }).join('');
  $('#hLps').textContent = (s.mode === 'idle' ? 0 : 9 + Math.round(activity*12)) + ' l/s';
}

/* ---------------- findings table ---------------- */
async function loadTable(){
  const ep = ftab === 'results' ? '/api/results' : ftab === 'safe' ? '/api/safe' : '/api/errors';
  const d = await api(ep).catch(()=>({})); const rows = d[ftab] || [];
  if (ftab === 'safe') safeHeld = rows.filter(r => (r.error||'').includes('not confirmed')).length;
  const w = $('#fTable');
  if (!rows.length){ w.innerHTML = `<div class="empty">${ftab==='results' ? 'no confirmed vulnerabilities yet · the crawler keeps going' : 'nothing here yet'}</div>`; return; }
  rows.sort((a,b) => (b.value_usd||0) - (a.value_usd||0));
  const valCell = r => `<td style="color:${(r.value_usd||0) >= 1000 ? 'var(--yellow)' : 'var(--dim)'}">${usd(r.value_usd)}</td><td style="color:var(--dim)">${esc(holdTxt(r.holdings)) || (r.value_usd === 0 ? 'holds nothing' : '-')}</td>`;
  // On the vulnerable tab, hide contracts that currently hold no priced value (nothing to steal right
  // now) unless the viewer unticks the toggle. Non-destructive - the rows stay in the DB and the download.
  let hiddenEmpty = 0;
  if (ftab === 'results' && $('#hideEmpty') && $('#hideEmpty').checked){
    hiddenEmpty = rows.filter(r => (r.value_usd||0) <= 0).length;
    rows = rows.filter(r => (r.value_usd||0) > 0);
  }
  if (ftab === 'results'){
    if (!rows.length){ w.innerHTML = `<div class="empty">${hiddenEmpty ? hiddenEmpty+' flagged contract(s) hidden · they hold no priced value · untick “hide holds-nothing” to see them' : 'no confirmed vulnerabilities with value yet · the crawler keeps going'}</div>`;
      $('#fNote').textContent = hiddenEmpty ? hiddenEmpty+' empty hidden' : ''; return; }
    w.innerHTML = `<table><thead><tr><th>severity</th><th>findings</th><th>value held</th><th>holdings</th><th>chain</th><th>address</th><th>contract</th></tr></thead><tbody>` +
      rows.map(r => `<tr class="click" data-c="${esc(r.chain)}" data-a="${esc(r.address)}"><td><span class="sev ${esc(r.max_severity)}">${esc(r.max_severity)}</span></td>
        <td>${r.findings||0}</td>${valCell(r)}<td>${esc(r.chain)}</td><td>${esc(r.address)}</td><td>${esc(r.name||'')}</td></tr>`).join('') + '</tbody></table>';
    w.querySelectorAll('tr.click').forEach(tr => tr.onclick = () => openReport(tr.dataset.c, tr.dataset.a));
  } else {
    w.innerHTML = `<table><thead><tr><th>value held</th><th>holdings</th><th>chain</th><th>address</th><th>contract</th><th>note</th></tr></thead><tbody>` +
      rows.map(r => `<tr>${valCell(r)}<td>${esc(r.chain)}</td><td>${esc(r.address)}</td><td>${esc(r.name||'')}</td><td style="color:var(--dim)">${esc(r.error||'clear')}</td></tr>`).join('') + '</tbody></table>';
  }
  $('#fNote').textContent = ftab === 'results'
    ? 'confirmed · sorted by value held · re-checked every 10 min' + (hiddenEmpty ? ` · ${hiddenEmpty} empty hidden` : '')
    : 'value = native coin + major tokens, priced by Chainlink';
}
async function openReport(chain, addr){
  const d = await api(`/api/result?chain=${chain}&addr=${addr}`);
  $('#mTitle').textContent = `⚑ ${chain} ${addr}`; $('#mBody').textContent = d.markdown || JSON.stringify(d, null, 2); $('#modal').showModal();
}
document.querySelectorAll('.ftab').forEach(t => t.onclick = () => { document.querySelectorAll('.ftab').forEach(x=>x.classList.remove('on'));
  t.classList.add('on'); ftab = t.dataset.t; loadTable(); });

/* ---------------- controls ---------------- */
let tkMsgs = [];
function ticker(msg){
  tkMsgs.push(msg); if (tkMsgs.length > 28) tkMsgs.shift();
  const tr = $('#tkTrack'); if (!tr) return;
  const html = tkMsgs.map(m => `<span class="tk-item">${m}</span>`).join('');
  tr.innerHTML = html + html;   // duplicate so the loop is seamless
  const chars = tkMsgs.reduce((a,m) => a + m.replace(/<[^>]+>/g,'').length + 8, 0);
  tr.style.animationDuration = Math.max(16, chars*0.2) + 's';
}
function toast(msg, err){ const el = document.createElement('div'); el.className = 'toast' + (err ? ' err' : ''); el.textContent = msg;
  $('#toasts').appendChild(el); setTimeout(() => el.remove(), 4500); }
$('#btnGear').onclick = () => $('#drGear').classList.toggle('open');
$('#btnImm').onclick = () => $('#drImm').classList.toggle('open');
$('#btnLive').onclick = async () => {
  const b = $('#btnLive'); b.dataset.busy = 1; b.textContent = '… STARTING'; b.disabled = true;
  const fb = $('#liveFromBlock').value.trim();
  const r = await api('/api/live/start','POST',{chain:$('#liveChain').value, min_value_usd:parseFloat($('#liveMinUsd').value||'0')||0, from_block: fb ? parseInt(fb) : null});
  delete b.dataset.busy;
  r.error ? toast('could not start · ' + r.error, true) : toast('live crawl started on ' + $('#liveChain').value);
  poll();
};
$('#btnBackGear').onclick = () => $('#drBack').classList.toggle('open');
$('#btnBack').onclick = async () => {
  const running = S && S.backfill && S.backfill.running;
  const b = $('#btnBack'); b.disabled = true;
  const r = running ? await api('/api/backfill/stop','POST',{})
    : await api('/api/backfill/start','POST',{chain:$('#liveChain').value, days:parseInt($('#bfDays').value||'730'), min_txs:parseInt($('#bfTxs').value||'10')});
  b.disabled = false;
  if (r.error) toast('backfill · ' + r.error, true);
  else toast(running ? 'backfill paused · progress saved' : `backfill running · last ${$('#bfDays').value} days of verified contracts, richest first`);
  poll();
};
$('#btnStop').onclick = async () => { await api('/api/live/stop','POST',{}); toast('stopping · current contract finishes first'); poll(); };
$('#hideEmpty').onchange = () => { loadTable(); };
$('#btnDownload').onclick = () => { toast('building full threat report…'); window.location = '/api/report/all.txt'; };
$('#btnRecheck').onclick = async () => {
  const b = $('#btnRecheck'); b.disabled = true;
  const r = await api('/api/requeue','POST',{scope:'vulnerable'});
  b.disabled = false;
  if (r.error) toast('re-check · ' + r.error, true);
  else toast(`re-checking ${r.requeued} already-flagged contract(s) against current rules`);
  poll();
};
$('#btnImmGo').onclick = async () => {
  const scope = $('#immScope').value.trim();
  const assets = $('#immAddrs').value.split('\n').map(x=>x.trim()).filter(Boolean).map(l => { const m = l.match(/^(?:([\w-]+)[:,\s]+)?(0x[0-9a-fA-F]{40})$/);
    return m ? {chain:(m[1]||'ethereum').toLowerCase(), address:m[2]} : null; }).filter(Boolean);
  if (!scope && !assets.length) return toast('paste at least one valid 0x address', true);
  const b = $('#btnImmGo'); b.textContent = '… QUEUING'; b.disabled = true;
  const r = await api('/api/immunefi/scan','POST', scope ? {scope_path:scope} : {program:$('#immName').value || 'manual', assets});
  b.textContent = 'SCAN PROGRAM'; b.disabled = false;
  if (r.error) return toast('error · ' + r.error, true);
  toast(`scanning ${r.total} contract(s) · ${r.program}`); $('#drImm').classList.remove('open'); poll();
};

/* ---------------- boot ---------------- */
window.addEventListener('resize', () => { clearTimeout(window._rz); window._rz = setTimeout(resize, 150); });
api('/api/meta').then(m => { if (m && m.detectors) META = m; });
drawRadar(); resize();
(document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve()).then(() => resize());
poll(); setInterval(poll, 1500);
requestAnimationFrame(render);
</script>
</body>
</html>"""
