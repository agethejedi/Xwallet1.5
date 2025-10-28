const { ethers } = window;
const XMTP = window.XMTP;

/* =========================
   CONFIG
   ========================= */
const RPCS = {
  sep: 'https://eth-sepolia.g.alchemy.com/v2/kxHg5y9yBXWAb9cOcJsf0', // <-- replace
  mainnet: "https://mainnet.infura.io/v3/0883fc4e792c4b78aa435b2332790b73",
  polygon: "https://polygon-mainnet.infura.io/v3/0883fc4e792c4b78aa435b2332790b73"
};

// If you’re using the plaintext Cloudflare Worker we set up, it should return:
// { risk_score, block, reasons, risk_factors, ... }
const SAFE_SEND_URL = 'https://xwalletv1dot2.agedotcom.workers.dev'; // <-- oreplace if different

/* =========================
   SafeSend / Risk helpers
   ========================= */

// Build a simple panel if missing
function ensureSafeSendPanel() {
  if (!document.querySelector('#safesend-status')) {
    const target = document.querySelector('#sendOut') || document.body;
    const panel = document.createElement('div');
    panel.id = 'safesend-status';
    panel.style.marginTop = '8px';
    target.parentElement.insertBefore(panel, target);
  }
}

// Normalizer: supports legacy {score, findings} or new {risk_score, block, reasons, risk_factors}
function normalizeSafeSendResponse(j) {
  // New worker format
  if (typeof j?.risk_score === 'number' || j?.reasons || j?.risk_factors) {
    const score = typeof j.risk_score === 'number' ? j.risk_score : 10;
    const findings = Array.isArray(j.risk_factors) && j.risk_factors.length
      ? j.risk_factors
      : Array.isArray(j.reasons) ? j.reasons.map(code => ({
          OFAC: 'OFAC/sanctions list match',
          BAD_LIST: 'Internal bad list match',
          BAD_ENS: 'Flagged ENS name'
        }[code] || code)) : [];
    const blocked = !!j.block || score >= 100 || (j.reasons && j.reasons.length > 0);
    return { score, findings, blocked, raw: j };
  }
  // Legacy format
  if (typeof j?.score === 'number') {
    const score = j.score;
    const findings = Array.isArray(j.findings) ? j.findings : [];
    const blocked = !!j.block || score >= 70; // your prior threshold
    return { score, findings, blocked, raw: j };
  }
  // Fallback
  return { score: 10, findings: [], blocked: false, raw: j || {} };
}

// Calls your SafeSend/Worker and returns normalized result
async function fetchSafeSend(to, chain = 'sepolia') {
  const u = new URL(SAFE_SEND_URL);
  // Support either ?chain or ?network param names, Worker will ignore unknowns
  u.searchParams.set('address', to);
  u.searchParams.set('chain', chain);
  u.searchParams.set('network', chain);

  const r = await fetch(u.toString(), { method: 'GET' });
  if (!r.ok) throw new Error(`SafeSend ${r.status}`);
  const j = await r.json();
  return normalizeSafeSendResponse(j);
}

// Simple UI helper to display SafeSend results (now includes factor list)
function renderSafeSendPanel(check) {
  ensureSafeSendPanel();
  const panel = document.querySelector('#safesend-status');
  if (!panel) return;

  const bg = (check.score >= 100 || check.blocked) ? '#f87171'
           : (check.score >= 70) ? '#facc15'
           : '#4ade80';

  const listHtml = (check.findings || []).map(f => `<li>${escapeHtml(String(f))}</li>`).join('') || '<li>No elevated factors detected</li>';

  panel.innerHTML = `
    <div style="padding:10px;border-radius:8px;background:${bg};color:#111;">
      <div style="font-weight:700;margin-bottom:4px;">SafeSend Result</div>
      <div><strong>Score:</strong> ${check.score}</div>
      <div style="margin-top:6px;"><strong>Risk factors</strong></div>
      <ul style="margin:4px 0 0 18px;padding:0;">${listHtml}</ul>
      ${check.blocked ? `<div style="margin-top:8px;font-weight:700;">Blocked by policy</div>` : ''}
    </div>
  `;
}

function escapeHtml(s) {
  return (s + '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/* =========================
   DOM helpers
   ========================= */
const $ = (q) => document.querySelector(q);
const $$ = (q) => [...document.querySelectorAll(q)];

/* =========================
   AES-GCM + PBKDF2 vault
   ========================= */
async function aesEncrypt(password, plaintext){
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const km = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(plaintext)));
  return { ct: Array.from(ct), iv: Array.from(iv), salt: Array.from(salt) };
}
async function aesDecrypt(password, payload){
  const dec = new TextDecoder();
  const { ct, iv, salt } = payload;
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:new Uint8Array(salt), iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:new Uint8Array(iv)}, key, new Uint8Array(ct));
  return dec.decode(pt);
}

/* =========================
   state/storage/lock
   ========================= */
const state = { unlocked:false, wallet:null, xmtp:null, provider:null, signer:null, inactivityTimer:null };
const STORAGE_KEY = 'xwallet_vault_v1.2';
function getVault(){ const s = localStorage.getItem(STORAGE_KEY); return s ? JSON.parse(s) : null; }
function setVault(v){ localStorage.setItem(STORAGE_KEY, JSON.stringify(v)); }
function lock(){ state.unlocked=false; state.wallet=null; state.xmtp=null; state.provider=null; state.signer=null; $('#lockState').textContent='Locked'; }
function scheduleAutoLock(){ clearTimeout(state.inactivityTimer); state.inactivityTimer = setTimeout(()=>{ lock(); showLock(); }, 10*60*1000); }

/* =========================
   Views
   ========================= */
const VIEWS = {
  dashboard(){ return `
    <div class="label">Welcome</div>
    <div class="alert">Create or import a wallet, then unlock to use Messaging, Send, and Markets. This wallet is non-custodial; your secret is encrypted locally.</div>
    <hr class="sep"/>
    <div class="grid-2">
      <div>
        <div class="label">Create wallet</div>
        <button class="btn" id="gen">Generate 12-word phrase</button>
        <div style="height:8px"></div>
        <textarea id="mnemonic" rows="3" readonly></textarea>
        <div style="height:8px"></div>
        <input id="password" type="password" placeholder="Password to encrypt (like MetaMask)"/>
        <div style="height:8px"></div>
        <button class="btn primary" id="save">Save vault</button>
      </div>
      <div>
        <div class="label">Import wallet</div>
        <textarea id="mnemonicIn" rows="3" placeholder="Enter your 12 or 24 words"></textarea>
        <div style="height:8px"></div>
        <input id="passwordIn" type="password" placeholder="Password to encrypt"/>
        <div style="height:8px"></div>
        <button class="btn" id="doImport">Import</button>
      </div>
    </div>
  `; },
  wallets(){ 
    const addr = state.wallet?.address || '—';
    return `
      <div class="label">Active wallet</div>
      <div class="kv"><div><b>Address</b></div><div class="mono">${addr}</div></div>
      <hr class="sep"/>
      <div class="label">Actions</div>
      <div class="flex"><button class="btn" id="copyAddr">Copy address</button><button class="btn" id="showPK">Show public key</button></div>
      <div id="out" class="small"></div>
    `;
  },
  send(){ 
    return `
      <div class="label">Send ETH (Sepolia)</div>
      <div class="small">Before each send, SafeSend will evaluate the recipient address and block if high risk.</div>
      <hr class="sep"/>
      <div class="send-form">
        <input id="sendTo" placeholder="0x recipient address"/>
        <input id="sendAmt" placeholder="Amount (ETH)"/>
        <button class="btn primary" id="doSend">Send</button>
      </div>
      <div id="sendOut" class="small" style="margin-top:8px"></div>
      <div id="safesend-status" style="margin-top:8px"></div>
      <div style="height:12px"></div>
      <div class="label">Recent transactions (testnet)</div>
      <div id="txList" class="small">—</div>
    `;
  },
  messaging(){ 
    return `
      <div class="label">XMTP Messaging</div>
      <div id="msgStatus" class="small">Status: ${state.xmtp ? 'Connected' : 'Disconnected'}</div>
      <hr class="sep"/>
      <div class="grid-2">
        <div>
          <div class="label">Start new chat</div>
          <input id="peer" placeholder="Recipient EVM address (0x...)"/>
          <div style="height:8px"></div>
          <div class="flex"><input id="msg" placeholder="Type a message" style="flex:1"/><button class="btn primary" id="send">Send</button></div>
          <div id="sendOut" class="small"></div>
        </div>
        <div>
          <div class="label">Inbox (last 20)</div>
          <div id="inbox" class="small">—</div>
        </div>
      </div>
    `;
  },
  markets(){ 
    return `
      <div class="label">Live Markets</div>
      <div class="small">BTC, ETH, SOL, MATIC, USDC — 60s refresh. Data from CoinGecko public API.</div>
      <hr class="sep"/>
      <div class="grid-2">
        ${['btc','eth','sol','matic','usdc'].map(id=>`
          <div class="card chart-card"><header><b>${id.toUpperCase()}</b></header><div class="chart-wrap" style="height:160px"><canvas id="mk_${id}"></canvas></div></div>
        `).join('')}
      </div>
    `;
  },
  settings(){ 
    const hasVault = !!getVault();
    return `
      <div class="label">Settings</div>
      <div class="kv"><div>Vault present</div><div>${hasVault ? '✅' : '❌'}</div></div>
      <div class="kv"><div>Auto-lock</div><div>10 minutes</div></div>
      <hr class="sep"/>
      <button class="btn" id="wipe">Delete vault (local)</button>
    `;
  }
};

function render(view){
  const root = $('#view');
  root.innerHTML = VIEWS[view]();

  if (view==='dashboard'){
    $('#gen').onclick = ()=>{ $('#mnemonic').value = ethers.Mnemonic.fromEntropy(ethers.randomBytes(16)).phrase; };
    $('#save').onclick = async ()=>{ const m = $('#mnemonic').value.trim(); const pw = $('#password').value; if (!m||!pw) return alert('Mnemonic+password required'); const enc = await aesEncrypt(pw,m); setVault({version:1,enc}); alert('Vault saved. Click Unlock.'); };
    $('#doImport').onclick = async ()=>{ const m = $('#mnemonicIn').value.trim(); const pw = $('#passwordIn').value; if (!m||!pw) return alert('Mnemonic+password required'); const enc = await aesEncrypt(pw,m); setVault({version:1,enc}); alert('Imported & saved. Click Unlock.'); };
  }

  if (view==='wallets'){
    $('#copyAddr').onclick = async ()=>{ if(!state.wallet) return; await navigator.clipboard.writeText(state.wallet.address); $('#out').textContent='Address copied.'; };
    $('#showPK').onclick = async ()=>{ if(!state.wallet) return; const pk = await state.wallet.getPublicKey(); $('#out').textContent='Public key: ' + pk; };
  }

  if (view==='send'){
    $('#doSend').onclick = async ()=>{
      const to = $('#sendTo').value.trim();
      const amt = $('#sendAmt').value.trim();
      if (!ethers.isAddress(to)) return alert('Invalid address');
      const n = Number(amt); if (isNaN(n) || n<=0) return alert('Invalid amount');

      $('#sendOut').textContent='Checking SafeSend...';
      try{
        // Always treat this flow as Sepolia (your UI says Sepolia)
        const check = await fetchSafeSend(to, 'sepolia');
        renderSafeSendPanel(check);

        // Policy: block if Cloudflare lists hit (score 100 / blocked)
        if (check.blocked || check.score >= 100) {
          $('#sendOut').textContent = `Blocked by policy (score ${check.score}).`;
          return;
        }

        // Legacy threshold fallback (kept from your original code)
        if (check.score > 70) {
          $('#sendOut').textContent = `Blocked by SafeSend: high risk (${check.score}).`;
          return;
        }

        $('#sendOut').textContent='SafeSend OK — preparing tx...';
        const res = await sendEth({ to, amountEth: n, chain:'sep' });
        $('#sendOut').innerHTML = 'Broadcasted: <a target=_blank href="https://sepolia.etherscan.io/tx/'+res.hash+'">'+res.hash+'</a>';
        await loadRecentTxs();
      }catch(e){
        $('#sendOut').textContent = 'Error: ' + (e.message||e);
      }
    };
    loadRecentTxs();
  }

  if (view==='messaging'){
    $('#msgStatus').textContent = 'Status: ' + (state.xmtp ? 'Connected' : 'Disconnected (unlock first)');
    $('#send').onclick = async ()=>{
      if (!state.xmtp) { $('#sendOut').textContent='Connect wallet (Unlock) first.'; return; }
      const peer = $('#peer').value.trim(); const txt = $('#msg').value.trim();
      if (!ethers.isAddress(peer)) { $('#sendOut').textContent='Enter valid 0x address'; return; }
      try { const convo = await state.xmtp.conversations.newConversation(peer); await convo.send(txt || '(no text)'); $('#sendOut').textContent='Sent ✅'; } catch(e){ $('#sendOut').textContent='Error: ' + e.message; }
    };
    if (state.xmtp){
      (async ()=>{
        const convos = await state.xmtp.conversations.list();
        const latest = [];
        for (const c of convos.slice(0,10)){
          const msgs = await c.messages({ pageSize: 1, direction: 'descending' });
          if (msgs.length) latest.push({ peer: c.peerAddress, text: msgs[0].content, at: msgs[0].sent });
        }
        latest.sort((a,b)=> b.at - a.at);
        $('#inbox').innerHTML = latest.slice(0,20).map(m=>`<div class="kv"><div>${m.peer}</div><div>${new Date(m.at).toLocaleString()}</div></div><div class="small">${m.text}</div><hr class="sep"/>`).join('') || 'No messages yet.';
      })();
    }
  }

  if (view==='markets'){ renderMarkets(); }

  if (view==='settings'){
    $('#wipe').onclick = ()=>{ if(confirm('Delete the local encrypted vault?')){ localStorage.removeItem(STORAGE_KEY); lock(); alert('Deleted.'); } };
  }
}

/* =========================
   Lock modal
   ========================= */
function showLock(){ $('#lockModal').classList.add('active'); $('#unlockPassword').value=''; $('#unlockMsg').textContent=''; }
function hideLock(){ $('#lockModal').classList.remove('active'); }
$('#btnLock').onclick = ()=>{ lock(); alert('Locked.'); };
$('#btnUnlock').onclick = ()=> showLock();
$('#cancelUnlock').onclick = ()=> hideLock();
$('#doUnlock').onclick = async ()=>{
  try{
    const v = getVault(); if (!v) { $('#unlockMsg').textContent='No vault found.'; return; }
    const pw = $('#unlockPassword').value; const phrase = await aesDecrypt(pw, v.enc);
    const wallet = ethers.HDNodeWallet.fromPhrase(phrase);
    state.wallet = wallet; state.unlocked = true; $('#lockState').textContent='Unlocked'; hideLock(); scheduleAutoLock();
    state.provider = new ethers.JsonRpcProvider(RPCS.sep); state.signer = state.wallet.connect(state.provider);
    try{ state.xmtp = await XMTP.Client.create({ getAddress: async ()=> state.wallet.address, sign: async (msg)=> await state.wallet.signMessage(msg) }, { env: 'production' }); }catch(e){ console.warn('XMTP init failed', e); }
    selectItem('wallets');
  }catch(e){ console.error(e); $('#unlockMsg').textContent = 'Wrong password (or corrupted vault).'; }
};

/* =========================
   Nav
   ========================= */
function selectItem(view){ $$('.sidebar .item').forEach(x=>x.classList.toggle('active', x.dataset.view===view)); render(view); }
$$('.sidebar .item').forEach(el=> el.onclick=()=> selectItem(el.dataset.view));
selectItem('dashboard');

// Landing CTAs
$('#ctaApp')?.addEventListener('click', ()=> window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' }));
$('#ctaLearn')?.addEventListener('click', ()=> window.scrollTo({ top: window.innerHeight, behavior: 'smooth' }));

/* =========================
   Provider + send
   ========================= */
async function getProvider(chain='sep'){ if (!RPCS[chain]) throw new Error('RPC not configured for ' + chain); return new ethers.JsonRpcProvider(RPCS[chain]); }
async function connectWalletToProvider(chain='sep'){ if (!state.wallet) throw new Error('Unlock first'); const provider = await getProvider(chain); state.provider = provider; state.signer = state.wallet.connect(provider); return state.signer; }
async function sendEth({ to, amountEth, chain='sep' }){
  if (!state.signer) await connectWalletToProvider(chain);
  const tx = { to, value: ethers.parseEther(String(amountEth)) };
  try{
    const fee = await state.signer.getFeeData();
    if (fee?.maxFeePerGas) { tx.maxFeePerGas = fee.maxFeePerGas; tx.maxPriorityFeePerGas = fee.maxPriorityFeePerGas; }
    const est = await state.signer.estimateGas(tx);
    tx.gasLimit = est;
  }catch(e){ console.warn('Gas estimation failed', e); }
  const sent = await state.signer.sendTransaction(tx);
  await sent.wait(1);
  return { hash: sent.hash, receipt: sent };
}

/* =========================
   recent txs
   ========================= */
async function loadRecentTxs(){
  try{
    if (!state.wallet || !state.provider) return;
    const addr = state.wallet.address;
    if (typeof state.provider.getHistory==='function'){
      const history = await state.provider.getHistory(addr);
      const recent = (history||[]).slice(-6).reverse();
      const el = document.getElementById('txList');
      if (el) el.innerHTML = recent.map(t=>`<div><a target=_blank href="https://sepolia.etherscan.io/tx/${t.hash}">${t.hash.slice(0,10)}…</a> • ${new Date(t.timestamp*1000).toLocaleString()}</div>`).join('') || 'No txs';
    } else {
      const el = document.getElementById('txList'); if (el) el.textContent='Recent txs unavailable for this provider.';
    }
  }catch(e){ console.warn(e); }
}

/* =========================
   markets
   ========================= */
async function fetchMarket(id){
  try{
    const r = await fetch(`https://api.coingecko.com/api/v3/coins/${id}/market_chart?vs_currency=usd&days=1&interval=minute`);
    const j = await r.json();
    return (j.prices||[]).slice(-120).map(([t,v])=>({t, v}));
  }catch(e){
    console.warn('Market fetch failed', id, e);
    return Array.from({length:60},(_,i)=>({t:Date.now()- (60-i)*60000, v: 100 + (Math.random()-0.5)*i}));
  }
}
async function renderMarkets(){
  const assets = [
    {id:'bitcoin', el:'mk_btc'},
    {id:'ethereum', el:'mk_eth'},
    {id:'solana', el:'mk_sol'},
    {id:'matic-network', el:'mk_matic'},
    {id:'usd-coin', el:'mk_usdc'}
  ];
  for (const a of assets){
    const data = await fetchMarket(a.id);
    const el = document.getElementById(a.el); if (!el) continue;
    const ctx = el.getContext('2d');
    new Chart(ctx, {
      type:'line',
      data:{ labels: data.map(p=>new Date(p.t).toLocaleTimeString()), datasets:[{ data: data.map(p=>p.v), tension:.25, pointRadius:0 }]},
      options:{ responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}, tooltip:{enabled:true}}, scales:{x:{display:false}, y:{display:false}} }
    });
  }
  setTimeout(renderMarkets, 60000);
}
