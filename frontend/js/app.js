// X-Wallet frontend app.js — v1.6.1
// New flow: score >= 90 (or listed) routes to a dedicated Blocked Module (no send action).

import { ethers } from 'https://esm.sh/ethers@6.13.2';
import { Client as XMTPClient } from 'https://esm.sh/@xmtp/xmtp-js@11.5.0';
window.ethers = ethers;
window.XMTP = { Client: XMTPClient };

/* ========= CONFIG ========= */
const RPCS = {
  sep: 'https://eth-sepolia.g.alchemy.com/v2/kxHg5y9yBXWAb9cOcJsf0',
  mainnet: 'https://mainnet.infura.io/v3/0883fc4e792c4b78aa435b2332790b73',
  polygon: 'https://polygon-mainnet.infura.io/v3/0883fc4e792c4b78aa435b2332790b73'
};
const SAFE_SEND_URL = 'https://xwalletv1dot2.agedotcom.workers.dev/check';

/* ========= POLICY ========= */
const HARD_BLOCK_THRESHOLD = 90;
const BLOCK_TEXT = "RiskXLabs is blocking transactions to this address because we have detected an elevated level of risk or regulatory action regarding this address.";

/* ========= HELPERS ========= */
const $  = (q) => document.querySelector(q);
const $$ = (q) => [...document.querySelectorAll(q)];
const escapeHtml = (s) => (s+'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

/* Normalize worker responses (new + legacy) */
function normalizeSafeSendResponse(j){
  if (typeof j?.risk_score === 'number' || j?.reasons || j?.risk_factors){
    const score = typeof j.risk_score === 'number' ? j.risk_score : 10;
    const findings = Array.isArray(j.risk_factors) && j.risk_factors.length
      ? j.risk_factors
      : Array.isArray(j.reasons)
        ? j.reasons.map(c => ({OFAC:'OFAC/sanctions list match',BAD_LIST:'Internal bad list match',BAD_ENS:'Flagged ENS name'}[c] || c))
        : [];
    const blocked = !!j.block || (j.reasons && j.reasons.includes('OFAC')) || score >= 100;
    return { score, findings, blocked, raw:j };
  }
  if (typeof j?.score === 'number'){
    const score = j.score;
    const findings = Array.isArray(j.findings) ? j.findings : [];
    const blocked = !!j.block || score >= 70;
    return { score, findings, blocked, raw:j };
  }
  return { score:10, findings:[], blocked:false, raw:j||{} };
}

async function fetchSafeSend(to, chain='sepolia'){
  const u = new URL(SAFE_SEND_URL);
  u.searchParams.set('address', String(to).toLowerCase());
  u.searchParams.set('network', chain);
  u.searchParams.set('_', Date.now());
  const r = await fetch(u.toString(), { method:'GET', cache:'no-store', headers:{'Cache-Control':'no-store, no-cache, must-revalidate','Pragma':'no-cache'} });
  if (!r.ok) throw new Error(`SafeSend ${r.status}`);
  const j = await r.json();
  const norm = normalizeSafeSendResponse(j);
  window.__lastSafeSendCheck = norm;
  return norm;
}

/* ========= MODAL (for scores < 90) ========= */
const modal = {
  get el(){ return document.getElementById('riskModal'); },
  q(sel){ return this.el?.querySelector(sel); },
  open(){ this.el?.classList.add('active'); this.el?.setAttribute('aria-hidden','false'); },
  hide(){
    this.el?.classList.remove('active');
    this.el?.setAttribute('aria-hidden','true');
    if (document.activeElement && this.el?.contains(document.activeElement)) document.activeElement.blur();
  },
  render(check){
    const bar=this.q('#riskMeterBar'); const scoreTxt=this.q('#riskScoreText');
    const factorsEl=this.q('#riskFactors'); const warn=this.q('#riskWarning'); const proceed=this.q('#riskProceed');

    bar?.style.setProperty('--score', check.score);
    if (scoreTxt) scoreTxt.textContent = `Risk score: ${check.score}`;

    const list = (check.findings||[]).map(f=>`<li>${escapeHtml(String(f))}</li>`).join('');
    if (factorsEl) factorsEl.innerHTML = list ? `<ul>${list}</ul>` : 'No notable factors.';

    // default disabled
    if (proceed){
      proceed.disabled = true;
      proceed.setAttribute('aria-disabled','true');
      proceed.style.pointerEvents = 'none';
      proceed.textContent = 'Complete transaction';
      proceed.removeAttribute('data-blocked');
      proceed.style.opacity = '';
    }
    if (warn){ warn.innerHTML = ''; warn.style.display='block'; }

    if (check.score >= 70){
      // require acknowledgement
      if (warn){
        warn.innerHTML = `
          <div class="warnbox">
            <strong>⚠️ High-risk transaction</strong><br><br>
            You must acknowledge to proceed.
            <label class="checkbox"><input id="riskAgree" type="checkbox"> <span>I understand the risks</span></label>
          </div>`;
        const agree = this.q('#riskAgree');
        agree?.addEventListener('change', ()=>{
          const ok = !!agree.checked;
          if (proceed){
            proceed.disabled = !ok;
            proceed.setAttribute('aria-disabled', String(!ok));
            proceed.style.pointerEvents = ok ? 'auto' : 'none';
            proceed.style.opacity = ok ? '' : '.6';
          }
        });
      }
      return;
    }

    // low risk → allow immediately
    if (proceed){
      proceed.disabled = false;
      proceed.setAttribute('aria-disabled','false');
      proceed.style.pointerEvents = 'auto';
      proceed.style.opacity = '';
    }
  }
};

function showRiskModal(check){
  modal.render(check);
  modal.open();
  const proceed = modal.q('#riskProceed'), cancel=modal.q('#riskCancel'), close=modal.q('#riskClose');
  return new Promise((resolve)=>{
    const done=()=>{ if (proceed) proceed.onclick=null; if (cancel) cancel.onclick=null; if (close) close.onclick=null; modal.hide(); };
    if (proceed){
      proceed.onclick = ()=>{
        if (proceed.disabled || proceed.getAttribute('aria-disabled')==='true' || proceed.hasAttribute('data-blocked')) return;
        done(); resolve(true);
      };
    }
    if (cancel) cancel.onclick = ()=>{ done(); resolve(false); };
    if (close)  close.onclick  = ()=>{ done(); resolve(false); };
  });
}

/* ========= BLOCKED MODULE (scores >= 90 or listed) ========= */
function renderBlockedModule(check){
  const root = $('#view');
  const findingsHtml = (check.findings||[]).map(f=>`<li>${escapeHtml(String(f))}</li>`).join('') || '<li>No additional factors provided.</li>';
  root.innerHTML = `
    <div class="label">Transaction Blocked</div>

    <div class="risk-meter">
      <div class="risk-meter__scale"><div class="risk-meter__bar" style="--score:${check.score}"></div></div>
      <div class="risk-meter__labels"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div>
      <div class="risk-meter__score">Risk score: ${check.score}</div>
    </div>

    <div class="card blocked-card">
      <strong>🚫 RiskXLabs Policy Enforcement</strong><br><br>
      ${escapeHtml(BLOCK_TEXT)}
      <br><br><strong>Detected factors:</strong>
      <ul class="blocked-factors">${findingsHtml}</ul>
    </div>

    <div style="margin-top:16px;">
      <button class="btn" id="returnSend">Return to Send</button>
    </div>
  `;
  $('#returnSend').onclick = ()=> selectItem('send');
}

/* ========= AES-GCM vault ========= */
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

/* ========= STATE / LOCK ========= */
const state = { unlocked:false, wallet:null, xmtp:null, provider:null, signer:null };
const STORAGE_KEY = 'xwallet_vault_v1.2';
function getVault(){ const s=localStorage.getItem(STORAGE_KEY); return s?JSON.parse(s):null; }
function lock(){ state.unlocked=false; state.wallet=null; state.xmtp=null; state.provider=null; state.signer=null; $('#lockState').textContent='Locked'; }

/* ========= VIEWS ========= */
const VIEWS = {
  dashboard(){ return `
    <div class="label">Welcome</div>
    <div class="alert">Create or import a wallet, then unlock to use Send. Keys never leave your device.</div>
    <hr class="sep"/>
    <div class="grid-2">
      <div>
        <div class="label">Create wallet</div>
        <button class="btn" id="gen">Generate 12-word phrase</button>
        <div style="height:8px"></div>
        <textarea id="mnemonic" rows="3" readonly></textarea>
        <div style="height:8px"></div>
        <input id="password" type="password" placeholder="Password to encrypt"/>
        <div style="height:8px"></div>
        <button class="btn primary" id="save">Save vault</button>
      </div>
      <div>
        <div class="label">Import wallet</div>
        <textarea id="mnemonicIn" rows="3" placeholder="Enter 12 or 24 words"></textarea>
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
      <div class="small">SafeSend evaluates the recipient before broadcasting. Policy: scores ≥ ${HARD_BLOCK_THRESHOLD} route to a blocked module.</div>
      <hr class="sep"/>
      <div class="send-form">
        <input id="sendTo" placeholder="0x recipient address"/>
        <input id="sendAmt" placeholder="Amount (ETH)"/>
        <button class="btn primary" id="doSend">Send</button>
      </div>
      <div id="sendOut" class="small" style="margin-top:8px"></div>
    `;
  },
  settings(){
    const hasVault = !!getVault();
    return `
      <div class="label">Settings</div>
      <div class="kv"><div>Vault present</div><div>${hasVault?'✅':'❌'}</div></div>
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
    $('#save').onclick = async ()=>{ const m=$('#mnemonic').value.trim(), pw=$('#password').value; if(!m||!pw) return alert('Mnemonic+password required'); const enc=await aesEncrypt(pw,m); localStorage.setItem(STORAGE_KEY, JSON.stringify({version:1,enc})); alert('Vault saved. Click Unlock.'); };
    $('#doImport').onclick = async ()=>{ const m=$('#mnemonicIn').value.trim(), pw=$('#passwordIn').value; if(!m||!pw) return alert('Mnemonic+password required'); const enc=await aesEncrypt(pw,m); localStorage.setItem(STORAGE_KEY, JSON.stringify({version:1,enc})); alert('Imported & saved. Click Unlock.'); };
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
        const check = await fetchSafeSend(to, 'sepolia');

        // 🚫 Route to Blocked Module for score >= 90 or explicit block
        if (check.blocked || check.score >= HARD_BLOCK_THRESHOLD){
          console.warn('[SafeSend] Hard block — routing to Blocked Module');
          renderBlockedModule(check);
          return;
        }

        // Otherwise show modal (ack needed for 70–89)
        const proceed = await showRiskModal(check);
        if (!proceed){ $('#sendOut').textContent='Cancelled.'; return; }

        $('#sendOut').textContent='SafeSend OK — preparing tx...';
        const res = await sendEth({ to, amountEth: n, chain:'sep' });
        $('#sendOut').innerHTML = `Broadcasted: <a target="_blank" href="https://sepolia.etherscan.io/tx/${res.hash}">${res.hash}</a>`;
      }catch(e){
        $('#sendOut').textContent = 'Error: ' + (e.message||e);
      }
    };
  }

  if (view==='settings'){
    $('#wipe').onclick = ()=>{ if(confirm('Delete the local encrypted vault?')){ localStorage.removeItem(STORAGE_KEY); lock(); alert('Deleted.'); } };
  }
}

/* ========= NAV & UNLOCK ========= */
function selectItem(view){ $$('.sidebar .item').forEach(x=>x.classList.toggle('active', x.dataset.view===view)); render(view); }
$$('.sidebar .item').forEach(el=> el.addEventListener('click', ()=> selectItem(el.dataset.view)));
selectItem('dashboard');

function showLock(){ $('#lockModal').classList.add('active'); $('#lockModal').setAttribute('aria-hidden','false'); $('#unlockPassword').value=''; $('#unlockMsg').textContent=''; }
function hideLock(){ $('#lockModal').classList.remove('active'); $('#lockModal').setAttribute('aria-hidden','true'); }
$('#btnLock').onclick = ()=>{ lock(); alert('Locked.'); };
$('#btnUnlock').onclick = ()=> showLock();
$('#cancelUnlock').onclick = ()=> hideLock();
$('#doUnlock').onclick = async ()=>{
  try{
    const v = getVault(); if (!v){ $('#unlockMsg').textContent='No vault found.'; return; }
    const pw = $('#unlockPassword').value; const phrase = await aesDecrypt(pw, v.enc);
    const wallet = ethers.HDNodeWallet.fromPhrase(phrase);
    state.wallet = wallet; $('#lockState').textContent='Unlocked'; hideLock();
    state.provider = new ethers.JsonRpcProvider(RPCS.sep); state.signer = state.wallet.connect(state.provider);
    try{ state.xmtp = await XMTPClient.create({ getAddress: async ()=> state.wallet.address, sign: async (m)=> await state.wallet.signMessage(m) }, { env:'production' }); }catch(e){ console.warn('XMTP init failed', e); }
    selectItem('wallets');
  }catch(e){ console.error(e); $('#unlockMsg').textContent='Wrong password (or corrupted vault).'; }
};

/* ========= SENDING ========= */
async function getProvider(chain='sep'){ if(!RPCS[chain]) throw new Error('RPC not configured for ' + chain); return new ethers.JsonRpcProvider(RPCS[chain]); }
async function connectWalletToProvider(chain='sep'){ if (!state.wallet) throw new Error('Unlock first'); const provider = await getProvider(chain); state.provider=provider; state.signer=state.wallet.connect(provider); return state.signer; }
async function sendEth({ to, amountEth, chain='sep' }){
  if (!state.signer) await connectWalletToProvider(chain);
  const tx = { to, value: ethers.parseEther(String(amountEth)) };
  try{
    const fee = await state.signer.getFeeData();
    if (fee?.maxFeePerGas){ tx.maxFeePerGas = fee.maxFeePerGas; tx.maxPriorityFeePerGas = fee.maxPriorityFeePerGas; }
    const est = await state.signer.estimateGas(tx); tx.gasLimit = est;
  }catch(e){ console.warn('Gas estimation failed', e); }
  const sent = await state.signer.sendTransaction(tx);
  await sent.wait(1);
  return { hash: sent.hash, receipt: sent };
}
