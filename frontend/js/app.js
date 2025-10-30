// X-Wallet frontend app.js v1.5.7 — CSP-friendly, modal always, hard block ≥90

// ESM imports (no inline scripts to satisfy CSP)
import { ethers } from 'https://esm.sh/ethers@6.13.2';
import { Client as XMTPClient } from 'https://esm.sh/@xmtp/xmtp-js@11.5.0';

// expose for any legacy references
window.ethers = ethers;
window.XMTP = { Client: XMTPClient };

/* =========================
   CONFIG
   ========================= */
const RPCS = {
  sep: 'https://eth-sepolia.g.alchemy.com/v2/kxHg5y9yBXWAb9cOcJsf0', // replace if needed
  mainnet: 'https://mainnet.infura.io/v3/0883fc4e792c4b78aa435b2332790b73',
  polygon: 'https://polygon-mainnet.infura.io/v3/0883fc4e792c4b78aa435b2332790b73'
};

// Cloudflare Worker (CORS enabled)
const SAFE_SEND_URL = 'https://xwalletv1dot2.agedotcom.workers.dev/check';

/* =========================
   POLICY
   ========================= */
const HARD_BLOCK_THRESHOLD = 90; // hard block for scores >= 90
const BLOCK_MSG =
  "Transfers to the wallet address your submitted are currently being blocked. RiskXLabs believes that transactions with the wallet address represent substantial risk or that the address has been sanctioned by regulatory bodies.";

/* =========================
   RISK HELPERS
   ========================= */
function normalizeSafeSendResponse(j) {
  // New worker format
  if (typeof j?.risk_score === 'number' || j?.reasons || j?.risk_factors) {
    const score = typeof j.risk_score === 'number' ? j.risk_score : 10;
    const findings = Array.isArray(j.risk_factors) && j.risk_factors.length
      ? j.risk_factors
      : Array.isArray(j.reasons)
        ? j.reasons.map(c => ({
            OFAC: 'OFAC/sanctions list match',
            BAD_LIST: 'Internal bad list match',
            BAD_ENS: 'Flagged ENS name'
          }[c] || c))
        : [];
    const blocked = !!j.block || (j.reasons && j.reasons.includes('OFAC')) || score >= 100;
    return { score, findings, blocked, raw: j };
  }
  // Legacy format
  if (typeof j?.score === 'number') {
    const score = j.score;
    const findings = Array.isArray(j.findings) ? j.findings : [];
    const blocked = !!j.block || score >= 70;
    return { score, findings, blocked, raw: j };
  }
  return { score: 10, findings: [], blocked: false, raw: j || {} };
}

async function fetchSafeSend(to, chain = 'sepolia') {
  const u = new URL(SAFE_SEND_URL);
  u.searchParams.set('address', String(to).toLowerCase());
  u.searchParams.set('network', chain);
  u.searchParams.set('_', Date.now()); // cache-buster

  const r = await fetch(u.toString(), {
    method: 'GET',
    cache: 'no-store',
    headers: {
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache'
    }
  });
  if (!r.ok) throw new Error(`SafeSend ${r.status}`);
  const j = await r.json();
  const norm = normalizeSafeSendResponse(j);
  window.__lastSafeSendCheck = norm;
  return norm;
}

/* =========================
   MODAL (ALWAYS SHOWN)
   ========================= */
const modal = {
  get el() { return document.getElementById('riskModal'); },
  q(sel) { return this.el?.querySelector(sel); },
  open() { this.el?.setAttribute('aria-hidden', 'false'); this.el?.classList.add('active'); },
  hide() { this.el?.classList.remove('active'); this.el?.setAttribute('aria-hidden', 'true'); },

  render(check) {
    const bar       = this.q('#riskMeterBar');
    const scoreTxt  = this.q('#riskScoreText');
    const factorsEl = this.q('#riskFactors');
    const warn      = this.q('#riskWarning');
    const proceed   = this.q('#riskProceed');

    // Meter + score
    bar?.style.setProperty('--score', check.score);
    if (scoreTxt) scoreTxt.textContent = `Risk score: ${check.score}`;

    // Findings
    const listHtml = (check.findings || []).map(f => `<li>${escapeHtml(String(f))}</li>`).join('');
    if (factorsEl) factorsEl.innerHTML = listHtml ? `<ul>${listHtml}</ul>` : 'No notable factors.';

    // Reset controls
    if (proceed) {
      proceed.disabled = true;
      proceed.setAttribute('aria-disabled', 'true');
      proceed.style.pointerEvents = 'none';
      proceed.textContent = 'Complete transaction';
      proceed.removeAttribute('data-blocked');
    }
    if (warn) {
      warn.style.display = 'none';
      warn.innerHTML = '';
    }

    // Decide hard block
    const isHardBlocked = (check.blocked || check.score >= HARD_BLOCK_THRESHOLD);
    console.log('[SafeSend modal]', { score: check.score, blocked: check.blocked, policyHardBlock: isHardBlocked });

    if (isHardBlocked) {
      if (warn) {
        warn.style.display = 'block';
        warn.innerHTML = `<div style="color:#fff"><strong>Blocked by policy.</strong> ${escapeHtml(BLOCK_MSG)}</div>`;
      }
      if (proceed) {
        proceed.disabled = true;
        proceed.setAttribute('aria-disabled', 'true');
        proceed.style.pointerEvents = 'none';
        proceed.textContent = 'Blocked';
        proceed.setAttribute('data-blocked', '1');
      }
      return; // cannot proceed
    }

    // High risk acknowledge (70–89)
    if (check.score >= 70) {
      if (warn) {
        warn.style.display = 'block';
        warn.innerHTML = `
          <div style="color:#fff">
            This transaction has been identified as high-risk. You must acknowledge to proceed.
            <label class="checkbox" style="display:block;margin-top:8px">
              <input id="riskAgree" type="checkbox"/> <span>I understand the risks</span>
            </label>
          </div>
        `;
        const agree = this.q('#riskAgree');
        agree?.addEventListener('change', () => {
          if (!proceed) return;
          const ok = !!agree.checked;
          proceed.disabled = !ok;
          proceed.setAttribute('aria-disabled', String(!ok));
          proceed.style.pointerEvents = ok ? 'auto' : 'none';
        });
      }
      return;
    }

    // Low risk (<70): can proceed immediately
    if (proceed) {
      proceed.disabled = false;
      proceed.setAttribute('aria-disabled', 'false');
      proceed.style.pointerEvents = 'auto';
    }
  }
};

function escapeHtml(s) {
  return (s + '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function showRiskModal(check) {
  modal.render(check);
  modal.open();

  const proceed = modal.q('#riskProceed');
  const cancel  = modal.q('#riskCancel');
  const close   = modal.q('#riskClose');

  return new Promise((resolve) => {
    const cleanup = () => {
      if (proceed) proceed.onclick = null;
      if (cancel)  cancel.onclick  = null;
      if (close)   close.onclick   = null;
      modal.hide();
    };

    // Hard block path: proceed stays disabled and flagged
    if (proceed) {
      proceed.onclick = () => {
        if (proceed.hasAttribute('data-blocked') || proceed.disabled ||
            proceed.getAttribute('aria-disabled') === 'true') return;
        cleanup(); resolve(true); // user explicitly continues
      };
    }
    if (cancel) cancel.onclick = () => { cleanup(); resolve(false); };
    if (close)  close.onclick  = () => { cleanup(); resolve(false); };
  });
}

/* =========================
   DOM HELPERS
   ========================= */
const $  = (q) => document.querySelector(q);
const $$ = (q) => [...document.querySelectorAll(q)];

/* =========================
   AES-GCM + PBKDF2 VAULT
   ========================= */
async function aesEncrypt(password, plaintext) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const km = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext)));
  return { ct: Array.from(ct), iv: Array.from(iv), salt: Array.from(salt) };
}
async function aesDecrypt(password, payload) {
  const dec = new TextDecoder();
  const { ct, iv, salt } = payload;
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: new Uint8Array(salt), iterations: 100000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, new Uint8Array(ct));
  return dec.decode(pt);
}

/* =========================
   STATE / LOCK
   ========================= */
const state = { unlocked: false, wallet: null, xmtp: null, provider: null, signer: null, inactivityTimer: null };
const STORAGE_KEY = 'xwallet_vault_v1.2';
function getVault() { const s = localStorage.getItem(STORAGE_KEY); return s ? JSON.parse(s) : null; }
function setVault(v) { localStorage.setItem(STORAGE_KEY, JSON.stringify(v)); }
function lock() { state.unlocked = false; state.wallet = null; state.xmtp = null; state.provider = null; state.signer = null; $('#lockState').textContent = 'Locked'; }
function scheduleAutoLock() { clearTimeout(state.inactivityTimer); state.inactivityTimer = setTimeout(() => { lock(); showLock(); }, 10 * 60 * 1000); }

/* =========================
   VIEWS
   ========================= */
const VIEWS = {
  dashboard() {
    return `
      <div class="label">Welcome</div>
      <div class="alert">Create or import a wallet, then unlock to use Send and Settings. Keys are encrypted locally.</div>
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
          <textarea id="mnemonicIn" rows="3" placeholder="Enter 12/24 words"></textarea>
          <div style="height:8px"></div>
          <input id="passwordIn" type="password" placeholder="Password to encrypt"/>
          <div style="height:8px"></div>
          <button class="btn" id="doImport">Import</button>
        </div>
      </div>
    `;
  },
  wallets() {
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
  send() {
    return `
      <div class="label">Send (Sepolia)</div>
      <div class="small">SafeSend evaluates the recipient before broadcasting. Policy: hard block for scores ≥ ${HARD_BLOCK_THRESHOLD} or list hits.</div>
      <hr class="sep"/>
      <div class="send-form">
        <input id="sendTo" placeholder="0x recipient address"/>
        <input id="sendAmt" placeholder="Amount (ETH)"/>
        <button class="btn primary" id="doSend">Send</button>
      </div>
      <div id="sendOut" class="small" style="margin-top:8px"></div>
    `;
  },
  settings() {
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

function render(view) {
  const root = $('#view');
  root.innerHTML = VIEWS[view]();

  if (view === 'dashboard') {
    $('#gen').onclick = () => { $('#mnemonic').value = ethers.Mnemonic.fromEntropy(ethers.randomBytes(16)).phrase; };
    $('#save').onclick = async () => { const m = $('#mnemonic').value.trim(); const pw = $('#password').value; if (!m || !pw) return alert('Mnemonic+password required'); const enc = await aesEncrypt(pw, m); setVault({ version: 1, enc }); alert('Vault saved. Click Unlock.'); };
    $('#doImport').onclick = async () => { const m = $('#mnemonicIn').value.trim(); const pw = $('#passwordIn').value; if (!m || !pw) return alert('Mnemonic+password required'); const enc = await aesEncrypt(pw, m); setVault({ version: 1, enc }); alert('Imported & saved. Click Unlock.'); };
  }

  if (view === 'wallets') {
    $('#copyAddr').onclick = async () => { if (!state.wallet) return; await navigator.clipboard.writeText(state.wallet.address); $('#out').textContent = 'Address copied.'; };
    $('#showPK').onclick = async () => { if (!state.wallet) return; const pk = await state.wallet.getPublicKey(); $('#out').textContent = 'Public key: ' + pk; };
  }

  if (view === 'send') {
    $('#doSend').onclick = async () => {
      const to = $('#sendTo').value.trim();
      const amt = $('#sendAmt').value.trim();
      if (!ethers.isAddress(to)) return alert('Invalid address');
      const n = Number(amt); if (isNaN(n) || n <= 0) return alert('Invalid amount');

      $('#sendOut').textContent = 'Checking SafeSend...';
      try {
        const check = await fetchSafeSend(to, 'sepolia');

        // ALWAYS show modal (branding + awareness)
        const proceed = await showRiskModal(check);

        // If user cancels OR policy hard-block, stop here with appropriate message.
        if (!proceed) {
          $('#sendOut').textContent =
            (check.blocked || check.score >= HARD_BLOCK_THRESHOLD)
              ? BLOCK_MSG
              : 'Cancelled.';
          return;
        }

        // Only reach here if user explicitly clicked "Complete transaction"
        $('#sendOut').textContent = 'SafeSend OK — preparing tx...';
        const res = await sendEth({ to, amountEth: n, chain: 'sep' });
        $('#sendOut').innerHTML = 'Broadcasted: <a target="_blank" href="https://sepolia.etherscan.io/tx/' + res.hash + '">' + res.hash + '</a>';
      } catch (e) {
        $('#sendOut').textContent = 'Error: ' + (e.message || e);
      }
    };
  }

  if (view === 'settings') {
    $('#wipe').onclick = () => { if (confirm('Delete the local encrypted vault?')) { localStorage.removeItem(STORAGE_KEY); lock(); alert('Deleted.'); } };
  }
}

/* =========================
   LOCK MODAL / NAV
   ========================= */
function showLock() { $('#lockModal').classList.add('active'); $('#unlockPassword').value = ''; $('#unlockMsg').textContent = ''; }
function hideLock() { $('#lockModal').classList.remove('active'); }
$('#btnLock')?.addEventListener('click', () => { lock(); alert('Locked.'); });
$('#btnUnlock')?.addEventListener('click', () => showLock());
$('#cancelUnlock')?.addEventListener('click', () => hideLock());
$('#doUnlock')?.addEventListener('click', async () => {
  try {
    const v = getVault(); if (!v) { $('#unlockMsg').textContent = 'No vault found.'; return; }
    const pw = $('#unlockPassword').value; const phrase = await aesDecrypt(pw, v.enc);
    const wallet = ethers.HDNodeWallet.fromPhrase(phrase);
    state.wallet = wallet; state.unlocked = true; $('#lockState').textContent = 'Unlocked'; hideLock(); scheduleAutoLock();
    state.provider = new ethers.JsonRpcProvider(RPCS.sep); state.signer = state.wallet.connect(state.provider);
    try {
      state.xmtp = await XMTPClient.create(
        { getAddress: async () => state.wallet.address, sign: async (m) => await state.wallet.signMessage(m) },
        { env: 'production' }
      );
    } catch (e) { console.warn('XMTP init failed', e); }
    selectItem('wallets');
  } catch (e) { console.error(e); $('#unlockMsg').textContent = 'Wrong password (or corrupted vault).'; }
});

function selectItem(view) { $$('.sidebar .item').forEach(x => x.classList.toggle('active', x.dataset.view === view)); render(view); }
$$('.sidebar .item').forEach(el => el.addEventListener('click', () => selectItem(el.dataset.view)));
selectItem('dashboard');

/* =========================
   PROVIDER + SEND
   ========================= */
async function getProvider(chain = 'sep') { if (!RPCS[chain]) throw new Error('RPC not configured for ' + chain); return new ethers.JsonRpcProvider(RPCS[chain]); }
async function connectWalletToProvider(chain = 'sep') { if (!state.wallet) throw new Error('Unlock first'); const provider = await getProvider(chain); state.provider = provider; state.signer = state.wallet.connect(provider); return state.signer; }
async function sendEth({ to, amountEth, chain = 'sep' }) {
  if (!state.signer) await connectWalletToProvider(chain);
  const tx = { to, value: ethers.parseEther(String(amountEth)) };
  try {
    const fee = await state.signer.getFeeData();
    if (fee?.maxFeePerGas) { tx.maxFeePerGas = fee.maxFeePerGas; tx.maxPriorityFeePerGas = fee.maxPriorityFeePerGas; }
    const est = await state.signer.estimateGas(tx);
    tx.gasLimit = est;
  } catch (e) { console.warn('Gas estimation failed', e); }
  const sent = await state.signer.sendTransaction(tx);
  await sent.wait(1);
  return { hash: sent.hash, receipt: sent };
}
