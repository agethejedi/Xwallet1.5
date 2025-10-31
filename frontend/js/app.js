// X-Wallet frontend app.js v1.6.0
// Always show SafeSend modal, enforce hard block ≥90, display warning visibly, and prevent any race between modal & send logic.

import { ethers } from 'https://esm.sh/ethers@6.13.2';
import { Client as XMTPClient } from 'https://esm.sh/@xmtp/xmtp-js@11.5.0';
window.ethers = ethers;
window.XMTP = { Client: XMTPClient };

/* =========================
   CONFIG & POLICY
   ========================= */
const RPCS = {
  sep: 'https://eth-sepolia.g.alchemy.com/v2/kxHg5y9yBXWAb9cOcJsf0',
  mainnet: 'https://mainnet.infura.io/v3/0883fc4e792c4b78aa435b2332790b73',
  polygon: 'https://polygon-mainnet.infura.io/v3/0883fc4e792c4b78aa435b2332790b73'
};

const SAFE_SEND_URL = 'https://xwalletv1dot2.agedotcom.workers.dev/check';
const HARD_BLOCK_THRESHOLD = 90;
const BLOCK_MSG =
  "🚫 Transfers to the wallet address you submitted are currently being blocked. RiskXLabs believes that transactions with the wallet address represent substantial risk or that the address has been sanctioned by regulatory bodies.";

/* =========================
   GLOBAL GUARD
   ========================= */
document.addEventListener(
  'click',
  (e) => {
    const btn = e.target.closest('#riskProceed');
    if (!btn) return;
    const blocked =
      btn.hasAttribute('data-blocked') ||
      btn.disabled ||
      btn.getAttribute('aria-disabled') === 'true';
    if (blocked) {
      e.preventDefault();
      e.stopPropagation();
    }
  },
  true
);

/* =========================
   SAFESEND HELPERS
   ========================= */
function normalizeSafeSendResponse(j) {
  if (typeof j?.risk_score === 'number' || j?.reasons || j?.risk_factors) {
    const score = typeof j.risk_score === 'number' ? j.risk_score : 10;
    const findings = Array.isArray(j.risk_factors) && j.risk_factors.length
      ? j.risk_factors
      : Array.isArray(j.reasons)
        ? j.reasons.map((c) => ({
            OFAC: 'OFAC/sanctions list match',
            BAD_LIST: 'Internal bad list match',
            BAD_ENS: 'Flagged ENS name'
          }[c] || c))
        : [];
    const blocked =
      !!j.block || (j.reasons && j.reasons.includes('OFAC')) || score >= 100;
    return { score, findings, blocked, raw: j };
  }
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
  u.searchParams.set('_', Date.now());
  const r = await fetch(u.toString(), {
    method: 'GET',
    cache: 'no-store',
    headers: {
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      Pragma: 'no-cache'
    }
  });
  if (!r.ok) throw new Error(`SafeSend ${r.status}`);
  const j = await r.json();
  const norm = normalizeSafeSendResponse(j);
  window.__lastSafeSendCheck = norm;
  return norm;
}

/* =========================
   MODAL
   ========================= */
const modal = {
  get el() {
    return document.getElementById('riskModal');
  },
  q(sel) {
    return this.el?.querySelector(sel);
  },
  open() {
    this.el?.classList.add('active');
    this.el?.setAttribute('aria-hidden', 'false');
  },
  hide() {
    this.el?.classList.remove('active');
    this.el?.setAttribute('aria-hidden', 'true');
    if (document.activeElement && this.el?.contains(document.activeElement)) {
      document.activeElement.blur();
    }
  },
  render(check, isHardBlocked = false) {
    const bar = this.q('#riskMeterBar');
    const scoreTxt = this.q('#riskScoreText');
    const factorsEl = this.q('#riskFactors');
    const warn = this.q('#riskWarning');
    const proceed = this.q('#riskProceed');

    bar?.style.setProperty('--score', check.score);
    if (scoreTxt) scoreTxt.textContent = `Risk score: ${check.score}`;
    const listHtml = (check.findings || [])
      .map((f) => `<li>${escapeHtml(String(f))}</li>`)
      .join('');
    if (factorsEl)
      factorsEl.innerHTML = listHtml ? `<ul>${listHtml}</ul>` : 'No notable factors.';

    // Reset proceed button
    if (proceed) {
      proceed.disabled = true;
      proceed.setAttribute('aria-disabled', 'true');
      proceed.style.pointerEvents = 'none';
      proceed.textContent = 'Complete transaction';
      proceed.removeAttribute('data-blocked');
      proceed.style.opacity = '';
    }

    // Warning box
    if (warn) {
      warn.style.display = 'block';
      warn.innerHTML = '';
    }

    // 🚫 Hard block: always display full message
    if (isHardBlocked) {
      if (warn) {
        warn.innerHTML = `
          <div style="
            color:#fff;
            background:#3b0d0d;
            border:1px solid #ff4d4d;
            border-radius:6px;
            padding:10px;
            margin-top:10px;
          ">
            <strong>🚫 Blocked by Policy</strong><br><br>${escapeHtml(BLOCK_MSG)}
          </div>`;
      }
      if (proceed) {
        proceed.disabled = true;
        proceed.setAttribute('aria-disabled', 'true');
        proceed.setAttribute('data-blocked', '1');
        proceed.textContent = 'Blocked';
        proceed.style.opacity = '.6';
      }
      return;
    }

    // Moderate risk (70–89): require user acknowledgment
    if (check.score >= 70) {
      if (warn) {
        warn.innerHTML = `
          <div style="
            color:#fff;
            background:#3f2d00;
            border:1px solid #f7b955;
            border-radius:6px;
            padding:10px;
            margin-top:10px;
          ">
            <strong>⚠️ High-risk transaction</strong><br><br>
            You must acknowledge to proceed.
            <label class="checkbox" style="display:block;margin-top:8px">
              <input id="riskAgree" type="checkbox"/> <span>I understand the risks</span>
            </label>
          </div>`;
        const agree = this.q('#riskAgree');
        agree?.addEventListener('change', () => {
          if (!proceed) return;
          const ok = !!agree.checked;
          proceed.disabled = !ok;
          proceed.setAttribute('aria-disabled', String(!ok));
          proceed.style.pointerEvents = ok ? 'auto' : 'none';
          proceed.style.opacity = ok ? '' : '.6';
        });
      }
      return;
    }

    // Low risk (<70): allow immediate proceed
    if (proceed) {
      proceed.disabled = false;
      proceed.setAttribute('aria-disabled', 'false');
      proceed.style.pointerEvents = 'auto';
      proceed.style.opacity = '';
    }
  }
};

function escapeHtml(s) {
  return (s + '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function showRiskModal(check, isHardBlocked = false) {
  modal.render(check, isHardBlocked);
  modal.open();
  const proceed = modal.q('#riskProceed');
  const cancel = modal.q('#riskCancel');
  const close = modal.q('#riskClose');

  return new Promise((resolve) => {
    const cleanup = () => {
      if (proceed) proceed.onclick = null;
      if (cancel) cancel.onclick = null;
      if (close) close.onclick = null;
      modal.hide();
    };

    if (proceed) {
      proceed.onclick = () => {
        if (
          proceed.hasAttribute('data-blocked') ||
          proceed.disabled ||
          proceed.getAttribute('aria-disabled') === 'true'
        )
          return;
        cleanup();
        resolve(true);
      };
    }
    if (cancel) cancel.onclick = () => {
      cleanup();
      resolve(false);
    };
    if (close) close.onclick = () => {
      cleanup();
      resolve(false);
    };
  });
}

/* =========================
   DOM HELPERS & CRYPTO
   ========================= */
const $ = (q) => document.querySelector(q);
const $$ = (q) => [...document.querySelectorAll(q)];

/* Vault Encryption */
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
const state = { unlocked: false, wallet: null, xmtp: null, provider: null, signer: null };
const STORAGE_KEY = 'xwallet_vault_v1.2';
function getVault() { const s = localStorage.getItem(STORAGE_KEY); return s ? JSON.parse(s) : null; }
function setVault(v) { localStorage.setItem(STORAGE_KEY, JSON.stringify(v)); }
function lock() { state.unlocked = false; state.wallet = null; state.xmtp = null; state.provider = null; state.signer = null; $('#lockState').textContent = 'Locked'; }

/* =========================
   UI VIEWS
   ========================= */
const VIEWS = {
  dashboard() {
    return `
      <div class="label">Welcome</div>
      <div class="alert">Create or import a wallet, then unlock to use Send. This wallet is non-custodial; your secret stays local.</div>
      <hr class="sep"/>
      <div class="grid-2">
        <div>
          <div class="label">Create wallet</div>
          <button class="btn" id="gen">Generate 12-word phrase</button>
          <textarea id="mnemonic" rows="3" readonly></textarea>
          <input id="password" type="password" placeholder="Password to encrypt"/>
          <button class="btn primary" id="save">Save vault</button>
        </div>
        <div>
          <div class="label">Import wallet</div>
          <textarea id="mnemonicIn" rows="3" placeholder="Enter 12 or 24 words"></textarea>
          <input id="passwordIn" type="password" placeholder="Password to encrypt"/>
          <button class="btn" id="doImport">Import</button>
        </div>
      </div>`;
  },
  send() {
    return `
      <div class="label">Send ETH (Sepolia)</div>
      <div class="small">SafeSend evaluates risk before each transaction. Policy: hard block ≥ ${HARD_BLOCK_THRESHOLD} or on listed addresses.</div>
      <hr class="sep"/>
      <div class="send-form">
        <input id="sendTo" placeholder="0x recipient address"/>
        <input id="sendAmt" placeholder="Amount (ETH)"/>
        <button class="btn primary" id="doSend">Send</button>
      </div>
      <div id="sendOut" class="small" style="margin-top:8px"></div>`;
  }
};

/* =========================
   VIEW RENDER
   ========================= */
function render(view) {
  const root = $('#view');
  root.innerHTML = VIEWS[view]();
  if (view === 'dashboard') {
    $('#gen').onclick = () => { $('#mnemonic').value = ethers.Mnemonic.fromEntropy(ethers.randomBytes(16)).phrase; };
    $('#save').onclick = async () => { const m = $('#mnemonic').value.trim(); const pw = $('#password').value; if (!m || !pw) return alert('Mnemonic+password required'); const enc = await aesEncrypt(pw, m); setVault({ version: 1, enc }); alert('Vault saved. Click Unlock.'); };
    $('#doImport').onclick = async () => { const m = $('#mnemonicIn').value.trim(); const pw = $('#passwordIn').value; if (!m || !pw) return alert('Mnemonic+password required'); const enc = await aesEncrypt(pw, m); setVault({ version: 1, enc }); alert('Imported & saved. Click Unlock.'); };
  }
  if (view === 'send') {
    $('#doSend').onclick = async () => {
      const to = $('#sendTo').value.trim();
      const amt = $('#sendAmt').value.trim();
      if (!ethers.isAddress(to)) return alert('Invalid address');
      const n = Number(amt);
      if (isNaN(n) || n <= 0) return alert('Invalid amount');
      $('#sendOut').textContent = 'Checking SafeSend...';
      try {
        const check = await fetchSafeSend(to, 'sepolia');
        const isHardBlocked = check.blocked || check.score >= HARD_BLOCK_THRESHOLD;

        // 🚫 Hard block before modal logic
        if (isHardBlocked) {
          console.warn('[SafeSend] Hard block enforced before modal open');
          await showRiskModal(check, true);
          $('#sendOut').innerHTML = `<span style="color:#ff4d4d">${BLOCK_MSG}</span>`;
          return;
        }

        // Otherwise show modal normally
        const proceed = await showRiskModal(check);
        if (!proceed) {
          $('#sendOut').textContent = 'Cancelled.';
          return;
        }

        $('#sendOut').textContent = 'SafeSend OK — preparing tx...';
        const res = await sendEth({ to, amountEth: n, chain: 'sep' });
        $('#sendOut').innerHTML = `Broadcasted: <a target="_blank" href="https://sepolia.etherscan.io/tx/${res.hash}">${res.hash}</a>`;
      } catch (e) {
        $('#sendOut').textContent = 'Error: ' + (e.message || e);
      }
    };
  }
}

/* =========================
   NAVIGATION
   ========================= */
function selectItem(view) {
  $$('.sidebar .item').forEach((x) =>
    x.classList.toggle('active', x.dataset.view === view)
  );
  render(view);
}
$$('.sidebar .item').forEach((el) =>
  el.addEventListener('click', () => selectItem(el.dataset.view))
);
selectItem('dashboard');

/* =========================
   SEND FUNCTION
   ========================= */
async function getProvider(chain = 'sep') {
  if (!RPCS[chain]) throw new Error('RPC not configured for ' + chain);
  return new ethers.JsonRpcProvider(RPCS[chain]);
}
async function connectWalletToProvider(chain = 'sep') {
  if (!state.wallet) throw new Error('Unlock first');
  const provider = await getProvider(chain);
  state.provider = provider;
  state.signer = state.wallet.connect(provider);
  return state.signer;
}
async function sendEth({ to, amountEth, chain = 'sep' }) {
  if (!state.signer) await connectWalletToProvider(chain);
  const tx = { to, value: ethers.parseEther(String(amountEth)) };
  const fee = await state.signer.getFeeData();
  if (fee?.maxFeePerGas) {
    tx.maxFeePerGas = fee.maxFeePerGas;
    tx.maxPriorityFeePerGas = fee.maxPriorityFeePerGas;
  }
  const est = await state.signer.estimateGas(tx);
  tx.gasLimit = est;
  const sent = await state.signer.sendTransaction(tx);
  await sent.wait(1);
  return { hash: sent.hash, receipt: sent };
}
