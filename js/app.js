// =========================================
// X-Wallet v1.5 — Control Center + TXs + SafeSend (Worker-only risk)
// =========================================
import { ethers } from "https://esm.sh/ethers@6.13.2";

document.addEventListener("DOMContentLoaded", () => {

/* ================================
   CONFIG
================================ */
// Alchemy Sepolia (balances, send, history) — keep using what already works for you
const RPCS = {
  sep: "https://eth-sepolia.g.alchemy.com/v2/kxHg5y9yBXWAb9cOcJsf0",
};

// SafeSend Worker (risk checks ONLY — no direct Etherscan calls here)
const SAFE_SEND_URL = "https://xwalletv1dot2.agedotcom.workers.dev";

/* ================================
   Tiny helpers
================================ */
const $  = (q) => document.querySelector(q);
const $$ = (q) => [...document.querySelectorAll(q)];
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

/* ================================
   AES-GCM vault
================================ */
async function aesEncrypt(password, plaintext){
  const enc  = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const km   = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key  = await crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['encrypt']);
  const ct   = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(plaintext)));
  return { ct: Array.from(ct), iv: Array.from(iv), salt: Array.from(salt) };
}
async function aesDecrypt(password, payload){
  const dec = new TextDecoder();
  const { ct, iv, salt } = payload;
  const km   = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key  = await crypto.subtle.deriveKey({name:'PBKDF2', salt:new Uint8Array(salt), iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['decrypt']);
  const pt   = await crypto.subtle.decrypt({name:'AES-GCM', iv:new Uint8Array(iv)}, key, new Uint8Array(ct));
  return dec.decode(pt);
}

/* ================================
   State / storage
================================ */
const STORAGE_KEY_VAULT = "xwallet_vault_v13";
const STORAGE_KEY_ACCTS = "xwallet_accounts_n";
const state = {
  unlocked:false,
  provider:null,
  decryptedPhrase:null,
  accounts:[], // [{ index, wallet, address }]
  signerIndex:0
};
const getVault = () => (localStorage.getItem(STORAGE_KEY_VAULT) ? JSON.parse(localStorage.getItem(STORAGE_KEY_VAULT)) : null);
const setVault = (v) => localStorage.setItem(STORAGE_KEY_VAULT, JSON.stringify(v));
const getAccountCount = () => {
  const n = Number(localStorage.getItem(STORAGE_KEY_ACCTS)||"0");
  return Number.isFinite(n)&&n>0?n:0;
};
const setAccountCount = (n) => localStorage.setItem(STORAGE_KEY_ACCTS, String(Math.max(0, n)));

function lock(){
  state.unlocked=false; state.provider=null; state.decryptedPhrase=null; state.accounts=[]; state.signerIndex=0;
  const ls = document.getElementById("lockState"); if (ls) ls.textContent = "Locked";
}
function scheduleAutoLock(){
  clearTimeout(window._inactivityTimer);
  window._inactivityTimer = setTimeout(()=>{ lock(); showLock(); }, 10*60*1000);
}

/* ================================
   Derivation helpers
================================ */
function deriveAccountFromPhrase(phrase, index){
  const path = `m/44'/60'/0'/0/${index}`;
  return ethers.HDNodeWallet.fromPhrase(phrase, undefined, path);
}
function loadAccountsFromPhrase(phrase){
  state.accounts=[];
  const n=getAccountCount()||1;
  for(let i=0;i<n;i++){
    const w=deriveAccountFromPhrase(phrase,i);
    state.accounts.push({index:i,wallet:w,address:w.address});
  }
}

/* ================================
   Alchemy transfers (history)
================================ */
async function getTxsAlchemy(address, { limit = 10 } = {}) {
  if (!state.provider) throw new Error("Provider not ready");
  if (!ethers.isAddress(address)) return [];
  const base = {
    fromBlock: "0x0",
    toBlock: "latest",
    category: ["external"],
    withMetadata: true,
    excludeZeroValue: false,
    maxCount: "0x" + Math.max(1, Math.min(100, limit)).toString(16),
    order: "desc",
  };
  const [outRes, inRes] = await Promise.all([
    state.provider.send("alchemy_getAssetTransfers", [{ ...base, fromAddress: address }]).catch(() => ({ transfers: [] })),
    state.provider.send("alchemy_getAssetTransfers", [{ ...base, toAddress: address }]).catch(() => ({ transfers: [] }))
  ]);

  const norm = (t) => {
    const ts = t?.metadata?.blockTimestamp ? Date.parse(t.metadata.blockTimestamp) : 0;
    return {
      hash: t?.hash || "",
      from: t?.from || "",
      to: t?.to || "",
      value: t?.value != null ? Number(t.value) : null,
      timestamp: Number.isFinite(ts) ? ts : 0
    };
  };

  const all = [...(outRes?.transfers||[]), ...(inRes?.transfers||[])].map(norm);
  all.sort((a,b)=>b.timestamp-a.timestamp);
  return all.slice(0, limit);
}

/* ================================
   Views
================================ */
const VIEWS={
  dashboard(){
    const hasVault=!!getVault();
    const unlocked=state.unlocked;
    const accRows=unlocked&&state.accounts.length?
      state.accounts.map(a=>`<tr><td>${a.index+1}</td><td class="mono">${a.address}</td></tr>`).join(""):
      "<tr><td colspan='2'>No wallets yet.</td></tr>";

    const createImport=!hasVault?`
      <div class="grid-2">
        <div>
          <div class="label">Create wallet</div>
          <button class="btn" id="gen">Generate 12-word phrase</button>
          <textarea id="mnemonic" rows="3" readonly></textarea>
          <input id="password" type="password" placeholder="Password"/>
          <button class="btn primary" id="save">Save vault</button>
        </div>
        <div>
          <div class="label">Import wallet</div>
          <textarea id="mnemonicIn" rows="3" placeholder="Enter words"></textarea>
          <input id="passwordIn" type="password" placeholder="Password"/>
          <button class="btn" id="doImport">Import</button>
        </div>
      </div>
    `:"";

    const manage=hasVault?`
      <div class="label">Wallets under your seed</div>
      <button class="btn" id="addAcct"${unlocked?"":" disabled"}>Add Wallet</button>
      <table class="table small">
        <thead><tr><th>#</th><th>Address</th></tr></thead>
        <tbody>${accRows}</tbody>
      </table>
    `:"";

    return `<div class="label">Control Center</div><hr class="sep"/>${createImport}${manage}`;
  },

  wallets(){
    const rows=state.accounts.map(a=>`
      <tr><td>${a.index+1}</td><td class="mono">${a.address}</td><td id="bal-${a.index}">—</td></tr>`).join("");
    return `<div class="label">Wallet Balances</div>
      <table class="table small"><thead><tr><th>#</th><th>Address</th><th>ETH</th></tr></thead><tbody>${rows}</tbody></table>
      <div id="totalBal" class="small"></div>`;
  },

  send(){
    const acctOpts=state.accounts.map(a=>`<option value="${a.index}" ${a.index===state.signerIndex?"selected":""}>
      Wallet #${a.index+1} — ${a.address.slice(0,6)}…${a.address.slice(-4)}</option>`).join("")||"<option disabled>No wallets</option>";

    return `
      <div class="label">Send ETH (Sepolia)</div>
      <div class="send-form">
        <select id="fromAccount">${acctOpts}</select>
        <input id="sendTo" placeholder="Recipient 0x address"/>
        <input id="sendAmt" placeholder="Amount (ETH)"/>
        <button class="btn primary" id="doSend">Send</button>
      </div>
      <div id="sendOut" class="small"></div>

      <hr class="sep"/>
      <div class="grid-2">
        <div>
          <div class="label">Your last 10 transactions</div>
          <div id="txList" class="small">—</div>
        </div>
        <div>
          <div class="label">Recipient recent txs</div>
          <div id="rxList" class="small">—</div>
        </div>
      </div>
    `;
  },

  settings(){
    return `<div class="label">Settings</div><button class="btn" id="wipe">Delete vault (local)</button>`;
  }
};

/* ================================
   Rendering + handlers
================================ */
function render(view){
  const root=$("#view");
  if(!VIEWS[view]){root.innerHTML="<div>Not found</div>";return;}
  root.innerHTML=VIEWS[view]();

  if(view==="dashboard"){
    $("#gen")?.addEventListener("click",()=>{$("#mnemonic").value=ethers.Mnemonic.fromEntropy(ethers.randomBytes(16)).phrase;});
    $("#save")?.addEventListener("click",async()=>{
      const m=$("#mnemonic").value.trim(); const pw=$("#password").value;
      if(!m||!pw) return alert("Mnemonic + password required");
      const enc=await aesEncrypt(pw,m); setVault({version:1,enc}); setAccountCount(1);
      alert("Vault saved. Click Unlock."); render("dashboard");
    });
    $("#doImport")?.addEventListener("click",async()=>{
      const m=$("#mnemonicIn").value.trim(); const pw=$("#passwordIn").value;
      if(!m||!pw) return alert("Mnemonic + password required");
      const enc=await aesEncrypt(pw,m); setVault({version:1,enc}); setAccountCount(1);
      alert("Imported. Click Unlock."); render("dashboard");
    });
    $("#addAcct")?.addEventListener("click",()=>{
      if(!state.unlocked) return alert("Unlock first");
      const n=getAccountCount()+1; setAccountCount(n);
      const w=deriveAccountFromPhrase(state.decryptedPhrase,n-1);
      state.accounts.push({index:n-1,wallet:w,address:w.address});
      render("dashboard");
    });
  }

  if(view==="wallets"){loadWalletBalances();}

  if(view==="send"){
    $("#fromAccount")?.addEventListener("change",(e)=>{ state.signerIndex=Number(e.target.value); loadRecentTxs(); });
    $("#doSend")?.addEventListener("click",sendEthFlow);

    const toEl=$("#sendTo");
    const updateRx = () => loadAddressTxs(toEl.value.trim(), 'rxList');
    toEl?.addEventListener('input', ()=>{ if(ethers.isAddress(toEl.value.trim())) updateRx();});
    toEl?.addEventListener('blur', updateRx);

    loadRecentTxs(); updateRx();
  }

  if(view==="settings"){
    $("#wipe")?.addEventListener("click",()=>{ if(confirm("Delete vault?")){ localStorage.clear(); lock(); alert("Deleted. Reload."); } });
  }
}

/* ================================
   Navigation + lock modal
================================ */
function selectItem(view){$$(".sidebar .item").forEach(x=>x.classList.toggle("active",x.dataset.view===view));render(view);}
$$(".sidebar .item").forEach(el=>el.onclick=()=>selectItem(el.dataset.view));
selectItem("dashboard");

function showLock(){ $("#lockModal").classList.add("active"); $("#unlockPassword").value=""; $("#unlockMsg").textContent=""; }
function hideLock(){ $("#lockModal").classList.remove("active"); }
$("#btnLock")?.addEventListener("click",()=>{ lock(); alert("Locked"); });
$("#btnUnlock")?.addEventListener("click",()=>showLock());
$("#cancelUnlock")?.addEventListener("click",()=>hideLock());
$("#doUnlock")?.addEventListener("click",async()=>{
  try{
    const v=getVault(); if(!v){$("#unlockMsg").textContent="No vault found.";return;}
    const pw=$("#unlockPassword").value;
    const phrase=await aesDecrypt(pw,v.enc);
    state.decryptedPhrase=phrase;
    if(!getAccountCount()) setAccountCount(1);
    loadAccountsFromPhrase(phrase);
    state.provider=new ethers.JsonRpcProvider(RPCS.sep);
    state.unlocked=true;
    const ls=document.getElementById("lockState"); if(ls) ls.textContent="Unlocked";
    hideLock(); scheduleAutoLock(); selectItem("dashboard");
  }catch(e){console.error(e); $("#unlockMsg").textContent="Wrong password or corrupted vault.";}
});

/* ================================
   Balances & History
================================ */
async function loadWalletBalances(){
  if(!state.unlocked||!state.provider) return;
  let total=0n;
  for(const a of state.accounts){
    try{
      const b=await state.provider.getBalance(a.address);
      total+=b;
      const cell=document.getElementById(`bal-${a.index}`);
      if(cell) cell.textContent=ethers.formatEther(b);
    }catch{}
  }
  const tb=document.getElementById("totalBal");
  if(tb) tb.textContent="Total (ETH): "+ethers.formatEther(total);
}

async function loadRecentTxs(){
  const el=$("#txList"); if(!el) return;
  el.textContent="Loading…";
  try{
    const acct=state.accounts[state.signerIndex]; if(!acct){ el.textContent="No wallet selected."; return; }
    const txs=await getTxsAlchemy(acct.address,{limit:10});
    if(!txs.length){ el.textContent="No recent txs."; return; }
    el.innerHTML=txs.map(t=>{
      const when=t.timestamp?new Date(t.timestamp).toLocaleString():"";
      return `<div>
        <a target=_blank href="https://sepolia.etherscan.io/tx/${t.hash}">${t.hash.slice(0,10)}…</a>
        • ${when} • ${t.from?.slice(0,6)}… → ${t.to?.slice(0,6)}… ${t.value!=null?`• ${t.value} ETH`:""}
      </div>`;
    }).join("");
  }catch(e){ console.warn(e); el.textContent="Could not load recent transactions."; }
}

async function loadAddressTxs(address, targetId){
  const el=document.getElementById(targetId); if(!el) return;
  if(!address || !ethers.isAddress(address)){ el.textContent="Enter a valid 0x address."; return; }
  el.textContent="Loading…";
  try{
    const txs=await getTxsAlchemy(address,{limit:10});
    if(!txs.length){ el.textContent="No recent txs."; return; }
    el.innerHTML=txs.map(t=>{
      const when=t.timestamp?new Date(t.timestamp).toLocaleString():"";
      return `<div>
        <a target=_blank href="https://sepolia.etherscan.io/tx/${t.hash}">${t.hash.slice(0,10)}…</a>
        • ${when} • ${t.from?.slice(0,6)}… → ${t.to?.slice(0,6)}… ${t.value!=null?`• ${t.value} ETH`:""}
      </div>`;
    }).join("");
  }catch(e){ console.warn(e); el.textContent="Could not load transactions for this address."; }
}

/* ================================
   SafeSend Worker (ONLY) + modal
================================ */
async function fetchSafeSendWorker({addr, chain="sepolia", amountEth=0, ens=""}){
  try{
    const u=new URL(SAFE_SEND_URL + "/check");
    u.searchParams.set("address", addr);
    u.searchParams.set("chain", chain);
    if (amountEth) u.searchParams.set("amount", String(amountEth));
    if (ens) u.searchParams.set("ens", ens);
    const r=await fetch(u.toString(), { cache: "no-store" });
    if(!r.ok) throw new Error("safesend_http_" + r.status);
    return await r.json(); // { score, decision, factors }
  }catch(e){
    console.warn("SafeSend fetch failed", e);
    return { score: 10, decision: "allow", factors: [{severity:"low",label:"Risk service unavailable",reason:"Using default low risk."}] };
  }
}

function severityClass(s){
  if(s==="high"||s==="critical") return "factor--high";
  if(s==="medium"||s==="med")    return "factor--med";
  return "factor--low";
}

function openRiskModal({score, factors, decision}, onCancel, onProceed){
  const modal = document.getElementById("riskModal");
  const bar   = document.getElementById("riskMeterBar");
  const scoreEl = document.getElementById("riskScoreText");
  const list  = document.getElementById("riskFactors");
  const warn  = document.getElementById("riskWarning");
  const agree = document.getElementById("riskAgree");
  const btnCancel  = document.getElementById("riskCancel");
  const btnProceed = document.getElementById("riskProceed");
  const btnClose   = document.getElementById("riskClose");

  // reset
  list.innerHTML = "";
  agree.checked = false;
  btnProceed.disabled = true;

  const isBlock = decision === "block";
  const needsAck = !isBlock && (score >= 60);
  warn.style.display = needsAck ? "block" : "none";

  // animate meter 0 -> score
  const target = clamp(Number(score)||0, 0, 100);
  let cur = 0;
  bar.style.setProperty("--score", "0");
  scoreEl.textContent = `Risk score: ${cur}`;
  modal.classList.add("active");

  const step = () => {
    cur = Math.min(cur + 2, target);
    bar.style.setProperty("--score", String(cur));
    scoreEl.textContent = `Risk score: ${cur}`;
    if(cur < target) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);

  // render factors
  (factors || []).forEach(f=>{
    const row = document.createElement("div");
    row.className = `factor ${severityClass(f.severity)}`;
    row.innerHTML = `<span class="factor__badge">${f.label || f.severity}</span><div>${f.reason || ""}</div>`;
    list.appendChild(row);
  });

  // wire buttons
  const off = () => {
    btnCancel.onclick = btnProceed.onclick = btnClose.onclick = agree.onchange = null;
    modal.classList.remove("active");
  };

  btnCancel.onclick = ()=>{ off(); onCancel?.(); };
  btnClose.onclick  = ()=>{ off(); onCancel?.(); };

  if (isBlock) {
    btnProceed.disabled = true;
    btnProceed.textContent = "Blocked";
    btnProceed.title = "This destination is blocked (e.g., OFAC).";
  } else if (needsAck) {
    btnProceed.textContent = "Complete transaction";
    agree.onchange = ()=>{ btnProceed.disabled = !agree.checked; };
    btnProceed.onclick = ()=>{ if(agree.checked){ off(); onProceed?.(); } };
  } else {
    btnProceed.disabled = false;
    btnProceed.textContent = "Complete transaction";
    btnProceed.onclick = ()=>{ off(); onProceed?.(); };
  }
}

/* ================================
   Send flow
================================ */
async function sendEthFlow(){
  const to=$("#sendTo").value.trim();
  const amt=$("#sendAmt").value.trim();
  if(!ethers.isAddress(to)) return alert("Invalid recipient");
  const n=Number(amt); if(isNaN(n)||n<=0) return alert("Invalid amount");
  const acct=state.accounts[state.signerIndex];
  if(!acct||!state.provider) return alert("Unlock first");

  $("#sendOut").textContent="Checking SafeSend…";

  // 1) Get risk from Worker (ONLY)
  const risk = await fetchSafeSendWorker({ addr: to, chain: "sepolia", amountEth: n });

  // 2) Always show modal
  openRiskModal(
    { score: risk.score ?? 0, factors: risk.factors ?? [], decision: risk.decision ?? "allow" },
    () => { $("#sendOut").textContent="Cancelled."; }, // cancel
    async () => { // proceed
      $("#sendOut").textContent = `SafeSend OK (${risk.score}). Sending…`;
      try{
        const signer=acct.wallet.connect(state.provider);
        const tx={ to, value:ethers.parseEther(String(n)) };
        const fee=await state.provider.getFeeData();
        if(fee?.maxFeePerGas){ tx.maxFeePerGas=fee.maxFeePerGas; tx.maxPriorityFeePerGas=fee.maxPriorityFeePerGas; }
        try { tx.gasLimit = await signer.estimateGas(tx); } catch {}
        const sent=await signer.sendTransaction(tx);
        $("#sendOut").innerHTML=`Broadcasted: <a target=_blank href="https://sepolia.etherscan.io/tx/${sent.hash}">${sent.hash}</a>`;
        await sent.wait(1);
        loadRecentTxs(); loadAddressTxs(to,'rxList');
      }catch(e){ $("#sendOut").textContent="Error: "+(e.message||e); }
    }
  );
}

}); // DOMContentLoaded
