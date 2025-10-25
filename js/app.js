// =========================================
// X-Wallet v1.5 — Multi-chain + ERC20 balances + refreshed history
// =========================================
import { ethers } from "https://esm.sh/ethers@6.13.2";

document.addEventListener("DOMContentLoaded", () => {

/* ================================
   CONFIG (set your Alchemy key)
================================ */
const ALCHEMY_KEY = "YOUR_ALCHEMY_KEY_HERE"; // <--- paste your key

// Build Alchemy RPCs from the single key
const CHAINS = {
  ethereum: {
    id: 1,
    label: "Ethereum",
    nativeSymbol: "ETH",
    rpc: `https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`,
    explorer: "https://etherscan.io",
  },
  base: {
    id: 8453,
    label: "Base",
    nativeSymbol: "ETH",
    rpc: `https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`,
    explorer: "https://basescan.org",
  },
  polygon: {
    id: 137,
    label: "Polygon",
    nativeSymbol: "MATIC",
    rpc: `https://polygon-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`,
    explorer: "https://polygonscan.com",
  },
  sepolia: {
    id: 11155111,
    label: "Sepolia",
    nativeSymbol: "ETH",
    rpc: `https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_KEY}`,
    explorer: "https://sepolia.etherscan.io",
  },
};

// SafeSend Worker (unchanged)
const SAFE_SEND_URL = "https://xwalletv1dot2.agedotcom.workers.dev";

/* ================================
   Tiny helpers
================================ */
const $  = (q) => document.querySelector(q);
const $$ = (q) => [...document.querySelectorAll(q)];
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
const fmt = (n) => Number(n).toLocaleString(undefined, { maximumFractionDigits: 6 });

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
const STORAGE_CHAIN     = "xw.chain";

const state = {
  unlocked:false,
  provider:null,
  chainKey: localStorage.getItem(STORAGE_CHAIN) || "sepolia",
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
function setChain(chainKey){
  if (!CHAINS[chainKey]) return;
  state.chainKey = chainKey;
  localStorage.setItem(STORAGE_CHAIN, chainKey);
  state.provider = new ethers.JsonRpcProvider(CHAINS[chainKey].rpc);
  // Refresh any open views that depend on provider
  refreshOpenView();
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
   Alchemy: history + ERC20 balances
================================ */
// History (include ERC20 so USDC transfers appear)
async function getTxsAlchemy(address, { limit = 10 } = {}) {
  if (!state.provider) throw new Error("Provider not ready");
  if (!ethers.isAddress(address)) return [];

  const base = {
    fromBlock: "0x0",
    toBlock: "latest",
    category: ["external","erc20"], // include ERC20 transfers
    withMetadata: true,
    excludeZeroValue: true,
    maxCount: "0x" + Math.max(1, Math.min(100, limit)).toString(16),
    order: "desc",
  };

  const [outRes, inRes] = await Promise.all([
    state.provider.send("alchemy_getAssetTransfers", [{ ...base, fromAddress: address }]).catch(() => ({ transfers: [] })),
    state.provider.send("alchemy_getAssetTransfers", [{ ...base, toAddress: address }]).catch(() => ({ transfers: [] }))
  ]);

  const all = [ ...(outRes?.transfers||[]), ...(inRes?.transfers||[]) ];
  // Normalize
  const norm = (t) => {
    const ts = t?.metadata?.blockTimestamp ? Date.parse(t.metadata.blockTimestamp) : 0;
    return {
      hash: t?.hash || "",
      from: t?.from || "",
      to: t?.to || "",
      asset: t?.asset || (t.category === "erc20" ? (t?.rawContract?.address||"ERC20") : CHAINS[state.chainKey].nativeSymbol),
      value: t?.value != null ? t.value : null,
      timestamp: Number.isFinite(ts) ? ts : 0
    };
  };
  const mapped = all.map(norm);
  mapped.sort((a,b)=>b.timestamp-a.timestamp);
  return mapped.slice(0, limit);
}

// ERC20 balances (non-zero) with metadata
async function getERC20Balances(address){
  if (!state.provider) return [];
  try{
    const res = await state.provider.send("alchemy_getTokenBalances", [address, "erc20"]);
    const list = (res?.tokenBalances || []).filter(tb => tb?.tokenBalance && tb.tokenBalance !== "0x0");
    // Pull metadata for the first 20 tokens with nonzero balances
    const top = list.slice(0, 20);
    const metas = await Promise.all(top.map(t =>
      state.provider.send("alchemy_getTokenMetadata", [t.contractAddress]).catch(()=>null)
    ));
    // Format
    return top.map((t, i) => {
      const m = metas[i] || {};
      const decimals = Number(m.decimals || 18);
      let raw = BigInt(t.tokenBalance);
      // Some responses include hex strings; ensure BigInt parse is correct
      // If it's a decimal string, fallback
      if (typeof raw !== "bigint") {
        try { raw = BigInt(t.tokenBalance); } catch { raw = 0n; }
      }
      const human = Number(raw) / 10**decimals;
      return {
        contract: t.contractAddress,
        symbol: m.symbol || "ERC20",
        name: m.name || "Token",
        decimals,
        amount: human
      };
    }).filter(x => x.amount > 0);
  }catch(e){
    console.warn("getERC20Balances failed", e);
    return [];
  }
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

    const networkSelect = `
      <div class="label">Network</div>
      <select id="netSelect">
        ${Object.keys(CHAINS).map(k=>`<option value="${k}" ${k===state.chainKey?"selected":""}>${CHAINS[k].label}</option>`).join("")}
      </select>
      <div class="small">Explorer: ${CHAINS[state.chainKey].explorer.replace(/^https?:\/\//,"")}</div>
      <hr class="sep"/>
    `;

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

    return `<div class="label">Control Center</div>
      ${networkSelect}
      ${createImport}${manage}`;
  },

  wallets(){
    const native = CHAINS[state.chainKey].nativeSymbol;
    const rows=state.accounts.map(a=>`
      <tr>
        <td>${a.index+1}</td>
        <td class="mono">${a.address}</td>
        <td id="bal-${a.index}">—</td>
      </tr>`).join("");
    return `
      <div class="label">Wallet Balances — ${native}</div>
      <table class="table small"><thead><tr><th>#</th><th>Address</th><th>${native}</th></tr></thead><tbody>${rows}</tbody></table>
      <div id="totalBal" class="small"></div>
      <hr class="sep"/>
      <div class="label">ERC-20 balances</div>
      <div id="erc20List" class="small">—</div>
    `;
  },

  send(){
    const acctOpts=state.accounts.map(a=>`<option value="${a.index}" ${a.index===state.signerIndex?"selected":""}>
      Wallet #${a.index+1} — ${a.address.slice(0,6)}…${a.address.slice(-4)}</option>`).join("")||"<option disabled>No wallets</option>";

    return `
      <div class="label">Send (${CHAINS[state.chainKey].label})</div>
      <div class="send-form">
        <select id="fromAccount">${acctOpts}</select>
        <input id="sendTo" placeholder="Recipient 0x address"/>
        <input id="sendAmt" placeholder="Amount (${CHAINS[state.chainKey].nativeSymbol})"/>
        <button class="btn primary" id="doSend">Send</button>
      </div>
      <div id="sendOut" class="small"></div>

      <hr class="sep"/>
      <div class="grid-2">
        <div>
          <div class="label">Your last 10 transfers</div>
          <div id="txList" class="small">—</div>
        </div>
        <div>
          <div class="label">Recipient recent transfers</div>
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

  // Network select (present on dashboard header)
  const ns = $("#netSelect");
  if (ns) {
    ns.addEventListener("change", (e) => {
      setChain(e.target.value); // rebuild provider + persist
    });
  }

  // ---- dashboard handlers ----
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

  // ---- wallets ----
  if(view==="wallets"){ loadWalletBalances(); loadERC20Balances(); }

  // ---- send ----
  if(view==="send"){
    $("#fromAccount")?.addEventListener("change",(e)=>{ state.signerIndex=Number(e.target.value); loadRecentTxs(); });
    $("#doSend")?.addEventListener("click",sendEthFlow);

    const toEl=$("#sendTo");
    const updateRx = () => loadAddressTxs(toEl.value.trim(), 'rxList');
    toEl?.addEventListener('input', ()=>{ if(ethers.isAddress(toEl.value.trim())) updateRx();});
    toEl?.addEventListener('blur', updateRx);

    loadRecentTxs(); updateRx();
  }

  // ---- settings ----
  if(view==="settings"){
    $("#wipe")?.addEventListener("click",()=>{ if(confirm("Delete vault?")){ localStorage.clear(); lock(); alert("Deleted. Reload."); } });
  }
}

function refreshOpenView(){
  // Re-render the active sidebar view to pick up new chain/provider
  const active = document.querySelector(".sidebar .item.active")?.dataset?.view || "dashboard";
  render(active);
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
    setChain(state.chainKey); // build provider for current chain
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
  const native = CHAINS[state.chainKey].nativeSymbol;
  let total=0n;
  for(const a of state.accounts){
    try{
      const b=await state.provider.getBalance(a.address);
      total+=b;
      const cell=document.getElementById(`bal-${a.index}`);
      if(cell) cell.textContent=`${fmt(ethers.formatEther(b))}`;
    }catch{}
  }
  const tb=document.getElementById("totalBal");
  if(tb) tb.textContent=`Total (${native}): ${fmt(ethers.formatEther(total))}`;
}

async function loadERC20Balances(){
  if(!state.unlocked||!state.provider) return;
  const acct = state.accounts[state.signerIndex];
  const el = $("#erc20List"); if (!el) return;
  el.textContent = "Loading…";
  try{
    const list = await getERC20Balances(acct.address);
    if (!list.length){ el.textContent = "No ERC-20 balances detected."; return; }
    el.innerHTML = list
      .sort((a,b)=>b.amount-a.amount)
      .map(t => `<div>${t.symbol} — ${fmt(t.amount)} <span class="small">(${t.name})</span></div>`)
      .join("");
  }catch(e){
    console.warn(e);
    el.textContent = "Could not load ERC-20 balances.";
  }
}

async function loadRecentTxs(){
  const el=$("#txList"); if(!el) return;
  el.textContent="Loading…";
  try{
    const acct=state.accounts[state.signerIndex]; if(!acct){ el.textContent="No wallet selected."; return; }
    const txs=await getTxsAlchemy(acct.address,{limit:10});
    if(!txs.length){ el.textContent="No recent transfers."; return; }
    el.innerHTML=txs.map(t=>{
      const when=t.timestamp?new Date(t.timestamp).toLocaleString():"";
      const ex=CHAINS[state.chainKey].explorer;
      return `<div>
        <a target=_blank href="${ex}/tx/${t.hash}">${t.hash.slice(0,10)}…</a>
        • ${when} • ${t.from?.slice(0,6)}… → ${t.to?.slice(0,6)}…
        ${t.value!=null?`• ${t.value} ${t.asset || ""}`:""}
      </div>`;
    }).join("");
  }catch(e){ console.warn(e); el.textContent="Could not load recent transfers."; }
}

async function loadAddressTxs(address, targetId){
  const el=document.getElementById(targetId); if(!el) return;
  if(!address || !ethers.isAddress(address)){ el.textContent="Enter a valid 0x address."; return; }
  el.textContent="Loading…";
  try{
    const txs=await getTxsAlchemy(address,{limit:10});
    if(!txs.length){ el.textContent="No recent transfers."; return; }
    const ex=CHAINS[state.chainKey].explorer;
    el.innerHTML=txs.map(t=>{
      const when=t.timestamp?new Date(t.timestamp).toLocaleString():"";
      return `<div>
        <a target=_blank href="${ex}/tx/${t.hash}">${t.hash.slice(0,10)}…</a>
        • ${when} • ${t.from?.slice(0,6)}… → ${t.to?.slice(0,6)}…
        ${t.value!=null?`• ${t.value} ${t.asset || ""}`:""}
      </div>`;
    }).join("");
  }catch(e){ console.warn(e); el.textContent="Could not load transfers for this address."; }
}

/* ================================
   SafeSend Worker (ONLY) + modal
   (unchanged logic; still called before send)
================================ */
async function fetchSafeSendWorker(addr){
  try{
    const u=new URL(SAFE_SEND_URL + "/check");
    u.searchParams.set("address", addr);
    // chain hint for worker (use key)
    u.searchParams.set("chain", state.chainKey);
    const r=await fetch(u.toString(), { cache: "no-store" });
    if(!r.ok) throw new Error("safesend_http_" + r.status);
    return await r.json(); // { score, decision, factors }
  }catch(e){
    console.warn("SafeSend fetch failed", e);
    return { score: 10, decision: "allow", factors: [{severity:"low",label:"Risk service unavailable",reason:"Using default low risk."}] };
  }
}
function severityClass(s){
  if(s==="high") return "factor--high";
  if(s==="medium") return "factor--medium";
  return "factor--low";
}
function openRiskModal({score, factors}, onCancel, onProceed){
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
  warn.style.display = (score >= 60) ? "block" : "none";

  // animate meter 0 -> score
  const target = clamp(Number(score)||0, 0, 100);
  let cur = 0;
  bar.style.setProperty("--score", "0");
  scoreEl.textContent = `Risk score: ${cur}`;
  modal.classList.add("show");

  const step = () => {
    cur = Math.min(cur + 2, target);
    bar.style.setProperty("--score", String(cur));
    scoreEl.textContent = `Risk score: ${cur}`;
    if(cur < target) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);

  (factors || []).forEach(f=>{
    const row = document.createElement("div");
    row.className = `factor ${severityClass(f.severity)}`;
    row.innerHTML = `<span class="factor__badge">${f.label || f.severity}</span><div>${f.reason || ""}</div>`;
    list.appendChild(row);
  });

  const off = () => {
    btnCancel.onclick = btnProceed.onclick = btnClose.onclick = agree.onchange = null;
    modal.classList.remove("show");
  };
  btnCancel.onclick = ()=>{ off(); onCancel?.(); };
  btnClose.onclick  = ()=>{ off(); onCancel?.(); };

  if (score >= 60) {
    agree.onchange = ()=>{ btnProceed.disabled = !agree.checked; };
    btnProceed.onclick = ()=>{ if(agree.checked){ off(); onProceed?.(); } };
  } else {
    btnProceed.disabled = false;
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

  const risk = await fetchSafeSendWorker(to);

  openRiskModal(
    { score: risk.score ?? 0, factors: risk.factors ?? [] },
    () => { $("#sendOut").textContent="Cancelled."; },
    async () => {
      $("#sendOut").textContent = `SafeSend OK (${risk.score}). Sending…`;
      try{
        const signer=acct.wallet.connect(state.provider);
        const tx={ to, value:ethers.parseEther(String(n)) };
        const fee=await state.provider.getFeeData();
        if(fee?.maxFeePerGas){ tx.maxFeePerGas=fee.maxFeePerGas; tx.maxPriorityFeePerGas=fee.maxPriorityFeePerGas; }
        try { tx.gasLimit = await signer.estimateGas(tx); } catch {}
        const sent=await signer.sendTransaction(tx);
        const ex=CHAINS[state.chainKey].explorer;
        $("#sendOut").innerHTML=`Broadcasted: <a target=_blank href="${ex}/tx/${sent.hash}">${sent.hash}</a>`;
        await sent.wait(1);
        loadRecentTxs(); loadAddressTxs(to,'rxList');
        loadWalletBalances(); // update balances after send
      }catch(e){ $("#sendOut").textContent="Error: "+(e.message||e); }
    }
  );
}

}); // DOMContentLoaded