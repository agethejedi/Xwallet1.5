// =============================================================
// X-Wallet v1.5 — Multi-network, ERC20 support, SafeSend fixed
// =============================================================
import { ethers } from "https://esm.sh/ethers@6.13.2";

document.addEventListener("DOMContentLoaded", () => {

/* ===== CONFIG ===================================================== */
const ALCHEMY_KEY = "kxHg5y9yBXWAb9cOcJsf0"; // your key
const SAFE_SEND_URL = "https://xwalletv1dot2.agedotcom.workers.dev";

const CHAINS = {
  ethereum:{id:1,label:"Ethereum",nativeSymbol:"ETH",
    rpc:`https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`,
    explorer:"https://etherscan.io"},
  base:{id:8453,label:"Base",nativeSymbol:"ETH",
    rpc:`https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`,
    explorer:"https://basescan.org"},
  polygon:{id:137,label:"Polygon",nativeSymbol:"MATIC",
    rpc:`https://polygon-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`,
    explorer:"https://polygonscan.com"},
  sepolia:{id:11155111,label:"Sepolia",nativeSymbol:"ETH",
    rpc:`https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_KEY}`,
    explorer:"https://sepolia.etherscan.io"}
};

/* ===== HELPERS ==================================================== */
const $  = q=>document.querySelector(q);
const $$ = q=>[...document.querySelectorAll(q)];
const clamp=(n,a,b)=>Math.max(a,Math.min(b,n));
const fmt=n=>Number(n).toLocaleString(undefined,{maximumFractionDigits:6});

/* ===== AES vault helpers ========================================== */
async function aesEncrypt(password, plaintext){
  const enc=new TextEncoder();
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const km=await crypto.subtle.importKey("raw",enc.encode(password),{name:"PBKDF2"},false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["encrypt"]);
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(plaintext)));
  return {ct:Array.from(ct),iv:Array.from(iv),salt:Array.from(salt)};
}
async function aesDecrypt(password,payload){
  const dec=new TextDecoder();
  const {ct,iv,salt}=payload;
  const km=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),{name:"PBKDF2"},false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:new Uint8Array(salt),iterations:100000,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["decrypt"]);
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(iv)},key,new Uint8Array(ct));
  return dec.decode(pt);
}

/* ===== STATE ====================================================== */
const STORAGE_KEY_VAULT="xwallet_vault_v13";
const STORAGE_KEY_ACCTS="xwallet_accounts_n";
const STORAGE_CHAIN="xw.chain";

const state={
  unlocked:false,
  provider:null,
  chainKey:localStorage.getItem(STORAGE_CHAIN)||"sepolia",
  decryptedPhrase:null,
  accounts:[],
  signerIndex:0
};

const getVault=()=>localStorage.getItem(STORAGE_KEY_VAULT)?
  JSON.parse(localStorage.getItem(STORAGE_KEY_VAULT)):null;
const setVault=v=>localStorage.setItem(STORAGE_KEY_VAULT,JSON.stringify(v));
const getAccountCount=()=>Number(localStorage.getItem(STORAGE_KEY_ACCTS)||"0")||0;
const setAccountCount=n=>localStorage.setItem(STORAGE_KEY_ACCTS,String(Math.max(0,n)));

function lock(){
  state.unlocked=false;state.provider=null;state.decryptedPhrase=null;
  state.accounts=[];state.signerIndex=0;
  const ls=$("#lockState");if(ls)ls.textContent="Locked";
}
function scheduleAutoLock(){
  clearTimeout(window._inactivityTimer);
  window._inactivityTimer=setTimeout(()=>{lock();showLock();},10*60*1000);
}
function setChain(chainKey){
  if(!CHAINS[chainKey])return;
  state.chainKey=chainKey;
  localStorage.setItem(STORAGE_CHAIN,chainKey);
  state.provider=new ethers.JsonRpcProvider(CHAINS[chainKey].rpc);
  refreshOpenView();
}

/* ===== Wallet derivation ========================================== */
function deriveAccountFromPhrase(phrase,index){
  const path=`m/44'/60'/0'/0/${index}`;
  return ethers.HDNodeWallet.fromPhrase(phrase,undefined,path);
}
function loadAccountsFromPhrase(phrase){
  state.accounts=[];
  const n=getAccountCount()||1;
  for(let i=0;i<n;i++){
    const w=deriveAccountFromPhrase(phrase,i);
    state.accounts.push({index:i,wallet:w,address:w.address});
  }
}

/* ===== Alchemy calls ============================================== */
async function getTxsAlchemy(address,{limit=10}={}){
  if(!state.provider)return[];
  const base={fromBlock:"0x0",toBlock:"latest",category:["external","erc20"],withMetadata:true,excludeZeroValue:true,
    maxCount:"0x"+Math.max(1,Math.min(100,limit)).toString(16),order:"desc"};
  const [outRes,inRes]=await Promise.all([
    state.provider.send("alchemy_getAssetTransfers",[ {...base,fromAddress:address} ]).catch(()=>({transfers:[]})),
    state.provider.send("alchemy_getAssetTransfers",[ {...base,toAddress:address} ]).catch(()=>({transfers:[]})),
  ]);
  const all=[...(outRes?.transfers||[]),...(inRes?.transfers||[])];
  const norm=t=>{
    const ts=t?.metadata?.blockTimestamp?Date.parse(t.metadata.blockTimestamp):0;
    return{
      hash:t?.hash||"",from:t?.from||"",to:t?.to||"",
      asset:t?.asset||(t.category==="erc20"?(t?.rawContract?.address||"ERC20"):CHAINS[state.chainKey].nativeSymbol),
      value:t?.value??null,timestamp:ts||0};
  };
  const mapped=all.map(norm).sort((a,b)=>b.timestamp-a.timestamp);
  return mapped.slice(0,limit);
}

async function getERC20Balances(address){
  if(!state.provider)return[];
  try{
    const res=await state.provider.send("alchemy_getTokenBalances",[address,"erc20"]);
    const list=(res?.tokenBalances||[]).filter(tb=>tb?.tokenBalance!=="0x0");
    const top=list.slice(0,20);
    const metas=await Promise.all(top.map(t=>state.provider.send("alchemy_getTokenMetadata",[t.contractAddress]).catch(()=>null)));
    return top.map((t,i)=>{
      const m=metas[i]||{},dec=Number(m.decimals||18);
      let raw=0n;try{raw=BigInt(t.tokenBalance);}catch{}
      return{contract:t.contractAddress,symbol:m.symbol||"ERC20",name:m.name||"Token",decimals:dec,amount:Number(raw)/10**dec};
    }).filter(x=>x.amount>0);
  }catch(e){console.warn("getERC20Balances failed",e);return[];}
}

/* ===== Views ======================================================= */
const VIEWS={
  dashboard(){
    const hasVault=!!getVault(),unlocked=state.unlocked;
    const accRows=unlocked&&state.accounts.length?
      state.accounts.map(a=>`<tr><td>${a.index+1}</td><td class="mono">${a.address}</td></tr>`).join(""):
      "<tr><td colspan='2'>No wallets yet.</td></tr>";
    const networkSelect=`<div class="label">Network</div>
      <select id="netSelect">${Object.keys(CHAINS).map(k=>`<option value="${k}" ${k===state.chainKey?"selected":""}>${CHAINS[k].label}</option>`).join("")}</select>
      <div class="small">Explorer: ${CHAINS[state.chainKey].explorer.replace(/^https?:\\/\\//,"")}</div><hr class="sep"/>`;
    const createImport=!hasVault?`
      <div class="grid-2">
        <div><div class="label">Create wallet</div>
          <button class="btn" id="gen">Generate 12-word phrase</button>
          <textarea id="mnemonic" rows="3" readonly></textarea>
          <input id="password" type="password" placeholder="Password"/>
          <button class="btn primary" id="save">Save vault</button></div>
        <div><div class="label">Import wallet</div>
          <textarea id="mnemonicIn" rows="3" placeholder="Enter words"></textarea>
          <input id="passwordIn" type="password" placeholder="Password"/>
          <button class="btn" id="doImport">Import</button></div></div>`:"";
    const manage=hasVault?`
      <div class="label">Wallets under your seed</div>
      <button class="btn" id="addAcct"${unlocked?"":" disabled"}>Add Wallet</button>
      <table class="table small"><thead><tr><th>#</th><th>Address</th></tr></thead>
      <tbody>${accRows}</tbody></table>`:"";
    return `<div class="label">Control Center</div>${networkSelect}${createImport}${manage}`;
  },
  wallets(){
    const native=CHAINS[state.chainKey].nativeSymbol;
    const rows=state.accounts.map(a=>`<tr><td>${a.index+1}</td><td class="mono">${a.address}</td><td id="bal-${a.index}">—</td></tr>`).join("");
    return `<div class="label">Wallet Balances — ${native}</div>
      <table class="table small"><thead><tr><th>#</th><th>Address</th><th>${native}</th></tr></thead><tbody>${rows}</tbody></table>
      <div id="totalBal" class="small"></div><hr class="sep"/>
      <div class="label">ERC-20 balances</div><div id="erc20List" class="small">—</div>`;
  },
  send(){
    const acctOpts=state.accounts.map(a=>`<option value="${a.index}" ${a.index===state.signerIndex?"selected":""}>
      Wallet #${a.index+1} — ${a.address.slice(0,6)}…${a.address.slice(-4)}</option>`).join("")||"<option disabled>No wallets</option>";
    return `<div class="label">Send (${CHAINS[state.chainKey].label})</div>
      <div class="send-form"><select id="fromAccount">${acctOpts}</select>
      <input id="sendTo" placeholder="Recipient 0x address"/>
      <input id="sendAmt" placeholder="Amount (${CHAINS[state.chainKey].nativeSymbol})"/>
      <button class="btn primary" id="doSend">Send</button></div>
      <div id="sendOut" class="small"></div><hr class="sep"/>
      <div class="grid-2">
        <div><div class="label">Your last 10 transfers</div><div id="txList" class="small">—</div></div>
        <div><div class="label">Recipient recent transfers</div><div id="rxList" class="small">—</div></div></div>`;
  },
  settings(){return `<div class="label">Settings</div><button class="btn" id="wipe">Delete vault (local)</button>`;}
};

/* ===== Rendering / navigation ===================================== */
function render(view){
  const root=$("#view");
  root.innerHTML=VIEWS[view]?VIEWS[view]():"Not found";
  const ns=$("#netSelect");
  if(ns)ns.addEventListener("change",e=>setChain(e.target.value));

  if(view==="dashboard"){
    $("#gen")?.addEventListener("click",()=>{$("#mnemonic").value=ethers.Mnemonic.fromEntropy(ethers.randomBytes(16)).phrase;});
    $("#save")?.addEventListener("click",async()=>{
      const m=$("#mnemonic").value.trim(),pw=$("#password").value;if(!m||!pw)return alert("Mnemonic + password required");
      const enc=await aesEncrypt(pw,m);setVault({version:1,enc});setAccountCount(1);alert("Vault saved. Click Unlock.");render("dashboard");
    });
    $("#doImport")?.addEventListener("click",async()=>{
      const m=$("#mnemonicIn").value.trim(),pw=$("#passwordIn").value;if(!m||!pw)return alert("Mnemonic + password required");
      const enc=await aesEncrypt(pw,m);setVault({version:1,enc});setAccountCount(1);alert("Imported. Click Unlock.");render("dashboard");
    });
    $("#addAcct")?.addEventListener("click",()=>{
      if(!state.unlocked)return alert("Unlock first");
      const n=getAccountCount()+1;setAccountCount(n);
      const w=deriveAccountFromPhrase(state.decryptedPhrase,n-1);
      state.accounts.push({index:n-1,wallet:w,address:w.address});
      render("dashboard");
    });
  }
  if(view==="wallets"){loadWalletBalances();loadERC20Balances();}
  if(view==="send"){
    $("#fromAccount")?.addEventListener("change",e=>{state.signerIndex=Number(e.target.value);loadRecentTxs();});
    $("#doSend")?.addEventListener("click",sendEthFlow);
    const toEl=$("#sendTo");
    const updateRx=()=>loadAddressTxs(toEl.value.trim(),"rxList");
    toEl?.addEventListener("input",()=>{if(ethers.isAddress(toEl.value.trim()))updateRx();});
    toEl?.addEventListener("blur",updateRx);
    loadRecentTxs();updateRx();
  }
  if(view==="settings")$("#wipe")?.addEventListener("click",()=>{if(confirm("Delete vault?")){localStorage.clear();lock();alert("Deleted. Reload.");}});
}
function refreshOpenView(){
  const active=document.querySelector(".sidebar .item.active")?.dataset?.view||"dashboard";
  render(active);
}
function selectItem(v){$$(".sidebar .item").forEach(x=>x.classList.toggle("active",x.dataset.view===v));render(v);}
$$(".sidebar .item").forEach(el=>el.onclick=()=>selectItem(el.dataset.view));
selectItem("dashboard");

/* ===== Lock modal ================================================= */
function showLock(){$("#lockModal").classList.add("active");$("#unlockPassword").value="";$("#unlockMsg").textContent="";}
function hideLock(){$("#lockModal").classList.remove("active");}
$("#btnLock")?.addEventListener("click",()=>{lock();alert("Locked");});
$("#btnUnlock")?.addEventListener("click",()=>showLock());
$("#cancelUnlock")?.addEventListener("click",()=>hideLock());
$("#doUnlock")?.addEventListener("click",async()=>{
  try{
    const v=getVault();if(!v)return $("#unlockMsg").textContent="No vault found.";
    const pw=$("#unlockPassword").value;
    const phrase=await aesDecrypt(pw,v.enc);
    state.decryptedPhrase=phrase;if(!getAccountCount())setAccountCount(1);
    loadAccountsFromPhrase(phrase);setChain(state.chainKey);
    state.unlocked=true;const ls=$("#lockState");if(ls)ls.textContent="Unlocked";
    hideLock();scheduleAutoLock();selectItem("dashboard");
  }catch(e){$("#unlockMsg").textContent="Wrong password or corrupted vault.";console.error(e);}
});

/* ===== Balance + History ========================================== */
async function loadWalletBalances(){
  if(!state.unlocked||!state.provider)return;
  const native=CHAINS[state.chainKey].nativeSymbol;
  let total=0n;
  for(const a of state.accounts){
    try{
      const b=await state.provider.getBalance(a.address);
      total+=b;const c=document.getElementById(`bal-${a.index}`);
      if(c)c.textContent=fmt(ethers.formatEther(b));
    }catch{}
  }
  const tb=$("#totalBal");if(tb)tb.textContent=`Total (${native}): ${fmt(ethers.formatEther(total))}`;
}
async function loadERC20Balances(){
  if(!state.unlocked||!state.provider)return;
  const acct=state.accounts[state.signerIndex];const el=$("#erc20List");if(!el)return;
  el.textContent="Loading…";
  const list=await getERC20Balances(acct.address);
  el.innerHTML=list.length?list.sort((a,b)=>b.amount-a.amount).map(t=>`${t.symbol} — ${fmt(t.amount)} <span class='small'>(${t.name})</span>`).join("<br>"):"No ERC-20 balances detected.";
}
async function loadRecentTxs(){
  const el=$("#txList");if(!el)return;el.textContent="Loading…";
  const acct=state.accounts[state.signerIndex];if(!acct)return el.textContent="No wallet selected.";
  const txs=await getTxsAlchemy(acct.address,{limit:10});
  if(!txs.length)return el.textContent="No recent transfers.";
  const ex=CHAINS[state.chainKey].explorer;
  el.innerHTML=txs.map(t=>`<div><a target=_blank href="${ex}/tx/${t.hash}">${t.hash.slice(0,10)}…</a> • ${t.from?.slice(0,6)}… → ${t.to?.slice(0,6)}… ${t.value?`• ${t.value} ${t.asset||""}`:""}</
  el.innerHTML = txs.map(t => {
    const when = t.timestamp ? new Date(t.timestamp).toLocaleString() : "";
    const ex = CHAINS[state.chainKey].explorer;
    return `<div>
      <a target="_blank" href="${ex}/tx/${t.hash}">${t.hash.slice(0, 10)}…</a>
      • ${when} • ${t.from?.slice(0,6)}… → ${t.to?.slice(0,6)}…
      ${t.value != null ? `• ${t.value} ${t.asset || ""}` : ""}
    </div>`;
  }).join("");
}

async function loadAddressTxs(address, targetId){
  const el = document.getElementById(targetId);
  if(!el) return;
  if(!address || !ethers.isAddress(address)){
    el.textContent = "Enter a valid 0x address.";
    return;
  }
  el.textContent = "Loading…";
  try{
    const txs = await getTxsAlchemy(address, {limit:10});
    if(!txs.length){
      el.textContent = "No recent transfers.";
      return;
    }
    const ex = CHAINS[state.chainKey].explorer;
    el.innerHTML = txs.map(t => {
      const when = t.timestamp ? new Date(t.timestamp).toLocaleString() : "";
      return `<div>
        <a target="_blank" href="${ex}/tx/${t.hash}">${t.hash.slice(0,10)}…</a>
        • ${when} • ${t.from?.slice(0,6)}… → ${t.to?.slice(0,6)}…
        ${t.value != null ? `• ${t.value} ${t.asset || ""}` : ""}
      </div>`;
    }).join("");
  } catch(e){
    console.warn(e);
    el.textContent = "Could not load transfers for this address.";
  }
}

/* ===== SafeSend Worker & modal ==================================== */
async function fetchSafeSendWorker(addr){
  try{
    const u = new URL(SAFE_SEND_URL + "/check");
    u.searchParams.set("address", addr);
    u.searchParams.set("chain", state.chainKey);
    const r = await fetch(u.toString(), { cache: "no-store" });
    if(!r.ok) throw new Error("SafeSend HTTP " + r.status);
    return await r.json();
  }catch(e){
    console.warn("SafeSend fallback", e);
    return { score: 10, decision: "allow", factors: [
      { severity: "low", label: "Risk service unavailable", reason: "Defaulting to low risk." }
    ]};
  }
}

/* ===== Send flow ================================================== */
async function sendEthFlow(){
  const to = $("#sendTo").value.trim();
  const amt = $("#sendAmt").value.trim();
  if(!ethers.isAddress(to)) return alert("Invalid recipient address");
  const n = Number(amt);
  if(isNaN(n) || n <= 0) return alert("Invalid amount");
  const acct = state.accounts[state.signerIndex];
  if(!acct || !state.provider) return alert("Unlock first");

  $("#sendOut").textContent = "Checking SafeSend…";

  const risk = await fetchSafeSendWorker(to);

  openRiskModal(
    { score: risk.score ?? 0, factors: risk.factors ?? [] },
    () => { $("#sendOut").textContent = "Cancelled."; },
    async () => {
      $("#sendOut").textContent = `SafeSend OK (${risk.score}). Sending…`;
      try{
        const signer = acct.wallet.connect(state.provider);
        const tx = { to, value: ethers.parseEther(String(n)) };
        const fee = await state.provider.getFeeData();
        if(fee?.maxFeePerGas){
          tx.maxFeePerGas = fee.maxFeePerGas;
          tx.maxPriorityFeePerGas = fee.maxPriorityFeePerGas;
        }
        try { tx.gasLimit = await signer.estimateGas(tx); } catch {}
        const sent = await signer.sendTransaction(tx);
        const ex = CHAINS[state.chainKey].explorer;
        $("#sendOut").innerHTML = `Broadcasted: <a target="_blank" href="${ex}/tx/${sent.hash}">${sent.hash}</a>`;
        await sent.wait(1);
        loadRecentTxs();
        loadAddressTxs(to, "rxList");
        loadWalletBalances();
      }catch(e){
        $("#sendOut").textContent = "Error: " + (e.message || e);
      }
    }
  );
}

/* ===== END ======================================================== */
}); // DOMContentLoaded
  
  
  
  