// X-Wallet v1.5 — fail-safe app.js (buttons always responsive)
// - No top-level imports. Ethers is loaded dynamically.
// - UI & listeners attach even if network/CSP block esm.sh.
// - Debug overlay shows boot / ethers status.
// - Regex fix: use host(explorerUrl) instead of .replace(/^https?:\/\//,'')

(function () {

  /* ================= CONFIG ================= */
  const CONFIG = {
    ALCHEMY_KEY: "kxHg5y9yBXWAb9cOcJsf0", // <-- set me
    SAFE_SEND_ORG: "https://xwalletv1dot2.agedotcom.workers.dev",
    CHAINS: {
      ethereum:{id:1, label:"Ethereum Mainnet",  nativeSymbol:"ETH",
        rpc:(k)=>`https://eth-mainnet.g.alchemy.com/v2/${k}`,  explorer:"https://etherscan.io"},
      sepolia:{id:11155111,label:"Ethereum Sepolia (testnet)",nativeSymbol:"ETH",
        rpc:(k)=>`https://eth-sepolia.g.alchemy.com/v2/${k}`, explorer:"https://sepolia.etherscan.io"},
      polygon:{id:137, label:"Polygon",           nativeSymbol:"MATIC",
        rpc:(k)=>`https://polygon-mainnet.g.alchemy.com/v2/${k}`, explorer:"https://polygonscan.com"},
      base:{id:8453,   label:"Base",              nativeSymbol:"ETH",
        rpc:(k)=>`https://base-mainnet.g.alchemy.com/v2/${k}`,    explorer:"https://basescan.org"},
      optimism:{id:10, label:"Optimism",          nativeSymbol:"ETH",
        rpc:(k)=>`https://opt-mainnet.g.alchemy.com/v2/${k}`,     explorer:"https://optimistic.etherscan.io"}
    }
  };

  /* ================= STATE ================== */
  let ethers = null;              // will be set by dynamic import
  let provider = null;

  const state = {
    unlocked: false,
    chainKey: localStorage.getItem("xw.chain") || "sepolia",
    decryptedPhrase: null,
    accounts: [],               // [{index, wallet, address}]
    signerIndex: 0,
    pendingTx: null,
    lastRisk: null
  };

  /* =============== DEBUG BAR ================= */
  const dbg = (function makeDebugBar(){
    const el = document.createElement("div");
    el.id = "xw-debug";
    el.style.cssText = "position:fixed;left:10px;bottom:10px;padding:6px 8px;border-radius:8px;background:#0b1220;border:1px solid #263040;color:#9aa4b2;font:12px/1.2 system-ui;z-index:9999;opacity:.9";
    el.textContent = "X-Wallet: booting…";
    document.addEventListener("DOMContentLoaded", () => document.body.appendChild(el));
    return (msg) => { const div = document.getElementById("xw-debug"); if (div) div.textContent = `X-Wallet: ${msg}`; };
  })();

  function safe(fn){ try { fn(); } catch(e){ console.warn(e); } }

  /* ============ DYNAMIC ETHERS LOAD ============ */
  async function ensureEthersLoaded(){
    if (ethers) return true;
    try {
      dbg("loading ethers…");
      const mod = await import("https://esm.sh/ethers@6.13.2?bundle");
      ethers = mod.ethers || mod.default || mod;
      dbg("ethers ready");
      return true;
    } catch (e) {
      console.warn("Ethers import failed:", e);
      dbg("ethers failed to load (UI still works)");
      return false;
    }
  }

  /* ============== SMALL HELPERS =============== */
  const $  = (q, el=document)=>el.querySelector(q);
  const $$ = (q, el=document)=>[...el.querySelectorAll(q)];
  const fmt = (n)=>Number(n).toLocaleString(undefined,{maximumFractionDigits:6});
  const clamp=(n,a=0,b=100)=>Math.max(a,Math.min(b,n));
  const host = (u)=>{ try { return new URL(u).host; } catch { return u; } }; // regex-free, safe

  function setChain(chainKey){
    if (!CONFIG.CHAINS[chainKey]) return;
    state.chainKey = chainKey;
    localStorage.setItem("xw.chain", chainKey);
    safe(async () => {
      if (!await ensureEthersLoaded()) { provider = null; return; }
      provider = new ethers.JsonRpcProvider(CONFIG.CHAINS[chainKey].rpc(CONFIG.ALCHEMY_KEY));
    });
    // sync selector
    const sel = $("#networkSelect");
    if (sel && sel.value !== chainKey) sel.value = chainKey;
    refreshOpenView();
  }

  function populateTopNetworkSelect(){
    const sel = $("#networkSelect");
    if (!sel) return;
    sel.innerHTML = Object.keys(CONFIG.CHAINS).map(k=>`<option value="${k}">${CONFIG.CHAINS[k].label}</option>`).join("");
    sel.value = state.chainKey in CONFIG.CHAINS ? state.chainKey : "sepolia";
    sel.addEventListener("change", e => setChain(e.target.value));
  }

  /* =============== LOCK MODAL ================== */
  function showLock(){ const m=$("#lockModal"); m?.classList.add("active"); $("#unlockPassword").value=""; $("#unlockMsg").textContent=""; }
  function hideLock(){ $("#lockModal")?.classList.remove("active"); }
  function lock(){
    state.unlocked=false; provider=null; state.decryptedPhrase=null;
    state.accounts=[]; state.signerIndex=0; state.pendingTx=null; state.lastRisk=null;
    const ls=$("#lockState"); if(ls) ls.textContent="Locked";
  }
  function scheduleAutoLock(){
    clearTimeout(window._inactivityTimer);
    window._inactivityTimer = setTimeout(()=>{ lock(); showLock(); }, 10*60*1000);
  }

  /* ========= DERIVATION (lazy ethers) ========= */
  function deriveAccountFromPhrase(phrase,index){
    if (!ethers) throw new Error("ethers not loaded");
    const path=`m/44'/60'/0'/0/${index}`;
    return ethers.HDNodeWallet.fromPhrase(phrase, undefined, path);
  }
  function loadAccountsFromPhrase(phrase){
    state.accounts = [];
    const n = Number(localStorage.getItem("xwallet_accounts_n")||"1");
    for (let i=0; i<n; i++){
      const w=deriveAccountFromPhrase(phrase,i);
      state.accounts.push({index:i,wallet:w,address:w.address});
    }
  }

  /* ================ VIEWS ===================== */
  const VIEWS = {
    dashboard(){
      const hasVault = !!localStorage.getItem("xwallet_vault_v13");
      const unlocked = state.unlocked;
      const net = CONFIG.CHAINS[state.chainKey];
      const accRows = unlocked && state.accounts.length
        ? state.accounts.map(a=>`<tr><td>${a.index+1}</td><td class="mono">${a.address}</td></tr>`).join("")
        : "<tr><td colspan='2'>No wallets yet.</td></tr>";

      const createImport = !hasVault ? `
        <div class="grid-2">
          <div><div class="label">Create wallet</div>
            <button class="btn" id="gen">Generate 12-word phrase</button>
            <textarea id="mnemonic" rows="3" readonly></textarea>
            <input id="password" type="password" placeholder="Password"/>
            <button class="btn primary" id="save">Save vault</button></div>
          <div><div class="label">Import wallet</div>
            <textarea id="mnemonicIn" rows="3" placeholder="Enter words"></textarea>
            <input id="passwordIn" type="password" placeholder="Password"/>
            <button class="btn" id="doImport">Import</button></div></div>` : "";

      const manage = hasVault ? `
        <div class="label">Wallets under your seed</div>
        <button class="btn" id="addAcct"${unlocked?"":" disabled"}>Add Wallet</button>
        <table class="table small"><thead><tr><th>#</th><th>Address</th></tr></thead>
        <tbody>${accRows}</tbody></table>` : "";

      return `
        <div class="label">Control Center</div>
        <div class="small">Current network</div>
        <div class="label">${net.label}</div>
        <div class="small">Explorer: ${host(net.explorer)}</div>
        <hr class="sep"/>
        ${createImport}
        ${manage}
      `;
    },
    wallets(){
      const native = CONFIG.CHAINS[state.chainKey].nativeSymbol;
      const rows = state.accounts.map(a=>`<tr><td>${a.index+1}</td><td class="mono">${a.address}</td><td id="bal-${a.index}">—</td></tr>`).join("");
      return `<div class="label">Wallet Balances — ${native}</div>
        <table class="table small"><thead><tr><th>#</th><th>Address</th><th>${native}</th></tr></thead><tbody>${rows}</tbody></table>
        <div id="totalBal" class="small"></div><hr class="sep"/>
        <div class="label">ERC-20 balances</div><div id="erc20List" class="small">—</div>`;
    },
    send(){
      const net = CONFIG.CHAINS[state.chainKey];
      const acctOpts = state.accounts.map(a=>`<option value="${a.index}" ${a.index===state.signerIndex?"selected":""}>
        Wallet #${a.index+1} — ${a.address.slice(0,6)}…${a.address.slice(-4)}</option>`).join("") || "<option disabled>No wallets</option>";
      return `<div class="label">Send (${net.label})</div>
        <div class="send-form"><select id="fromAccount">${acctOpts}</select>
        <input id="sendTo" placeholder="Recipient 0x address"/>
        <input id="sendAmt" placeholder="Amount (${net.nativeSymbol})"/>
        <button class="btn primary" id="doSend">Send</button></div>
        <div id="sendOut" class="small"></div><hr class="sep"/>
        <div class="grid-2">
          <div><div class="label">Your last 10 transfers</div><div id="txList" class="small">—</div></div>
          <div><div class="label">Recipient recent transfers</div><div id="rxList" class="small">—</div></div></div>`;
    },
    settings(){
      return `<div class="label">Settings</div><button class="btn" id="wipe">Delete vault (local)</button>`;
    }
  };

  function render(view){
    const root = $("#view");
    root.innerHTML = VIEWS[view] ? VIEWS[view]() : "Not found";

    // dashboard buttons
    if (view==="dashboard"){
      $("#gen")?.addEventListener("click", async ()=>{
        if (!await ensureEthersLoaded()) return alert("Network blocked ethers. Try again or check CSP.");
        $("#mnemonic").value = ethers.Mnemonic.fromEntropy(ethers.randomBytes(16)).phrase;
      });
      $("#save")?.addEventListener("click", async ()=>{
        const m=$("#mnemonic").value.trim(), pw=$("#password").value;
        if(!m||!pw) return alert("Mnemonic + password required");
        const enc=await aesEncrypt(pw,m);
        localStorage.setItem("xwallet_vault_v13", JSON.stringify({version:1,enc}));
        localStorage.setItem("xwallet_accounts_n","1");
        alert("Vault saved. Click Unlock."); render("dashboard");
      });
      $("#doImport")?.addEventListener("click", async ()=>{
        const m=$("#mnemonicIn").value.trim(), pw=$("#passwordIn").value;
        if(!m||!pw) return alert("Mnemonic + password required");
        const enc=await aesEncrypt(pw,m);
        localStorage.setItem("xwallet_vault_v13", JSON.stringify({version:1,enc}));
        localStorage.setItem("xwallet_accounts_n","1");
        alert("Imported. Click Unlock."); render("dashboard");
      });
      $("#addAcct")?.addEventListener("click", async ()=>{
        if (!state.unlocked) return alert("Unlock first");
        if (!await ensureEthersLoaded()) return alert("Ethers not loaded.");
        const n = Number(localStorage.getItem("xwallet_accounts_n")||"1")+1;
        localStorage.setItem("xwallet_accounts_n", String(n));
        const w = deriveAccountFromPhrase(state.decryptedPhrase, n-1);
        state.accounts.push({index:n-1, wallet:w, address:w.address});
        render("dashboard");
      });
    }

    // wallets
    if (view==="wallets"){
      safe(loadWalletBalances);
      safe(loadERC20Balances);
    }

    // send
    if (view==="send"){
      $("#fromAccount")?.addEventListener("change", e=>{
        state.signerIndex = Number(e.target.value);
        safe(loadRecentTxs);
      });
      $("#doSend")?.addEventListener("click", sendEthFlow);
      const toEl = $("#sendTo");
      const updateRx = ()=> safe(()=>loadAddressTxs(toEl.value.trim(),"rxList"));
      toEl?.addEventListener("input",()=>{ if (/^0x[a-fA-F0-9]{40}$/.test(toEl.value.trim())) updateRx(); });
      toEl?.addEventListener("blur", updateRx);
      safe(loadRecentTxs); updateRx();
    }

    // settings
    if (view==="settings"){
      $("#wipe")?.addEventListener("click", ()=>{
        if (confirm("Delete vault?")) { localStorage.clear(); lock(); alert("Deleted. Reload."); }
      });
    }
  }

  function refreshOpenView(){
    const active = document.querySelector(".sidebar .item.active")?.dataset?.view || "dashboard";
    render(active);
  }
  function selectItem(v){
    $$(".sidebar .item").forEach(x=>x.classList.toggle("active", x.dataset.view===v));
    render(v);
  }

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

  /* ===== History / Balances (all guarded) ===== */
  async function getTxsAlchemy(address,{limit=10}={}){
    if (!await ensureEthersLoaded() || !provider) return [];
    const base={fromBlock:"0x0",toBlock:"latest",category:["external","erc20"],withMetadata:true,excludeZeroValue:true,
      maxCount:"0x"+Math.max(1,Math.min(100,limit)).toString(16),order:"desc"};
    const [outRes,inRes]=await Promise.all([
      provider.send("alchemy_getAssetTransfers",[ {...base,fromAddress:address} ]).catch(()=>({transfers:[]})),
      provider.send("alchemy_getAssetTransfers",[ {...base,toAddress:address} ]).catch(()=>({transfers:[]})),
    ]);
    const all=[...(outRes?.transfers||[]),...(inRes?.transfers||[])];
    const net = CONFIG.CHAINS[state.chainKey];
    const norm=t=>{
      const ts=t?.metadata?.blockTimestamp?Date.parse(t.metadata.blockTimestamp):0;
      return {
        hash:t?.hash||"",from:t?.from||"",to:t?.to||"",
        asset:t?.asset||(t.category==="erc20"?(t?.rawContract?.address||"ERC20"):net.nativeSymbol),
        value:t?.value??null,timestamp:ts||0
      };
    };
    return all.map(norm).sort((a,b)=>b.timestamp-a.timestamp).slice(0,limit);
  }
  async function getERC20Balances(address){
    if (!await ensureEthersLoaded() || !provider) return [];
    try{
      const res=await provider.send("alchemy_getTokenBalances",[address,"erc20"]);
      const list=(res?.tokenBalances||[]).filter(tb=>tb?.tokenBalance!=="0x0").slice(0,20);
      const metas=await Promise.all(list.map(t=>provider.send("alchemy_getTokenMetadata",[t.contractAddress]).catch(()=>null)));
      return list.map((t,i)=>{
        const m=metas[i]||{},dec=Number(m.decimals||18);
        let raw=0n; try{ raw=BigInt(t.tokenBalance); }catch{}
        return {contract:t.contractAddress,symbol:m.symbol||"ERC20",name:m.name||"Token",decimals:dec,amount:Number(raw)/10**dec};
      }).filter(x=>x.amount>0);
    }catch(e){ console.warn("getERC20Balances failed",e); return[]; }
  }
  async function loadWalletBalances(){
    if(!state.unlocked) return;
    if (!await ensureEthersLoaded() || !provider) { $$("#view [id^='bal-']").forEach(el=>el.textContent="—"); return; }
    const netSym=CONFIG.CHAINS[state.chainKey].nativeSymbol;
    let total=0n;
    for(const a of state.accounts){
      try{
        const b=await provider.getBalance(a.address);
        total+=b;
        const c=document.getElementById(`bal-${a.index}`); if(c) c.textContent=fmt(ethers.formatEther(b));
      }catch{}
    }
    const tb=$("#totalBal"); if(tb) tb.textContent = `Total (${netSym}): ${fmt(ethers.formatEther(total))}`;
  }
  async function loadERC20Balances(){
    if(!state.unlocked) return;
    const el=$("#erc20List"); if(!el) return;
    el.textContent="Loading…";
    const acct=state.accounts[state.signerIndex]; if(!acct){ el.textContent="No wallet selected."; return; }
    const list=await getERC20Balances(acct.address);
    el.innerHTML = list.length
      ? list.sort((a,b)=>b.amount-a.amount).map(t=>`${t.symbol} — ${fmt(t.amount)} <span class='small'>(${t.name})</span>`).join("<br>")
      : "No ERC-20 balances detected.";
  }
  async function loadRecentTxs(){
    const el=$("#txList"); if(!el) return; el.textContent="Loading…";
    const acct=state.accounts[state.signerIndex]; if(!acct){ el.textContent="No wallet selected."; return; }
    const txs=await getTxsAlchemy(acct.address,{limit:10});
    if(!txs.length){ el.textContent="No recent transfers."; return; }
    const ex=CONFIG.CHAINS[state.chainKey].explorer;
    el.innerHTML = txs.map(t=>{
      const when = t.timestamp ? new Date(t.timestamp).toLocaleString() : "";
      return `<div>
        <a target="_blank" href="${ex}/tx/${t.hash}">${t.hash.slice(0,10)}…</a>
        • ${when} • ${t.from?.slice(0,6)}… → ${t.to?.slice(0,6)}…
        ${t.value != null ? `• ${t.value} ${t.asset || ""}` : ""}
      </div>`;
    }).join("");
  }
  async function loadAddressTxs(address, targetId){
    const el = document.getElementById(targetId); if(!el) return;
    if(!address || !/^0x[a-fA-F0-9]{40}$/.test(address)){ el.textContent="Enter a valid 0x address."; return; }
    el.textContent="Loading…";
    try{
      const txs=await getTxsAlchemy(address,{limit:10});
      if(!txs.length){ el.textContent="No recent transfers."; return; }
      const ex=CONFIG.CHAINS[state.chainKey].explorer;
      el.innerHTML = txs.map(t=>{
        const when = t.timestamp ? new Date(t.timestamp).toLocaleString() : "";
        return `<div>
          <a target="_blank" href="${ex}/tx/${t.hash}">${t.hash.slice(0,10)}…</a>
          • ${when} • ${t.from?.slice(0,6)}… → ${t.to?.slice(0,6)}…
          ${t.value != null ? `• ${t.value} ${t.asset || ""}` : ""}
        </div>`;
      }).join("");
    }catch(e){ console.warn(e); el.textContent="Could not load transfers for this address."; }
  }

  /* ============ RISK MODAL (UI only; network calls are same origin) ============ */
  function wireRiskModal(){
    $("#riskClose")?.addEventListener("click", closeRiskModal);
    $("#riskCancel")?.addEventListener("click", closeRiskModal);
    $("#riskAgree")?.addEventListener("change", onRiskAcknowledgeChange);
    $("#riskProceed")?.addEventListener("click", doProceedAfterRisk);
  }
  function openRiskModal(){
    const m=$("#riskModal"); if(!m) return;
    m.classList.add("active"); m.setAttribute("aria-hidden","false");
    setRiskScore(0); setRiskFactors([]); setHighRisk(false); setProceedEnabled(false);
  }
  function closeRiskModal(){
    const m=$("#riskModal"); if(!m) return;
    m.classList.remove("active"); m.setAttribute("aria-hidden","true");
  }
  function setRiskScore(score){
    const s=clamp(Math.round(score||0),0,100);
    $("#riskMeterBar")?.style.setProperty("--score", s);
    const txt=$("#riskScoreText"); if(txt) txt.textContent=`Risk score: ${s}`;
  }
  function setRiskFactors(factors){
    const panel=$("#riskFactors"); if(!panel) return;
    if(!factors?.length){ panel.innerHTML=`<div class="muted small">No notable factors.</div>`; return; }
    panel.innerHTML = factors.map(f=>{
      const label = typeof f==="string" ? f : (f?.label || f?.reason || "Signal");
      const sev = (typeof f==="object" ? (f.severity||f.sev||"").toLowerCase() : "");
      const sevCls = sev==="high" ? "factor--high" : (sev.startsWith("med") ? "factor--med" : (sev==="low" ? "factor--low" : ""));
      const badge = sev ? `<span class="factor__badge">${sev.toUpperCase()}</span>` : "";
      return `<div class="factor ${sevCls}">${badge}<span>${label}</span></div>`;
    }).join("");
  }
  function setHighRisk(isHigh){ const w=$("#riskWarning"); if(w) w.style.display = isHigh ? "block" : "none"; onRiskAcknowledgeChange(); }
  function onRiskAcknowledgeChange(){ const warned=(($("#riskWarning")?.style.display)||"none")!=="none"; const agreed=$("#riskAgree")?.checked; setProceedEnabled(!warned||!!agreed); }
  function setProceedEnabled(en){ const b=$("#riskProceed"); if(b) b.disabled = !en; }

  async function fetchSafeSend(addr, chainKey){
    const url = `${CONFIG.SAFE_SEND_ORG}/check?address=${encodeURIComponent(addr)}&chain=${encodeURIComponent(chainKey)}`;
    const controller = new AbortController(); const t=setTimeout(()=>controller.abort("risk-timeout"),8000);
    try{
      const r=await fetch(url,{cache:"no-store",signal:controller.signal});
      if(!r.ok) throw new Error("SafeSend HTTP "+r.status);
      return await r.json();
    }catch(e){
      console.warn("SafeSend fallback", e);
      return { score: 35, decision: "allow", factors: [{severity:"low",label:"Risk service unavailable",reason:"Conservative default."}] };
    }finally{ clearTimeout(t); }
  }
  async function fetchEnrichment(addr, chainKey){
    const url = `${CONFIG.SAFE_SEND_ORG}/analytics?address=${encodeURIComponent(addr)}&chain=${encodeURIComponent(chainKey)}`;
    const controller = new AbortController(); const t=setTimeout(()=>controller.abort("analytics-timeout"),3000);
    try{
      const r=await fetch(url,{cache:"no-store",signal:controller.signal});
      if(!r.ok) return null;
      return await r.json();
    }catch{ return null; } finally{ clearTimeout(t); }
  }
  function mergeRisk(server, enrich){
    let score = Number(server?.score ?? 0);
    const factors = [...(server?.factors || [])];
    const ofac = server?.flags?.ofac || enrich?.sanctions?.hit;
    if(ofac){ score += 55; factors.push({label:"Sanctions watchlist match (OFAC)"}); }
    const mixer = server?.flags?.mixer || enrich?.exposures?.mixer;
    const scam  = server?.flags?.scam  || enrich?.exposures?.scam;
    if(mixer){ score += 20; factors.push({label:"Exposure to known mixers"}); }
    if(scam) { score += 25; factors.push({label:"Exposure to reported scam clusters"}); }
    const newAddr = server?.flags?.newAddr ?? (enrich?.heuristics?.ageDays !== undefined && enrich.heuristics.ageDays < 7);
    if(newAddr){ score += 8; factors.push({label:"Newly observed address"}); }
    return { score: clamp(Math.round(score),0,100), factors };
  }

  async function sendEthFlow(){
    const to = $("#sendTo")?.value.trim();
    const amt = $("#sendAmt")?.value.trim();
    if(!/^0x[a-fA-F0-9]{40}$/.test(to||"")) return alert("Invalid recipient address");
    const n = Number(amt); if(isNaN(n) || n<=0) return alert("Invalid amount");

    state.pendingTx = { to, amount:n };
    $("#sendOut").textContent = "Checking SafeSend…";
    openRiskModal();

    try{
      const server = await fetchSafeSend(to, state.chainKey);
      const enrich = await fetchEnrichment(to, state.chainKey);
      const result = mergeRisk(server, enrich);
      state.lastRisk = result;
      setRiskScore(result.score);
      setRiskFactors(result.factors);
      setHighRisk(result.score >= 70);
      $("#sendOut").textContent = `Risk score ${result.score}. ${result.score>=70?"High risk — acknowledgement required.":"You may proceed."}`;
    }catch(e){
      console.warn(e);
      state.lastRisk = { score: 35, factors: [{label:"Risk service timeout — default applied"}] };
      setRiskScore(35); setRiskFactors(state.lastRisk.factors); setHighRisk(false);
      $("#sendOut").textContent = "Risk check fallback applied.";
    }
  }
  async function doProceedAfterRisk(){
    const ctx = state.pendingTx;
    if(!ctx){ closeRiskModal(); return; }
    closeRiskModal();
    if (!await ensureEthersLoaded()) return alert("Ethers not loaded — sending disabled. Check CSP / network.");

    try{
      $("#sendOut").textContent = `Sending ${ctx.amount}…`;
      if (!provider) provider = new ethers.JsonRpcProvider(CONFIG.CHAINS[state.chainKey].rpc(CONFIG.ALCHEMY_KEY));
      const acct = state.accounts[state.signerIndex];
      if(!acct) throw new Error("No wallet selected");
      const signer = acct.wallet.connect(provider);
      const tx = { to: ctx.to, value: ethers.parseEther(String(ctx.amount)) };
      const fee = await provider.getFeeData();
      if (fee?.maxFeePerGas){ tx.maxFeePerGas = fee.maxFeePerGas; tx.maxPriorityFeePerGas = fee.maxPriorityFeePerGas; }
      try { tx.gasLimit = await signer.estimateGas(tx); } catch {}
      const sent = await signer.sendTransaction(tx);
      const ex = CONFIG.CHAINS[state.chainKey].explorer;
      $("#sendOut").innerHTML = `Broadcasted: <a target="_blank" href="${ex}/tx/${sent.hash}">${sent.hash}</a>`;
      await sent.wait(1);
      safe(loadRecentTxs);
      safe(()=>loadAddressTxs(ctx.to, "rxList"));
      safe(loadWalletBalances);
    }catch(e){
      $("#sendOut").textContent = "Error: " + (e?.message || e);
    }finally{
      state.pendingTx = null;
    }
  }

  /* =============== INIT & WIRING =============== */
  document.addEventListener("DOMContentLoaded", () => {
    dbg("boot complete (UI ready)");
    // top CTA
    $("#ctaLearn")?.addEventListener("click", ()=>alert("Docs/learn more coming soon."));
    $("#ctaApp")?.addEventListener("click", ()=>selectItem("dashboard"));

    // sidebar
    $$(".sidebar .item").forEach(el=>el.addEventListener("click", ()=>selectItem(el.dataset.view)));

    // lock
    $("#btnLock")?.addEventListener("click", ()=>{ lock(); alert("Locked"); });
    $("#btnUnlock")?.addEventListener("click", showLock);
    $("#cancelUnlock")?.addEventListener("click", hideLock);
    $("#doUnlock")?.addEventListener("click", async ()=>{
      try{
        const v = localStorage.getItem("xwallet_vault_v13");
        if(!v) return $("#unlockMsg").textContent="No vault found.";
        const pw=$("#unlockPassword").value;
        const payload=JSON.parse(v);
        if (!await ensureEthersLoaded()) return $("#unlockMsg").textContent="Ethers not loaded. Check CSP.";
        const phrase = await (async ()=>{ // decrypt
          const {ct,iv,salt} = payload.enc;
          const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), {name:"PBKDF2"}, false, ["deriveKey"]);
          const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:new Uint8Array(salt),iterations:100000,hash:"SHA-256"}, km, {name:"AES-GCM",length:256}, false, ["decrypt"]);
          const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(iv)}, key, new Uint8Array(ct));
          return new TextDecoder().decode(pt);
        })();
        state.decryptedPhrase = phrase;
        if (!localStorage.getItem("xwallet_accounts_n")) localStorage.setItem("xwallet_accounts_n","1");
        loadAccountsFromPhrase(phrase);
        setChain(state.chainKey);
        state.unlocked = true;
        const ls=$("#lockState"); if(ls) ls.textContent="Unlocked";
        hideLock(); scheduleAutoLock(); selectItem("dashboard");
      }catch(e){ $("#unlockMsg").textContent="Wrong password or corrupted vault."; console.error(e); }
    });

    // network select + initial render
    populateTopNetworkSelect();
    setChain(state.chainKey);
    selectItem("dashboard");

    // risk modal
    wireRiskModal();
  });

})();
