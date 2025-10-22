// worker.js — SafeSend risk service (Alchemy-only, multi-chain, OFAC hard block, Scam cluster >=60)

// ---------------- CORS ----------------
function corsHeaders(origin) {
  const allow = origin || "https://agethejedi.github.io"; // adjust if you deploy elsewhere
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Content-Type": "application/json; charset=utf-8",
    "Vary": "Origin",
  };
}

// ---------------- utils ----------------
const isHexAddr = (s) => /^0x[a-fA-F0-9]{40}$/.test(s);
function clamp(n, lo, hi){ return Math.max(lo, Math.min(hi, n)); }
function nowMs(){ return Date.now(); }
function parseCSVSecret(v){
  if (!v) return [];
  return String(v)
    .split(/[,\s]+/)
    .map(x => x.trim().toLowerCase())
    .filter(Boolean);
}
function severityWeight(sev){
  switch(String(sev).toLowerCase()){
    case "critical": return 60; // >=60 alone
    case "high":     return 35;
    case "med":
    case "medium":   return 15;
    default:         return 5;  // low
  }
}
function scoreFromFactors(factors){
  const s = factors.reduce((sum,f)=> sum + severityWeight(f.severity||"low"), 0);
  return clamp(s, 0, 100);
}
function decisionFromScore(score){
  if (score >= 80) return "block";
  if (score >= 60) return "review";
  return "allow";
}

// ---------------- Alchemy RPC ----------------
function chainToAlchemyUrl(env, chain){
  const c = (chain || "sepolia").toLowerCase();
  if (c === "sepolia")  return env.ALCHEMY_SEPOLIA_URL;
  if (c === "mainnet")  return env.ALCHEMY_MAINNET_URL;
  if (c === "base")     return env.ALCHEMY_BASE_URL;
  if (c === "polygon")  return env.ALCHEMY_POLYGON_URL;
  if (c === "optimism") return env.ALCHEMY_OPTIMISM_URL;
  if (c === "arbitrum") return env.ALCHEMY_ARBITRUM_URL;
  return env.ALCHEMY_SEPOLIA_URL;
}

async function rpc(url, method, params = [], timeoutMs = 8000) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`rpc_http_${res.status}`);
  const j = await res.json();
  if (j.error) throw new Error(`rpc_${method}_${j.error.code}:${j.error.message}`);
  return j.result;
}

async function getCode(url, address) {
  // eth_getCode returns "0x" for EOAs, bytecode hex for contracts
  return rpc(url, "eth_getCode", [address, "latest"]);
}

async function getTransfers(url, address, { limit = 50 } = {}) {
  const base = {
    fromBlock: "0x0",
    toBlock: "latest",
    category: ["external"], // ETH transfers only (extend if desired)
    withMetadata: true,
    excludeZeroValue: false,
    maxCount: "0x" + Math.max(1, Math.min(limit, 100)).toString(16),
    order: "desc",
  };

  const [outRes, inRes] = await Promise.all([
    rpc(url, "alchemy_getAssetTransfers", [{ ...base, fromAddress: address }]).catch(() => ({ transfers: [] })),
    rpc(url, "alchemy_getAssetTransfers", [{ ...base, toAddress: address }]).catch(() => ({ transfers: [] })),
  ]);

  const out = outRes?.transfers || [];
  const inn = inRes?.transfers || [];

  const all = [...out, ...inn].map(t => ({
    hash: t.hash,
    from: (t.from || "").toLowerCase(),
    to: (t.to || "").toLowerCase(),
    valueEth: typeof t.value === "number" ? t.value : (t.value ? Number(t.value) : 0),
    tsMs: t.metadata?.blockTimestamp ? Date.parse(t.metadata.blockTimestamp) : 0,
  }));

  all.sort((a, b) => b.tsMs - a.tsMs);
  return all.slice(0, limit);
}

// ---------------- Heuristics ----------------
async function runHeuristics({ address, ens, chain, amountEth, env }) {
  const alchemyUrl = chainToAlchemyUrl(env, chain);
  const lower = address.toLowerCase();
  const factors = [];

  if (!alchemyUrl) {
    factors.push({ label: "Config", severity: "high", reason: "Missing Alchemy URL for selected chain" });
    return { factors, score: scoreFromFactors(factors), decision: decisionFromScore(scoreFromFactors(factors)) };
  }

  // Parse lists from env (CSV/whitespace), lowercase
  const badlist      = parseCSVSecret(env.BADLIST);
  const badEns       = parseCSVSecret(env.BAD_ENS);
  const ofacList     = parseCSVSecret(env.OFAC_SET);
  const scamClusters = parseCSVSecret(env.SCAM_CLUSTERS);

  const inList = (list, v) => v && list.includes(String(v).toLowerCase());

  // 0) OFAC => immediate block (score 100, single critical factor)
  if (inList(ofacList, lower) || (ens && inList(ofacList, ens))) {
    const f = [{ label: "OFAC match", severity: "critical", reason: "Address/ENS is on OFAC sanctions list" }];
    return { factors: f, score: 100, decision: "block" };
  }

  // 1) Scam cluster => critical factor (>= 60 score by itself)
  if (inList(scamClusters, lower) || (ens && inList(scamClusters, ens))) {
    factors.push({ label: "Scam cluster", severity: "critical", reason: "Address/ENS appears in known scam clusters" });
  }

  // 2) Internal lists
  if (inList(badlist, lower)) {
    factors.push({ label: "Badlist", severity: "critical", reason: "Address appears on internal blocklist" });
  }
  if (ens && inList(badEns, ens)) {
    factors.push({ label: "ENS", severity: "high", reason: `ENS name flagged (${ens})` });
  }

  // 3) Contract code check
  try {
    const code = await getCode(alchemyUrl, address);
    if (typeof code === "string" && code !== "0x") {
      factors.push({ label: "Contract", severity: "med", reason: "Address is a contract (eth_getCode != 0x)" });
    }
  } catch (e) {
    factors.push({ label: "RPC", severity: "low", reason: `eth_getCode failed: ${e.message || e}` });
  }

  // 4) Transfers analysis (Alchemy)
  let transfers = [];
  try {
    transfers = await getTransfers(alchemyUrl, address, { limit: 50 });
  } catch (e) {
    factors.push({ label: "RPC", severity: "low", reason: `Transfers fetch failed: ${e.message || e}` });
  }

  if (transfers.length === 0) {
    factors.push({ label: "Activity", severity: "med", reason: "No on-chain transfer history" });
  } else {
    const latest = transfers[0];
    const ageMin = (nowMs() - (latest.tsMs || 0)) / 60000;
    if (ageMin < 60) {
      factors.push({ label: "Fresh activity", severity: "low", reason: "Recent transfer in the last hour" });
    }
    const in1h = transfers.filter(t => nowMs() - t.tsMs <= 60 * 60 * 1000);
    if (in1h.length >= 10) {
      factors.push({ label: "Bursting", severity: "med", reason: `High activity: ${in1h.length} transfers in last hour` });
    }
    const dust = isFinite(Number(env.DUST_THRESHOLD)) ? Number(env.DUST_THRESHOLD) : 0.001; // ETH
    const tinyOut = transfers.filter(t => t.from === lower && t.valueEth > 0 && t.valueEth <= dust).length;
    if (tinyOut >= 5) {
      factors.push({ label: "Dust spam", severity: "med", reason: `Multiple tiny outgoing transfers (${tinyOut})` });
    }
    if (amountEth && amountEth <= dust) {
      factors.push({ label: "Amount", severity: "low", reason: `Send amount <= dust threshold (${dust} ETH)` });
    }
  }

  const score = scoreFromFactors(factors);
  const decision = decisionFromScore(score);
  return { factors, score, decision };
}

// ---------------- Worker entry ----------------
export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "*";

    // Preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(origin) });
    }

    const url = new URL(req.url);

    // Health
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ ok: true, build: "safesend-alchemy-v1.5" }), {
        headers: corsHeaders(origin),
      });
    }

    // Main: /check
    if (url.pathname === "/check") {
      const address = (url.searchParams.get("address") || "").trim();
      const chain   = (url.searchParams.get("chain") || "sepolia").toLowerCase();
      const amount  = Number(url.searchParams.get("amount") || "0");
      const ens     = (url.searchParams.get("ens") || "").trim();

      if (!isHexAddr(address)) {
        return new Response(JSON.stringify({
          score: 0,
          decision: "allow",
          factors: [{ label: "Input", severity: "low", reason: "Invalid 0x address" }],
        }), { headers: corsHeaders(origin) });
      }

      let result = { score: 0, decision: "allow", factors: [] };
      try {
        result = await runHeuristics({ address, ens, chain, amountEth: amount, env });
      } catch (e) {
        result = {
          score: 10,
          decision: "allow",
          factors: [{ label: "Engine", severity: "low", reason: `Heuristics failed: ${e.message || e}` }]
        };
      }

      return new Response(JSON.stringify(result), {
        headers: corsHeaders(origin),
      });
    }

    // 404
    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: corsHeaders(origin),
    });
  },
};
