// OxBuy web page. No framework; everything from the server is rendered with textContent.

const LAYER = {
  agent: "Agent",
  pdp: "Policy (PDP)",
  gateway: "Gateway (PEP)",
  executor: "Executor",
  seller: "Seller's 402",
  chain: "Chain",
};

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};

async function api(path, body) {
  const res = await fetch(path, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : {});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `The server answered ${res.status}.`);
  return data;
}

// ── Playground ────────────────────────────────────────────────────────────

let scenarios = [];
let busy = false;

function renderScenarioList() {
  const list = $("scenarios");
  list.replaceChildren();
  for (const s of scenarios) {
    const li = el("li");
    const b = el("button", "scn");
    b.type = "button";
    b.dataset.id = s.id;
    b.setAttribute("aria-pressed", "false");
    b.append(el("span", "scn-title", s.title), el("span", "scn-exp", s.expected === "ALLOW" ? "should pay" : "should be refused"), el("span", "scn-sum", s.summary));
    b.addEventListener("click", () => runOne(s.id));
    li.append(b);
    list.append(li);
  }
}

function setBusy(on) {
  busy = on;
  for (const b of document.querySelectorAll(".scn, #run-all")) b.disabled = on;
}

function showTrace(r) {
  $("trace-empty").hidden = true;
  $("summary").hidden = true;
  $("trace-body").hidden = false;
  const v = $("verdict");
  v.dataset.d = r.decision;
  $("verdict-word").textContent = r.decision;
  $("verdict-reason").textContent = r.reason || (r.decision === "ALLOW" ? "paid exactly what was authorized" : "");
  const keys = $("f-keys");
  keys.textContent = String(r.keyReads);
  keys.classList.toggle("zero", r.keyReads === 0);
  $("f-transfers").textContent = String(r.transfers.length);
  $("f-layer").textContent = r.stoppedAt ? LAYER[r.stoppedAt] : "nothing";
  $("f-ms").textContent = `${r.ms} ms`;
  const rail = $("rail");
  rail.replaceChildren();
  r.steps.forEach((s, i) => {
    const li = el("li");
    if (s.verdict) li.dataset.v = s.verdict;
    li.style.animationDelay = `${i * 70}ms`;
    li.append(el("span", "who", LAYER[s.layer] || s.layer), el("span", "what", s.text));
    rail.append(li);
  });
  if (r.decision === "ALLOW" && r.transfers[0]) {
    const t = r.transfers[0];
    const li = el("li");
    li.style.animationDelay = `${r.steps.length * 70}ms`;
    li.append(el("span", "who", "Result"), el("span", "what", `${t.value} units to ${t.to.slice(0, 10)}…; nonce bound to the authorized intent: ${r.nonceBoundToIntent ? "yes" : "no"}`));
    rail.append(li);
  }
}

async function runOne(id) {
  if (busy) return;
  setBusy(true);
  for (const b of document.querySelectorAll(".scn")) b.setAttribute("aria-pressed", String(b.dataset.id === id));
  try {
    showTrace(await api("/api/scenario", { id }));
    if (window.matchMedia("(max-width: 899px)").matches) {
      const smooth = window.matchMedia("(prefers-reduced-motion: no-preference)").matches;
      $("trace").scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" });
    }
  } catch (e) {
    $("trace-body").hidden = true;
    $("summary").hidden = true;
    $("trace-empty").hidden = false;
    $("trace-empty").replaceChildren(el("p", "", e.message));
  } finally {
    setBusy(false);
  }
}

async function runAll() {
  if (busy) return;
  setBusy(true);
  for (const b of document.querySelectorAll(".scn")) b.setAttribute("aria-pressed", "false");
  $("trace-empty").hidden = true;
  $("trace-body").hidden = true;
  $("summary").hidden = false;
  const rows = $("summary-rows");
  rows.replaceChildren();
  try {
    for (const s of scenarios) {
      const r = await api("/api/scenario", { id: s.id });
      const tr = el("tr");
      tr.append(
        el("td", "", r.title),
        el("td", `d-${r.decision}`, r.decision),
        el("td", "", r.stoppedAt ? LAYER[r.stoppedAt] : "nothing"),
        el("td", "", String(r.keyReads)),
        el("td", "", String(r.transfers.length)),
      );
      rows.append(tr);
    }
  } catch (e) {
    const tr = el("tr");
    const td = el("td", "", e.message);
    td.colSpan = 5;
    tr.append(td);
    rows.append(tr);
  } finally {
    setBusy(false);
  }
}

// ── Live purchase ─────────────────────────────────────────────────────────

const usdc = (atomic) => (Number(atomic) / 1e6).toLocaleString("en", { maximumFractionDigits: 6 });

/** Minimal, safe rendering of the brief's markdown (headings, bullets, emphasis as plain text). */
function renderBrief(md) {
  const box = el("div", "brief");
  let ul = null;
  const strip = (s) => s.replace(/\*\*(.+?)\*\*/g, "$1").replace(/^_(.+)_$/, "$1");
  for (const raw of md.split("\n")) {
    const line = raw.trimEnd();
    if (!line) { ul = null; continue; }
    if (line.startsWith("# ")) { box.append(el("h3", "", strip(line.slice(2)))); ul = null; }
    else if (line.startsWith("## ")) { box.append(el("h4", "", strip(line.slice(3)))); ul = null; }
    else if (line.startsWith("- ")) {
      if (!ul) { ul = el("ul"); box.append(ul); }
      ul.append(el("li", "", strip(line.slice(2))));
    } else { box.append(el("p", "", strip(line))); ul = null; }
  }
  return box;
}

let liveInfo = null;

function setupLive(live) {
  const note = $("live-note");
  if (!live.enabled) {
    $("live-h").textContent = "Make one real purchase";
    note.textContent = `${live.why} The playground above still runs the full authorization and signing code.`;
    $("net-line").textContent = "Live purchases are turned off on this server.";
    return;
  }
  liveInfo = live;
  const net = live.mainnet ? "mainnet" : "testnet";
  const badge = el("span", "net-badge", live.mainnet ? "real money" : "testnet");
  badge.dataset.net = net;
  $("live-h").replaceChildren(document.createTextNode(`Make one real purchase on ${live.network}`), badge);
  note.replaceChildren(
    document.createTextNode(`The agent buys one search of recent X posts from the buy gateway (${usdc(live.price)} USDC${live.mainnet ? "" : ", testnet"}), then writes a short brief from them. The payment comes from the agent's wallet `),
    Object.assign(el("a", "", `${live.wallet.slice(0, 8)}…${live.wallet.slice(-6)}`), { href: live.walletUrl }),
    document.createTextNode(", never from yours."),
  );
  $("net-line").textContent = live.mainnet
    ? `Live purchases on this server spend real USDC on Celo mainnet, from a dedicated agent wallet with a small balance, one purchase per ${live.cooldownSeconds} s at most.`
    : "Live purchases on this server use Celo Sepolia (testnet).";
  if (live.requiresConfirmation) {
    $("confirm-row").hidden = false;
    $("confirm-text").textContent = `I understand this spends ${usdc(live.price)} USDC of real money from the OxBuy agent wallet on Celo mainnet.`;
  }
  $("live-form").hidden = false;
  updateRemaining(live.remaining, live.cooldownLeft);
  $("live-form").addEventListener("submit", onLive);
}

function updateRemaining(n, wait = 0) {
  const per = liveInfo && liveInfo.cooldownSeconds ? ` One purchase per ${liveInfo.cooldownSeconds} s across all visitors.` : "";
  $("live-hint").textContent = n > 0
    ? `${n} live purchase${n === 1 ? "" : "s"} left on this server.${per}${wait > 0 ? ` Next one possible in ${wait} s.` : ""} Takes about 10 to 30 seconds.`
    : "The live purchase allowance for this server is used up. The playground still works.";
  $("live-btn").disabled = n <= 0;
}

async function onLive(ev) {
  ev.preventDefault();
  const topic = $("topic").value.trim();
  const btn = $("live-btn");
  const out = $("live-out");
  const confirm = liveInfo && liveInfo.requiresConfirmation ? $("confirm").checked : undefined;
  if (confirm === false) {
    out.hidden = false;
    out.replaceChildren(el("p", "err", "Tick the confirmation first: this purchase spends real USDC."));
    return;
  }
  btn.disabled = true;
  btn.textContent = "Buying…";
  out.hidden = false;
  out.replaceChildren(el("p", "", `Authorizing, then paying on ${liveInfo ? liveInfo.network : "Celo"}…`));
  try {
    const r = await api("/api/live", confirm === undefined ? { topic } : { topic, confirm });
    const head = el("div", "verdict");
    head.dataset.d = r.decision;
    head.append(el("span", "verdict-word", r.decision), el("span", "verdict-reason", r.decision === "ALLOW" ? `paid ${usdc(r.amount)} USDC` : r.reason || ""));
    out.replaceChildren(head);
    if (r.tx) {
      const p = el("p", "live-tx");
      p.append(document.createTextNode("Transaction: "), Object.assign(el("a", "mono", r.tx), { href: r.txUrl }));
      out.append(p);
    }
    if (r.brief) out.append(renderBrief(r.brief));
    updateRemaining(r.remaining, liveInfo ? liveInfo.cooldownSeconds : 0);
    if (liveInfo && liveInfo.requiresConfirmation) $("confirm").checked = false;
  } catch (e) {
    out.replaceChildren(el("p", "err", e.message));
    btn.disabled = false;
  } finally {
    btn.textContent = "Buy the brief";
  }
}

// ── Start ─────────────────────────────────────────────────────────────────

$("run-all").addEventListener("click", runAll);
try {
  const st = await api("/api/status");
  scenarios = st.scenarios;
  renderScenarioList();
  setupLive(st.live);
  if (st.commit) $("commit").textContent = `Running commit ${st.commit}.`;
} catch (e) {
  $("scenarios").replaceChildren(el("li", "note", `The server did not answer: ${e.message} Reload the page in a minute; a sleeping free server takes up to a minute to wake.`));
  $("live-note").textContent = "Unavailable while the server is not answering.";
}
