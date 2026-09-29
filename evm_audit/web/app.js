// Front end for every evm-audit layer. No framework, no build step.
//
// Untrusted text (contract names, function names, decoded values, source
// comments) is only ever set with textContent -- never innerHTML -- so a
// contract cannot inject markup into the page that is reading it.

const VISIBLE_APPROVAL_STATUSES = new Set(["unlimited", "operator", "active", "unreadable"]);

const EXAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract Vault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;

    function initialize(address o) external {
        owner = o;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] = 0;
    }

    function sharePrice() external view returns (uint256) {
        return IERC20(address(this)).balanceOf(address(this)) * 1e18 / totalSupply;
    }

    function isOwner() external view returns (bool) {
        return tx.origin == owner;
    }

    function pay(IERC20 token, address to) external {
        token.transfer(to, 1);
    }
}
`;

const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------ elements
function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.class) node.className = opts.class;
  if (opts.text != null) node.textContent = String(opts.text);
  if (opts.type) node.type = opts.type;
  for (const child of children) node.append(child);
  return node;
}

function chip(text, kind) {
  return el("span", { class: "chip" + (kind ? " " + kind : ""), text });
}

function section(title) {
  return el("h2", { class: "section", text: title });
}

function chipsRow(pairs) {
  const row = el("div", { class: "summary" });
  for (const [text, kind] of pairs) {
    if (text === undefined || text === null || text === "") continue;
    row.append(chip(text, kind));
  }
  return row;
}

function kvTable(pairs) {
  const table = el("table", { class: "kv" });
  for (const [key, value] of pairs) {
    if (value === undefined || value === null || value === "") continue;
    const shown = Array.isArray(value) ? value.join(", ") : value;
    const tr = el("tr");
    tr.append(el("td", { class: "k", text: key }), el("td", { text: shown }));
    table.append(tr);
  }
  return table;
}

function dataTable(columns, rows) {
  const table = el("table");
  const head = el("tr");
  for (const col of columns) head.append(el("th", { text: col.label ?? col.key ?? col }));
  table.append(head);
  for (const row of rows) {
    const tr = el("tr");
    for (const col of columns) {
      const key = col.key ?? col;
      let value = row[key];
      if (Array.isArray(value)) value = value.join(" ");
      if (value === null || value === undefined) value = "";
      tr.append(el("td", { text: value }));
    }
    table.append(tr);
  }
  return table;
}

function findingCard(f) {
  const level = f.level || "info";
  const card = el("div", { class: "finding " + level });
  const head = el("div", { class: "finding-head" });
  head.append(
    el("span", { class: "finding-level", text: String(level).toUpperCase() }),
    el("span", { class: "finding-rule", text: f.rule || f.status || "" }),
    el("span", { class: "finding-loc", text: f.file ? `${f.file}:${f.line}` : (f.line || "") })
  );
  card.append(head, el("p", { class: "finding-msg", text: f.message }));
  return card;
}

function findingsBlock(title, items, out) {
  out.append(section(`${title} (${items.length})`));
  if (!items.length) {
    out.append(el("p", { class: "empty", text: "none — which is not a clean bill of health" }));
  }
  for (const f of items) out.append(findingCard(f));
}

function showError(out, message) {
  out.replaceChildren(el("div", { class: "error", text: message }));
}

// Save/Copy JSON, attached under whichever output just produced a result.
function safeName(name) {
  return String(name).replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 60) || "evm-audit";
}

function downloadJson(text, filename) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const link = el("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function setResultActions(out, result) {
  let bar = out.nextElementSibling;
  if (!bar || !bar.classList.contains("result-actions")) {
    bar = el("div", { class: "result-actions" });
    out.after(bar);
  }
  const json = JSON.stringify(result, null, 2);
  const base = result.target || result.address || result.selector || "evm-audit";
  const filename = `${safeName(base)}.json`;

  bar.replaceChildren();
  bar.hidden = false;

  const save = el("button", { class: "secondary", type: "button", text: "Save JSON" });
  save.addEventListener("click", () => downloadJson(json, filename));

  const copy = el("button", { class: "secondary", type: "button", text: "Copy JSON" });
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(json);
      copy.textContent = "Copied";
    } catch {
      copy.textContent = "Copy failed";
    }
    setTimeout(() => { copy.textContent = "Copy JSON"; }, 1200);
  });

  bar.append(save, copy);
}

function hideResultActions(out) {
  const bar = out.nextElementSibling;
  if (bar && bar.classList.contains("result-actions")) bar.hidden = true;
}

function loading(out, message = "working…") {
  out.replaceChildren(el("p", { class: "hint", text: message }));
}

// ------------------------------------------------------------------- network
async function request(url, options) {
  const res = await fetch(url, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}

function post(path, payload) {
  return request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

// -------------------------------------------------------------------- source
function contractBlock(file, ct) {
  const details = el("details", { class: "contract" });
  const base = ct.bases && ct.bases.length ? ` is ${ct.bases.join(", ")}` : "";
  details.append(el("summary", {
    text: `${ct.name} (${ct.kind})${base}  —  ${file}:${ct.line}`,
  }));

  const body = el("div", { class: "body" });
  if (ct.functions && ct.functions.length) {
    const table = el("table");
    table.append(el("tr", {}, [
      el("th", { text: "function" }), el("th", { text: "visibility" }),
      el("th", { text: "mutability" }), el("th", { text: "modifiers" }),
      el("th", { text: "line" }),
    ]));
    for (const fn of ct.functions) {
      table.append(el("tr", {}, [
        el("td", { text: `${fn.name}(${fn.params || ""})` }),
        el("td", { text: fn.visibility || "-" }),
        el("td", { text: fn.mutability || "-" }),
        el("td", { text: (fn.modifiers || []).join(" ") || "-" }),
        el("td", { text: fn.line }),
      ]));
    }
    body.append(table);
  }
  if (ct.stateVariables && ct.stateVariables.length) {
    const table = el("table");
    table.append(el("tr", {}, [
      el("th", { text: "state variable" }), el("th", { text: "type" }),
      el("th", { text: "visibility" }), el("th", { text: "line" }),
    ]));
    for (const v of ct.stateVariables) {
      table.append(el("tr", {}, [
        el("td", { text: v.name }), el("td", { text: v.type }),
        el("td", { text: (v.visibility || "-") + (v.constant ? " constant" : "") }),
        el("td", { text: v.line }),
      ]));
    }
    body.append(table);
  }
  if (!body.childElementCount) body.append(el("p", { class: "empty", text: "no members parsed" }));
  details.append(body);
  return details;
}

function renderSource(report, out) {
  out.replaceChildren();
  const s = report.summary || {};
  const counts = report.counts || {};
  out.append(
    chipsRow([
      [report.kind, ""], [`${s.files || 0} files`, ""], [`${s.contracts || 0} contracts`, ""],
      [`${s.functions || 0} functions`, ""], [`${s.state_variables || 0} state vars`, ""],
    ]),
    chipsRow([
      [`${counts.high || 0} high`, "high"], [`${counts.notable || 0} notable`, "notable"],
      [`${counts.info || 0} info`, "info"],
    ])
  );

  for (const note of report.notes || []) out.append(el("p", { class: "note", text: note }));

  const astFacts = report.ast_facts || [];
  const abi = report.abi_signatures || [];
  if (astFacts.length || abi.length) {
    out.append(section("structural facts (no source text)"));
    const list = el("ul", { class: "card" });
    for (const fact of astFacts) list.append(el("li", { text: fact }));
    out.append(list);
    if (abi.length) {
      out.append(section("ABI functions"));
      out.append(dataTable([{ key: "selector" }, { key: "signature" }], abi));
    }
  }

  findingsBlock("findings", report.findings || [], out);

  const contracts = [];
  for (const file of report.files || []) {
    for (const ct of file.contracts || []) contracts.push({ file: file.path, ct });
  }
  if (contracts.length) {
    out.append(section("contracts"));
    for (const item of contracts) out.append(contractBlock(item.file, item.ct));
  }

  if ((report.not_checked || []).length) {
    out.append(section("not checked"));
    const list = el("ul", { class: "card" });
    for (const item of report.not_checked) list.append(el("li", { text: item }));
    out.append(list);
  }
  out.append(el("p", { class: "hint", text: "Findings are places to look, not a verdict." }));
}

// ------------------------------------------------------------------ bytecode
function renderFeatures(data, out) {
  out.replaceChildren();
  const f = data.features || {};
  out.append(chipsRow([
    [data.target, ""], [`${f.code_size ?? "?"} bytes`, ""],
    [`${f.instruction_count ?? "?"} instructions`, ""],
    [`${(f.function_selectors || []).length} selectors`, ""],
    [f.is_minimal_proxy ? "minimal proxy" : (f.proxy_like ? "proxy-like" : ""), "notable"],
  ]));

  findingsBlock("signals", f.risk_signals || [], out);

  out.append(section("features"));
  out.append(kvTable([
    ["code size", f.code_size], ["stripped size", f.stripped_size],
    ["instructions", f.instruction_count], ["jumpdests", f.jumpdest_count],
    ["pushes", f.push_count], ["unknown opcodes", f.unknown_opcode_count],
    ["entropy (bits/byte)", f.bytecode_entropy], ["delegatecall", f.delegatecall_count],
    ["storage writes", f.storage_writes], ["storage reads", f.storage_reads],
    ["create ops", f.create_ops], ["logs", f.log_count],
    ["minimal proxy target", f.minimal_proxy_target],
    ["eip-1967 slots", (f.eip1967_slots || []).join(", ")],
  ]));

  if (f.metadata && (f.metadata.solc || f.metadata.ipfs)) {
    out.append(kvTable([["solc", f.metadata.solc], ["ipfs", f.metadata.ipfs]]));
  }
  if (f.external_calls) {
    out.append(section("external calls"));
    out.append(kvTable(Object.entries(f.external_calls)));
  }
  if ((f.function_selectors || []).length) {
    out.append(section(`function selectors (${f.function_selectors.length})`));
    const list = el("div", { class: "card mono", text: f.function_selectors.join("  ") });
    out.append(list);
  }
  if ((f.audit_notes || []).length) {
    out.append(section("why these opcodes matter"));
    out.append(dataTable(
      [{ key: "opcode" }, { key: "count" }, { key: "note" }], f.audit_notes
    ));
  }
}

function renderDisasm(data, out) {
  out.replaceChildren();
  out.append(chipsRow([
    [data.target, ""], [`${data.rawSize} raw bytes`, ""],
    [`${data.instructionCount} instructions`, ""],
    [data.metadata && data.metadata.solc ? `solc ${data.metadata.solc}` : "", ""],
  ]));
  out.append(el("pre", { class: "disasm", text: (data.instructions || []).join("\n") }));
  if (data.truncated) {
    out.append(el("p", { class: "hint", text: `... ${data.truncated} more instructions not shown` }));
  }
}

function renderResolve(info, out) {
  out.replaceChildren();
  out.append(chipsRow([[info.kind, ""], [info.address, ""]]));
  out.append(kvTable([
    ["kind", info.kind], ["implementation", info.implementation],
    ["beacon", info.beacon], ["admin", info.admin],
  ]));
  if (info.implementationFeaturesError) {
    out.append(el("p", { class: "note", text: `implementation features failed: ${info.implementationFeaturesError}` }));
  }
  if (info.implementationFeatures) {
    out.append(section("implementation features"));
    const child = el("div");
    out.append(child);
    renderFeatures({ target: info.implementation, features: info.implementationFeatures }, child);
  }
}

// -------------------------------------------------------------------- decode
function renderCalldata(result, out) {
  out.replaceChildren();
  if (result.error) {
    showError(out, result.error);
    return;
  }
  out.append(chipsRow([
    [result.selector, ""], [result.signature || "unknown signature", ""],
    [result.label || "", ""],
  ]));
  if ((result.args || []).length) {
    out.append(section("arguments"));
    out.append(dataTable(
      [{ key: "name" }, { key: "type" }, { key: "value" }], result.args
    ));
  }
  findingsBlock("findings", result.findings || [], out);
}

function renderSelectors(data, out) {
  out.replaceChildren();
  out.append(dataTable([{ key: "selector" }, { key: "signature" }], data.selectors || []));
}

// ---------------------------------------------------------------------- sign
function renderTypedData(result, out) {
  out.replaceChildren();
  const domain = result.domain || {};
  out.append(chipsRow([
    [result.primaryType, ""], [result.digest || "", ""], [result.signer || "", ""],
  ]));
  out.append(section("domain"));
  out.append(kvTable([
    ["name", domain.name], ["version", domain.version],
    ["chainId", domain.chainId], ["verifyingContract", domain.verifyingContract],
  ]));
  if ((result.fields || []).length) {
    out.append(section("message"));
    out.append(dataTable([{ key: "path" }, { key: "value" }], result.fields));
  }
  findingsBlock(
    "findings",
    [...(result.findings || []), ...(result.eip712_findings || [])],
    out
  );
}

function renderEip712(info, out) {
  out.replaceChildren();
  out.append(chipsRow([
    [info.address, ""],
    [`node chainId ${info.node_chain_id ?? "?"}`, ""],
    info.match === true ? "separator matches" : (info.match === false ? "MISMATCH" : "not comparable"),
    info.match === false ? "high" : "",
  ]));
  out.append(kvTable([
    ["declaration", info.declaration_source],
    ["declared name", (info.declared_domain || {}).name],
    ["declared version", (info.declared_domain || {}).version],
    ["declared chainId", (info.declared_domain || {}).chainId],
    ["on-chain separator", info.onchain_separator],
    ["recomputed separator", info.recomputed_separator],
    ["extensions", info.extensions],
  ]));
  findingsBlock("findings", info.findings || [], out);
}

// ----------------------------------------------------------------- approvals
function renderAllowances(report, out) {
  out.replaceChildren();
  const blocks = report.blocks || [];
  out.append(chipsRow([
    [report.owner, ""],
    [`chain ${report.chainId ?? "?"}`, ""],
    [`blocks ${blocks[0]}..${blocks[1]}`, ""],
    [`${report.tokensScanned} tokens`, ""],
    [report.permit2 ? `permit2 ${report.permit2.status}` : "", ""],
  ]));

  const rows = (report.rows || []).filter((r) => VISIBLE_APPROVAL_STATUSES.has(r.status));
  const hidden = (report.rows || []).length - rows.length;
  findingsBlock("exposure", rows, out);
  if (hidden > 0) {
    out.append(el("p", { class: "hint", text: `${hidden} revoked/expired/self row(s) hidden.` }));
  }

  const counts = report.counts || {};
  if (Object.keys(counts).length) {
    out.append(section("counts"));
    out.append(kvTable(Object.entries(counts)));
  }
  if (report.unreadable) {
    out.append(el("p", { class: "note", text: "'unreadable' is not 'revoked'. Those states were not read." }));
  }
  out.append(el("p", {
    class: "hint",
    text: `Bounded by the scanned range and token list. Approvals before block ${blocks[0]} or on unlisted tokens are invisible here.`,
  }));
}

// ------------------------------------------------------------------ handlers
async function withOutput(outId, buttonId, loader, call, render) {
  const out = $(outId);
  const button = $(buttonId);
  if (button) button.disabled = true;
  loading(out, loader);
  hideResultActions(out);
  try {
    const result = await call();
    render(result, out);
    setResultActions(out, result);
  } catch (err) {
    showError(out, err.message);
  } finally {
    if (button) button.disabled = false;
  }
}

document.querySelectorAll(".navbtn").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

function switchView(name) {
  for (const btn of document.querySelectorAll(".navbtn")) {
    btn.classList.toggle("active", btn.dataset.view === name);
  }
  for (const view of document.querySelectorAll(".view")) {
    view.classList.toggle("active", view.id === `view-${name}`);
  }
}

$("analyze").addEventListener("click", () => withOutput(
  "src-out", "analyze", "reading…",
  () => post("/api/analyze", { source: $("src-text").value, name: ($("src-name").value || "Pasted.sol").trim() }),
  renderSource
));
$("clear-src").addEventListener("click", () => {
  $("src-text").value = "";
  $("src-out").replaceChildren();
  $("src-text").focus();
});
$("load-example").addEventListener("click", () => {
  $("src-name").value = "Vault.sol";
  $("src-text").value = EXAMPLE;
  switchView("source");
  $("analyze").click();
});

const bc = () => ({ target: $("bc-target").value.trim(), raw: $("bc-raw").checked });
$("bc-features").addEventListener("click", () => withOutput(
  "bc-out", "bc-features", "reading…", () => post("/api/features", bc()), renderFeatures
));
$("bc-disasm").addEventListener("click", () => withOutput(
  "bc-out", "bc-disasm", "disassembling…", () => post("/api/disasm", bc()), renderDisasm
));
$("bc-resolve").addEventListener("click", () => withOutput(
  "bc-out", "bc-resolve", "resolving…",
  () => request(`/api/resolve?target=${encodeURIComponent($("bc-target").value.trim())}&features=1`),
  renderResolve
));

$("cd-run").addEventListener("click", () => withOutput(
  "cd-out", "cd-run", "decoding…", () => post("/api/calldata", { data: $("cd-data").value.trim() }), renderCalldata
));
$("sel-run").addEventListener("click", () => withOutput(
  "sel-out", "sel-run", "deriving…", () => post("/api/selector", { signatures: $("sel-sigs").value }), renderSelectors
));

$("td-run").addEventListener("click", () => withOutput(
  "td-out", "td-run", "decoding…",
  () => post("/api/typed-data", {
    payload: $("td-payload").value,
    signature: $("td-signature").value.trim(),
    signer: $("td-signer").value.trim(),
    checkDomain: $("td-domain").checked,
  }),
  renderTypedData
));
$("ep-run").addEventListener("click", () => withOutput(
  "ep-out", "ep-run", "checking…",
  () => post("/api/eip712", {
    target: $("ep-target").value.trim(),
    name: $("ep-name").value.trim(),
    version: $("ep-version").value.trim(),
    chainId: $("ep-chain").value.trim(),
  }),
  renderEip712
));

$("al-run").addEventListener("click", () => withOutput(
  "al-out", "al-run", "scanning logs and re-reading state… this can take a while",
  () => post("/api/allowances", {
    owner: $("al-owner").value.trim(),
    tokens: $("al-tokens").value.trim(),
    lookback: $("al-lookback").value.trim() || "5000",
    maxCalls: $("al-maxcalls").value.trim() || "1200",
  }),
  renderAllowances
));

function markAllowancesUnavailable(info) {
  const note = "Not available on this deployment: the allowance scan needs a "
    + "long-lived server (many eth_getLogs calls). Run `python -m evm_audit "
    + "serve` locally, or use the CLI.";
  const nav = document.querySelector('.navbtn[data-view="approvals"]');
  if (nav) {
    nav.disabled = true;
    nav.title = note;
  }
  const run = $("al-run");
  if (run) run.disabled = true;
  const status = $("al-status");
  if (status) status.textContent = "not available on this deployment";

  const view = $("view-approvals");
  if (view && !view.querySelector(".deploy-note")) {
    view.prepend(el("p", { class: "note deploy-note", text: note }));
  }
}

request("/api/health")
  .then((info) => {
    $("version").textContent = info.version ? `v${info.version}` : "";
    if (info.allowances === false) markAllowancesUnavailable(info);
  })
  .catch(() => {});
