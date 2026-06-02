"use strict";

const PAGE_SIZE = 50;
const state = {
  statuses: {},
  severities: [],
  filters: { q: "", status: "", keyword: "", severity: "", sort: "published" },
  offset: 0,
  total: 0,
};

// ---------- helpers ----------
const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, children = []) => {
  const node = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  });
  (Array.isArray(children) ? children : [children]).forEach((c) => {
    if (c != null) node.append(c.nodeType ? c : document.createTextNode(c));
  });
  return node;
};

async function api(path, options) {
  const resp = await fetch("/api" + path, options);
  if (!resp.ok) {
    const detail = await resp.json().catch(() => ({}));
    throw new Error(detail.detail || resp.statusText);
  }
  return resp.status === 204 ? null : resp.json();
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 2500);
}

function fmtDate(iso) {
  if (!iso) return "-";
  return iso.slice(0, 10);
}

function sevClass(sev) {
  return "sev-" + (sev || "UNKNOWN");
}

// ---------- stats / chips ----------
async function loadStats() {
  const stats = await api("/stats");
  state.statuses = stats.statuses;
  state.severities = stats.severities;
  $("#last-polled").textContent = stats.last_polled_at
    ? "最終チェック: " + stats.last_polled_at.slice(0, 16).replace("T", " ") + " UTC"
    : "未チェック";
  renderChips(stats);
  populateFilterSelects();
}

function renderChips(stats) {
  const chips = $("#status-chips");
  chips.innerHTML = "";
  chips.append(chipNode("すべて", "", stats.total));
  Object.entries(state.statuses).forEach(([code, label]) => {
    chips.append(chipNode(label, code, stats.by_status[code] || 0));
  });
}

function chipNode(label, code, count) {
  const active = state.filters.status === code;
  return el("button", {
    class: "chip" + (active ? " active" : ""),
    onclick: () => {
      state.filters.status = code;
      $("#f-status").value = code;
      state.offset = 0;
      refresh();
    },
  }, [label, el("span", { class: "count" }, String(count))]);
}

function populateFilterSelects() {
  fillSelect($("#f-status"), [["", "ステータス: すべて"], ...Object.entries(state.statuses)]);
  fillSelect($("#f-severity"), [["", "深刻度: すべて"], ...state.severities.map((s) => [s, s])]);
  $("#f-status").value = state.filters.status;
}

function fillSelect(select, pairs) {
  select.innerHTML = "";
  pairs.forEach(([value, label]) => select.append(el("option", { value }, label)));
}

async function loadWatchOptions() {
  const watches = await api("/watches");
  fillSelect($("#f-keyword"), [["", "ワード: すべて"], ...watches.map((w) => [w.keyword, w.keyword])]);
  $("#f-keyword").value = state.filters.keyword;
}

// ---------- cve table ----------
function queryString() {
  const f = state.filters;
  const p = new URLSearchParams({ sort: f.sort, limit: PAGE_SIZE, offset: state.offset });
  ["q", "status", "keyword", "severity"].forEach((k) => f[k] && p.set(k, f[k]));
  return p.toString();
}

async function refresh() {
  const data = await api("/cves?" + queryString());
  state.total = data.total;
  renderRows(data.items);
  renderPager();
  loadStats(); // keep chip counts fresh
}

function renderRows(items) {
  const tbody = $("#cve-rows");
  tbody.innerHTML = "";
  $("#cve-empty").classList.toggle("hidden", items.length > 0);
  items.forEach((cve) => tbody.append(rowNode(cve)));
}

function rowNode(cve) {
  const sev = cve.cvss_severity || "UNKNOWN";
  const kw = el("td", {}, cve.keywords.map((k) => el("span", { class: "kw-tag" }, k)));
  const tr = el("tr", { onclick: (e) => { if (e.target.tagName !== "SELECT") openModal(cve.id); } }, [
    el("td", {}, el("span", { class: "sev-badge " + sevClass(sev) }, sev)),
    el("td", { class: "cve-id" }, cve.id),
    el("td", {}, cve.cvss_score != null ? String(cve.cvss_score) : "-"),
    el("td", {}, fmtDate(cve.published)),
    kw,
    el("td", {}, statusSelect(cve)),
  ]);
  return tr;
}

function statusSelect(cve) {
  const select = el("select", {
    class: "status-select status-" + cve.status,
    onchange: async (e) => {
      await api("/cves/" + cve.id, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: e.target.value }),
      });
      e.target.className = "status-select status-" + e.target.value;
      toast(cve.id + " を更新しました");
      loadStats();
    },
  });
  Object.entries(state.statuses).forEach(([code, label]) => {
    const opt = el("option", { value: code }, label);
    if (code === cve.status) opt.selected = true;
    select.append(opt);
  });
  return select;
}

function renderPager() {
  const from = state.total === 0 ? 0 : state.offset + 1;
  const to = Math.min(state.offset + PAGE_SIZE, state.total);
  $("#page-info").textContent = `${from}-${to} / ${state.total} 件`;
  $("#prev-btn").disabled = state.offset === 0;
  $("#next-btn").disabled = to >= state.total;
}

// ---------- detail modal ----------
async function openModal(cveId) {
  const cve = await api("/cves/" + cveId);
  $("#modal-content").innerHTML = "";
  $("#modal-content").append(modalContent(cve));
  $("#modal").classList.remove("hidden");
  location.hash = "#/cve/" + cveId;
}

function closeModal() {
  $("#modal").classList.add("hidden");
  if (location.hash.startsWith("#/cve/")) history.replaceState(null, "", location.pathname);
}

function modalContent(cve) {
  const sev = cve.cvss_severity || "UNKNOWN";
  const refs = cve.references.length
    ? el("ul", { class: "refs" }, cve.references.map((u) => el("li", {}, el("a", { href: u, target: "_blank" }, u))))
    : el("p", { class: "muted" }, "参照リンクなし");
  return el("div", {}, [
    el("h2", {}, cve.id),
    metaRow("深刻度", el("span", { class: "sev-badge " + sevClass(sev) }, sev)),
    metaRow("CVSS", cve.cvss_score != null ? String(cve.cvss_score) : "-"),
    metaRow("公開日", fmtDate(cve.published)),
    metaRow("更新日", fmtDate(cve.last_modified)),
    metaRow("該当ワード", cve.keywords.join(", ") || "-"),
    el("p", { class: "label" }, "説明"),
    el("div", { class: "desc" }, cve.description || "(説明なし)"),
    el("p", { class: "label" }, "参照"),
    refs,
    el("a", { href: "https://nvd.nist.gov/vuln/detail/" + cve.id, target: "_blank", class: "muted" }, "NVD で開く ↗"),
    el("hr", {}),
    editForm(cve),
  ]);
}

function metaRow(label, value) {
  return el("div", { class: "meta-row" }, [el("span", { class: "label" }, label), value]);
}

function editForm(cve) {
  const statusSel = el("select", { class: "status-select", id: "modal-status" });
  Object.entries(state.statuses).forEach(([code, label]) => {
    const opt = el("option", { value: code }, label);
    if (code === cve.status) opt.selected = true;
    statusSel.append(opt);
  });
  const note = el("textarea", { id: "modal-note", placeholder: "メモ" }, cve.note || "");
  const save = el("button", {
    class: "btn",
    onclick: () => saveDetail(cve.id),
  }, "保存");
  return el("div", {}, [
    el("p", { class: "label" }, "ステータス / メモ"),
    statusSel,
    el("div", { style: "height:8px" }),
    note,
    el("div", { class: "modal-actions" }, [save]),
  ]);
}

async function saveDetail(cveId) {
  await api("/cves/" + cveId, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: $("#modal-status").value, note: $("#modal-note").value }),
  });
  toast(cveId + " を保存しました");
  closeModal();
  refresh();
}

// ---------- watches ----------
async function loadWatches() {
  const watches = await api("/watches");
  const list = $("#watch-list");
  list.innerHTML = "";
  watches.forEach((w) => list.append(watchNode(w)));
}

function watchNode(w) {
  const toggle = el("input", {
    type: "checkbox",
    onchange: async (e) => {
      await api("/watches/" + w.id, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: e.target.checked }),
      });
      loadWatches();
      loadWatchOptions();
    },
  });
  if (w.enabled) toggle.checked = true;
  const del = el("button", { class: "btn danger", onclick: () => deleteWatch(w.id) }, "削除");
  return el("li", {}, [
    el("span", { class: "kw" + (w.enabled ? "" : " disabled-kw") }, w.keyword),
    el("div", { class: "actions" }, [el("label", {}, [toggle, " 有効"]), del]),
  ]);
}

async function addWatch(e) {
  e.preventDefault();
  const input = $("#watch-input");
  const keyword = input.value.trim();
  if (!keyword) return;
  try {
    await api("/watches", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ keyword }),
    });
    input.value = "";
    toast("「" + keyword + "」を追加しました");
    loadWatches();
    loadWatchOptions();
  } catch (err) {
    toast(err.message);
  }
}

async function deleteWatch(id) {
  if (!confirm("この監視ワードを削除しますか?")) return;
  await api("/watches/" + id, { method: "DELETE" });
  loadWatches();
  loadWatchOptions();
}

// ---------- wiring ----------
function switchTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  $("#tab-cves").classList.toggle("hidden", name !== "cves");
  $("#tab-watches").classList.toggle("hidden", name !== "watches");
  if (name === "watches") loadWatches();
}

function wireEvents() {
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => switchTab(t.dataset.tab)));
  $("#f-q").addEventListener("input", debounce((e) => { state.filters.q = e.target.value; state.offset = 0; refresh(); }, 300));
  ["status", "keyword", "severity", "sort"].forEach((k) => {
    $("#f-" + k).addEventListener("change", (e) => { state.filters[k] = e.target.value; state.offset = 0; refresh(); });
  });
  $("#prev-btn").addEventListener("click", () => { state.offset = Math.max(0, state.offset - PAGE_SIZE); refresh(); });
  $("#next-btn").addEventListener("click", () => { state.offset += PAGE_SIZE; refresh(); });
  $("#modal-close").addEventListener("click", closeModal);
  $("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });
  $("#watch-form").addEventListener("submit", addWatch);
  $("#poll-btn").addEventListener("click", triggerPoll);
}

async function triggerPoll() {
  const btn = $("#poll-btn");
  btn.disabled = true;
  await api("/poll", { method: "POST" });
  toast("チェックを開始しました（バックグラウンド実行）");
  setTimeout(() => { btn.disabled = false; loadStats(); refresh(); }, 4000);
}

function debounce(fn, ms) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}

async function init() {
  wireEvents();
  await loadStats();
  await loadWatchOptions();
  await refresh();
  const m = location.hash.match(/^#\/cve\/(.+)$/);
  if (m) openModal(m[1]).catch(() => {});
}

init();
