"use strict";

const $ = (sel) => document.querySelector(sel);

const state = {
  running: false,
  total: 0,
  counts: { open: 0, closed: 0, filtered: 0 },
  filter: "",
  stateFilter: new Set(["open"]),
  results: [], // resultJSON objects
  osResults: {}, // ip -> os result
  events: null,
};

const stateColors = {
  open: "open",
  closed: "closed",
  filtered: "filtered",
};

function fmtRtt(ms) {
  if (ms == null || ms === 0) return "";
  if (ms < 1) return (ms * 1000).toFixed(0) + "µs";
  if (ms < 1000) return ms.toFixed(2) + "ms";
  return (ms / 1000).toFixed(2) + "s";
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
}

function detailMarkup(r) {
  const rows = [];
  if (r.service) rows.push(["service", r.service]);
  if (r.product) rows.push(["product", r.product]);
  if (r.version) rows.push(["version", r.version]);
  if (r.extra) rows.push(["extra", r.extra]);
  if (r.cpe) rows.push(["cpe", r.cpe]);
  if (r.method) rows.push(["method", r.method]);
  if (r.title) rows.push(["title", r.title]);
  if (r.server) rows.push(["server", r.server]);
  if (r.ja3) rows.push(["ja3", r.ja3]);
  if (r.ja3s) rows.push(["ja3s", r.ja3s]);
  if (r.favicon) rows.push(["favicon", r.favicon]);
  if (r.banner) rows.push(["banner", r.banner]);
  if (!rows.length) return "";
  return rows.map(([k, v]) => `<b>${k}</b>: ${esc(v)}`).join("<br>");
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function matches(r) {
  if (!state.stateFilter.has(r.state)) return false;
  if (!state.filter) return true;
  const hay = [r.ip, String(r.port), r.service, r.product, r.version, r.extra, r.banner]
    .filter(Boolean).join(" ").toLowerCase();
  return hay.includes(state.filter);
}

function renderResults() {
  const body = $("#results-body");
  body.textContent = "";
  const visible = state.results.filter(matches);
  $("#empty").classList.toggle("hidden", visible.length > 0);

  const frag = document.createDocumentFragment();
  for (const r of visible) {
    const tr = document.createElement("tr");

    const host = el("td", "", r.ip);
    const port = el("td", "", String(r.port));
    const proto = el("td", "");
    const protoBadge = el("span", "badge proto", r.protocol || "tcp");
    proto.appendChild(protoBadge);

    const st = el("td", "");
    const badge = el("span", "badge " + (stateColors[r.state] || ""), r.state);
    st.appendChild(badge);

    const service = el("td", "", r.service || "");
    const product = el("td", "", r.product || "");
    const version = el("td", "", r.version || "");
    const rtt = el("td", "dim", fmtRtt(r.rtt_ms));

    const toggleTd = el("td", "");
    const detail = detailMarkup(r);
    if (detail) {
      const btn = el("button", "detail-toggle", "▸");
      btn.title = "details";
      toggleTd.appendChild(btn);
    }

    tr.append(host, port, proto, st, service, product, version, rtt, toggleTd);
    frag.appendChild(tr);

    if (detail) {
      const dtr = document.createElement("tr");
      dtr.className = "detail-row hidden";
      const dtd = document.createElement("td");
      dtd.colSpan = 9;
      const div = el("div", "detail");
      div.innerHTML = detail;
      dtd.appendChild(div);
      dtr.appendChild(dtd);
      frag.appendChild(dtr);
      toggleTd.querySelector("button").addEventListener("click", () => {
        const open = !dtr.classList.contains("hidden");
        dtr.classList.toggle("hidden", open);
        btn.textContent = open ? "▸" : "▾";
      });
    }
  }
  body.appendChild(frag);
}

function renderStats() {
  $("#s-total").textContent = state.total;
  $("#s-open").textContent = state.counts.open;
  $("#s-closed").textContent = state.counts.closed;
  $("#s-filtered").textContent = state.counts.filtered;
  const done = state.counts.open + state.counts.closed + state.counts.filtered;
  const pct = state.total ? Math.min(100, (done / state.total) * 100) : 0;
  $("#progress-fill").style.width = pct.toFixed(1) + "%";
  $("#status-dot").classList.toggle("running", state.running);
  $("#status-text").textContent = state.running ? "scanning" : "idle";
  $("#start-btn").disabled = state.running;
  $("#stop-btn").disabled = !state.running;
}

function setElapsed(seconds) {
  $("#s-elapsed").textContent = (seconds == null ? 0 : seconds).toFixed(1) + "s";
}

function addResult(r) {
  if (r.os) {
    state.osResults[r.ip] = r.os;
    renderOS();
    return;
  }
  state.results.push(r);
  const counts = state.counts;
  if (r.state === "open") counts.open++;
  else if (r.state === "closed") counts.closed++;
  else if (r.state === "filtered") counts.filtered++;
}

function renderOS() {
  const box = $("#os-results");
  const entries = Object.entries(state.osResults);
  box.classList.toggle("hidden", entries.length === 0);
  box.textContent = "";
  for (const [ip, os] of entries) {
    const chip = document.createElement("div");
    chip.className = "os-chip";
    chip.appendChild(el("span", "os-ip", ip));
    chip.appendChild(el("span", "os-name", os.os || "unknown"));
    if (os.accuracy != null) chip.appendChild(el("span", "os-acc", os.accuracy + "%"));
    if (os.description) chip.appendChild(el("span", "os-desc", os.description));
    box.appendChild(chip);
  }
}

function applyStats(s) {
  if (s == null) return;
  if (s.total != null) state.total = s.total;
  if (s.open != null) state.counts.open = s.open;
  if (s.closed != null) state.counts.closed = s.closed;
  if (s.filtered != null) state.counts.filtered = s.filtered;
  setElapsed(s.elapsed_seconds);
}

function connectEvents() {
  if (state.events) state.events.close();
  state.events = new EventSource("/api/events");

  state.events.addEventListener("start", (e) => {
    const ev = JSON.parse(e.data);
    state.total = ev.total || 0;
    state.running = true;
    state.counts = { open: 0, closed: 0, filtered: 0 };
    state.results = [];
    state.osResults = {};
    renderResults();
    renderOS();
    renderStats();
  });

  state.events.addEventListener("result", (e) => {
    const ev = JSON.parse(e.data);
    if (ev.result) addResult(ev.result);
    renderResults();
    renderStats();
  });

  state.events.addEventListener("stats", (e) => {
    const ev = JSON.parse(e.data);
    applyStats(ev.stats);
    renderStats();
  });

  state.events.addEventListener("done", (e) => {
    const ev = JSON.parse(e.data);
    state.running = false;
    if (ev.error) {
      $("#form-error").textContent = ev.error;
    } else if (ev.stopped) {
      $("#form-error").textContent = "scan stopped";
    } else {
      $("#form-error").textContent = "";
    }
    renderStats();
  });

  state.events.onerror = () => {
    // EventSource reconnects automatically.
  };
}

async function fetchState() {
  try {
    const res = await fetch("/api/state");
    const data = await res.json();
    state.results = [];
    state.osResults = {};
    state.counts = { open: 0, closed: 0, filtered: 0 };
    for (const r of data.results || []) {
      if (r.os) {
        state.osResults[r.ip] = r.os;
        continue;
      }
      state.results.push(r);
      if (r.state === "open") state.counts.open++;
      else if (r.state === "closed") state.counts.closed++;
      else state.counts.filtered++;
    }
    applyStats(data.stats);
    state.running = !!(data.stats && data.stats.running);
    renderResults();
    renderOS();
    renderStats();
  } catch (_) {
    /* ignore */
  }
}

async function fetchInfo() {
  try {
    const res = await fetch("/api/info");
    const info = await res.json();
    $("#version").textContent = info.version
      ? `${info.version.version} (${info.version.commit})`
      : "";
    const syn = $("#engine option[value='syn']");
    syn.disabled = !info.syn_available;
    if (!info.syn_available) {
      syn.textContent = "syn (needs root)";
    }
  } catch (_) {
    /* ignore */
  }
}

async function startScan() {
  const targets = $("#targets").value.trim();
  const ports = $("#ports").value.trim();
  const topPorts = parseInt(document.querySelector("button[data-top].active")?.dataset?.top || "0", 10) || 0;

  $("#form-error").textContent = "";

  const body = {
    targets,
    ports: topPorts ? "" : ports,
    top_ports: topPorts,
    engine: $("#engine").value,
    detect: $("#detect").checked,
    os_detect: $("#os-detect").checked,
    ja3: $("#ja3").checked,
    favicon: $("#favicon").checked,
    show_all: $("#showall").checked,
    timeout_ms: parseInt($("#timeout").value, 10) || 1000,
    rate: parseFloat($("#rate").value) || 0,
    concurrency: parseInt($("#concurrency").value, 10) || 0,
    source_addr: $("#source-addr").value.trim(),
  };

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      $("#form-error").textContent = data.error || "scan failed";
      return;
    }
    state.running = true;
    state.results = [];
    state.counts = { open: 0, closed: 0, filtered: 0 };
    state.osResults = {};
    applyStats(data.stats);
    renderResults();
    renderOS();
    renderStats();
  } catch (err) {
    $("#form-error").textContent = String(err);
  }
}

async function stopScan() {
  try {
    await fetch("/api/stop", { method: "POST" });
  } catch (_) {
    /* ignore */
  }
}

function bindUI() {
  $("#scan-form").addEventListener("submit", (e) => {
    e.preventDefault();
    startScan();
  });
  $("#stop-btn").addEventListener("click", stopScan);

  document.querySelectorAll("button[data-top]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const active = btn.classList.contains("active");
      document.querySelectorAll("button[data-top]").forEach((b) => b.classList.remove("active"));
      if (!active) btn.classList.add("active");
      $("#ports").disabled = !!document.querySelector("button[data-top].active");
    });
  });

  $("#filter").addEventListener("input", () => {
    state.filter = $("#filter").value.toLowerCase();
    renderResults();
  });

  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const s = chip.dataset.state;
      if (state.stateFilter.has(s)) state.stateFilter.delete(s);
      else state.stateFilter.add(s);
      chip.classList.toggle("active", state.stateFilter.has(s));
      renderResults();
    });
  });
}

function init() {
  bindUI();
  fetchInfo();
  fetchState();
  connectEvents();
}

document.addEventListener("DOMContentLoaded", init);
