"use strict";

const $ = (id) => document.getElementById(id);

let severityFilter = "all";
let apFilter = "";
let startedAt = null;

function fmtSeverity(sev) {
  return (sev || "").toUpperCase();
}

function setStatus(running, text) {
  $("status-dot").classList.toggle("running", running);
  $("status-text").textContent = text;
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function loadInfo() {
  try {
    const res = await fetch("/api/info");
    const info = await res.json();
    $("version").textContent = "v" + info.version.version;

    const select = $("interface");
    select.innerHTML = "";
    const ifaces = info.interfaces || [];
    if (ifaces.length === 0) {
      const opt = el("option", null, "no wireless interface found");
      opt.value = "";
      select.appendChild(opt);
    } else {
      for (const name of ifaces) {
        const opt = el("option", null, name);
        opt.value = name;
        select.appendChild(opt);
      }
    }
    if (!info.root) {
      const warn = $("monitor-warn");
      warn.classList.remove("hidden");
      warn.textContent =
        "The auditor is not running as root, so the capture needs the sudo password " +
        "below or a passwordless sudo. Monitor mode also needs it.";
    }
  } catch (err) {
    setStatus(false, "the interface could not be reached");
  }
}

function renderStats(state) {
  $("s-grade").textContent = state.grade || "—";
  const counts = state.counts || {};
  $("s-findings").textContent = (state.findings || []).length;
  $("s-critical").textContent = counts.critical || 0;
  $("s-high").textContent = counts.high || 0;
  $("s-medium").textContent = counts.medium || 0;
  $("s-low").textContent = counts.low || 0;
  $("s-aps").textContent = (state.access_points || []).length;
  $("s-clients").textContent = state.stats && state.stats.clients ? state.stats.clients : 0;
  $("s-packets").textContent = state.stats ? state.stats.packets : 0;

  const started = state.started ? new Date(state.started) : null;
  const ended = state.ended ? new Date(state.ended) : null;
  if (started) {
    startedAt = started;
    const end = ended || new Date();
    $("s-elapsed").textContent = Math.max(0, Math.round((end - started) / 1000)) + "s";
  } else {
    $("s-elapsed").textContent = "0s";
  }
}

function renderAPs(aps) {
  const body = $("aps-body");
  body.innerHTML = "";
  const list = (aps || []).filter((ap) => {
    if (!apFilter) return true;
    const hay = (ap.ssid || "").toLowerCase() + " " + (ap.bssid || "").toLowerCase() +
      " " + (ap.security || "").toLowerCase();
    return hay.includes(apFilter);
  });

  $("aps-empty").classList.toggle("hidden", list.length > 0);
  $("aps-empty").textContent = (aps || []).length === 0
    ? "Start a capture to see access points."
    : "No access point matches the filter.";

  for (const ap of list) {
    const tr = document.createElement("tr");
    const ssid = el("td", null, ap.hidden ? "<hidden>" : (ap.ssid || "<hidden>"));
    tr.appendChild(ssid);
    tr.appendChild(el("td", null, ap.bssid));
    tr.appendChild(el("td", null, ap.channel));
    tr.appendChild(el("td", null, ap.security));
    const pmf = el("td", null, ap.mfpr ? "required" : (ap.mfpc ? "capable" : "none"));
    if (!ap.mfpr) pmf.className = "dim";
    tr.appendChild(pmf);
    tr.appendChild(el("td", null, ap.grade + " (" + ap.score + ")"));
    body.appendChild(tr);
  }
}

function renderFindings(findings) {
  const host = $("findings");
  const list = (findings || []).filter((f) => {
    if (severityFilter === "all") return true;
    return f.severity === severityFilter;
  });

  host.innerHTML = "";
  if (list.length === 0) {
    const empty = el("div", "empty", (findings || []).length === 0
      ? "Start a capture to see findings."
      : "No finding matches the filter.");
    empty.id = "findings-empty";
    host.appendChild(empty);
    return;
  }

  for (const f of list) {
    const wrap = el("div", "finding");
    const head = el("div", "finding-head");
    head.appendChild(el("span", "badge " + f.severity, fmtSeverity(f.severity)));
    head.appendChild(el("span", "id", f.id));
    head.appendChild(el("span", "title", f.title));
    head.addEventListener("click", () => wrap.classList.toggle("open"));
    wrap.appendChild(head);

    const body = el("div", "finding-body");
    if (f.target) {
      const p = el("p");
      p.appendChild(el("span", "k", "target: "));
      p.appendChild(el("span", "mono", f.target));
      body.appendChild(p);
    }
    const detail = el("p", null, f.detail || "");
    body.appendChild(detail);
    if (f.evidence) {
      const p = el("p");
      p.appendChild(el("span", "k", "evidence: "));
      p.appendChild(el("span", "mono", f.evidence));
      body.appendChild(p);
    }
    if (f.remedy) {
      const p = el("p");
      p.appendChild(el("span", "k", "remedy: "));
      p.appendChild(document.createTextNode(f.remedy));
      body.appendChild(p);
    }
    const fam = el("p");
    fam.appendChild(el("span", "badge family", f.family));
    body.appendChild(fam);

    wrap.appendChild(body);
    host.appendChild(wrap);
  }
}

function renderCounters(stats) {
  const host = $("counters");
  host.innerHTML = "";
  if (!stats) return;
  const rows = [
    ["packets", stats.packets], ["bytes", stats.bytes],
    ["management", stats.management], ["data", stats.data],
    ["beacons", stats.beacons], ["probe requests", stats.probe_requests],
    ["authentications", stats.authentications], ["associations", stats.associations],
    ["deauthentications", stats.deauthentications], ["disassociations", stats.disassociations],
    ["channel switches", stats.channel_switch_announcements],
    ["SAE commits", stats.sae_commits], ["SAE confirms", stats.sae_confirms],
    ["EAPOL frames", stats.eapol_frames], ["handshakes", stats.handshakes],
    ["ARP", stats.arp_packets], ["DHCP", stats.dhcp_packets], ["DNS", stats.dns_packets],
  ];
  for (const [name, value] of rows) {
    const chip = el("div", "counter");
    chip.appendChild(el("b", null, String(value ?? 0)));
    chip.appendChild(document.createTextNode(" " + name));
    host.appendChild(chip);
  }
}

function applyState(state) {
  if (!state) return;
  renderStats(state);
  renderAPs(state.access_points);
  renderFindings(state.findings);
  renderCounters(state.stats);

  $("start-btn").disabled = state.running;
  $("stop-btn").disabled = !state.running;
  if (state.running) {
    setStatus(true, "capturing");
  } else if (state.error) {
    setStatus(false, "failed: " + state.error);
  } else if (state.started) {
    setStatus(false, "finished");
  } else {
    setStatus(false, "idle");
  }
}

async function startCapture(ev) {
  ev.preventDefault();
  $("form-error").textContent = "";

  const savePcap = $("save-pcap").checked;
  const payload = {
    interface: $("interface").value,
    channels: $("channels").value,
    hop: $("hop").checked,
    hop_interval_ms: parseInt($("hop-interval").value || "250", 10),
    monitor: $("monitor").checked,
    filter: $("filter").value,
    output: savePcap ? ($("output").value || "wyrm-capture.pcap") : "",
    sudo_password: $("sudo").value,
    duration_s: parseInt($("duration").value || "0", 10),
  };

  try {
    const res = await fetch("/api/capture", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (!res.ok) {
      $("form-error").textContent = body.error || "the capture could not be started";
      return;
    }
    $("sudo").value = "";
    applyState(body.state);
  } catch (err) {
    $("form-error").textContent = String(err);
  }
}

async function stopCapture() {
  try {
    await fetch("/api/stop", { method: "POST" });
  } catch (err) {
    /* the page keeps polling anyway */
  }
}

function connect() {
  const source = new EventSource("/api/events");
  source.onmessage = (ev) => {
    try {
      const payload = JSON.parse(ev.data);
      if (payload.type === "state" || payload.type === "start" || payload.type === "done") {
        applyState(payload.state);
      } else if (payload.type === "log" && payload.error) {
        $("form-error").textContent = payload.error;
      } else if (payload.error) {
        $("form-error").textContent = payload.error;
      }
    } catch (err) {
      /* ignore a malformed frame */
    }
  };
  source.onerror = () => {
    /* the browser reconnects on its own */
  };
}

$("capture-form").addEventListener("submit", startCapture);
$("stop-btn").addEventListener("click", stopCapture);
$("ap-filter").addEventListener("input", (ev) => {
  apFilter = ev.target.value.trim().toLowerCase();
  fetch("/api/state").then((r) => r.json()).then(applyState);
});

for (const chip of document.querySelectorAll("#sev-chips .chip")) {
  chip.addEventListener("click", () => {
    for (const other of document.querySelectorAll("#sev-chips .chip")) {
      other.classList.remove("active");
    }
    chip.classList.add("active");
    severityFilter = chip.dataset.sev;
    fetch("/api/state").then((r) => r.json()).then(applyState);
  });
}

loadInfo();
connect();
setInterval(() => {
  if (startedAt && !$("stop-btn").disabled) {
    $("s-elapsed").textContent = Math.round((Date.now() - startedAt.getTime()) / 1000) + "s";
  }
}, 1000);
