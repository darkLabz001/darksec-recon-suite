package report

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/audit"
)

// htmlPage is the template of the standalone report.
var htmlPage = template.Must(template.New("report").Funcs(template.FuncMap{
	"severityClass": func(s string) string {
		switch strings.ToLower(s) {
		case "critical":
			return "critical"
		case "high":
			return "high"
		case "medium":
			return "medium"
		case "low":
			return "low"
		default:
			return "info"
		}
	},
	"upper": strings.ToUpper,
	"add":   func(a, b int) int { return a + b },
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wyrm report · {{.Source}}</title>
<style>
:root {
  --bg: #0b1220; --panel: #111a2e; --panel-2: #0f172a; --border: #1e293b;
  --text: #e2e8f0; --muted: #64748b; --accent: #34d399; --accent-dim: #10b981;
  --red: #f87171; --amber: #fbbf24; --blue: #60a5fa; --violet: #a78bfa;
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0; color: var(--text); font-family: var(--sans); font-size: 14px;
  background: radial-gradient(1200px 600px at 80% -10%, #14243d 0%, var(--bg) 55%);
  min-height: 100vh;
}
header { padding: 20px 26px; border-bottom: 1px solid var(--border); background: rgba(11,18,32,.6); }
.logo { font-family: var(--mono); font-weight: 700; font-size: 22px; letter-spacing: -.5px;
  background: linear-gradient(90deg, var(--accent), var(--blue)); -webkit-background-clip: text; background-clip: text; color: transparent; }
.sub { color: var(--muted); font-family: var(--mono); font-size: 12px; margin-top: 4px; }
main { max-width: 1200px; margin: 0 auto; padding: 20px; display: grid; gap: 16px; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 0 0 12px; font-weight: 600; }
.stats { display: flex; gap: 26px; flex-wrap: wrap; align-items: center; }
.stat { display: flex; flex-direction: column; align-items: center; min-width: 68px; }
.stat-num { font-family: var(--mono); font-size: 22px; font-weight: 700; }
.stat-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
.stat.critical .stat-num { color: var(--red); }
.stat.high .stat-num { color: #fb923c; }
.stat.medium .stat-num { color: var(--amber); }
.stat.low .stat-num { color: var(--blue); }
.stat.info .stat-num { color: var(--muted); }
.grade { font-family: var(--mono); font-size: 44px; font-weight: 800; color: var(--accent); }
table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 13px; }
thead th { text-align: left; padding: 8px 10px; color: var(--muted); font-weight: 500;
  font-size: 11px; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid var(--border); }
tbody td { padding: 7px 10px; border-bottom: 1px solid rgba(30,41,59,.5); white-space: nowrap; }
tbody tr:hover { background: rgba(52,211,153,.05); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; }
.badge.critical { background: rgba(248,113,113,.16); color: var(--red); }
.badge.high { background: rgba(251,146,60,.16); color: #fb923c; }
.badge.medium { background: rgba(251,191,36,.16); color: var(--amber); }
.badge.low { background: rgba(96,165,250,.16); color: var(--blue); }
.badge.info { background: rgba(100,116,139,.18); color: var(--muted); }
.badge.ok { background: rgba(52,211,153,.15); color: var(--accent); }
.finding { border: 1px solid var(--border); border-radius: 10px; margin-bottom: 10px; overflow: hidden; }
.finding-head { display: flex; gap: 10px; align-items: center; padding: 10px 12px; background: var(--panel-2); cursor: pointer; }
.finding-head .id { font-family: var(--mono); font-size: 12px; color: var(--muted); }
.finding-head .title { font-weight: 600; }
.finding-body { padding: 12px 14px; display: none; border-top: 1px solid var(--border); }
.finding.open .finding-body { display: block; }
.finding-body p { margin: 0 0 8px; line-height: 1.6; }
.finding-body .k { color: var(--muted); font-family: var(--mono); font-size: 12px; }
.finding-body .mono { font-family: var(--mono); font-size: 12px; color: var(--muted); word-break: break-all; }
.chip { display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 11px; background: rgba(167,139,250,.15); color: var(--violet); margin-right: 6px; }
.empty { padding: 26px; text-align: center; color: var(--muted); }
</style>
</head>
<body>
<header>
  <div class="logo">wyrm</div>
  <div class="sub">wireless security audit · {{.Version.Version}} · {{.Source}}</div>
</header>
<main>
  <section class="panel">
    <h2>Verdict</h2>
    <div class="stats">
      <div class="grade">{{.Summary.Grade}}</div>
      <div class="stat"><span class="stat-num">{{.Summary.Findings}}</span><span class="stat-label">findings</span></div>
      <div class="stat critical"><span class="stat-num">{{.Summary.Counts.critical}}</span><span class="stat-label">critical</span></div>
      <div class="stat high"><span class="stat-num">{{.Summary.Counts.high}}</span><span class="stat-label">high</span></div>
      <div class="stat medium"><span class="stat-num">{{.Summary.Counts.medium}}</span><span class="stat-label">medium</span></div>
      <div class="stat low"><span class="stat-num">{{.Summary.Counts.low}}</span><span class="stat-label">low</span></div>
      <div class="stat info"><span class="stat-num">{{.Summary.Counts.info}}</span><span class="stat-label">info</span></div>
      <div class="stat"><span class="stat-num">{{.Summary.APs}}</span><span class="stat-label">access points</span></div>
      <div class="stat"><span class="stat-num">{{.Summary.Clients}}</span><span class="stat-label">clients</span></div>
      <div class="stat"><span class="stat-num">{{.Stats.Packets}}</span><span class="stat-label">packets</span></div>
    </div>
    <p style="margin:14px 0 0;color:var(--muted)">{{.Summary.Verdict}}.</p>
  </section>

  <section class="panel">
    <h2>Access points</h2>
    {{if .AccessPoints}}
    <table>
      <thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>Security</th><th>AKM</th><th>Ciphers</th><th>PMF</th><th>Grade</th></tr></thead>
      <tbody>
      {{range .AccessPoints}}
        <tr>
          <td>{{if .SSID}}{{.SSID}}{{else}}&lt;hidden&gt;{{end}}</td>
          <td>{{.BSSID}}</td>
          <td>{{.Channel}}</td>
          <td>{{.Security.Label}}</td>
          <td>{{range .Security.AKMs}}<span class="chip">{{.}}</span>{{end}}</td>
          <td>{{range .Security.Ciphers}}<span class="chip">{{.}}</span>{{end}}</td>
          <td>{{if .Security.MFPR}}required{{else if .Security.MFPC}}capable{{else}}none{{end}}</td>
          <td>{{.Security.Grade}} ({{.Security.Score}})</td>
        </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<div class="empty">No access points were seen.</div>{{end}}
  </section>

  <section class="panel">
    <h2>Findings</h2>
    {{if .Findings}}
      {{range .Findings}}
      <div class="finding" onclick="this.classList.toggle('open')">
        <div class="finding-head">
          <span class="badge {{severityClass .Severity}}">{{upper .Severity}}</span>
          <span class="id">{{.ID}}</span>
          <span class="title">{{.Title}}</span>
        </div>
        <div class="finding-body">
          {{if .Target}}<p><span class="k">target:</span> <span class="mono">{{.Target}}</span>{{if .Target2}} <span class="k">against</span> <span class="mono">{{.Target2}}</span>{{end}}</p>{{end}}
          <p>{{.Detail}}</p>
          {{if .Evidence}}<p><span class="k">evidence:</span> <span class="mono">{{.Evidence}}</span></p>{{end}}
          {{if .Remedy}}<p><span class="k">remedy:</span> {{.Remedy}}</p>{{end}}
          <p><span class="k">family:</span> {{.Family}}{{if .At}} <span class="k">at</span> <span class="mono">{{.At}}</span>{{end}}</p>
        </div>
      </div>
      {{end}}
    {{else}}<div class="empty">Nothing was reported.</div>{{end}}
  </section>

  {{if .SAE}}
  <section class="panel">
    <h2>SAE handshakes</h2>
    <table>
      <thead><tr><th>Station</th><th>Access point</th><th>Group</th><th>Rating</th><th>Commits</th><th>Confirms</th><th>Token</th><th>Validation</th></tr></thead>
      <tbody>
      {{range .SAE}}
        <tr>
          <td>{{.Client}}</td><td>{{.BSSID}}</td><td>{{.Group}} ({{.GroupID}})</td><td>{{.Rating}}</td>
          <td>{{.Commits}}</td><td>{{.Confirms}}</td><td>{{if .AntiClog}}yes{{else}}no{{end}}</td>
          <td>{{if .Valid}}<span class="badge ok">valid</span>{{else}}<span class="badge critical">invalid</span>{{end}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
  </section>
  {{end}}

  {{if .Handshakes}}
  <section class="panel">
    <h2>WPA2 handshakes</h2>
    <table>
      <thead><tr><th>Station</th><th>Access point</th><th>Messages</th><th>PMKID</th></tr></thead>
      <tbody>
      {{range .Handshakes}}
        <tr><td>{{.Client}}</td><td>{{.BSSID}}</td><td>{{.Messages}} of 4</td><td>{{if .PMKID}}{{.PMKID}}{{else}}—{{end}}</td></tr>
      {{end}}
      </tbody>
    </table>
  </section>
  {{end}}

  {{if .EAPPwd}}
  <section class="panel">
    <h2>EAP-pwd exchanges</h2>
    <table>
      <thead><tr><th>Station</th><th>Server</th><th>Group</th><th>Rating</th><th>Reflection</th></tr></thead>
      <tbody>
      {{range .EAPPwd}}
        <tr><td>{{.Client}}</td><td>{{.Server}}</td><td>{{.Group}} ({{.GroupID}})</td><td>{{.Rating}}</td>
        <td>{{if .Reflect}}<span class="badge critical">yes</span>{{else}}<span class="badge ok">no</span>{{end}}</td></tr>
      {{end}}
      </tbody>
    </table>
  </section>
  {{end}}

  <section class="panel">
    <h2>Capture statistics</h2>
    <table>
      <tbody>
        <tr><td>packets</td><td>{{.Stats.Packets}}</td><td>bytes</td><td>{{.Stats.Bytes}}</td></tr>
        <tr><td>management</td><td>{{.Stats.Management}}</td><td>data</td><td>{{.Stats.Data}}</td></tr>
        <tr><td>beacons</td><td>{{.Stats.Beacons}}</td><td>probe requests</td><td>{{.Stats.ProbeRequests}}</td></tr>
        <tr><td>authentications</td><td>{{.Stats.Auths}}</td><td>associations</td><td>{{.Stats.Assocs}}</td></tr>
        <tr><td>deauthentications</td><td>{{.Stats.Deauths}}</td><td>disassociations</td><td>{{.Stats.Disassocs}}</td></tr>
        <tr><td>SAE commits</td><td>{{.Stats.SAECommits}}</td><td>SAE confirms</td><td>{{.Stats.SAEConfirms}}</td></tr>
        <tr><td>EAPOL frames</td><td>{{.Stats.EAPOLFrames}}</td><td>handshakes</td><td>{{.Stats.Handshakes}}</td></tr>
        <tr><td>ARP</td><td>{{.Stats.ARPPackets}}</td><td>DHCP</td><td>{{.Stats.DHCPPackets}}</td></tr>
        <tr><td>duration</td><td>{{.Stats.Duration}}</td><td>source</td><td>{{.Source}}</td></tr>
      </tbody>
    </table>
  </section>
</main>
</body>
</html>
`))

// HTML renders the report as a self contained HTML page.
func HTML(s *audit.Session) (string, error) {
	var b strings.Builder
	if err := htmlPage.Execute(&b, Build(s)); err != nil {
		return "", fmt.Errorf("report: rendering the page: %w", err)
	}
	return b.String(), nil
}
