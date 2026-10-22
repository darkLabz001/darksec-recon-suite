package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Rule matches a banner and extracts product, version and CPE information.
//
// A rule is applied to the raw bytes a service sent, which makes it useful
// both for protocol probers and for the generic banner fallback.
type Rule struct {
	// Name identifies the rule.
	Name string
	// Service is the canonical service name the rule applies to.
	Service string
	// Pattern selects the banner. The capture groups hold the product
	// and version text.
	Pattern *regexp.Regexp
	// Product is the canonical product name. When it is empty the
	// product is taken from the capture group selected by ProductGroup.
	Product string
	// ProductGroup is the capture group holding the product name. Zero
	// means the whole match.
	ProductGroup int
	// VersionGroup is the capture group holding the version.
	VersionGroup int
	// CPE is a Common Platform Enumeration template. The verb "%s" is
	// replaced by the detected version.
	CPE string
}

// builtInRules is the bundled fingerprint database.
var builtInRules = []Rule{
	{Name: "openssh", Service: "ssh", Pattern: regexp.MustCompile(`(?i)OpenSSH[_-]?([0-9][0-9A-Za-z.\-]*)`),
		Product: "OpenSSH", VersionGroup: 1, CPE: "cpe:2.3:a:openbsd:openssh:%s:*:*:*:*:*:*:*"},
	{Name: "dropbear", Service: "ssh", Pattern: regexp.MustCompile(`(?i)dropbear[_-]?([0-9][0-9A-Za-z.\-]*)`),
		Product: "Dropbear SSH", VersionGroup: 1, CPE: "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:%s:*:*:*:*:*:*:*"},
	{Name: "libssh", Service: "ssh", Pattern: regexp.MustCompile(`(?i)libssh[_-]?([0-9][0-9A-Za-z.\-]*)`),
		Product: "libssh", VersionGroup: 1, CPE: "cpe:2.3:a:libssh:libssh:%s:*:*:*:*:*:*:*"},
	{Name: "nginx", Service: "http", Pattern: regexp.MustCompile(`(?i)nginx[/ ]?([0-9][0-9.]*)`),
		Product: "nginx", VersionGroup: 1, CPE: "cpe:2.3:a:f5:nginx:%s:*:*:*:*:*:*:*"},
	{Name: "apache", Service: "http", Pattern: regexp.MustCompile(`(?i)Apache(?:[/ ])([0-9][0-9.]*)`),
		Product: "Apache HTTP Server", VersionGroup: 1, CPE: "cpe:2.3:a:apache:http_server:%s:*:*:*:*:*:*:*"},
	{Name: "apache2", Service: "http", Pattern: regexp.MustCompile(`(?i)Apache2/([0-9][0-9.]*)`),
		Product: "Apache HTTP Server", VersionGroup: 1, CPE: "cpe:2.3:a:apache:http_server:%s:*:*:*:*:*:*:*"},
	{Name: "iis", Service: "http", Pattern: regexp.MustCompile(`(?i)Microsoft-IIS/([0-9][0-9.]*)`),
		Product: "Microsoft IIS", VersionGroup: 1, CPE: "cpe:2.3:a:microsoft:internet_information_services:%s:*:*:*:*:*:*:*"},
	{Name: "lighttpd", Service: "http", Pattern: regexp.MustCompile(`(?i)lighttpd[/ ]([0-9][0-9.]*)`),
		Product: "lighttpd", VersionGroup: 1, CPE: "cpe:2.3:a:lighttpd_project:lighttpd:%s:*:*:*:*:*:*:*"},
	{Name: "caddy", Service: "http", Pattern: regexp.MustCompile(`(?i)Caddy[/ ]?([0-9][0-9.]*)`),
		Product: "Caddy", VersionGroup: 1, CPE: "cpe:2.3:a:caddyserver:caddy:%s:*:*:*:*:*:*:*"},
	{Name: "gunicorn", Service: "http", Pattern: regexp.MustCompile(`(?i)gunicorn/([0-9][0-9.]*)`),
		Product: "Gunicorn", VersionGroup: 1, CPE: "cpe:2.3:a:benoitc:gunicorn:%s:*:*:*:*:*:*:*"},
	{Name: "werkzeug", Service: "http", Pattern: regexp.MustCompile(`(?i)Werkzeug/([0-9][0-9.]*)`),
		Product: "Werkzeug", VersionGroup: 1, CPE: "cpe:2.3:a:pallets:werkzeug:%s:*:*:*:*:*:*:*"},
	{Name: "tomcat", Service: "http", Pattern: regexp.MustCompile(`(?i)(?:Apache-Coyote|Tomcat)[/ ]([0-9][0-9.]*)`),
		Product: "Apache Tomcat", VersionGroup: 1, CPE: "cpe:2.3:a:apache:tomcat:%s:*:*:*:*:*:*:*"},
	{Name: "jetty", Service: "http", Pattern: regexp.MustCompile(`(?i)Jetty\(([0-9][0-9.]*)`),
		Product: "Eclipse Jetty", VersionGroup: 1, CPE: "cpe:2.3:a:eclipse:jetty:%s:*:*:*:*:*:*:*"},
	{Name: "node", Service: "http", Pattern: regexp.MustCompile(`(?i)Express[/ ]([0-9][0-9.]*)`),
		Product: "Express", VersionGroup: 1, CPE: "cpe:2.3:a:expressjs:express:%s:*:*:*:*:*:*:*"},
	{Name: "squid", Service: "http", Pattern: regexp.MustCompile(`(?i)Squid[/ ]([0-9][0-9.]*)`),
		Product: "Squid", VersionGroup: 1, CPE: "cpe:2.3:a:squid-cache:squid:%s:*:*:*:*:*:*:*"},
	{Name: "varnish", Service: "http", Pattern: regexp.MustCompile(`(?i)Varnish[/ ]([0-9][0-9.]*)`),
		Product: "Varnish", VersionGroup: 1, CPE: "cpe:2.3:a:varnish-cache:varnish_cache:%s:*:*:*:*:*:*:*"},
	{Name: "haproxy", Service: "http", Pattern: regexp.MustCompile(`(?i)HAProxy[/ ]([0-9][0-9.]*)`),
		Product: "HAProxy", VersionGroup: 1, CPE: "cpe:2.3:a:haproxy:haproxy:%s:*:*:*:*:*:*:*"},
	{Name: "cloudflare", Service: "http", Pattern: regexp.MustCompile(`(?i)cloudflare-nginx`),
		Product: "Cloudflare", CPE: "cpe:2.3:a:cloudflare:cloudflare:*:*:*:*:*:*:*:*"},
	{Name: "php", Service: "http", Pattern: regexp.MustCompile(`(?i)PHP/([0-9][0-9.]*)`),
		Product: "PHP", VersionGroup: 1, CPE: "cpe:2.3:a:php:php:%s:*:*:*:*:*:*:*"},
	{Name: "python", Service: "http", Pattern: regexp.MustCompile(`(?i)Python/([0-9][0-9.]*)`),
		Product: "Python", VersionGroup: 1, CPE: "cpe:2.3:a:python:python:%s:*:*:*:*:*:*:*"},
	{Name: "go-http", Service: "http", Pattern: regexp.MustCompile(`(?i)Go-http-client/([0-9][0-9.]*)`),
		Product: "Go", VersionGroup: 1, CPE: "cpe:2.3:a:golang:go:%s:*:*:*:*:*:*:*"},
	{Name: "envoy", Service: "http", Pattern: regexp.MustCompile(`(?i)envoy`),
		Product: "Envoy", CPE: "cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"},
	{Name: "vsftpd", Service: "ftp", Pattern: regexp.MustCompile(`(?i)vsFTPd\s+([0-9][0-9.]*)`),
		Product: "vsftpd", VersionGroup: 1, CPE: "cpe:2.3:a:beasts:vsftpd:%s:*:*:*:*:*:*:*"},
	{Name: "proftpd", Service: "ftp", Pattern: regexp.MustCompile(`(?i)ProFTPD\s+([0-9][0-9.]*)`),
		Product: "ProFTPD", VersionGroup: 1, CPE: "cpe:2.3:a:proftpd:proftpd:%s:*:*:*:*:*:*:*"},
	{Name: "pure-ftpd", Service: "ftp", Pattern: regexp.MustCompile(`(?i)Pure-FTPd\s+([0-9][0-9.]*)`),
		Product: "Pure-FTPd", VersionGroup: 1, CPE: "cpe:2.3:a:pureftpd:pure-ftpd:%s:*:*:*:*:*:*:*"},
	{Name: "serv-u", Service: "ftp", Pattern: regexp.MustCompile(`(?i)Serv-U\s+([0-9][0-9.]*)`),
		Product: "Serv-U", VersionGroup: 1, CPE: "cpe:2.3:a:solarwinds:serv-u:%s:*:*:*:*:*:*:*"},
	{Name: "filezilla", Service: "ftp", Pattern: regexp.MustCompile(`(?i)FileZilla\s+(?:Server\s+)?([0-9][0-9.]*)`),
		Product: "FileZilla Server", VersionGroup: 1, CPE: "cpe:2.3:a:filezilla_project:filezilla_server:%s:*:*:*:*:*:*:*"},
	{Name: "exim", Service: "smtp", Pattern: regexp.MustCompile(`(?i)Exim\s+([0-9][0-9.]*)`),
		Product: "Exim", VersionGroup: 1, CPE: "cpe:2.3:a:exim:exim:%s:*:*:*:*:*:*:*"},
	{Name: "postfix", Service: "smtp", Pattern: regexp.MustCompile(`(?i)Postfix`),
		Product: "Postfix", CPE: "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"},
	{Name: "sendmail", Service: "smtp", Pattern: regexp.MustCompile(`(?i)Sendmail\s+([0-9][0-9.]*)`),
		Product: "Sendmail", VersionGroup: 1, CPE: "cpe:2.3:a:sendmail:sendmail:%s:*:*:*:*:*:*:*"},
	{Name: "microsoft-smtp", Service: "smtp", Pattern: regexp.MustCompile(`(?i)Microsoft ESMTP MAIL Server`),
		Product: "Microsoft Exchange Server", CPE: "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"},
	{Name: "dovecot", Service: "imap", Pattern: regexp.MustCompile(`(?i)Dovecot\s+([0-9][0-9.]*)`),
		Product: "Dovecot", VersionGroup: 1, CPE: "cpe:2.3:a:dovecot:dovecot:%s:*:*:*:*:*:*:*"},
	{Name: "courier", Service: "imap", Pattern: regexp.MustCompile(`(?i)Courier-IMAP\s+([0-9][0-9.]*)`),
		Product: "Courier IMAP", VersionGroup: 1, CPE: "cpe:2.3:a:courier:courier-imap:%s:*:*:*:*:*:*:*"},
	{Name: "cyrus", Service: "imap", Pattern: regexp.MustCompile(`(?i)Cyrus\s+IMAP\s+([0-9][0-9.]*)`),
		Product: "Cyrus IMAP", VersionGroup: 1, CPE: "cpe:2.3:a:cyrus:imapd:%s:*:*:*:*:*:*:*"},
	{Name: "mariadb", Service: "mysql", Pattern: regexp.MustCompile(`(?i)([0-9][0-9.]*)-MariaDB`),
		Product: "MariaDB", VersionGroup: 1, CPE: "cpe:2.3:a:mariadb:mariadb:%s:*:*:*:*:*:*:*"},
	{Name: "mysql", Service: "mysql", Pattern: regexp.MustCompile(`(?i)(?:^|\x0a|\x09)([0-9][0-9.]*)-`),
		Product: "MySQL", VersionGroup: 1, CPE: "cpe:2.3:a:oracle:mysql:%s:*:*:*:*:*:*:*"},
	{Name: "postgres", Service: "postgres", Pattern: regexp.MustCompile(`(?i)PostgreSQL\s+([0-9][0-9.]*)`),
		Product: "PostgreSQL", VersionGroup: 1, CPE: "cpe:2.3:a:postgresql:postgresql:%s:*:*:*:*:*:*:*"},
	{Name: "redis", Service: "redis", Pattern: regexp.MustCompile(`(?i)redis[^0-9]{0,12}([0-9][0-9A-Za-z.\-]*)`),
		Product: "Redis", VersionGroup: 1, CPE: "cpe:2.3:a:redis:redis:%s:*:*:*:*:*:*:*"},
	{Name: "memcached", Service: "memcached", Pattern: regexp.MustCompile(`(?i)VERSION\s+([0-9][0-9.]*)`),
		Product: "Memcached", VersionGroup: 1, CPE: "cpe:2.3:a:memcached:memcached:%s:*:*:*:*:*:*:*"},
	{Name: "mongodb", Service: "mongodb", Pattern: regexp.MustCompile(`"version"\s*:\s*"([0-9][0-9A-Za-z.\-]*)"`),
		Product: "MongoDB", VersionGroup: 1, CPE: "cpe:2.3:a:mongodb:mongodb:%s:*:*:*:*:*:*:*"},
	{Name: "elasticsearch", Service: "elasticsearch", Pattern: regexp.MustCompile(`(?i)"number"\s*:\s*"([0-9][0-9A-Za-z.\-]*)"`),
		Product: "Elasticsearch", VersionGroup: 1, CPE: "cpe:2.3:a:elastic:elasticsearch:%s:*:*:*:*:*:*:*"},
	{Name: "docker", Service: "docker", Pattern: regexp.MustCompile(`"Version"\s*:\s*"([0-9][0-9A-Za-z.\-]*)"`),
		Product: "Docker", VersionGroup: 1, CPE: "cpe:2.3:a:docker:docker:%s:*:*:*:*:*:*:*"},
	{Name: "squid-proxy", Service: "squid", Pattern: regexp.MustCompile(`(?i)Squid/([0-9][0-9.]*)`),
		Product: "Squid", VersionGroup: 1, CPE: "cpe:2.3:a:squid-cache:squid:%s:*:*:*:*:*:*:*"},
	{Name: "mikrotik", Service: "http", Pattern: regexp.MustCompile(`(?i)MikroTik`),
		Product: "MikroTik RouterOS", CPE: "cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*"},
	{Name: "fortigate", Service: "http", Pattern: regexp.MustCompile(`(?i)FortiGate`),
		Product: "Fortinet FortiGate", CPE: "cpe:2.3:a:fortinet:fortigate:*:*:*:*:*:*:*:*"},
	{Name: "synology", Service: "http", Pattern: regexp.MustCompile(`(?i)Synology`),
		Product: "Synology DSM", CPE: "cpe:2.3:a:synology:diskstation_manager:*:*:*:*:*:*:*:*"},
	{Name: "openwrt", Service: "http", Pattern: regexp.MustCompile(`(?i)OpenWrt`),
		Product: "OpenWrt", CPE: "cpe:2.3:a:openwrt:openwrt:*:*:*:*:*:*:*:*"},
	{Name: "busybox", Service: "http", Pattern: regexp.MustCompile(`(?i)BusyBox`),
		Product: "BusyBox", CPE: "cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*"},
	{Name: "zeroshell", Service: "http", Pattern: regexp.MustCompile(`(?i)ZeroShell`),
		Product: "ZeroShell", CPE: "cpe:2.3:a:zeroshell:zeroshell:*:*:*:*:*:*:*:*"},
	{Name: "routeros", Service: "http", Pattern: regexp.MustCompile(`(?i)RouterOS`),
		Product: "MikroTik RouterOS", CPE: "cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*"},
	{Name: "webmin", Service: "http", Pattern: regexp.MustCompile(`(?i)Webmin\s+([0-9][0-9.]*)`),
		Product: "Webmin", VersionGroup: 1, CPE: "cpe:2.3:a:webmin:webmin:%s:*:*:*:*:*:*:*"},
	{Name: "grafana", Service: "http", Pattern: regexp.MustCompile(`(?i)Grafana`),
		Product: "Grafana", CPE: "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"},
	{Name: "jira", Service: "http", Pattern: regexp.MustCompile(`(?i)Atlassian`),
		Product: "Atlassian Jira", CPE: "cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*"},
	{Name: "gitlab", Service: "http", Pattern: regexp.MustCompile(`(?i)GitLab`),
		Product: "GitLab", CPE: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"},
	{Name: "portainer", Service: "http", Pattern: regexp.MustCompile(`(?i)Portainer`),
		Product: "Portainer", CPE: "cpe:2.3:a:portainer:portainer:*:*:*:*:*:*:*:*"},
	{Name: "telemetry", Service: "http", Pattern: regexp.MustCompile(`(?i)MikroTik/([0-9][0-9.]*)`),
		Product: "MikroTik RouterOS", VersionGroup: 1, CPE: "cpe:2.3:a:mikrotik:routeros:%s:*:*:*:*:*:*:*"},
	{Name: "rdp", Service: "rdp", Pattern: regexp.MustCompile(`(?i)Remote Desktop`),
		Product: "Microsoft Remote Desktop", CPE: "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"},
	{Name: "vnc", Service: "vnc", Pattern: regexp.MustCompile(`RFB (\d{3}\.\d{3})`),
		Product: "VNC", VersionGroup: 1},
	{Name: "samba", Service: "smb", Pattern: regexp.MustCompile(`(?i)Samba\s+([0-9][0-9.]*)`),
		Product: "Samba", VersionGroup: 1, CPE: "cpe:2.3:a:samba:samba:%s:*:*:*:*:*:*:*"},
	{Name: "netdata", Service: "http", Pattern: regexp.MustCompile(`(?i)Netdata`),
		Product: "Netdata", CPE: "cpe:2.3:a:netdata:netdata:*:*:*:*:*:*:*:*"},
	{Name: "prometheus", Service: "http", Pattern: regexp.MustCompile(`(?i)Prometheus`),
		Product: "Prometheus", CPE: "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*"},
	{Name: "cockpit", Service: "http", Pattern: regexp.MustCompile(`(?i)Cockpit`),
		Product: "Cockpit", CPE: "cpe:2.3:a:cockpit_project:cockpit:*:*:*:*:*:*:*:*"},
	{Name: "rdp-open", Service: "rdp", Pattern: regexp.MustCompile(`(?i)X.224`),
		Product: "Microsoft Remote Desktop", CPE: "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"},
	{Name: "postgresql", Service: "postgres", Pattern: regexp.MustCompile(`(?i)Postgres`),
		Product: "PostgreSQL", CPE: "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"},
}

// Match applies the rule to a banner and fills in the product, version and
// CPE fields. It reports whether the rule matched.
func (r Rule) Match(banner string, info *ServiceInfo) bool {
	m := r.Pattern.FindStringSubmatch(banner)
	if m == nil {
		return false
	}

	switch {
	case r.Product != "":
		info.Product = r.Product
	case r.ProductGroup > 0 && r.ProductGroup < len(m) && m[r.ProductGroup] != "":
		info.Product = m[r.ProductGroup]
	case r.ProductGroup == 0 && m[0] != "":
		info.Product = strings.TrimSpace(m[0])
	}
	if r.VersionGroup > 0 && r.VersionGroup < len(m) && m[r.VersionGroup] != "" {
		info.Version = m[r.VersionGroup]
	}
	if r.CPE != "" {
		info.CPE = strings.Replace(r.CPE, "%s", info.Version, 1)
	}
	return true
}

// Rules returns the bundled fingerprint rules plus any user supplied ones.
func Rules(extra []Rule) []Rule {
	out := make([]Rule, 0, len(builtInRules)+len(extra))
	out = append(out, builtInRules...)
	out = append(out, extra...)
	return out
}

// ruleFile is the on disk representation of a rule set.
type ruleFile struct {
	Rules []ruleJSON `json:"rules"`
}

type ruleJSON struct {
	Name         string `json:"name"`
	Service      string `json:"service"`
	Pattern      string `json:"pattern"`
	Product      string `json:"product"`
	ProductGroup int    `json:"product_group"`
	VersionGroup int    `json:"version_group"`
	CPE          string `json:"cpe"`
}

// LoadRules reads additional fingerprint rules from a JSON file.
//
// The file holds a "rules" array whose entries carry a regular expression
// pattern, the canonical service name, the product name and the capture
// groups that hold the product and the version.
func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file ruleFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	out := make([]Rule, 0, len(file.Rules))
	for _, r := range file.Rules {
		if r.Pattern == "" {
			return nil, fmt.Errorf("%s: rule %q has no pattern", path, r.Name)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%s: rule %q: %w", path, r.Name, err)
		}
		out = append(out, Rule{
			Name:         r.Name,
			Service:      r.Service,
			Pattern:      re,
			Product:      r.Product,
			ProductGroup: r.ProductGroup,
			VersionGroup: r.VersionGroup,
			CPE:          r.CPE,
		})
	}
	return out, nil
}
