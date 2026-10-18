"""Embedded fallback wordlist for DNS brute-force.

Kept deliberately small and high-signal; point sunder at a bigger list
(e.g. seclists' dns/subdomains-top1million) with the wordlist field for deep runs.
"""

DEFAULT_SUBDOMAINS: list[str] = [
    # web basics
    "www", "www2", "www3", "m", "mobile", "mp", "amp", "pwa", "web", "home",
    "blog", "shop", "store", "ecommerce", "cart", "checkout", "cdn", "cdn1", "cdn2",
    "static", "assets", "img", "images", "image", "media", "video", "videos", "files",
    "file", "upload", "uploads", "download", "downloads", "origin", "edge", "geo",
    # mail
    "mail", "mail2", "mail3", "email", "webmail", "webmail2", "smtp", "smtp2", "imap",
    "pop", "pop3", "mx", "mx1", "mx2", "mx3", "relay", "lists", "newsletter", "mailer",
    "autodiscover", "autoconfig", "spam", "filter", "antivirus", "virus",
    # dns / infra
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "dns3", "ftp", "ftp2",
    "sftp", "ssh", "bastion", "jump", "tunnel", "vpn", "remote", "gateway", "proxy",
    "lb", "lb2", "loadbalancer", "nat", "router", "switch", "firewall", "waf",
    "ciscoasa", "nginx", "apache", "haproxy", "tomcat", "jetty", "weblogic", "jboss", "iis",
    # services / apps
    "api", "api2", "api3", "rest", "graphql", "grpc", "rpc", "ws", "wss", "websocket",
    "realtime", "stream", "streaming", "push", "notifications", "notify", "webhook",
    "webhooks", "hooks", "svc", "service", "services", "app", "apps", "backend",
    "frontend", "dashboard", "panel", "portal", "portal2", "manage", "management", "cp",
    "cpanel", "whm", "webdisk", "admin", "admin2", "administrator", "root", "sysadmin",
    "webmaster", "postmaster", "hostmaster", "abuse",
    # auth / accounts
    "login", "auth", "sso", "oauth", "id", "identity", "signup", "register", "secure",
    "ssl", "account", "accounts", "user", "users", "member", "members", "client",
    "clients", "customer", "customers",
    # dev / ci
    "dev", "devel", "development", "dev2", "staging", "stage", "test", "testing", "qa",
    "uat", "sandbox", "demo", "beta", "alpha", "preview", "old", "new", "backup", "bak",
    "archive", "temp", "tmp", "git", "gitlab", "github", "bitbucket", "gitea", "gogs",
    "ci", "cd", "jenkins", "build", "buildbot", "drone", "argocd", "travis", "sonarqube",
    "sonar", "sentry", "nexus", "artifactory", "registry", "docker", "k8s", "kubernetes",
    "rancher", "helm", "openshift", "devops", "sre", "ops", "redmine", "jira",
    "confluence", "wiki", "trac", "bugzilla", "phabricator", "swarm", "bamboo",
    # data / monitoring
    "db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb", "redis",
    "memcached", "cache", "cache2", "sql", "oracle", "mssql", "phpmyadmin", "adminer",
    "varnish", "logs", "log", "splunk", "elastic", "elasticsearch", "kibana", "grafana",
    "prometheus", "monitor", "monitoring", "status", "health", "uptime", "analytics",
    "stats", "statistics", "metrics", "nagios", "zabbix", "icinga",
    # cloud
    "aws", "azure", "gcp", "cloud", "s3", "storage", "backup2", "iot", "mqtt", "edge1",
    # internal / corp
    "internal", "intranet", "extranet", "office", "corp", "corpweb", "lan", "dmz",
    "erp", "sap", "crm", "salesforce", "workday", "hr", "payroll", "staff", "employee",
    "employees", "training", "learn", "lms", "helpdesk", "support", "help", "ticket",
    "tickets", "chat", "live", "meet", "zoom", "calendar", "contacts", "drive",
    "sharepoint", "sp", "owa", "exchange", "outlook", "lync", "lyncdiscover", "sip", "teams",
    # corporate pages
    "about", "contact", "careers", "jobs", "legal", "privacy", "terms", "press", "news",
    "forum", "community", "social", "marketing", "ads", "ad", "campaign", "seo",
    "partners", "partner", "affiliate", "affiliates", "reseller", "suppliers",
    "investor", "investors", "pricing", "plans", "subscribe", "billing", "invoice",
    "payments", "payment", "secure2",
    # regional / language
    "eu", "us", "uk", "de", "fr", "es", "it", "nl", "se", "au", "ca", "jp", "cn", "in", "br", "mx",
    "en", "fr2", "de2",
    # hosts
    "server", "servers", "node", "node1", "node2", "host", "host1", "host2", "srv",
    "srv1", "srv2", "vps", "vm", "vm1", "vm2", "container", "pod",
]
