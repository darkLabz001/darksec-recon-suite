package osdetect

// signature describes the SYN-ACK of a known operating system.
type signature struct {
	name        string
	description string
	ttl         uint8    // initial TTL (64, 128 or 255)
	windows     []uint16 // common advertised window sizes
	mss         uint16
	wscale      int // -1 when the option is absent
	sackOK      bool
	ts          bool
	options     string // ordered option list, matching Fingerprint.Options
}

// signatures is a small, curated database of well known TCP/IP stacks. The
// values are the classic signatures each system advertises and are
// approximate: window sizes and option orders shift between patch levels.
var signatures = []signature{
	{
		name: "Linux", description: "Linux 5.x/6.x (Ubuntu, Debian, Arch, Fedora)",
		ttl: 64, windows: []uint16{64240, 65535, 29200, 32768}, mss: 1460,
		wscale: 7, sackOK: true, ts: true, options: "MSS,SACKOK,TS,NOP,WScale",
	},
	{
		name: "Android", description: "Android (Linux kernel)",
		ttl: 64, windows: []uint16{65535, 29200}, mss: 1460,
		wscale: 7, sackOK: true, ts: true, options: "MSS,SACKOK,TS,NOP,WScale",
	},
	{
		name: "Windows", description: "Windows 10 / 11",
		ttl: 128, windows: []uint16{8192, 65535, 64240, 16384, 32768}, mss: 1460,
		wscale: 8, sackOK: true, ts: true, options: "MSS,NOP,WScale,NOP,NOP,SACKOK,NOP,TS",
	},
	{
		name: "Windows", description: "Windows 7 / Server 2008",
		ttl: 128, windows: []uint16{8192}, mss: 1460,
		wscale: 8, sackOK: true, ts: false, options: "MSS,NOP,WScale,NOP,NOP,SACKOK",
	},
	{
		name: "macOS", description: "macOS 11+ (Big Sur and later)",
		ttl: 64, windows: []uint16{65535}, mss: 1460,
		wscale: 3, sackOK: true, ts: true, options: "MSS,NOP,WScale,NOP,NOP,TS,SACKOK,NOP,NOP",
	},
	{
		name: "iOS", description: "iOS / iPadOS",
		ttl: 64, windows: []uint16{65535}, mss: 1460,
		wscale: 3, sackOK: true, ts: true, options: "MSS,NOP,WScale,SACKOK,TS",
	},
	{
		name: "FreeBSD", description: "FreeBSD 12/13/14",
		ttl: 64, windows: []uint16{65535}, mss: 1460,
		wscale: 7, sackOK: true, ts: true, options: "MSS,NOP,WScale,NOP,NOP,TS,SACKOK,NOP,NOP",
	},
	{
		name: "OpenBSD", description: "OpenBSD",
		ttl: 64, windows: []uint16{16384}, mss: 1460,
		wscale: 6, sackOK: true, ts: true, options: "MSS,NOP,NOP,SACKOK,NOP,TS,NOP,WScale",
	},
	{
		name: "NetBSD", description: "NetBSD",
		ttl: 64, windows: []uint16{65535}, mss: 1460,
		wscale: 3, sackOK: true, ts: true, options: "MSS,NOP,WScale,NOP,NOP,TS,SACKOK",
	},
	{
		name: "Solaris", description: "Solaris / illumos",
		ttl: 255, windows: []uint16{49152, 10240}, mss: 1460,
		wscale: 3, sackOK: true, ts: true, options: "MSS,SACKOK,TS,NOP,WScale",
	},
	{
		name: "Cisco", description: "Cisco IOS / IOS-XE",
		ttl: 255, windows: []uint16{4128, 16384, 16304}, mss: 536,
		wscale: -1, sackOK: false, ts: false, options: "MSS",
	},
	{
		name: "Juniper", description: "Juniper Junos (FreeBSD based)",
		ttl: 64, windows: []uint16{65535}, mss: 1460,
		wscale: 7, sackOK: true, ts: true, options: "MSS,NOP,WScale,NOP,NOP,TS,SACKOK",
	},
	{
		name: "AIX", description: "IBM AIX",
		ttl: 64, windows: []uint16{65535}, mss: 1460,
		wscale: -1, sackOK: false, ts: false, options: "MSS",
	},
	{
		name: "HP-UX", description: "HP-UX",
		ttl: 64, windows: []uint16{32768}, mss: 1460,
		wscale: -1, sackOK: false, ts: false, options: "MSS",
	},
}
