package engine

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/ports"
	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/target"
)

func TestConnectScannerFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go acceptLoop(ln)

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	results := scanTCP(t, NewConnectScanner(Config{Timeout: 2 * time.Second}),
		[]target.Host{{V4: netip.MustParseAddr("127.0.0.1")}}, []uint16{port})

	if len(results) != 1 {
		t.Fatalf("the scan produced %d results, want 1", len(results))
	}
	if results[0].State != StateOpen {
		t.Errorf("state = %q, want open (error: %v)", results[0].State, results[0].Err)
	}
	if results[0].Port != port {
		t.Errorf("port = %d, want %d", results[0].Port, port)
	}
	if results[0].Proto != ports.TCP {
		t.Errorf("protocol = %q, want tcp", results[0].Proto)
	}
	if !results[0].Open() {
		t.Error("Open reported false for an open port")
	}
	if results[0].Endpoint() != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String() {
		t.Errorf("endpoint = %q", results[0].Endpoint())
	}
}

func TestConnectScannerFindsClosedPort(t *testing.T) {
	// Bind a port and release it straight away, so that nothing listens
	// on it while the scan runs.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()

	results := scanTCP(t, NewConnectScanner(Config{Timeout: 2 * time.Second}),
		[]target.Host{{V4: netip.MustParseAddr("127.0.0.1")}}, []uint16{port})

	if len(results) != 1 {
		t.Fatalf("the scan produced %d results, want 1", len(results))
	}
	if results[0].State != StateClosed {
		t.Errorf("state = %q, want closed (error: %v)", results[0].State, results[0].Err)
	}
}

func TestConnectScannerDetectsService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(buf)
				body := "<html><head><title>vantage</title></head></html>"
				resp := "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n" +
					"Content-Length: 47\r\nConnection: close\r\n\r\n" + body
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	scanner := NewConnectScanner(Config{
		Timeout:       2 * time.Second,
		Detect:        true,
		DetectTimeout: 2 * time.Second,
		EnableHTTP:    true,
	})
	results := scanTCP(t, scanner, []target.Host{{V4: netip.MustParseAddr("127.0.0.1")}}, []uint16{port})

	if len(results) != 1 {
		t.Fatalf("the scan produced %d results, want 1", len(results))
	}
	res := results[0]
	if res.State != StateOpen {
		t.Fatalf("state = %q, want open", res.State)
	}
	if res.Service == nil {
		t.Fatal("the service was not detected")
	}
	if res.Service.Service != "http" {
		t.Errorf("service = %q, want http", res.Service.Service)
	}
	if res.Service.Product != "nginx" {
		t.Errorf("product = %q, want nginx", res.Service.Product)
	}
	if res.Service.Version != "1.24.0" {
		t.Errorf("version = %q, want 1.24.0", res.Service.Version)
	}
}

func TestConnectScannerScansEveryPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go acceptLoop(ln)

	open := uint16(ln.Addr().(*net.TCPAddr).Port)
	ports := []uint16{open, open + 1, open + 2}

	results := scanTCP(t, NewConnectScanner(Config{Timeout: 2 * time.Second, Concurrency: 10}),
		[]target.Host{{V4: netip.MustParseAddr("127.0.0.1")}}, ports)

	if len(results) != len(ports) {
		t.Fatalf("the scan produced %d results, want %d", len(results), len(ports))
	}
	openCount := 0
	for _, res := range results {
		if res.State == StateOpen {
			openCount++
		}
	}
	if openCount != 1 {
		t.Errorf("%d ports were open, want 1", openCount)
	}
}

func TestUDPScannerFindsOpenPort(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo([]byte("PONG"), addr)
			_ = n
		}
	}()

	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	scanner, err := NewUDPScanner(Config{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	results := scanUDP(t, scanner, []target.Host{{V4: netip.MustParseAddr("127.0.0.1")}}, []uint16{port})

	if len(results) != 1 {
		t.Fatalf("the scan produced %d results, want 1", len(results))
	}
	if results[0].State != StateOpen {
		t.Errorf("state = %q, want open (error: %v)", results[0].State, results[0].Err)
	}
	if results[0].Proto != ports.UDP {
		t.Errorf("protocol = %q, want udp", results[0].Proto)
	}
}

func TestUDPScannerIdentifiesService(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			_, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// A DNS version.bind answer.
			_, _ = pc.WriteTo([]byte{
				0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
				0x04, 'b', 'i', 'n', 'd', 0x00, 0x00, 0x10, 0x00, 0x03,
				0x00, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0b,
				0x0b, 'B', 'i', 'n', 'd', ' ', '9', '.', '1', '8', '.', '0',
			}, addr)
		}
	}()

	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	scanner, err := NewUDPScanner(Config{Timeout: 2 * time.Second, Detect: true})
	if err != nil {
		t.Fatal(err)
	}
	results := scanUDP(t, scanner, []target.Host{{V4: netip.MustParseAddr("127.0.0.1")}}, []uint16{port})

	if len(results) != 1 {
		t.Fatalf("the scan produced %d results, want 1", len(results))
	}
	res := results[0]
	if res.State != StateOpen {
		t.Fatalf("state = %q, want open (error: %v)", res.State, res.Err)
	}
	if res.Service == nil {
		t.Fatal("the service was not detected")
	}
	if res.Service.Service != "dns" {
		t.Errorf("service = %q, want dns", res.Service.Service)
	}
}

func TestScanOrder(t *testing.T) {
	s := newScanner(Config{Order: OrderPort})
	var got []uint16
	for _, job := range collectJobs(s, []target.Host{
		{V4: netip.MustParseAddr("192.0.2.1")},
		{V4: netip.MustParseAddr("192.0.2.2")},
	}, []uint16{80, 443}) {
		got = append(got, job.port)
	}
	want := []uint16{80, 80, 443, 443}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the port order is %v, want %v", got, want)
		}
	}

	s = newScanner(Config{Order: OrderHost})
	got = nil
	for _, job := range collectJobs(s, []target.Host{
		{V4: netip.MustParseAddr("192.0.2.1")},
		{V4: netip.MustParseAddr("192.0.2.2")},
	}, []uint16{80, 443}) {
		got = append(got, job.port)
	}
	want = []uint16{80, 443, 80, 443}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the host order is %v, want %v", got, want)
		}
	}
}

func TestScanAutoOrder(t *testing.T) {
	s := newScanner(Config{Order: OrderAuto})
	hosts := make([]target.Host, 9)
	for i := range hosts {
		hosts[i] = target.Host{V4: netip.MustParseAddr("192.0.2.1")}
	}
	jobs := collectJobs(s, hosts, []uint16{80, 443})
	if len(jobs) != 18 {
		t.Fatalf("the scan produced %d jobs, want 18", len(jobs))
	}
	if jobs[0].port != 80 || jobs[1].port != 80 {
		t.Errorf("the automatic order did not group by port: %v", jobs[:3])
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		err  error
		want State
	}{
		{nil, StateOpen},
		{syscall.ECONNREFUSED, StateClosed},
		{syscall.ECONNRESET, StateClosed},
		{syscall.EHOSTUNREACH, StateFiltered},
		{syscall.ENETUNREACH, StateFiltered},
		{syscall.EPERM, StateFiltered},
		{os.ErrDeadlineExceeded, StateFiltered},
		{context.DeadlineExceeded, StateFiltered},
	}
	for _, tt := range tests {
		if got := classify(tt.err); got != tt.want {
			t.Errorf("classify(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func TestClassifyUDP(t *testing.T) {
	if got := classifyUDP(syscall.ECONNREFUSED); got != StateClosed {
		t.Errorf("classifyUDP(ECONNREFUSED) = %q, want closed", got)
	}
	if got := classifyUDP(syscall.EHOSTUNREACH); got != StateFiltered {
		t.Errorf("classifyUDP(EHOSTUNREACH) = %q, want filtered", got)
	}
	if got := classifyUDP(context.DeadlineExceeded); got != StateFiltered {
		t.Errorf("classifyUDP(deadline) = %q, want filtered", got)
	}
}

func TestGateLimitsConcurrency(t *testing.T) {
	g := newGate(2)
	ctx := context.Background()

	var mu sync.Mutex
	active := 0
	peak := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = g.acquire(ctx)
			mu.Lock()
			active++
			if active > peak {
				peak = active
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			mu.Lock()
			active--
			mu.Unlock()
			g.release()
		}()
	}
	wg.Wait()

	if peak > 2 {
		t.Errorf("the gate allowed %d concurrent probes, want at most 2", peak)
	}
}

func TestGateResize(t *testing.T) {
	g := newGate(1)
	g.setLimit(4)
	if _, limit := g.current(); limit != 4 {
		t.Errorf("the limit is %d, want 4", limit)
	}
	g.setLimit(0)
	if _, limit := g.current(); limit != 1 {
		t.Errorf("the limit is %d, want 1", limit)
	}
}

func TestGateRespectsCancellation(t *testing.T) {
	g := newGate(1)
	ctx, cancel := context.WithCancel(context.Background())
	_ = g.acquire(ctx)

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	done := make(chan error, 1)
	go func() {
		done <- g.acquire(ctx)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("acquire returned no error after the context was cancelled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquire did not return after the context was cancelled")
	}
}

func TestControllerGrowsOnHealthyTarget(t *testing.T) {
	c := newController(64, 1024)
	for i := 0; i < 64; i++ {
		c.observe(10*time.Millisecond, false)
	}
	if got := c.currentLimit(); got <= 64 {
		t.Errorf("the limit is %d, want more than 64", got)
	}
}

func TestControllerShrinksOnFailingTarget(t *testing.T) {
	c := newController(64, 1024)
	for i := 0; i < 64; i++ {
		c.observe(10*time.Millisecond, false)
	}
	grown := c.currentLimit()

	for i := 0; i < 64; i++ {
		c.observe(10*time.Millisecond, true)
	}
	if got := c.currentLimit(); got >= grown {
		t.Errorf("the limit is %d, want less than %d", got, grown)
	}
	if got := c.currentLimit(); got < 64 {
		t.Errorf("the limit is %d, want at least 64", got)
	}
}

func TestControllerStaysWithinBounds(t *testing.T) {
	c := newController(10, 50)
	for i := 0; i < 1000; i++ {
		c.observe(time.Millisecond, false)
	}
	if got := c.currentLimit(); got > 50 {
		t.Errorf("the limit is %d, want at most 50", got)
	}
}

func TestRateLimiterPaces(t *testing.T) {
	scanner := newScanner(Config{Rate: 50, Timeout: time.Second})
	if scanner.limiter == nil {
		t.Fatal("the rate limiter was not created")
	}

	start := time.Now()
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := scanner.limiter.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	// The bucket starts full, so a handful of probes are free, but the
	// rest must be paced at the configured rate.
	if elapsed < 50*time.Millisecond {
		t.Errorf("ten probes took %v, want at least 50ms", elapsed)
	}
}

func TestSYNScannerReportsMissingPrivileges(t *testing.T) {
	s, err := NewSYNScanner(Config{Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewSYNScanner returned an error: %v", err)
	}
	out := make(chan Result, 1)
	err = s.Scan(context.Background(), []target.Host{{V4: netip.MustParseAddr("127.0.0.1")}}, []uint16{80}, out)
	if err == nil {
		t.Skip("the process may hold CAP_NET_RAW, so the raw socket opened")
	}
	if !contains(err.Error(), "raw socket") {
		t.Errorf("the error does not mention the raw socket: %v", err)
	}
}

func TestSYNPacketBuilders(t *testing.T) {
	if len(buildSYN(synSpec{})) == 0 {
		t.Error("buildSYN returned an empty packet")
	}
}

func TestPrintableText(t *testing.T) {
	if got := printableText([]byte("hello world")); got != "hello world" {
		t.Errorf("printableText = %q", got)
	}
	if got := printableText([]byte{0x00, 0x01, 0x02}); got != "" {
		t.Errorf("printableText = %q, want an empty string", got)
	}
	if got := printableText([]byte{0x01, 0x02, 0x03, 0x04, 'a', 'b'}); got != "" {
		t.Errorf("printableText = %q, want an empty string", got)
	}
}

func TestLooksLikeDNS(t *testing.T) {
	resp := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	if !looksLikeDNS(resp) {
		t.Error("a DNS response was not recognised")
	}
	if looksLikeDNS([]byte{0x12, 0x34, 0x01, 0x00}) {
		t.Error("a query was recognised as a response")
	}
}

func TestLooksLikeNetBIOS(t *testing.T) {
	data := make([]byte, 60)
	data[2] = 0x80
	data[3] = 0x00
	if !looksLikeNetBIOS(data) {
		t.Error("a NetBIOS response was not recognised")
	}
	if looksLikeNetBIOS([]byte{0x00, 0x00, 0x00, 0x00}) {
		t.Error("an empty datagram was recognised as NetBIOS")
	}
}

// acceptLoop accepts connections until the listener is closed.
func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}
}

// scanTCP runs a connect scanner and collects every result.
func scanTCP(t *testing.T, s *ConnectScanner, hosts []target.Host, portList []uint16) []Result {
	t.Helper()
	return scanWith(t, func(ctx context.Context, out chan<- Result) error {
		return s.Scan(ctx, hosts, portList, out)
	})
}

// scanUDP runs a UDP scanner and collects every result.
func scanUDP(t *testing.T, s *UDPScanner, hosts []target.Host, portList []uint16) []Result {
	t.Helper()
	return scanWith(t, func(ctx context.Context, out chan<- Result) error {
		return s.Scan(ctx, hosts, portList, out)
	})
} // scanWith runs any scanner and collects every result.
func scanWith(t *testing.T, run func(context.Context, chan<- Result) error) []Result {
	t.Helper()
	out := make(chan Result, 256)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []Result

	wg.Add(1)
	go func() {
		defer wg.Done()
		for res := range out {
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}
	}()

	if err := run(context.Background(), out); err != nil {
		t.Fatalf("the scan failed: %v", err)
	}
	close(out)
	wg.Wait()
	return results
}

// collectJobs runs the producer of the pipeline and returns the jobs.
func collectJobs(s *scanner, hosts []target.Host, portList []uint16) []probeJob {
	jobs := make(chan probeJob, 1024)
	s.produce(context.Background(), hosts, portList, jobs)
	close(jobs)

	var out []probeJob
	for job := range jobs {
		out = append(out, job)
	}
	return out
}

// contains reports whether the string holds the substring.
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
