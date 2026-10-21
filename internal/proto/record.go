package proto

import (
	"net"
	"sync"
)

// maxRecorded bounds how many bytes a recorder keeps, so that a hostile or
// misbehaving service cannot exhaust memory.
const maxRecorded = 64 * 1024

// recorder wraps a connection and keeps a copy of the bytes read from and
// written to it. It is used to capture raw banners and TLS handshakes.
type recorder struct {
	net.Conn
	mu      sync.Mutex
	read    []byte
	written []byte
}

func newRecorder(c net.Conn) *recorder { return &recorder{Conn: c} }

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		if len(r.read) < maxRecorded {
			room := maxRecorded - len(r.read)
			if room > n {
				room = n
			}
			r.read = append(r.read, p[:room]...)
		}
		r.mu.Unlock()
	}
	return n, err
}

func (r *recorder) Write(p []byte) (int, error) {
	n, err := r.Conn.Write(p)
	if n > 0 {
		r.mu.Lock()
		if len(r.written) < maxRecorded {
			room := maxRecorded - len(r.written)
			if room > n {
				room = n
			}
			r.written = append(r.written, p[:room]...)
		}
		r.mu.Unlock()
	}
	return n, err
}

// ReadBytes returns a copy of the bytes read so far.
func (r *recorder) ReadBytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.read))
	copy(out, r.read)
	return out
}

// WrittenBytes returns a copy of the bytes written so far.
func (r *recorder) WrittenBytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.written))
	copy(out, r.written)
	return out
}
