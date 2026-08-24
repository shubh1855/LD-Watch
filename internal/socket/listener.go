package socket

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"sync"

	"github.com/shubh1855/ld-watch/internal/proto"
)

// Listener accepts connections from audit.so instances and
// dispatches decoded events onto the Events channel.
type Listener struct {
	Events   chan *proto.Event
	path     string
	listener net.Listener
	acceptWg sync.WaitGroup // guards the single accept-loop goroutine
	connWg   sync.WaitGroup // guards all active handleConn goroutines
}

// New creates a Listener bound to a unix socket at path.
// Any stale socket file from a previous run is removed first.
func New(path string) (*Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		_ = ln.Close()
		return nil, err
	}

	return &Listener{
		Events:   make(chan *proto.Event, 512),
		path:     path,
		listener: ln,
	}, nil
}

// Start begins accepting connections in a background goroutine.
func (l *Listener) Start() {
	l.acceptWg.Add(1)
	go func() {
		defer l.acceptWg.Done()
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				// listener was closed; exit accept loop
				return
			}
			l.connWg.Add(1)
			go l.handleConn(conn)
		}
	}()
	log.Printf("[socket] listening on %s", l.path)
}

// Stop shuts the listener down cleanly:
//  1. Close the net.Listener — unblocks Accept().
//  2. Wait for the accept loop to exit — guarantees no more connWg.Add calls.
//  3. Wait for all handleConn goroutines — guarantees all events are enqueued.
//  4. Close Events — workers ranging over Events exit naturally.
func (l *Listener) Stop() {
	if err := l.listener.Close(); err != nil {
		log.Printf("[socket] error closing listener: %v", err)
	}
	l.acceptWg.Wait()
	l.connWg.Wait()
	close(l.Events)
	log.Println("[socket] stopped")
}

// handleConn reads ld_watch_event_t structs from a single connection
// until the connection is closed or an error occurs.
func (l *Listener) handleConn(conn net.Conn) {
	defer l.connWg.Done()
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("[socket] error closing connection: %v", err)
		}
	}()

	for {
		var ev proto.Event
		// binary.Read fills the struct field-by-field in declaration order,
		// matching the exact byte layout of ld_watch_event_t in C.
		if err := binary.Read(conn, binary.LittleEndian, &ev); err != nil {
			return
		}
		l.Events <- &ev
	}
}
