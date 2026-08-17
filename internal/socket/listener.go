package socket

import (
	"encoding/binary"
	"log"
	"net"
	"os"

	"github.com/shubh1855/ld-watch/internal/proto"
)

const SockPath = "/run/ldwatch.sock"

// Listener accepts connections form audit.so instances
// dispatches decoded events onto the events channel
type Listener struct {
	Events   chan *proto.Event
	listener net.Listener
}

// New creates a Listener and binds to unix socket
// removes stale file from a previous run first
func New() (*Listener, error) {

	if err := os.Remove(SockPath); err != nil && os.IsNotExist(err) {
		return nil, err
	}

	ln, err := net.Listen("unix", SockPath)
	if err != nil {
		return nil, err
	}

	return &Listener{
		Events:   make(chan *proto.Event, 512),
		listener: ln,
	}, nil
}

func (l *Listener) Start() {
	go func() {
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				// listener closed; so exit
				return
			}
			go l.handleConn(conn)
		}
	}()
	log.Printf("[socket] listening on %s", SockPath)
}

// Stop closes the listener and Events channel
func (l *Listener) Stop() {
	if err := l.listener.Close(); err != nil {
		log.Printf("[socket] error closing listener: %v", err)
	}
	close(l.Events)
	log.Println("[socket] stopped")
}

// handleConn reads ld_watch_event_t struct from a single connection
// until the connection is closed
func (l *Listener) handleConn(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("[socket] error closing connection: %v", err)
		}
	}()

	for {
		var ev proto.Event

		// encoding/binary.Read fills the struct field by field in order
		// matching the exact byte layout of ld_watch_event_t in C.
		err := binary.Read(conn, binary.LittleEndian, &ev)
		if err != nil {
			return
		}

		l.Events <- &ev
	}

}
