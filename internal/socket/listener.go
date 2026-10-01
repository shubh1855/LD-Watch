package socket

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shubh1855/ld-watch/internal/proto"
	"golang.org/x/sys/unix"
)

const (
	maxConnections = 128
	shutdownDrain  = 250 * time.Millisecond
)

var (
	ErrActiveSocket = errors.New("socket path is owned by an active collector")
	ErrUnsafePath   = errors.New("socket path is not a safe unix socket")
)

type Stats struct {
	RejectedConnections uint64
	InvalidRecords      uint64
	DroppedRecords      uint64
}

// Listener accepts v1 SOCK_SEQPACKET connections and dispatches validated
// events onto Events. Peer credentials are attached to each decoded event.
type Listener struct {
	Events   chan *proto.Event
	path     string
	listener net.Listener

	acceptWg sync.WaitGroup
	connWg   sync.WaitGroup
	connMu   sync.Mutex
	conns    map[net.Conn]struct{}
	slots    chan struct{}
	stopCh   chan struct{}
	stopOnce sync.Once

	rejected atomic.Uint64
	invalid  atomic.Uint64
	dropped  atomic.Uint64
}

func New(path string) (*Listener, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect socket path: %w", err)
	}

	ln, err := net.Listen("unixpacket", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &Listener{
		Events:   make(chan *proto.Event, 512),
		path:     path,
		listener: ln,
		conns:    make(map[net.Conn]struct{}),
		slots:    make(chan struct{}, maxConnections),
		stopCh:   make(chan struct{}),
	}, nil
}

// ValidatePath checks configuration and protects existing files before any
// database or listener resources are created by the collector.
func ValidatePath(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("socket path must be absolute")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect socket path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return ErrUnsafePath
	}
	conn, dialErr := net.DialTimeout("unixpacket", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return ErrActiveSocket
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, syscall.ENOENT) {
		return fmt.Errorf("probe existing socket: %w", dialErr)
	}
	return nil
}

func (l *Listener) Start() {
	l.acceptWg.Add(1)
	go func() {
		defer l.acceptWg.Done()
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				return
			}
			select {
			case l.slots <- struct{}{}:
				l.connMu.Lock()
				l.conns[conn] = struct{}{}
				l.connMu.Unlock()
				l.connWg.Add(1)
				go l.handleConn(conn)
			default:
				l.rejected.Add(1)
				_ = conn.Close()
			}
		}
	}()
	log.Printf("[socket] listening on %s", l.path)
}

func (l *Listener) handleConn(conn net.Conn) {
	defer l.connWg.Done()
	defer func() {
		l.connMu.Lock()
		delete(l.conns, conn)
		l.connMu.Unlock()
		<-l.slots
		_ = conn.Close()
	}()

	peerPID, peerUID, peerGID := peerCredentials(conn)
	for {
		packet := make([]byte, proto.EventSize+1)
		n, err := conn.Read(packet)
		if err != nil {
			return
		}
		if n != proto.EventSize {
			l.invalid.Add(1)
			log.Printf("[socket] rejected packet length %d", n)
			return
		}
		ev, err := proto.Decode(packet[:n])
		if err != nil {
			l.invalid.Add(1)
			log.Printf("[socket] rejected packet: %v", err)
			return
		}
		ev.PeerPID, ev.PeerUID, ev.PeerGID = peerPID, peerUID, peerGID
		select {
		case l.Events <- ev:
		case <-l.stopCh:
			l.dropped.Add(1)
			return
		}
	}
}

func peerCredentials(conn net.Conn) (int32, uint32, uint32) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, 0, 0
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return -1, 0, 0
	}
	var cred *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || controlErr != nil || cred == nil {
		return -1, 0, 0
	}
	return int32(cred.Pid), cred.Uid, cred.Gid
}

// Stop stops accepting, gives in-flight packets a short drain window, then
// closes idle/remaining connections so shutdown cannot depend on clients.
func (l *Listener) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopCh)
		_ = l.listener.Close()
		l.acceptWg.Wait()

		deadline := time.Now().Add(shutdownDrain)
		l.connMu.Lock()
		for conn := range l.conns {
			_ = conn.SetReadDeadline(deadline)
		}
		l.connMu.Unlock()

		done := make(chan struct{})
		go func() {
			l.connWg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(shutdownDrain):
			l.connMu.Lock()
			for conn := range l.conns {
				_ = conn.Close()
			}
			l.connMu.Unlock()
			<-done
		}
		close(l.Events)
		_ = os.Remove(l.path)
		log.Println("[socket] stopped")
	})
}

func (l *Listener) Stats() Stats {
	return Stats{
		RejectedConnections: l.rejected.Load(),
		InvalidRecords:      l.invalid.Load(),
		DroppedRecords:      l.dropped.Load(),
	}
}
