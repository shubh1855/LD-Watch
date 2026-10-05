package socket

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shubh1855/ld-watch/internal/proto"
)

func TestNewRejectsUnrelatedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("New accepted an unrelated regular file")
	}
}

func TestListenerCountsAndRejectsInvalidRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldwatch.sock")
	ln, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ln.Start()
	defer ln.Stop()
	for _, record := range [][]byte{make([]byte, 408), make([]byte, proto.EventSize)} {
		if len(record) == proto.EventSize {
			copy(record, "NOPE")
		}
		conn, err := net.Dial("unixpacket", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(record); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ln.Stats().InvalidRecords == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("invalid packet count=%d, want 2", ln.Stats().InvalidRecords)
}

func TestStopClosesIdleConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldwatch.sock")
	ln, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ln.Start()
	conn, err := net.Dial("unixpacket", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		ln.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("listener stop blocked on idle client")
	}
}
