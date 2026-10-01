package socket

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
