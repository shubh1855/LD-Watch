package integration_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/shubh1855/ld-watch/internal/store"
)

// This fixture uses the real glibc loader and C sender, never a synthetic packet.
func TestRealAuditSourcePersistsIdentity(t *testing.T) {
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Fatal("gcc is required for real-source acceptance")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	auditLib := filepath.Join(t.TempDir(), "audit.so")
	args := []string{"-shared", "-fPIC", "-Wall", "-Wextra", "-O2", "-I" + filepath.Join(root, "audit/include"), "-o", auditLib, filepath.Join(root, "audit/src/audit.c"), filepath.Join(root, "audit/src/hooks.c"), filepath.Join(root, "audit/src/ipc.c"), "-ldl"}
	if output, err := exec.Command(gcc, args...).CombinedOutput(); err != nil {
		t.Fatalf("build audit: %s %v", output, err)
	}
	p := newPipeline(t, 4)
	defer p.close(t)
	defer p.drain(t)
	cmd := exec.Command("/bin/true")
	cmd.Env = append(os.Environ(), "LD_AUDIT="+auditLib, "LDWATCH_SOCKET="+p.SockPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("audited program: %s %v", output, err)
	}
	ctx := context.Background()
	deadline := time.Now().Add(3 * time.Second)
	var rows []store.LoaderEvent
	for time.Now().Before(deadline) {
		rows, err = p.Queries.ListLoaderEvents(ctx, store.ListLoaderEventsParams{Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		loads := 0
		for _, row := range rows {
			if row.EventType == "LOAD" {
				loads++
			}
		}
		if loads >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rows) == 0 {
		t.Fatal("no actual C telemetry persisted")
	}
	loads := 0
	for _, row := range rows {
		if row.EventType == "LOAD" {
			loads++
		}
		if row.IdentityStatus != "source" || row.Exe == "" || row.ProcessKey == "" || row.PeerPid <= 0 || row.Pid != int64(cmd.Process.Pid) || row.Tid <= 0 {
			t.Fatalf("bad C attribution: %+v", row)
		}
		proc, err := p.Queries.GetProcessInstance(ctx, row.ProcessKey)
		if err != nil || proc.StartTicks == "0" {
			t.Fatalf("missing real lifetime: %+v %v", proc, err)
		}
	}
	if loads < 3 {
		t.Fatalf("only %d confirmed loads", loads)
	}
	t.Logf("real source persisted %d records, %d confirmed loads, executable %s", len(rows), loads, rows[0].Exe)
}
