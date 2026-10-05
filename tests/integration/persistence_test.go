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

func TestThreadedDlopenUnloadReloadLifecycle(t *testing.T) {
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Fatal("gcc is required for lifecycle acceptance")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	auditLib := filepath.Join(out, "audit.so")
	plugin := filepath.Join(out, "lifecycle.so")
	probe := filepath.Join(out, "lifecycle-probe")
	builds := [][]string{
		{"-shared", "-fPIC", "-Wall", "-Wextra", "-O2", "-I" + filepath.Join(root, "audit/include"), "-o", auditLib, filepath.Join(root, "audit/src/audit.c"), filepath.Join(root, "audit/src/hooks.c"), filepath.Join(root, "audit/src/ipc.c"), "-ldl"},
		{"-shared", "-fPIC", "-Wall", "-Wextra", "-O2", "-o", plugin, filepath.Join(root, "tests/fixtures/lifecycle_library.c")},
		{"-Wall", "-Wextra", "-O2", "-pthread", "-o", probe, filepath.Join(root, "tests/fixtures/lifecycle_probe.c"), "-ldl"},
	}
	outputs := []string{auditLib, plugin, probe}
	for i, args := range builds {
		if output, err := exec.Command(gcc, args...).CombinedOutput(); err != nil {
			t.Fatalf("build %s: %s %v", outputs[i], output, err)
		}
	}
	p := newPipeline(t, 4)
	defer p.close(t)
	defer p.drain(t)
	cmd := exec.Command(probe, plugin)
	cmd.Env = append(os.Environ(), "LD_AUDIT="+auditLib, "LDWATCH_SOCKET="+p.SockPath, "LDWATCH_VERBOSE=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("threaded lifecycle fixture: %s %v", output, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var rows []store.LoaderEvent
	for time.Now().Before(deadline) {
		rows, err = p.Queries.ListLoaderEvents(context.Background(), store.ListLoaderEventsParams{Limit: 2000})
		if err != nil {
			t.Fatal(err)
		}
		loads, closes := 0, 0
		for _, row := range rows {
			if row.SubjectPath != plugin {
				continue
			}
			if row.EventType == "LOAD" {
				loads++
			}
			if row.EventType == "OBJECT_CLOSE" {
				closes++
			}
		}
		if loads >= 2 && closes >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var loads, closes int
	var workerThreadObserved bool
	var processKey string
	for _, row := range rows {
		if row.SubjectPath != plugin {
			continue
		}
		if processKey == "" {
			processKey = row.ProcessKey
		}
		if row.EventType == "LOAD" {
			loads++
			if row.Tid != row.Pid {
				workerThreadObserved = true
			}
			if row.ProcessKey != processKey {
				t.Fatalf("process identity changed during dlopen lifecycle: %q != %q", row.ProcessKey, processKey)
			}
		}
		if row.EventType == "OBJECT_CLOSE" {
			closes++
			if row.ProcessKey != processKey {
				t.Fatalf("close event process identity mismatch: %+v", row)
			}
		}
	}
	if loads < 2 || closes < 2 {
		t.Fatalf("expected repeated plugin load/unload records, got LOAD=%d OBJECT_CLOSE=%d", loads, closes)
	}
	if !workerThreadObserved {
		t.Fatal("no plugin load was attributed to a worker thread")
	}
}
