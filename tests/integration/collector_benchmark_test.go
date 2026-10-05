package integration_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shubh1855/ld-watch/internal/proto"
)

// BenchmarkCollectorIngest measures Go packet encoding, Unix SOCK_SEQPACKET
// ingress, decoding, worker processing, and SQLite persistence as one path.
// The final row count must equal the number of packets sent or the benchmark
// fails; this workload benchmark is not a universal no-loss guarantee.
func BenchmarkCollectorIngest(b *testing.B) {
	p := newPipeline(b, 4)
	defer p.close(b)
	defer p.drain(b)
	conn, err := net.Dial("unixpacket", p.SockPath)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	ev := &proto.Event{PID: 64001, TID: 64001, EventType: proto.EventSOSearch, ProcessStartTicks: 777, TimestampNs: 1}
	copy(ev.ExePath[:], "/usr/bin/ldwatch-benchmark")
	copy(ev.SOPath[:], "libbenchmark-candidate.so")
	record := ev.MarshalBinary()
	b.SetBytes(int64(len(record)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(record); err != nil {
			b.Fatalf("send packet %d: %v", i, err)
		}
	}
	if err := conn.Close(); err != nil {
		b.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		var count int
		if err := p.db.QueryRow(`SELECT COUNT(*) FROM loader_events WHERE process_key=?`, fmt.Sprintf("%d:%d", ev.PID, ev.ProcessStartTicks)).Scan(&count); err != nil {
			b.Fatal(err)
		}
		if count == b.N {
			break
		}
		if count > b.N {
			b.Fatalf("persisted %d rows for %d packets", count, b.N)
		}
		if time.Now().After(deadline) {
			b.Fatalf("persisted %d of %d packets before deadline", count, b.N)
		}
		time.Sleep(5 * time.Millisecond)
	}
	b.StopTimer()
	if elapsed := b.Elapsed().Seconds(); elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed, "events/s")
	}
}

// BenchmarkShortLivedProgramAuditOverhead compares repeated /bin/true starts
// with and without LD_AUDIT while the collector is absent. This isolates
// startup and bounded failed-connect cost; it is not a sustained workload.
func BenchmarkShortLivedProgramAuditOverhead(b *testing.B) {
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		b.Fatal("gcc is required for audit overhead benchmark")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		b.Fatal(err)
	}
	auditLib := filepath.Join(b.TempDir(), "audit.so")
	args := []string{"-shared", "-fPIC", "-Wall", "-Wextra", "-O2", "-I" + filepath.Join(root, "audit/include"), "-o", auditLib, filepath.Join(root, "audit/src/audit.c"), filepath.Join(root, "audit/src/hooks.c"), filepath.Join(root, "audit/src/ipc.c"), "-ldl"}
	if output, err := exec.Command(gcc, args...).CombinedOutput(); err != nil {
		b.Fatalf("build audit library: %s %v", output, err)
	}
	missingSocket := filepath.Join(b.TempDir(), "missing-collector.sock")
	for _, audited := range []bool{false, true} {
		name := "without_audit"
		if audited {
			name = "LD_AUDIT_collector_absent"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cmd := exec.Command("/bin/true")
				cmd.Env = cleanAuditEnvironment(os.Environ())
				if audited {
					cmd.Env = append(cmd.Env, "LD_AUDIT="+auditLib, "LDWATCH_SOCKET="+missingSocket, "LDWATCH_VERBOSE=0")
				}
				if output, err := cmd.CombinedOutput(); err != nil {
					b.Fatalf("/bin/true run %d: %s %v", i, output, err)
				}
			}
		})
	}
}

func cleanAuditEnvironment(in []string) []string {
	out := make([]string, 0, len(in))
	for _, item := range in {
		if strings.HasPrefix(item, "LD_AUDIT=") || strings.HasPrefix(item, "LDWATCH_SOCKET=") || strings.HasPrefix(item, "LDWATCH_VERBOSE=") {
			continue
		}
		out = append(out, item)
	}
	return out
}
