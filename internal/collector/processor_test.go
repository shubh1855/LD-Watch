package collector

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/proto"
	"github.com/shubh1855/ld-watch/internal/store"
)

func TestLifetimeAttributionAndEventVocabulary(t *testing.T) {
	s, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := NewProcessor(s.Queries)
	ctx := context.Background()
	ev := &proto.Event{PID: 42, TID: 43, ProcessStartTicks: 100, TimestampNs: 20, EventType: proto.EventSOLoad, PeerPID: 42, PeerUID: 123, PeerGID: 456, NamespaceID: ^uint64(0)}
	copy(ev.ExePath[:], "/bin/old")
	copy(ev.SOPath[:], "/lib/a.so")
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// Exec replacement retains lifetime but updates event-time executable identity.
	ev.TimestampNs = 30
	ev.ExePath = [256]byte{}
	copy(ev.ExePath[:], "/bin/new")
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// A delayed pre-exec record must not revert the registry's latest metadata.
	ev.TimestampNs = 10
	ev.ExePath = [256]byte{}
	copy(ev.ExePath[:], "/bin/old")
	ev.EventType = proto.EventSOSearch
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	ev.ExePath = [256]byte{}
	copy(ev.ExePath[:], "/bin/new")
	ev.TimestampNs = 40
	ev.EventType = proto.EventObjectClose
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// PID reuse is a different process instance.
	ev.ProcessStartTicks = 200
	ev.EventType = proto.EventSymBind
	copy(ev.Symbol[:], "read")
	copy(ev.RelatedPath[:], "<main>")
	ev.ResolvedAddr = ^uint64(0)
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// Missing lifetime is never merged with a certain instance or each other.
	ev.ProcessStartTicks = 0
	ev.ExePath = [256]byte{}
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListLoaderEvents(ctx, store.ListLoaderEventsParams{Limit: 100})
	if err != nil || len(rows) != 7 {
		t.Fatalf("events %d %v", len(rows), err)
	}
	if rows[0].Exe != "/bin/old" || rows[1].Exe != "/bin/new" || rows[2].EventType != "SEARCH" || rows[3].EventType != "OBJECT_CLOSE" {
		t.Fatalf("event identity changed: %+v", rows)
	}
	if rows[0].ProcessKey == rows[4].ProcessKey || rows[5].ProcessKey == rows[6].ProcessKey || rows[5].Exe != "" {
		t.Fatal("process lifetime alias")
	}
	if rows[0].NamespaceID != "18446744073709551615" || rows[4].ResolvedAddr != "ffffffffffffffff" || rows[0].PeerUid != 123 || rows[0].Tid != 43 {
		t.Fatal("metadata lost")
	}
	proc, err := s.GetProcessInstance(ctx, "42:100")
	if err != nil || proc.Exe != "/bin/new" || proc.FirstSeen != 10 || proc.LastSeen != 40 {
		t.Fatalf("registry: %+v %v", proc, err)
	}
	// A delayed pre-exec search did not revert the latest registry identity.
	loads, err := s.ListSOEventsForPID(ctx, 42)
	if err != nil || len(loads) != 2 {
		t.Fatal("search or close treated as load")
	}
	if p.Stats().Persisted != 7 || p.Stats().UnresolvedIdentity != 2 {
		t.Fatalf("health: %+v", p.Stats())
	}
	s.Close()
	if err := p.Process(ctx, ev); err == nil || p.Stats().PersistenceFailures != 1 {
		t.Fatal("write failure not reported")
	}
}

func TestTruncationRemainsUncertain(t *testing.T) {
	for _, flags := range []uint16{proto.FlagExeTruncated, proto.FlagExeUnresolved} {
		ev := &proto.Event{PID: 999999, ProcessStartTicks: 1, Flags: flags}
		copy(ev.ExePath[:], "/partial/path")
		if exe, status := EnrichExecutable(ev); exe != "" || status != "unresolved" {
			t.Fatalf("uncertain path accepted: %q %q", exe, status)
		}
	}
}

func TestProcessorPersistsMissingBaselineAlert(t *testing.T) {
	s, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ev := detectionEvent("/bin/app", "/tmp/unapproved.so", 10)
	p := NewProcessor(s.Queries, "production")
	if err := p.Process(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	alerts, err := s.QueryAlerts(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Rule != "MISSING_BASELINE" || p.Stats().MissingBaselines != 1 {
		t.Fatalf("missing-baseline result: alerts=%+v stats=%+v", alerts, p.Stats())
	}
}

func TestProcessorEvaluatesApprovedBaseline(t *testing.T) {
	s, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	seed := detectionEvent("/bin/app", "/lib/libc.so.6", 10)
	if err := s.PersistEvent(ctx, seed, "/bin/app", "source"); err != nil {
		t.Fatal(err)
	}
	if err := s.LearnBaselineEvents(ctx, "/bin/app", "production"); err != nil {
		t.Fatal(err)
	}
	version, err := s.ApproveBaseline(ctx, "/bin/app", "production")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SelectBaseline(ctx, "/bin/app", "production", version.Version); err != nil {
		t.Fatal(err)
	}

	p := NewProcessor(s.Queries, "production")
	known := detectionEvent("/bin/app", "/lib/libc.so.6", 20)
	if err := p.Process(ctx, known); err != nil {
		t.Fatal(err)
	}
	unknown := detectionEvent("/bin/app", "/tmp/evil.so", 30)
	if err := p.Process(ctx, unknown); err != nil {
		t.Fatal(err)
	}
	alerts, err := s.QueryAlerts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Rule != "UNKNOWN_SO" || p.Stats().AlertsPersisted != 1 {
		t.Fatalf("approved-baseline result: alerts=%+v stats=%+v", alerts, p.Stats())
	}
}

func detectionEvent(exe, so string, timestamp uint64) *proto.Event {
	ev := &proto.Event{PID: 7, TID: 7, ProcessStartTicks: 1, TimestampNs: timestamp, EventType: proto.EventSOLoad}
	copy(ev.ExePath[:], exe)
	copy(ev.SOPath[:], so)
	return ev
}

func TestProcessorAcceptsAllApprovedSymbolProviders(t *testing.T) {
	s, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	providers := []string{"/lib/libc.so.6", "/opt/libalternate.so"}
	binding := func(provider string, timestamp uint64) *proto.Event {
		ev := detectionEvent("/bin/app", provider, timestamp)
		ev.EventType = proto.EventSymBind
		copy(ev.Symbol[:], "open")
		copy(ev.RelatedPath[:], "/lib/requester.so")
		return ev
	}
	for i, provider := range providers {
		if err := s.PersistEvent(ctx, binding(provider, uint64(i+1)), "/bin/app", "source"); err != nil {
			t.Fatal(err)
		}
	}
	approve := func(environment string) {
		t.Helper()
		if err := s.LearnBaselineEvents(ctx, "/bin/app", environment); err != nil {
			t.Fatal(err)
		}
		candidates, err := s.ListBaselineCandidates(ctx, store.ListBaselineCandidatesParams{Exe: "/bin/app", EnvironmentKey: environment})
		if err != nil {
			t.Fatal(err)
		}
		if environment == "production" && len(candidates) != 2 {
			t.Fatalf("candidates = %+v", candidates)
		}
		version, err := s.ApproveBaseline(ctx, "/bin/app", environment)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SelectBaseline(ctx, "/bin/app", environment, version.Version); err != nil {
			t.Fatal(err)
		}
	}
	approve("production")
	p := NewProcessor(s.Queries, "production")
	// Both providers, canonical path aliases, and a different requester are
	// permitted within the selected executable/environment profile.
	for i, provider := range []string{providers[0], providers[1], "/lib/./libc.so.6"} {
		ev := binding(provider, uint64(10+i))
		copy(ev.RelatedPath[:], "/lib/requester2.so")
		if err := p.Process(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	alerts, err := s.QueryAlerts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("approved providers triggered alerts: %+v", alerts)
	}

	// A provider approved only in staging must still alert in production.
	outsider := "/tmp/libc.so.6"
	if err := s.PersistEvent(ctx, binding(outsider, 20), "/bin/app", "source"); err != nil {
		t.Fatal(err)
	}
	approve("staging")
	if err := NewProcessor(s.Queries, "staging").Process(ctx, binding(outsider, 21)); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, binding(outsider, 22)); err != nil {
		t.Fatal(err)
	}
	alerts, err = s.QueryAlerts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Rule != "SYMBOL_INTERPOSITION" || alerts[0].Severity != engine.SeverityCritical {
		t.Fatalf("unapproved provider result: %+v", alerts)
	}
	var detail struct {
		Baseline struct {
			Version int64 `json:"version"`
			Value   struct {
				Providers []string `json:"providers"`
			} `json:"value"`
		} `json:"baseline"`
	}
	if err := json.Unmarshal([]byte(alerts[0].Detail), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Baseline.Version != 1 || !reflect.DeepEqual(detail.Baseline.Value.Providers, providers) {
		t.Fatalf("alert lost approved providers: %s", alerts[0].Detail)
	}
}
