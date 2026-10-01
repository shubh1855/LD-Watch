// Package integration_test exercises the full event pipeline:
// unix socket → listener → worker goroutines → SQLite.
// It mirrors what cmd/collector/main.go does without importing package main.
package integration_test

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shubh1855/ld-watch/internal/collector"
	"github.com/shubh1855/ld-watch/internal/proto"
	"github.com/shubh1855/ld-watch/internal/socket"
	"github.com/shubh1855/ld-watch/internal/store"
)

// ---- helpers ----------------------------------------------------------------

// pipeline wires a Listener and a store together with N workers,
// mirroring cmd/collector/main.go — without importing package main.
type pipeline struct {
	SockPath string
	Queries  *store.Queries
	ln       *socket.Listener
	db       *sql.DB
	wg       sync.WaitGroup
}

func newPipeline(t *testing.T, numWorkers int) *pipeline {
	t.Helper()

	sockPath := filepath.Join(t.TempDir(), "ldwatch-test.sock")

	ln, err := socket.New(sockPath)
	if err != nil {
		t.Fatalf("socket.New: %v", err)
	}

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := store.Migrate(db); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	q := store.New(db)
	p := &pipeline{SockPath: sockPath, Queries: q, ln: ln, db: db}
	processor := collector.NewProcessor(q)

	ln.Start()

	ctx := context.Background()
	for i := 0; i < numWorkers; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for ev := range ln.Events {
				if err := processor.Process(ctx, ev); err != nil {
					t.Errorf("process event: %v", err)
				}
			}
		}()
	}

	return p
}

// drain stops the listener (which closes Events after all handleConn goroutines
// finish), then waits for all workers to exit their range loops.
// Call this after all senders are done to get a consistent DB snapshot.
func (p *pipeline) drain(t *testing.T) {
	t.Helper()
	p.ln.Stop()
	p.wg.Wait()
}

// close releases the DB. Call after assertions are done.
func (p *pipeline) close(t *testing.T) {
	t.Helper()
	if err := p.db.Close(); err != nil {
		t.Errorf("db.Close: %v", err)
	}
}

// sendEvents dials sockPath, writes all events, then closes the connection.
func sendEvents(t *testing.T, sockPath string, evs ...*proto.Event) {
	t.Helper()
	conn, err := net.Dial("unixpacket", sockPath)
	if err != nil {
		t.Errorf("dial: %v", err)
		return
	}
	defer conn.Close()
	for _, ev := range evs {
		if _, err := conn.Write(ev.MarshalBinary()); err != nil {
			t.Errorf("binary.Write: %v", err)
			return
		}
	}
}

func makeSOEvent(pid uint32, soPath string, ts uint64) *proto.Event {
	ev := &proto.Event{
		PID:        pid,
		TID:        pid,
		EventType:  proto.EventSOLoad,
		Mechanism:  proto.MechLDPreload,
		TimeStamNs: ts,
	}
	copy(ev.SOPath[:], soPath)
	return ev
}

func makeSymbolEvent(pid uint32, soPath, sym string, addr, ts uint64) *proto.Event {
	ev := &proto.Event{
		PID:          pid,
		TID:          pid,
		EventType:    proto.EventSymBind,
		ResolvedAddr: addr,
		TimeStamNs:   ts,
	}
	copy(ev.SOPath[:], soPath)
	copy(ev.RelatedPath[:], "requester")
	copy(ev.Symbol[:], sym)
	return ev
}

func waitForSOEventCount(t *testing.T, q *store.Queries, pids []int64, want int) {
	t.Helper()
	waitForEventCounts(t, q, pids, want, 0)
}

func waitForEventCounts(t *testing.T, q *store.Queries, pids []int64, wantSO, wantSymbol int) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		soTotal := 0
		symbolTotal := 0
		for _, pid := range pids {
			soRows, err := q.ListSOEventsForPID(ctx, pid)
			if err != nil {
				t.Fatalf("ListSOEventsForPID pid=%d: %v", pid, err)
			}
			symbolRows, err := q.ListSymbolEventsForPID(ctx, pid)
			if err != nil {
				t.Fatalf("ListSymbolEventsForPID pid=%d: %v", pid, err)
			}
			soTotal += len(soRows)
			symbolTotal += len(symbolRows)
		}
		if soTotal == wantSO && symbolTotal == wantSymbol {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d so_events and %d symbol_events", wantSO, wantSymbol)
}

// ---- tests ------------------------------------------------------------------

// TestCollectorReceivesSOLoadEvent verifies that one SO_LOAD event written
// to the socket appears on the Events channel with the correct fields.
func TestCollectorReceivesSOLoadEvent(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "ldwatch-test.sock")
	ln, err := socket.New(sockPath)
	if err != nil {
		t.Fatalf("socket.New: %v", err)
	}
	ln.Start()

	ev := makeSOEvent(1111, "/lib/x86_64-linux-gnu/libc.so.6", 1_000_000)

	go sendEvents(t, sockPath, ev)

	var got *proto.Event
	select {
	case got = <-ln.Events:
	case <-time.After(2 * time.Second):
		ln.Stop()
		t.Fatal("timeout waiting for event")
	}
	ln.Stop()
	if got.PID != 1111 {
		t.Errorf("PID: got %d, want 1111", got.PID)
	}
	if got.EventType != proto.EventSOLoad {
		t.Errorf("EventType: got %d, want %d (SO_LOAD)", got.EventType, proto.EventSOLoad)
	}
	if got.SOPathStr() != "/lib/x86_64-linux-gnu/libc.so.6" {
		t.Errorf("SOPath: got %q", got.SOPathStr())
	}
	if got.Mechanism != proto.MechLDPreload {
		t.Errorf("Mechanism: got %d, want %d (LD_PRELOAD)", got.Mechanism, proto.MechLDPreload)
	}
	if got.PeerPID <= 0 {
		t.Errorf("PeerPID: got %d, want a positive credential", got.PeerPID)
	}
}

// TestCollectorWritesToSQLite verifies that SO_LOAD and SYM_BIND events
// sent over the socket are persisted to the database by the workers.
func TestCollectorWritesToSQLite(t *testing.T) {
	p := newPipeline(t, 2)

	sendEvents(t, p.SockPath,
		makeSOEvent(2222, "/usr/lib/libssl.so.3", 100),
		makeSymbolEvent(2222, "/usr/lib/libssl.so.3", "SSL_read", 0xdeadbeef, 200),
	)

	// Wait for persistence before stopping the listener; otherwise Stop can close
	// the accept loop before it drains the kernel's pending connection queue.
	waitForEventCounts(t, p.Queries, []int64{2222}, 1, 1)

	p.drain(t)
	defer p.close(t)

	ctx := context.Background()

	soRows, err := p.Queries.ListSOEventsForPID(ctx, 2222)
	if err != nil {
		t.Fatalf("ListSOEventsForPID: %v", err)
	}
	if len(soRows) != 1 {
		t.Fatalf("so_events: got %d rows, want 1", len(soRows))
	}
	if soRows[0].SoPath != "/usr/lib/libssl.so.3" {
		t.Errorf("so_path: got %q", soRows[0].SoPath)
	}
	if soRows[0].Mechanism != "LD_PRELOAD" {
		t.Errorf("mechanism: got %q, want LD_PRELOAD", soRows[0].Mechanism)
	}

	symRows, err := p.Queries.ListSymbolEventsForPID(ctx, 2222)
	if err != nil {
		t.Fatalf("ListSymbolEventsForPID: %v", err)
	}
	if len(symRows) != 1 {
		t.Fatalf("symbol_events: got %d rows, want 1", len(symRows))
	}
	if symRows[0].SymbolName != "SSL_read" {
		t.Errorf("symbol_name: got %q", symRows[0].SymbolName)
	}
	if symRows[0].ResolvedAddr != "deadbeef" {
		t.Errorf("resolved_addr: got %s, want deadbeef", symRows[0].ResolvedAddr)
	}
}

// TestCollectorHandlesMultipleConnections verifies that events arriving
// concurrently from N separate connections all land in the database.
func TestCollectorHandlesMultipleConnections(t *testing.T) {
	const connections = 5
	const eventsPerConn = 3

	p := newPipeline(t, 4)

	var senderWg sync.WaitGroup
	for c := 0; c < connections; c++ {
		senderWg.Add(1)
		pid := uint32(3000 + c) // unique PID per connection
		go func(pid uint32) {
			defer senderWg.Done()
			evs := make([]*proto.Event, eventsPerConn)
			for i := range evs {
				evs[i] = makeSOEvent(pid, "/lib/libc.so.6", uint64(i+1)*1000)
			}
			sendEvents(t, p.SockPath, evs...)
		}(pid)
	}

	// All senders done → all connections closed. Wait until workers persist every
	// event before stopping listener; otherwise Stop can close the listener before
	// the accept loop drains pending kernel connections.
	senderWg.Wait()

	expected := connections * eventsPerConn
	pids := make([]int64, 0, connections)
	for c := 0; c < connections; c++ {
		pids = append(pids, int64(3000+c))
	}
	waitForSOEventCount(t, p.Queries, pids, expected)

	p.drain(t)
	defer p.close(t)

	ctx := context.Background()
	total := 0
	for c := 0; c < connections; c++ {
		rows, err := p.Queries.ListSOEventsForPID(ctx, int64(3000+c))
		if err != nil {
			t.Fatalf("ListSOEventsForPID pid=%d: %v", 3000+c, err)
		}
		if len(rows) != eventsPerConn {
			t.Errorf("pid=%d: got %d events, want %d", 3000+c, len(rows), eventsPerConn)
		}
		total += len(rows)
	}

	if total != expected {
		t.Errorf("total so_events: got %d, want %d", total, expected)
	}
}
