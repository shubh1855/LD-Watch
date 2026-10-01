package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/shubh1855/ld-watch/internal/collector"
	"github.com/shubh1855/ld-watch/internal/socket"
	"github.com/shubh1855/ld-watch/internal/store"
)

var (
	dbPath   = flag.String("db", "/var/ldwatch/events.db", "SQLite DB path")
	sockPath = flag.String("socket", "/run/ldwatch/ldwatch.sock", "Unix socket path")
	workers  = flag.Int("workers", 4, "Event processor goroutines")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if *workers <= 0 {
		return fmt.Errorf("workers must be positive (got %d)", *workers)
	}
	if err := socket.ValidatePath(*sockPath); err != nil {
		return fmt.Errorf("validate socket path: %w", err)
	}

	if err := ensureParentDir(*dbPath); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}
	if err := ensureParentDir(*sockPath); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	db, err := store.NewStore(*dbPath)
	if err != nil {
		return fmt.Errorf("initialize db: %w", err)
	}
	defer db.Close()

	ln, err := socket.New(*sockPath)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer ln.Stop()
	ln.Start()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		s := <-sig
		log.Printf("[collector] received %s, shutting down...", s)
		ln.Stop()
	}()

	ctx := context.Background()
	processor := collector.NewProcessor(db.Queries)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ev := range ln.Events {
				if err := processor.Process(ctx, ev); err != nil {
					failures := processor.Stats().PersistenceFailures
					if failures <= 5 || failures%100 == 0 {
						log.Printf("[collector] persistence failures=%d: %v", failures, err)
					}
				}
			}
		}()
	}

	wg.Wait()
	log.Printf("[collector] persistence health: %+v", processor.Stats())
	log.Println("[collector] all workers done, exiting")
	return nil
}

func ensureParentDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o755)
}
