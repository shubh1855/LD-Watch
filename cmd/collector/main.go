package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/shubh1855/ld-watch/internal/collector"
	"github.com/shubh1855/ld-watch/internal/socket"
	"github.com/shubh1855/ld-watch/internal/store"
)

var (
	dbPath   = flag.String("db", "/var/ldwatch/events.db", "SQLite DB path")
	sockPath = flag.String("socket", "/run/ldwatch.sock", "Unix socket path")
	workers  = flag.Int("workers", 4, "Event processor goroutines")
)

func main() {
	flag.Parse()

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("[collector] open db: %v", err)
	}
	defer db.Close()

	if err := store.Migrate(db); err != nil {
		log.Fatalf("[collector] migrate: %v", err)
	}

	ln, err := socket.New(*sockPath)
	if err != nil {
		log.Fatalf("[collector] socket: %v", err)
	}
	ln.Start()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Printf("[collector] received %s, shutting down...", s)
		ln.Stop()
	}()

	ctx := context.Background()
	processor := collector.NewProcessor(store.New(db), nil)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ev := range ln.Events {
				if err := processor.Process(ctx, ev); err != nil {
					log.Printf("[collector] process event: %v", err)
				}
			}
		}()
	}

	wg.Wait()
	log.Println("[collector] all workers done, exiting")
}
