package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/shubh1855/ld-watch/internal/engine/baseline"
	"github.com/shubh1855/ld-watch/internal/identity"
	"github.com/shubh1855/ld-watch/internal/store"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "baseline" {
		fmt.Fprintln(os.Stderr, "usage: ldwatch-cli baseline <profile|inspect|approve|use> [flags]")
		os.Exit(2)
	}
	if err := baselineCommand(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "baseline:", err)
		os.Exit(1)
	}
}
func baselineCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("expected profile, inspect, approve, or use")
	}
	action := args[0]
	fs := flag.NewFlagSet("baseline "+action, flag.ContinueOnError)
	dbPath := fs.String("db", "/var/ldwatch/events.db", "SQLite database path")
	exe := fs.String("exe", "", "executable path")
	env := fs.String("environment-key", "", "explicit profile environment label")
	version := fs.Int("version", 0, "approved profile version")
	library := fs.String("library", "", "exact library path to change candidate optionality")
	optional := fs.Bool("optional", false, "mark the candidate library optional before approval")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *exe == "" || *env == "" {
		return fmt.Errorf("--exe and --environment-key are required")
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := store.Migrate(db); err != nil {
		return err
	}
	p := baseline.New(db)
	ctx := context.Background()
	switch action {
	case "profile":
		if err := p.ProfileExecutable(ctx, *exe, *env); err != nil {
			return err
		}
		v, err := p.Candidate(ctx, *exe, *env)
		if err != nil {
			return err
		}
		fmt.Printf("candidate %s\n", v)
		return nil
	case "inspect":
		var v *baseline.Profile
		if *version == 0 {
			v, err = p.Candidate(ctx, *exe, *env)
		} else {
			v, err = p.Inspect(ctx, *exe, *env, *version)
		}
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", v)
		for _, l := range v.ExpectedLibraries() {
			state := "required"
			if l.Optional {
				state = "optional"
			}
			fmt.Printf("LOAD\t%s\t%s\n", l.Identity, state)
		}
		for _, s := range v.SymbolProviders() {
			fmt.Printf("SYMBOL_PROVIDER\t%s\t%s\n", s.Name, s.Provider)
		}
		return nil
	case "approve":
		if *library != "" {
			if err := p.SetOptional(ctx, *exe, *env, identity.Library(*library), *optional); err != nil {
				return err
			}
		}
		v, err := p.Approve(ctx, *exe, *env)
		if err != nil {
			return err
		}
		fmt.Printf("approved %s (%s) v%d\n", *exe, *env, v)
		return nil
	case "use":
		if *version < 1 {
			return fmt.Errorf("--version is required")
		}
		return p.Activate(ctx, *exe, *env, *version)
	default:
		return fmt.Errorf("unknown action %q", action)
	}
}
