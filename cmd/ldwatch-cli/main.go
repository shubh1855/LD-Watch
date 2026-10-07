package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shubh1855/ld-watch/internal/engine/baseline"
	"github.com/shubh1855/ld-watch/internal/identity"
	"github.com/shubh1855/ld-watch/internal/store"
)

const defaultDB = "/var/ldwatch/events.db"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage(os.Stdout)
		return 0
	}
	if args[0] == "--version" {
		fmt.Println("ldwatch-cli (development)")
		return 0
	}
	var err error
	switch args[0] {
	case "alerts":
		err = alerts(args[1:])
	case "baseline":
		err = baselineCommand(args[1:])
	case "watch":
		err = watch(args[1:])
	case "diff":
		err = diff(args[1:])
	case "report":
		err = report(args[1:])
	default:
		usage(os.Stderr)
		return 2
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintln(os.Stderr, err)
	var usageErr *cliUsageError
	if errors.As(err, &usageErr) || isFlagUsage(err) {
		return 2
	}
	return 1
}

func isFlagUsage(err error) bool {
	s := err.Error()
	return strings.Contains(s, "flag provided but not defined") || strings.Contains(s, "flag needs an argument") || strings.Contains(s, "invalid value")
}

type cliUsageError struct{ message string }

func (e *cliUsageError) Error() string { return e.message }
func usage(w *os.File) {
	fmt.Fprintln(w, `Usage: ldwatch-cli <alerts|baseline|watch|diff|report> [flags]
  alerts   List persisted alerts; --severity filters by CRITICAL, HIGH, MEDIUM or LOW
  baseline Display an active approved profile (also supports profile/inspect/approve/use)
  watch    Stream stored events using an increasing database row cursor
  diff     Compare observations from --source events with an active approved profile
  report   Export persisted alerts as JSON; --since/--until accept YYYY-MM-DD or RFC3339
Global database option: --db PATH (default `+defaultDB+`).`)
}

func open(path string) (*store.Queries, func(), error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, &cliUsageError{"--db must not be empty"}
	}
	db, e := store.Open(path)
	if e != nil {
		return nil, nil, e
	}
	if e = store.Migrate(db); e != nil {
		db.Close()
		return nil, nil, e
	}
	return store.New(db), func() { db.Close() }, nil
}

func alerts(args []string) error {
	f := flag.NewFlagSet("alerts", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	dbp := f.String("db", defaultDB, "SQLite database path")
	sev := f.String("severity", "", "severity: CRITICAL, HIGH, MEDIUM, LOW")
	limit := f.Int64("limit", 100, "maximum rows (1..10000)")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return &cliUsageError{"alerts takes flags only"}
	}
	if *limit < 1 || *limit > 10000 {
		return &cliUsageError{"--limit must be 1..10000"}
	}
	severity := strings.ToUpper(*sev)
	if severity != "" && !validSeverity(severity) {
		return &cliUsageError{"--severity must be CRITICAL, HIGH, MEDIUM or LOW"}
	}
	q, close, e := open(*dbp)
	if e != nil {
		return e
	}
	defer close()
	ctx := context.Background()
	var rows []store.Alert
	if severity == "" {
		rows, e = q.ListAlerts(ctx, *limit)
	} else {
		rows, e = q.ListAlertsBySeverity(ctx, store.ListAlertsBySeverityParams{Severity: severity, Limit: *limit})
	}
	if e != nil {
		return e
	}
	for _, a := range rows {
		fmt.Printf("%s\t%s\t%s\t%s\tpid=%d\t%s\t%s\n", time.Unix(0, a.Timestamp).UTC().Format(time.RFC3339Nano), a.Severity, a.Rule, a.ProcessKey, a.Pid, a.Exe, a.Detail)
	}
	return nil
}
func validSeverity(s string) bool {
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return true
	}
	return false
}

func baselineCommand(args []string) error {
	if len(args) == 0 {
		return &cliUsageError{"expected profile, inspect, approve, use, or show"}
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Println("Usage: ldwatch-cli baseline <profile|inspect|approve|use|show> --exe PATH --environment-key LABEL [flags]")
		return nil
	}
	if args[0] == "show" {
		return showBaseline(args[1:])
	}
	action := args[0]
	fs := flag.NewFlagSet("baseline "+action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dbPath := fs.String("db", defaultDB, "SQLite database path")
	exe := fs.String("exe", "", "executable path")
	env := fs.String("environment-key", "", "explicit profile environment label")
	version := fs.Int("version", 0, "approved profile version")
	library := fs.String("library", "", "exact library path to change candidate optionality")
	optional := fs.Bool("optional", false, "mark candidate library optional before approval")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if *exe == "" || *env == "" {
		return &cliUsageError{"--exe and --environment-key are required"}
	}
	db, e := store.Open(*dbPath)
	if e != nil {
		return e
	}
	defer db.Close()
	if e = store.Migrate(db); e != nil {
		return e
	}
	p := baseline.New(db)
	ctx := context.Background()
	switch action {
	case "profile":
		if e = p.ProfileExecutable(ctx, *exe, *env); e != nil {
			return e
		}
		v, e := p.Candidate(ctx, *exe, *env)
		if e == nil {
			fmt.Printf("candidate %s\n", v)
		}
		return e
	case "inspect":
		var v *baseline.Profile
		if *version == 0 {
			v, e = p.Candidate(ctx, *exe, *env)
		} else {
			v, e = p.Inspect(ctx, *exe, *env, *version)
		}
		if e != nil {
			return e
		}
		printProfile(v)
		return nil
	case "approve":
		if *library != "" {
			if e = p.SetOptional(ctx, *exe, *env, identity.Library(*library), *optional); e != nil {
				return e
			}
		}
		v, e := p.Approve(ctx, *exe, *env)
		if e == nil {
			fmt.Printf("approved %s (%s) v%d\n", *exe, *env, v)
		}
		return e
	case "use":
		if *version < 1 {
			return &cliUsageError{"--version must be positive"}
		}
		return p.Activate(ctx, *exe, *env, *version)
	default:
		return &cliUsageError{fmt.Sprintf("unknown baseline action %q", action)}
	}
}
func showBaseline(args []string) error {
	f := flag.NewFlagSet("baseline show", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	dbp := f.String("db", defaultDB, "SQLite database path")
	exe := f.String("exe", "", "executable path")
	env := f.String("environment-key", "", "explicit profile environment label")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *exe == "" || *env == "" {
		return &cliUsageError{"baseline show requires --exe and --environment-key"}
	}
	q, close, e := open(*dbp)
	if e != nil {
		return e
	}
	defer close()
	v, entries, e := q.ActiveBaseline(context.Background(), *exe, *env)
	if e != nil {
		return e
	}
	fmt.Printf("approved %s (%s) v%d\n", v.Exe, v.EnvironmentKey, v.Version)
	for _, x := range entries {
		kind := x.EntryType
		if kind == "LOAD" {
			state := "required"
			if x.Optional != 0 {
				state = "optional"
			}
			fmt.Printf("LOAD\t%s\t%s\n", x.Identity, state)
		} else {
			fmt.Printf("%s\t%s\t%s\n", kind, x.Identity, x.Symbol)
		}
	}
	return nil
}
func printProfile(v *baseline.Profile) {
	fmt.Printf("%s\n", v)
	for _, l := range v.ExpectedLibraries() {
		s := "required"
		if l.Optional {
			s = "optional"
		}
		fmt.Printf("LOAD\t%s\t%s\n", l.Identity, s)
	}
	for _, s := range v.SymbolProviders() {
		fmt.Printf("SYMBOL_PROVIDER\t%s\t%s\n", s.Name, s.Provider)
	}
}

func watch(args []string) error {
	f := flag.NewFlagSet("watch", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	dbp := f.String("db", defaultDB, "SQLite database path")
	pid := f.Int64("pid", 0, "filter by PID")
	after := f.Int64("after", 0, "resume after event row ID")
	interval := f.Duration("interval", 500*time.Millisecond, "poll interval")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *pid < 0 || *after < 0 || *interval < 50*time.Millisecond {
		return &cliUsageError{"watch: invalid PID/cursor/interval"}
	}
	q, close, e := open(*dbp)
	if e != nil {
		return e
	}
	defer close()
	cursor := *after
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	ctx := context.Background()
	for {
		rows, err := q.ListLoaderEvents(ctx, store.ListLoaderEventsParams{ID: cursor, Limit: 500})
		if err != nil {
			return err
		}
		for _, ev := range rows {
			if ev.ID > cursor {
				cursor = ev.ID
			}
			if *pid != 0 && ev.Pid != *pid {
				continue
			}
			fmt.Printf("id=%d\t%s\tpid=%d\tprocess=%s\t%s\t%s\t%s\n", ev.ID, time.Unix(0, ev.Timestamp).UTC().Format(time.RFC3339Nano), ev.Pid, ev.ProcessKey, ev.EventType, ev.Exe, ev.SubjectPath)
		}
		<-tick.C
	}
}

func diff(args []string) error {
	f := flag.NewFlagSet("diff", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	dbp := f.String("db", defaultDB, "SQLite database path")
	source := f.String("source", "", "observation source; currently events")
	exe := f.String("exe", "", "executable path")
	env := f.String("environment-key", "", "baseline environment label")
	since := f.Int64("since-id", 0, "only observations with row ID greater than this")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *source != "events" || *exe == "" || *env == "" || *since < 0 {
		return &cliUsageError{"diff requires --source events, --exe, --environment-key; --since-id must be nonnegative"}
	}
	q, close, e := open(*dbp)
	if e != nil {
		return e
	}
	defer close()
	v, entries, e := q.ActiveBaseline(context.Background(), *exe, *env)
	if e != nil {
		return e
	}
	expected := map[string]bool{}
	required := map[string]bool{}
	for _, x := range entries {
		if x.EntryType == "LOAD" {
			expected[x.Identity] = true
			if x.Optional == 0 {
				required[x.Identity] = true
			}
		}
	}
	observed := map[string]bool{}
	cursor := *since
	for {
		rows, err := q.ListLoaderEvents(context.Background(), store.ListLoaderEventsParams{ID: cursor, Limit: 500})
		if err != nil {
			return err
		}
		for _, x := range rows {
			if x.ID > cursor {
				cursor = x.ID
			}
			if x.Exe == *exe && x.EventType == "LOAD" && x.IdentityStatus == "source" && x.SubjectPath != "" {
				observed[identity.Library(x.SubjectPath)] = true
			}
		}
		if len(rows) < 500 {
			break
		}
	}
	fmt.Printf("source=events baseline=v%d executable=%s\n", v.Version, *exe)
	for p := range observed {
		if !expected[p] {
			fmt.Printf("UNEXPECTED\t%s\n", p)
		}
	}
	for p := range required {
		if !observed[p] {
			fmt.Printf("MISSING\t%s\n", p)
		}
	}
	return nil
}

func report(args []string) error {
	f := flag.NewFlagSet("report", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	dbp := f.String("db", defaultDB, "SQLite database path")
	out := f.String("output", "-", "JSON output file or - for stdout")
	since := f.String("since", "", "start date/time inclusive")
	until := f.String("until", "", "end date/time exclusive")
	severity := f.String("severity", "", "severity filter")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return &cliUsageError{"report takes flags only"}
	}
	start, e := parseDate(*since)
	if e != nil {
		return &cliUsageError{"invalid --since: " + e.Error()}
	}
	end, e := parseDate(*until)
	if e != nil {
		return &cliUsageError{"invalid --until: " + e.Error()}
	}
	if start != 0 && end != 0 && start >= end {
		return &cliUsageError{"--since must be earlier than --until"}
	}
	s := strings.ToUpper(*severity)
	if s != "" && !validSeverity(s) {
		return &cliUsageError{"invalid --severity"}
	}
	q, close, e := open(*dbp)
	if e != nil {
		return e
	}
	defer close()
	const pageSize int64 = 1000
	filtered := make([]store.Alert, 0)
	for offset := int64(0); ; offset += pageSize {
		rows, err := q.ListAlertsForReport(context.Background(), store.ListAlertsForReportParams{
			Severity: s, Start: start, End: end, Limit: pageSize, Offset: offset,
		})
		if err != nil {
			return err
		}
		filtered = append(filtered, rows...)
		if int64(len(rows)) < pageSize {
			break
		}
	}
	data, e := json.MarshalIndent(filtered, "", "  ")
	if e != nil {
		return e
	}
	data = append(data, '\n')
	if *out == "-" {
		_, e = os.Stdout.Write(data)
		return e
	}
	return os.WriteFile(*out, data, 0600)
}
func parseDate(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	var t time.Time
	var e error
	if len(s) == 10 {
		t, e = time.Parse("2006-01-02", s)
	} else {
		t, e = time.Parse(time.RFC3339, s)
	}
	if e != nil {
		return 0, e
	}
	return t.UnixNano(), nil
}
